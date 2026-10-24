"""前端可設定的金鑰與模型。

金鑰解析順序：環境變數（含 .env）→ Windows 認證管理員（keyring）→ 未設定。
每次呼叫時才解析，改完立即生效。金鑰只存 keyring，絕不落地成明文檔案；
keyring 不可用時直接拒絕，不降級。非機密設定（模型、更新時間）存 data/settings.json。
"""
import json
import os
import re
import threading
from datetime import datetime
from typing import Literal, Optional

import anthropic
import httpx
import keyring

import database
from postprocess import TW_TZ

KEYRING_SERVICE = "Alert-Message-Management-System"

# 前端名稱 → 環境變數／keyring 條目名稱
KEY_NAMES = {"vt": "VT_API_KEY", "llm": "LLM_API_KEY"}

DEFAULT_LLM_MODEL = "claude-sonnet-5-5"
# 不開放任意字串：模型只能從這份清單選
ALLOWED_MODELS = ("claude-sonnet-5-5", "claude-opus-5-5", "claude-haiku-5-5")

VT_BASE_URL = "https://www.virustotal.com/api/v3"

# 金鑰只允許可見 ASCII（無空白、無控制字元），避免變成 header 注入或奇怪字元
KEY_PATTERN = re.compile(r"^[\x21-\x7e]{1,512}$")

# 允許使用的 keyring 後端（完整類別名稱）。只放真正加密保存的後端：裝了 keyrings.alt、
# 設了 PYTHON_KEYRING_BACKEND 或 keyringrc 指到 PlaintextKeyring 時，金鑰會明文寫進磁碟。
# ChainerBackend 不在白名單：它會依序委派給所有可用後端，實際寫到哪一個取決於環境。
# 測試以 monkeypatch 把 in-memory 後端加進來。
ALLOWED_KEYRING_BACKENDS = frozenset({"keyring.backends.Windows.WinVaultKeyring"})

_file_lock = threading.Lock()


class KeyringUnavailableError(Exception):
    """認證管理員不可用或讀寫失敗。訊息不含金鑰。"""


class ValidationFailedError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        super().__init__(message)


class SourceLockedError(Exception):
    """設定來自 .env／環境變數，前端不可改。"""


def _settings_path():
    return database.BASE_DIR / "data" / "settings.json"


def _read_file() -> dict:
    try:
        data = json.loads(_settings_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_file(data: dict) -> None:
    path = _settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def _update_file(mutate) -> None:
    with _file_lock:
        path = _settings_path()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("not a dict")
        except FileNotFoundError:
            data = {}
        except (OSError, ValueError):
            # 損毀的檔案先改名備份（已存在就覆蓋），不悄悄丟掉
            try:
                os.replace(path, path.with_name(path.name + ".bak"))
            except OSError:
                pass
            data = {}
        mutate(data)
        _write_file(data)


def _now() -> str:
    return datetime.now(TW_TZ).isoformat(timespec="seconds")


def _keyring_error(action: str, e: Exception) -> KeyringUnavailableError:
    return KeyringUnavailableError(
        f"Windows 認證管理員（keyring）無法{action}：{type(e).__name__}。"
        "為避免明文落地，不會改用其他方式儲存；請改在 .env 設定。")


def _require_safe_backend() -> None:
    """讀寫 keyring 前都要檢查實際使用的後端，不在白名單一律拒絕。"""
    try:
        backend = keyring.get_keyring()
    except Exception as e:
        raise _keyring_error("取得後端", e) from None
    cls = type(backend)
    if f"{cls.__module__}.{cls.__qualname__}" not in ALLOWED_KEYRING_BACKENDS:
        raise KeyringUnavailableError(
            f"keyring 後端 {cls.__name__} 不在安全白名單內（可能以明文儲存）。"
            "為避免明文落地，不會使用它；請改在 .env 設定。")


def _keyring_get(name: str) -> Optional[str]:
    _require_safe_backend()
    try:
        return keyring.get_password(KEYRING_SERVICE, name) or None
    except Exception as e:  # keyring 後端的例外型別五花八門，一律視為不可用
        raise _keyring_error("讀取", e) from None


def get_key(kind: str) -> Optional[str]:
    """解析金鑰：環境變數優先，其次 keyring。keyring 壞掉時丟 KeyringUnavailableError。"""
    name = KEY_NAMES[kind]
    env = os.environ.get(name)
    if env:
        return env
    return _keyring_get(name)


def _hint(value: str) -> Optional[str]:
    # 太短的金鑰露出末四碼等於洩漏大半
    return "…" + value[-4:] if len(value) >= 12 else None


def key_status(kind: str) -> dict:
    name = KEY_NAMES[kind]
    env = os.environ.get(name)
    if env:
        return {"configured": True, "source": "env", "hint": _hint(env), "updated_at": None}
    value = _keyring_get(name)
    if value is None:
        return {"configured": False, "source": "none", "hint": None, "updated_at": None}
    updated = (_read_file().get("key_updated_at") or {}).get(kind)
    return {"configured": True, "source": "ui", "hint": _hint(value), "updated_at": updated}


def get_model() -> tuple[str, Literal["env", "ui", "default"]]:
    env = os.environ.get("LLM_MODEL")
    if env:
        return env, "env"
    saved = _read_file().get("model")
    if saved in ALLOWED_MODELS:
        return saved, "ui"
    return DEFAULT_LLM_MODEL, "default"


def get_status() -> dict:
    keys = {}
    keyring_error = None
    for kind in KEY_NAMES:
        try:
            keys[kind] = key_status(kind)
        except KeyringUnavailableError as e:
            keyring_error = str(e)
            keys[kind] = {"configured": False, "source": "none", "hint": None, "updated_at": None}
    model, source = get_model()
    return {
        "keys": keys,
        "keyring_error": keyring_error,
        "model": {"value": model, "source": source, "options": list(ALLOWED_MODELS)},
    }


# ---------- 儲存前驗證（錯誤訊息一律不含金鑰） ----------

def _validate_llm(value: str) -> None:
    try:
        with anthropic.Anthropic(api_key=value, timeout=anthropic.Timeout(15.0, connect=10.0),
                                 max_retries=0) as client:
            client.models.list(limit=1)
    except anthropic.APITimeoutError:
        raise ValidationFailedError(504, "驗證逾時：無法在時限內連線至 Anthropic") from None
    except anthropic.APIConnectionError as e:
        raise ValidationFailedError(502, f"無法連線至 Anthropic：{type(e).__name__}") from None
    except (anthropic.AuthenticationError, anthropic.PermissionDeniedError):
        raise ValidationFailedError(400, "Anthropic 拒絕這把金鑰（無效或無權限）") from None
    except anthropic.APIStatusError as e:
        if e.status_code == 429 or e.status_code >= 500:
            raise ValidationFailedError(502, f"Anthropic 暫時無法驗證：{e.status_code}") from None
        raise ValidationFailedError(400, f"Anthropic 驗證失敗：{e.status_code}") from None


def _validate_vt(value: str) -> None:
    # 金鑰只放 x-apikey 標頭，絕不進 URL（httpx 會把 URL 印進 log）
    try:
        response = httpx.get(f"{VT_BASE_URL}/ip_addresses/8.8.8.8",
                             headers={"x-apikey": value}, timeout=10.0)
    except httpx.TimeoutException:
        raise ValidationFailedError(504, "驗證逾時：無法在時限內連線至 VirusTotal") from None
    except httpx.RequestError as e:
        raise ValidationFailedError(502, f"無法連線至 VirusTotal：{type(e).__name__}") from None
    code = response.status_code
    if code == 200:
        return
    if code in (401, 403):
        raise ValidationFailedError(400, "VirusTotal 拒絕這把金鑰（無效或無權限）")
    if code == 429 or code >= 500:
        raise ValidationFailedError(502, f"VirusTotal 暫時無法驗證：{code}")
    raise ValidationFailedError(400, f"VirusTotal 驗證失敗：{code}")


_VALIDATORS = {"vt": _validate_vt, "llm": _validate_llm}


def _clear_llm_client() -> None:
    # 換／刪金鑰後清掉共用 client，舊金鑰不再留在記憶體裡也不會被沿用
    import lookup
    lookup._client.cache_clear()


def _try_update_file(mutate) -> None:
    """金鑰已經寫入／刪除 keyring 後，settings.json 只是附屬資訊（更新時間）。
    它失敗不能讓整個請求失敗，否則 client 快取不會清、使用者以為沒存成功。"""
    try:
        _update_file(mutate)
    except OSError:
        pass


def set_key(kind: str, value: str) -> dict:
    name = KEY_NAMES[kind]
    if os.environ.get(name):
        raise SourceLockedError(f"{name} 由 .env 設定，無法從前端修改")
    value = value.strip()
    if not KEY_PATTERN.match(value):
        raise ValidationFailedError(400, "金鑰格式不正確（只允許可見 ASCII 字元、不含空白）")
    _VALIDATORS[kind](value)
    _require_safe_backend()
    try:
        keyring.set_password(KEYRING_SERVICE, name, value)
    except Exception as e:
        raise _keyring_error("寫入", e) from None

    def mark(data):
        data.setdefault("key_updated_at", {})[kind] = _now()
    _try_update_file(mark)
    if kind == "llm":
        _clear_llm_client()
    return key_status(kind)


def delete_key(kind: str) -> dict:
    name = KEY_NAMES[kind]
    if os.environ.get(name):
        raise SourceLockedError(f"{name} 由 .env 設定，無法從前端刪除")
    if _keyring_get(name) is not None:
        try:
            keyring.delete_password(KEYRING_SERVICE, name)
        except Exception as e:
            raise _keyring_error("刪除", e) from None
    _try_update_file(lambda data: (data.get("key_updated_at") or {}).pop(kind, None))
    if kind == "llm":
        _clear_llm_client()
    return key_status(kind)


def set_model(model: str) -> dict:
    if os.environ.get("LLM_MODEL"):
        raise SourceLockedError("LLM_MODEL 由 .env 設定，無法從前端修改")
    if model not in ALLOWED_MODELS:
        raise ValueError("不支援的模型")
    _update_file(lambda data: data.__setitem__("model", model))
    return get_status()["model"]
