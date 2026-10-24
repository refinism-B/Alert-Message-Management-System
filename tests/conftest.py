import os

import pytest

# TestClient 預設 Host 為 testserver；正式白名單不含它，測試靠環境變數追加
os.environ.setdefault("ALLOWED_HOSTS", "testserver")

import keyring  # noqa: E402
import keyring.backend  # noqa: E402
import keyring.errors  # noqa: E402

import lookup  # noqa: E402
import settings_store  # noqa: E402


class MemoryKeyring(keyring.backend.KeyringBackend):
    """測試用的記憶體後端，不碰真實的 Windows 認證管理員。"""
    priority = 1

    def __init__(self):
        self.items: dict[tuple[str, str], str] = {}

    def get_password(self, service, username):
        return self.items.get((service, username))

    def set_password(self, service, username, password):
        self.items[(service, username)] = password

    def delete_password(self, service, username):
        if (service, username) not in self.items:
            raise keyring.errors.PasswordDeleteError("not found")
        del self.items[(service, username)]


@pytest.fixture(autouse=True)
def memory_keyring(monkeypatch):
    previous = keyring.get_keyring()
    backend = MemoryKeyring()
    # 正式白名單只有 WinVaultKeyring；測試把記憶體後端加進去
    monkeypatch.setattr(
        settings_store, "ALLOWED_KEYRING_BACKENDS",
        settings_store.ALLOWED_KEYRING_BACKENDS | {f"{MemoryKeyring.__module__}.{MemoryKeyring.__qualname__}"})
    keyring.set_keyring(backend)
    yield backend
    keyring.set_keyring(previous)


@pytest.fixture(autouse=True)
def _isolated_settings_file(tmp_path, monkeypatch):
    """settings.json 一律指向 tmp_path，測試不會寫到真實的 data/settings.json。"""
    path = tmp_path / "data" / "settings.json"
    monkeypatch.setattr(settings_store, "_settings_path", lambda: path)
    return path


@pytest.fixture(autouse=True)
def _reset_lookup_state():
    """lookup 有三份模組層級狀態：VT 快取、whoisit bootstrap 失敗時間、共用的
    Anthropic client。不清掉的話，前一個測試的快取或 client 會漏進下一個測試。"""
    lookup._vt_cache.clear()
    lookup._bootstrap_failed_at = None
    lookup._client.cache_clear()
    yield
    lookup._vt_cache.clear()
    lookup._bootstrap_failed_at = None
    lookup._client.cache_clear()
