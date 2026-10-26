import json

import anthropic
import httpx
import pytest
from fastapi.testclient import TestClient

import lookup
import main  # noqa: F401  先載入：它在 import 時會 load_dotenv()，晚載入會把 .env 的值灌回已清掉的環境變數
import settings_store

SECRET = "sk-test-SECRETVALUE-9f8e7d6c5b4a"
SECRET2 = "sk-test-OTHERVALUE-1a2b3c4d5e6f"


@pytest.fixture(autouse=True)
def _no_env_keys(monkeypatch):
    # 開發機可能有真的 .env；隔離掉才測得到 keyring 路徑
    for name in ("VT_API_KEY", "LLM_API_KEY", "LLM_MODEL"):
        monkeypatch.delenv(name, raising=False)


def client_from(host: str) -> TestClient:
    """此版 Starlette 的 TestClient 沒有 client 參數，以 ASGI 包一層改寫 scope['client']。
    只在測試端偽裝來源位址，正式程式不放行 'testclient'。"""
    from main import app

    async def wrapped(scope, receive, send):
        if scope["type"] in ("http", "websocket"):
            scope = {**scope, "client": (host, 50000)}
        await app(scope, receive, send)
    return TestClient(wrapped)


@pytest.fixture
def client():
    return client_from("127.0.0.1")


@pytest.fixture
def valid(monkeypatch):
    """驗證呼叫一律通過，並記下收到的金鑰。"""
    seen = {}
    monkeypatch.setitem(settings_store._VALIDATORS, "vt", lambda v: seen.__setitem__("vt", v))
    monkeypatch.setitem(settings_store._VALIDATORS, "llm", lambda v: seen.__setitem__("llm", v))
    return seen


def _all_text_under(path) -> str:
    return "".join(p.read_text(encoding="utf-8", errors="ignore")
                   for p in path.rglob("*") if p.is_file())


def test_get_settings_defaults(client):
    r = client.get("/api/settings")
    assert r.status_code == 200
    body = r.json()
    assert body["keys"]["vt"] == {"configured": False, "source": "none", "hint": None, "updated_at": None}
    assert body["model"]["value"] == "claude-sonnet-5-5"
    assert body["model"]["source"] == "default"
    assert body["model"]["options"] == ["claude-sonnet-5-5", "claude-opus-5-5", "claude-haiku-5-5"]


def test_put_key_stores_in_keyring_and_never_echoes(client, valid, memory_keyring, tmp_path):
    r = client.put("/api/settings/keys/vt", json={"value": SECRET})
    assert r.status_code == 200
    assert SECRET not in json.dumps(r.json())
    assert r.json()["source"] == "ui"
    assert r.json()["hint"] == "…" + SECRET[-4:]
    assert memory_keyring.items[(settings_store.KEYRING_SERVICE, "VT_API_KEY")] == SECRET
    g = client.get("/api/settings")
    assert SECRET not in g.text
    assert SECRET not in json.dumps(g.json())
    assert g.json()["keys"]["vt"]["configured"] is True
    assert g.json()["keys"]["vt"]["updated_at"]
    assert SECRET not in _all_text_under(tmp_path)


def test_short_key_has_no_hint(client, valid):
    r = client.put("/api/settings/keys/vt", json={"value": "short-key"})
    assert r.status_code == 200
    assert r.json()["hint"] is None


def test_invalid_key_format_rejected(client, valid, memory_keyring):
    r = client.put("/api/settings/keys/vt", json={"value": "has space"})
    assert r.status_code == 400
    assert not memory_keyring.items


def test_unknown_key_kind_404(client):
    assert client.put("/api/settings/keys/other", json={"value": SECRET}).status_code == 404


def test_validation_failure_does_not_store(client, monkeypatch, memory_keyring, tmp_path):
    def reject(_value):
        raise settings_store.ValidationFailedError(400, "VirusTotal 拒絕這把金鑰（無效或無權限）")
    monkeypatch.setitem(settings_store._VALIDATORS, "vt", reject)
    r = client.put("/api/settings/keys/vt", json={"value": SECRET})
    assert r.status_code == 400
    assert "拒絕" in r.json()["detail"]
    assert SECRET not in r.text
    assert not memory_keyring.items
    assert client.get("/api/settings").json()["keys"]["vt"]["configured"] is False
    assert SECRET not in _all_text_under(tmp_path)


def test_vt_validation_key_only_in_header(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return httpx.Response(200, json={})
    monkeypatch.setattr(httpx, "get", fake_get)
    settings_store._validate_vt(SECRET)
    url, kwargs = calls[0]
    assert SECRET not in url
    assert kwargs["headers"] == {"x-apikey": SECRET}
    assert "params" not in kwargs


@pytest.mark.parametrize("response,expected", [
    (httpx.Response(401), 400),
    (httpx.Response(403), 400),
    (httpx.Response(429), 502),
    (httpx.Response(500), 502),
])
def test_vt_validation_status_mapping(monkeypatch, response, expected):
    monkeypatch.setattr(httpx, "get", lambda *a, **k: response)
    with pytest.raises(settings_store.ValidationFailedError) as ei:
        settings_store._validate_vt(SECRET)
    assert ei.value.status_code == expected
    assert SECRET not in str(ei.value)


def test_vt_validation_network_errors(monkeypatch):
    def timeout(*a, **k):
        raise httpx.ReadTimeout("slow")
    monkeypatch.setattr(httpx, "get", timeout)
    with pytest.raises(settings_store.ValidationFailedError) as ei:
        settings_store._validate_vt(SECRET)
    assert ei.value.status_code == 504

    def refused(*a, **k):
        raise httpx.ConnectError(f"boom {SECRET}")
    monkeypatch.setattr(httpx, "get", refused)
    with pytest.raises(settings_store.ValidationFailedError) as ei:
        settings_store._validate_vt(SECRET)
    assert ei.value.status_code == 502
    assert SECRET not in str(ei.value)


class _FakeModels:
    def __init__(self, exc):
        self.exc = exc

    def list(self, **kwargs):
        if self.exc:
            raise self.exc
        return []


class _FakeAnthropic:
    exc = None
    keys: list = []

    def __init__(self, api_key=None, **kwargs):
        type(self).keys.append(api_key)
        self.models = _FakeModels(type(self).exc)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _status_error(cls, code):
    request = httpx.Request("GET", "https://api.anthropic.com/v1/models")
    return cls("x", response=httpx.Response(code, request=request), body=None)


def test_llm_validation_uses_models_list(monkeypatch):
    _FakeAnthropic.exc, _FakeAnthropic.keys = None, []
    monkeypatch.setattr(anthropic, "Anthropic", _FakeAnthropic)
    settings_store._validate_llm(SECRET)
    assert _FakeAnthropic.keys == [SECRET]


@pytest.mark.parametrize("make_exc,expected", [
    (lambda: _status_error(anthropic.AuthenticationError, 401), 400),
    (lambda: _status_error(anthropic.RateLimitError, 429), 502),
    (lambda: anthropic.APITimeoutError(request=httpx.Request("GET", "https://x")), 504),
    (lambda: anthropic.APIConnectionError(request=httpx.Request("GET", "https://x")), 502),
])
def test_llm_validation_error_mapping(monkeypatch, make_exc, expected):
    _FakeAnthropic.exc, _FakeAnthropic.keys = make_exc(), []
    monkeypatch.setattr(anthropic, "Anthropic", _FakeAnthropic)
    with pytest.raises(settings_store.ValidationFailedError) as ei:
        settings_store._validate_llm(SECRET)
    assert ei.value.status_code == expected
    assert SECRET not in str(ei.value)


def test_env_source_locks_put_and_delete(client, valid, monkeypatch, memory_keyring):
    monkeypatch.setenv("VT_API_KEY", SECRET)
    s = client.get("/api/settings").json()["keys"]["vt"]
    assert s["source"] == "env" and s["configured"] is True
    assert SECRET not in client.get("/api/settings").text
    assert client.put("/api/settings/keys/vt", json={"value": SECRET2}).status_code == 409
    assert client.delete("/api/settings/keys/vt").status_code == 409
    assert not memory_keyring.items
    assert "vt" not in valid


def test_env_wins_over_keyring(client, valid, monkeypatch):
    client.put("/api/settings/keys/vt", json={"value": SECRET})
    monkeypatch.setenv("VT_API_KEY", SECRET2)
    assert settings_store.get_key("vt") == SECRET2
    assert client.get("/api/settings").json()["keys"]["vt"]["source"] == "env"


def test_delete_ui_key(client, valid, memory_keyring):
    client.put("/api/settings/keys/llm", json={"value": SECRET})
    r = client.delete("/api/settings/keys/llm")
    assert r.status_code == 200 and r.json()["configured"] is False
    assert not memory_keyring.items
    # 再刪一次是冪等的
    assert client.delete("/api/settings/keys/llm").status_code == 200


class _BrokenKeyring:
    def __init__(self, backend):
        self.backend = backend

    def get_password(self, *a):
        raise RuntimeError("backend exploded")

    def set_password(self, *a):
        raise RuntimeError("backend exploded")

    def delete_password(self, *a):
        raise RuntimeError("backend exploded")


def test_keyring_failure_returns_503_without_plaintext(client, valid, monkeypatch, tmp_path):
    import keyring
    monkeypatch.setattr(keyring, "set_password", _BrokenKeyring(None).set_password)
    monkeypatch.setattr(keyring, "get_password", _BrokenKeyring(None).get_password)
    r = client.put("/api/settings/keys/vt", json={"value": SECRET})
    assert r.status_code == 503
    assert "keyring" in r.json()["detail"]
    assert SECRET not in r.text
    assert SECRET not in _all_text_under(tmp_path)
    assert not (tmp_path / "data").exists() or not list((tmp_path / "data").iterdir())
    # GET 仍可用並回報問題；查詢端點也回 503 而不是 500
    g = client.get("/api/settings")
    assert g.status_code == 200 and g.json()["keyring_error"]
    assert client.get("/api/lookup/vt?target=8.8.8.8").status_code == 503


def test_model_selection(client):
    r = client.put("/api/settings/model", json={"model": "claude-haiku-5-5"})
    assert r.status_code == 200
    assert r.json()["value"] == "claude-haiku-5-5" and r.json()["source"] == "ui"
    assert client.get("/api/settings").json()["model"]["value"] == "claude-haiku-5-5"
    assert settings_store.get_model() == ("claude-haiku-5-5", "ui")


def test_model_not_in_list_rejected(client):
    r = client.put("/api/settings/model", json={"model": "gpt-4"})
    assert r.status_code == 422
    assert settings_store.get_model()[1] == "default"


def test_env_model_is_readonly_and_unlisted_value_used(client, monkeypatch):
    monkeypatch.setenv("LLM_MODEL", "claude-custom-9")
    m = client.get("/api/settings").json()["model"]
    assert m["value"] == "claude-custom-9" and m["source"] == "env"
    assert client.put("/api/settings/model", json={"model": "claude-haiku-5-5"}).status_code == 409


def test_empty_env_model_is_treated_as_unset(client, monkeypatch):
    """.env.example 的 LLM_MODEL= 留空時，前端模型選單必須可修改。"""
    monkeypatch.setenv("LLM_MODEL", "")
    m = client.get("/api/settings").json()["model"]
    assert m["source"] == "default"
    assert client.put("/api/settings/model", json={"model": "claude-haiku-5-5"}).status_code == 200
    assert settings_store.get_model() == ("claude-haiku-5-5", "ui")


def test_env_example_does_not_prefill_model():
    import database
    lines = (database.BASE_DIR / ".env.example").read_text(encoding="utf-8").splitlines()
    prefilled = [l for l in lines if l.startswith("LLM_MODEL=") and l.split("=", 1)[1].strip()]
    assert prefilled == []


def test_settings_file_follows_base_dir(monkeypatch, tmp_path):
    import database
    monkeypatch.undo()  # 取消 conftest 的路徑覆寫，改測以 BASE_DIR 為基準的預設路徑
    monkeypatch.setattr(database, "BASE_DIR", tmp_path)
    assert settings_store._settings_path() == tmp_path / "data" / "settings.json"


# ---------- 防跨站 ----------

@pytest.mark.parametrize("method,path,kwargs", [
    ("get", "/api/settings", {}),
    ("get", "/api/lookup/vt?target=8.8.8.8", {}),
    ("post", "/api/lookup/analyze", {"json": {"target": "8.8.8.8"}}),
    ("get", "/api/dates", {}),
    ("put", "/api/settings/keys/vt", {"json": {"value": SECRET}}),
])
@pytest.mark.parametrize("site", ["cross-site", "same-site", "bogus"])
def test_cross_site_blocked(client, valid, memory_keyring, method, path, kwargs, site):
    r = getattr(client, method)(path, headers={"Sec-Fetch-Site": site}, **kwargs)
    assert r.status_code == 403
    assert not memory_keyring.items


@pytest.mark.parametrize("headers", [{"Sec-Fetch-Site": "same-origin"}, {"Sec-Fetch-Site": "none"}, {}])
def test_same_origin_and_headerless_allowed(client, headers):
    assert client.get("/api/settings", headers=headers).status_code == 200


def test_non_api_paths_not_filtered(client):
    r = client.get("/", headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code != 403


def test_non_loopback_cannot_write_settings(valid, memory_keyring):
    remote = client_from("192.168.1.50")
    assert remote.put("/api/settings/keys/vt", json={"value": SECRET}).status_code == 403
    assert remote.delete("/api/settings/keys/vt").status_code == 403
    assert remote.put("/api/settings/model", json={"model": "claude-haiku-5-5"}).status_code == 403
    assert not memory_keyring.items
    assert remote.get("/api/settings").status_code == 200


def test_testclient_default_host_is_not_allowed(valid):
    from main import app
    assert TestClient(app).put("/api/settings/keys/vt", json={"value": SECRET}).status_code == 403


def test_ipv6_loopback_allowed(valid):
    assert client_from("::1").put(
        "/api/settings/keys/vt", json={"value": SECRET}).status_code == 200


# ---------- 設定的金鑰確實被查詢端點使用 ----------

def test_lookup_vt_uses_ui_key(client, valid, monkeypatch):
    client.put("/api/settings/keys/vt", json={"value": SECRET})
    seen = {}

    def fake_query(target, api_key):
        seen["key"] = api_key
        return {"target": target, "type": "ip", "source": "VirusTotal Public API v3",
                "queried_at": "2026-09-10 10:00:00 (UTC+8)", "data": {"data": {}}}
    monkeypatch.setattr(lookup, "query_virustotal", fake_query)
    client.get("/api/lookup/vt?target=8.8.8.8")
    assert seen["key"] == SECRET


def test_lookup_analyze_uses_ui_key_and_model(client, valid, monkeypatch):
    client.put("/api/settings/keys/llm", json={"value": SECRET})
    client.put("/api/settings/model", json={"model": "claude-opus-5-5"})
    seen = {}

    def fake_analyze(target, rdap, vt, api_key, model):
        seen.update(key=api_key, model=model)
        return {"content": "x", "analyzed_at": "t", "target": target, "model": model, "usage": {}}
    monkeypatch.setattr(lookup, "analyze_with_llm", fake_analyze)
    r = client.post("/api/lookup/analyze", json={"target": "8.8.8.8", "rdap": {}, "vt": {}})
    assert r.status_code == 200
    assert seen == {"key": SECRET, "model": "claude-opus-5-5"}


def test_unset_messages_keep_variable_names(client):
    assert "VT_API_KEY" in client.get("/api/lookup/vt?target=8.8.8.8").json()["detail"]
    r = client.post("/api/lookup/analyze", json={"target": "8.8.8.8", "rdap": {}, "vt": {}})
    assert "LLM_API_KEY" in r.json()["detail"]


def test_changing_llm_key_drops_old_client(client, valid, monkeypatch):
    created = []

    class FakeClient:
        def __init__(self, api_key, **kw):
            created.append(api_key)
            self.api_key = api_key
    monkeypatch.setattr(lookup.anthropic, "Anthropic", FakeClient)
    client.put("/api/settings/keys/llm", json={"value": SECRET})
    c1 = lookup._client(SECRET)
    assert lookup._client(SECRET) is c1  # 同金鑰仍共用
    client.put("/api/settings/keys/llm", json={"value": SECRET2})
    assert lookup._client.cache_info().currsize == 0  # 舊金鑰的 client 已被清掉
    c2 = lookup._client(SECRET2)
    assert c2 is not c1 and c2.api_key == SECRET2
    client.delete("/api/settings/keys/llm")
    assert lookup._client.cache_info().currsize == 0


# ---------- 安全審查補強 ----------

def test_non_allowlisted_keyring_backend_rejected(client, valid, tmp_path):
    """假的明文後端（不在白名單）：PUT 回 503、訊息含類別名稱、沒有寫入。"""
    import keyring
    import keyring.backend

    class PlaintextKeyring(keyring.backend.KeyringBackend):
        priority = 1
        items: dict = {}

        def get_password(self, service, username):
            return self.items.get((service, username))

        def set_password(self, service, username, password):
            self.items[(service, username)] = password

        def delete_password(self, service, username):
            self.items.pop((service, username), None)

    bad = PlaintextKeyring()
    keyring.set_keyring(bad)  # conftest 的 fixture 結束時會還原
    r = client.put("/api/settings/keys/vt", json={"value": SECRET})
    assert r.status_code == 503
    assert "PlaintextKeyring" in r.json()["detail"] and SECRET not in r.text
    assert not bad.items
    assert client.delete("/api/settings/keys/vt").status_code in (200, 503)
    assert client.get("/api/settings").json()["keyring_error"]
    assert "WinVaultKeyring" in "".join(settings_store.ALLOWED_KEYRING_BACKENDS)


def test_chainer_backend_rejected(client, valid):
    from keyring.backends.chainer import ChainerBackend
    import keyring
    keyring.set_keyring(ChainerBackend())
    r = client.put("/api/settings/keys/vt", json={"value": SECRET})
    assert r.status_code == 503 and "ChainerBackend" in r.json()["detail"]


@pytest.mark.parametrize("bad_value", ["x" * 5000, 12345, ["a"], {"k": SECRET}])
def test_422_does_not_echo_key(client, bad_value):
    r = client.put("/api/settings/keys/vt", json={"value": bad_value})
    assert r.status_code == 422
    assert "input" not in r.text and "ctx" not in r.text
    if isinstance(bad_value, str):
        assert bad_value not in r.text
    assert SECRET not in r.text


def test_422_outside_settings_keeps_default_format(client):
    r = client.get("/api/reports")  # 缺必填 date
    assert r.status_code == 422
    assert "input" in r.json()["detail"][0]


@pytest.mark.parametrize("path", ["/", "/api/dates", "/api/settings", "/index.html"])
def test_anti_clickjacking_headers(client, path):
    r = client.get(path)
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["content-security-policy"] .startswith("frame-ancestors 'none'")


def test_anti_clickjacking_headers_on_403(client):
    r = client.get("/api/dates", headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403 and r.headers["x-frame-options"] == "DENY"


@pytest.mark.parametrize("path", ["/docs", "/redoc", "/openapi.json"])
def test_api_docs_disabled(client, path):
    assert client.get(path).status_code == 404


def test_file_write_failure_after_keyring_write_still_succeeds(client, valid, monkeypatch, memory_keyring):
    cleared = []
    monkeypatch.setattr(settings_store, "_clear_llm_client", lambda: cleared.append(1))

    def boom(mutate):
        raise OSError("disk full")
    monkeypatch.setattr(settings_store, "_update_file", boom)
    r = client.put("/api/settings/keys/llm", json={"value": SECRET})
    assert r.status_code == 200
    assert r.json()["configured"] and r.json()["updated_at"] is None
    assert memory_keyring.items[(settings_store.KEYRING_SERVICE, "LLM_API_KEY")] == SECRET
    assert cleared == [1]
    d = client.delete("/api/settings/keys/llm")
    assert d.status_code == 200 and not memory_keyring.items
    assert cleared == [1, 1]


def test_corrupt_settings_file_is_backed_up(client, valid, _isolated_settings_file):
    path = _isolated_settings_file
    path.parent.mkdir(parents=True)
    path.write_text("{not json", encoding="utf-8")
    assert client.put("/api/settings/keys/vt", json={"value": SECRET}).status_code == 200
    bak = path.with_name("settings.json.bak")
    assert bak.read_text(encoding="utf-8") == "{not json"
    assert "VT_API_KEY" not in path.read_text(encoding="utf-8")
    assert json.loads(path.read_text(encoding="utf-8"))["key_updated_at"]["vt"]
    # 再損毀一次：舊 .bak 被覆蓋
    path.write_text("also broken", encoding="utf-8")
    client.put("/api/settings/keys/vt", json={"value": SECRET2})
    assert bak.read_text(encoding="utf-8") == "also broken"


@pytest.mark.parametrize("host,allowed", [
    ("::ffff:127.0.0.1", True), ("127.0.0.2", True), ("127.0.0.1", True), ("::1", True),
    ("testclient", False), ("192.168.1.50", False), ("::ffff:192.168.1.50", False), ("", False),
])
def test_loopback_judgement(host, allowed):
    import main
    assert main._is_loopback(host) is allowed


@pytest.mark.parametrize("host", ["::ffff:127.0.0.1", "127.0.0.2"])
def test_loopback_variants_can_write(valid, host):
    assert client_from(host).put(
        "/api/settings/keys/vt", json={"value": SECRET}).status_code == 200
