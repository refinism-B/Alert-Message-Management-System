import pytest
from fastapi.testclient import TestClient

import lookup


@pytest.fixture
def client():
    from main import app
    return TestClient(app)


def test_lookup_rdap_returns_result(client, monkeypatch):
    monkeypatch.setattr(
        lookup, "query_rdap_whois",
        lambda target: {
            "target": target, "type": "ip", "source": "RDAP（IANA bootstrap）",
            "queried_at": "2026-09-10 10:00:00 (UTC+8)", "data": {"name": target},
        },
    )
    r = client.get("/api/lookup/rdap?target=8.8.8.8")
    assert r.status_code == 200
    assert r.json()["source"] == "RDAP（IANA bootstrap）"


def test_lookup_rdap_failure_returns_502(client, monkeypatch):
    def raise_failed(target):
        raise lookup.LookupFailedError("RDAP 與 WHOIS 查詢皆失敗：查無資料")

    monkeypatch.setattr(lookup, "query_rdap_whois", raise_failed)
    r = client.get("/api/lookup/rdap?target=nonexist.invalid")
    assert r.status_code == 502
    assert "查無資料" in r.json()["detail"]


def test_lookup_vt_missing_api_key_returns_503(client, monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    r = client.get("/api/lookup/vt?target=8.8.8.8")
    assert r.status_code == 503
    assert "VT_API_KEY" in r.json()["detail"]


def test_lookup_vt_success(client, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-key")
    monkeypatch.setattr(
        lookup, "query_virustotal",
        lambda target, api_key: {
            "target": target, "type": "ip", "source": "VirusTotal Public API v3",
            "queried_at": "2026-09-10 10:00:00 (UTC+8)", "data": {"data": {}},
        },
    )
    r = client.get("/api/lookup/vt?target=8.8.8.8")
    assert r.status_code == 200
    assert r.json()["source"] == "VirusTotal Public API v3"


def test_lookup_vt_rate_limited_returns_429(client, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-key")

    def raise_rate_limited(target, api_key):
        raise lookup.VtQueryError(429, "VirusTotal 查詢失敗：429 Too Many Requests")

    monkeypatch.setattr(lookup, "query_virustotal", raise_rate_limited)
    r = client.get("/api/lookup/vt?target=8.8.8.8")
    assert r.status_code == 429


def test_lookup_vt_invalid_domain_returns_400(client, monkeypatch):
    """使用者打錯字是輸入問題（400），不是上游服務失敗（502）。"""
    monkeypatch.setenv("VT_API_KEY", "test-key")
    monkeypatch.setattr(lookup.httpx, "get",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("no network call")))
    r = client.get("/api/lookup/vt?target=invalid..domain")
    assert r.status_code == 400
    assert "invalid..domain" in r.json()["detail"]


def test_lookup_analyze_missing_api_key_returns_503(client, monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    r = client.post("/api/lookup/analyze", json={"target": "8.8.8.8", "rdap": {}, "vt": {}})
    assert r.status_code == 503
    assert "LLM_API_KEY" in r.json()["detail"]


def test_lookup_analyze_success(client, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.delenv("LLM_MODEL", raising=False)  # .env 可能有設；這裡驗的是程式預設值
    monkeypatch.setattr(
        lookup, "analyze_with_llm",
        lambda target, rdap, vt, api_key, model: {
            "content": "以下因素可能提高風險：\n...", "analyzed_at": "2026-09-10 10:05:00 (UTC+8)",
            "target": target, "model": model,
        },
    )
    r = client.post("/api/lookup/analyze", json={"target": "8.8.8.8", "rdap": {"a": 1}, "vt": None})
    assert r.status_code == 200
    body = r.json()
    assert body["target"] == "8.8.8.8"
    assert body["model"] == "claude-sonnet-5-5"


def test_lookup_analyze_llm_error_returns_mapped_status(client, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key")

    def raise_llm_error(target, rdap, vt, api_key, model):
        raise lookup.LlmQueryError(429, "LLM 進階分析失敗：429 Too Many Requests")

    monkeypatch.setattr(lookup, "analyze_with_llm", raise_llm_error)
    r = client.post("/api/lookup/analyze", json={"target": "8.8.8.8", "rdap": {}, "vt": {}})
    assert r.status_code == 429
    assert "429" in r.json()["detail"]


def test_lookup_rdap_private_ip_returns_400(client, monkeypatch):
    monkeypatch.setattr(lookup.whoisit, "ip",
                        lambda t: (_ for _ in ()).throw(AssertionError("no network call")))
    r = client.get("/api/lookup/rdap?target=192.168.1.10")
    assert r.status_code == 400
    assert r.json()["detail"] == lookup.NON_PUBLIC_MESSAGE


def test_lookup_rdap_scoped_ipv6_returns_400(client):
    r = client.get("/api/lookup/rdap", params={"target": "fe80::1%eth0"})
    assert r.status_code == 400


def test_lookup_vt_timeout_returns_504(client, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-key")

    def timeout(*args, **kwargs):
        raise lookup.httpx.ReadTimeout("timed out")

    monkeypatch.setattr(lookup.httpx, "get", timeout)
    r = client.get("/api/lookup/vt?target=8.8.8.8")
    assert r.status_code == 504


def test_lookup_vt_reports_cache_status(client, monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "test-key")

    class _Response:
        status_code = 200
        reason_phrase = "OK"

        def json(self):
            return {"data": {"id": "8.8.8.8", "attributes": {}}}

    monkeypatch.setattr(lookup.httpx, "get", lambda *a, **k: _Response())
    first = client.get("/api/lookup/vt?target=8.8.8.8").json()
    second = client.get("/api/lookup/vt?target=8.8.8.8").json()
    assert first["cached"] is False and first["cached_at"] is None
    assert second["cached"] is True and second["cached_at"]
    assert second["queried_at"] == first["queried_at"]


def test_lookup_rdap_idn_keeps_input(client, monkeypatch):
    monkeypatch.setattr(lookup.whoisit, "bootstrap", lambda: None)
    monkeypatch.setattr(lookup.whoisit, "domain", lambda t: {"name": t, "url": ""})
    body = client.get("/api/lookup/rdap", params={"target": "例子.台灣"}).json()
    assert body["target"] == "xn--fsqu00a.xn--kpry57d"
    assert body["input_target"] == "例子.台灣"


@pytest.mark.parametrize("payload", [
    {"rdap": {"target": "1.1.1.1", "source": "RDAP", "data": [1]}, "vt": None},
    {"rdap": None, "vt": {"target": "1.1.1.1", "source": "VirusTotal", "data": {"data": [1]}}},
    {"rdap": {"target": 123, "source": "RDAP", "data": "x"}, "vt": {"data": "y"}},
])
def test_lookup_compare_malformed_body_does_not_500(client, payload):
    r = client.post("/api/lookup/compare", json=payload)
    assert r.status_code == 200


def test_lookup_analyze_non_public_target_returns_400(client, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    r = client.post("/api/lookup/analyze", json={"target": "10.0.0.1", "rdap": None, "vt": None})
    assert r.status_code == 400
    assert r.json()["detail"] == lookup.NON_PUBLIC_MESSAGE


def _oversized_payload():
    import main
    return {"target": "8.8.8.8", "source": "RDAP", "data": {"blob": "x" * (main.MAX_LOOKUP_PAYLOAD_BYTES + 1)}}


def test_lookup_analyze_oversized_payload_returns_413(client, monkeypatch):
    """rdap／vt 是任意 dict；不設上限的話一個大 payload 就變成大量 input tokens。"""
    monkeypatch.setenv("LLM_API_KEY", "test-key")
    monkeypatch.setattr(lookup, "analyze_with_llm",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("不得呼叫 LLM")))
    r = client.post("/api/lookup/analyze", json={"target": "8.8.8.8", "rdap": None, "vt": _oversized_payload()})
    assert r.status_code == 413
    assert "vt" in r.json()["detail"]


def test_lookup_compare_oversized_payload_returns_413(client):
    r = client.post("/api/lookup/compare", json={"rdap": _oversized_payload(), "vt": None})
    assert r.status_code == 413


def test_real_vt_result_is_well_under_payload_limit():
    import json
    import pathlib

    import main
    fixture = pathlib.Path(__file__).parent / "fixtures" / "vt_ip_full.json"
    assert len(fixture.read_bytes()) < main.MAX_LOOKUP_PAYLOAD_BYTES / 10
    assert json.loads(fixture.read_text(encoding="utf-8"))["source"]


# ---------------------------------------------------------------------------
# request body 大小上限（JSON 解析之前）
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/api/lookup/compare", "/api/lookup/analyze"])
def test_oversized_content_length_rejected_before_parsing(client, path):
    """body 不是合法 JSON：若有進到解析會是 422，回 413 代表在解析前就被擋下。"""
    import main
    r = client.post(path, content=b"x" * (main.MAX_LOOKUP_BODY_BYTES + 1),
                    headers={"content-type": "application/json"})
    assert r.status_code == 413
    assert "請求內容過大" in r.json()["detail"]


def test_oversized_chunked_body_rejected_without_content_length(client):
    import main

    def chunks():
        for _ in range(main.MAX_LOOKUP_BODY_BYTES // 65536 + 2):
            yield b"x" * 65536

    r = client.post("/api/lookup/compare", content=chunks(),
                    headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_body_limit_allows_two_payloads_under_per_field_cap(client):
    """rdap 與 vt 各接近單欄上限時，加總超過 2 MB 也必須放行。"""
    import main
    blob = "x" * (main.MAX_LOOKUP_PAYLOAD_BYTES - 1024)
    r = client.post("/api/lookup/compare", json={
        "rdap": {"target": "8.8.8.8", "source": "RDAP", "data": {"blob": blob}},
        "vt": {"target": "8.8.8.8", "source": "VirusTotal Public API v3", "data": {"blob": blob}},
    })
    assert r.status_code == 200


def test_body_limit_only_applies_to_lookup_post_paths(client):
    import main
    r = client.put("/api/settings/model", content=b"x" * (main.MAX_LOOKUP_BODY_BYTES + 1),
                   headers={"content-type": "application/json"})
    assert r.status_code != 413
