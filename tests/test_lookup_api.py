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


def test_lookup_analyze_missing_api_key_returns_503(client, monkeypatch):
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    r = client.post("/api/lookup/analyze", json={"target": "8.8.8.8", "rdap": {}, "vt": {}})
    assert r.status_code == 503
    assert "LLM_API_KEY" in r.json()["detail"]


def test_lookup_analyze_success(client, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test-key")
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
    assert body["model"] == "claude-sonnet-5"
