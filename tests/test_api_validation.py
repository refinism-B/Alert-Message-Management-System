import pytest
from fastapi.testclient import TestClient

import database


@pytest.fixture(autouse=True)
def tmp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "test.db")
    database.init_db()
    yield


@pytest.fixture
def client():
    from main import app
    with TestClient(app) as c:
        yield c


def _report(date="2026-06-06", oid="X-1"):
    return {"date": date, "fields": {"Offense ID": oid}, "field_order": ["Offense ID"]}


def test_host_header_validation(client):
    assert client.get("/api/dates", headers={"Host": "evil.example"}).status_code == 400
    assert client.get("/api/dates", headers={"Host": "127.0.0.1"}).status_code == 200
    assert client.get("/api/dates", headers={"Host": "localhost:8000"}).status_code == 200


def test_lifespan_runs_init_db(tmp_path, monkeypatch):
    from main import app
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "fresh" / "lifespan.db")
    with TestClient(app) as c:
        assert c.get("/api/schema").status_code == 200
    assert (tmp_path / "fresh" / "lifespan.db").exists()


def test_delete_missing_report_returns_404(client):
    assert client.delete("/api/reports/9999").status_code == 404


def test_update_missing_report_with_duplicate_offense_id_returns_404(client):
    client.post("/api/reports", json=_report(oid="TAKEN"))
    r = client.put("/api/reports/9999", json={"fields": {"Offense ID": "TAKEN"}, "field_order": ["Offense ID"]})
    assert r.status_code == 404


@pytest.mark.parametrize("bad", ["2026-6-6", "20260606", "2026-02-30", "abc", "2026-13-01", ""])
def test_report_date_validation(client, bad):
    assert client.post("/api/reports", json=_report(date=bad)).status_code == 422
    assert client.get("/api/reports", params={"date": bad}).status_code == 422


def test_search_date_params_validated(client):
    assert client.get("/api/search", params={"date_from": "2026/06/01"}).status_code == 422
    assert client.get("/api/search", params={"date_to": "nope"}).status_code == 422
    assert client.get("/api/search", params={"date_from": "2026-06-01", "date_to": "2026-06-30"}).status_code == 200


@pytest.mark.parametrize("fields", [
    [], ["Offense ID", ""], ["Offense ID", "   "], ["Offense ID", "A", "A"],
    ["Offense ID", "A", " A "], ["A", "B"],
])
@pytest.mark.parametrize("template", ["general", "waf"])
def test_put_schema_rejects_invalid(client, fields, template):
    assert client.put(f"/api/schema?template={template}", json={"fields": fields}).status_code == 422


def test_put_schema_missing_offense_id_message_is_chinese(client):
    r = client.put("/api/schema", json={"fields": ["A"]})
    assert "必須保留" in str(r.json()["detail"]) and "Offense ID" in str(r.json()["detail"])


def test_put_schema_strips_whitespace(client):
    r = client.put("/api/schema", json={"fields": [" Offense ID ", " A"]})
    assert r.status_code == 200 and r.json()["fields"] == ["Offense ID", "A"]


def test_write_requires_json_content_type(client):
    """C4 回歸：舊瀏覽器沒有 Sec-Fetch-Site，改靠 Content-Type 擋跨站 no-cors POST。"""
    body = b'{"date": "2026-01-01", "fields": {"a": "b"}}'
    for headers in ({}, {"content-type": "text/plain"}):
        r = client.post("/api/reports", content=body, headers=headers)
        assert r.status_code == 415
        assert r.json() == {"detail": "只接受 application/json"}
    r = client.post("/api/reports", content=body,
                    headers={"content-type": "Application/JSON; charset=utf-8"})
    assert r.status_code != 415


def test_security_headers_on_page_and_api(client):
    csp = ("frame-ancestors 'none'; object-src 'none'; base-uri 'none'; "
           "form-action 'self'; connect-src 'self'")
    for path in ("/", "/api/dates"):
        r = client.get(path)
        assert r.headers["x-content-type-options"] == "nosniff"
        assert r.headers["content-security-policy"] == csp
