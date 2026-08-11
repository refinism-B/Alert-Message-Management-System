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
    return TestClient(app)

def test_get_schema(client):
    r = client.get("/api/schema")
    assert r.status_code == 200
    data = r.json()
    assert "fields" in data
    assert "Offense ID" in data["fields"]

def test_put_schema(client):
    r = client.put("/api/schema", json={"fields": ["欄位A", "欄位B"]})
    assert r.status_code == 200
    assert r.json()["fields"] == ["欄位A", "欄位B"]

def test_get_schema_waf_template(client):
    r = client.get("/api/schema?template=waf")
    assert r.status_code == 200
    fields = r.json()["fields"]
    assert "Offense ID" in fields
    assert "response code" in fields

def test_put_schema_waf_template_does_not_affect_general(client):
    r = client.put("/api/schema?template=waf", json={"fields": ["A", "B"]})
    assert r.status_code == 200
    assert r.json()["fields"] == ["A", "B"]
    general = client.get("/api/schema").json()
    assert general["fields"] != ["A", "B"]

def test_get_schema_invalid_template_rejected(client):
    r = client.get("/api/schema?template=bogus")
    assert r.status_code == 422

def test_create_report(client):
    r = client.post("/api/reports", json={
        "date": "2026-06-06",
        "fields": {"Offense ID": "OFN-001", "來源IP": "1.2.3.4"},
        "field_order": ["Offense ID", "來源IP"],
    })
    assert r.status_code == 200
    data = r.json()
    assert data["id"] is not None
    assert data["fields"]["Offense ID"] == "OFN-001"

def test_get_reports_by_date(client):
    client.post("/api/reports", json={"date": "2026-06-06", "fields": {"x": "1"}, "field_order": ["x"]})
    client.post("/api/reports", json={"date": "2026-06-06", "fields": {"x": "2"}, "field_order": ["x"]})
    r = client.get("/api/reports?date=2026-06-06")
    assert r.status_code == 200
    assert len(r.json()) == 2

def test_get_dates(client):
    client.post("/api/reports", json={"date": "2026-06-06", "fields": {"x": "1"}, "field_order": ["x"]})
    client.post("/api/reports", json={"date": "2026-06-05", "fields": {"x": "1"}, "field_order": ["x"]})
    r = client.get("/api/dates")
    assert r.status_code == 200
    assert r.json() == ["2026-06-06", "2026-06-05"]

def test_update_report(client):
    created = client.post("/api/reports", json={
        "date": "2026-06-06", "fields": {"Offense ID": "OLD"}, "field_order": ["Offense ID"]
    }).json()
    r = client.put(f"/api/reports/{created['id']}", json={
        "fields": {"Offense ID": "NEW"}, "field_order": ["Offense ID"]
    })
    assert r.status_code == 200
    assert r.json()["fields"]["Offense ID"] == "NEW"

def test_update_nonexistent_report(client):
    r = client.put("/api/reports/9999", json={"fields": {}, "field_order": []})
    assert r.status_code == 404

def test_delete_report(client):
    created = client.post("/api/reports", json={
        "date": "2026-06-06", "fields": {"x": "1"}, "field_order": ["x"]
    }).json()
    r = client.delete(f"/api/reports/{created['id']}")
    assert r.status_code == 200
    remaining = client.get("/api/reports?date=2026-06-06").json()
    assert len(remaining) == 0

def test_search(client):
    client.post("/api/reports", json={
        "date": "2026-06-06",
        "fields": {"來源IP": "192.168.1.100"},
        "field_order": ["來源IP"],
    })
    client.post("/api/reports", json={
        "date": "2026-06-06",
        "fields": {"來源IP": "10.0.0.1"},
        "field_order": ["來源IP"],
    })
    r = client.get("/api/search?q=192.168")
    assert r.status_code == 200
    data = r.json()
    assert len(data["reports"]) == 1

def test_search_with_date_range(client):
    client.post("/api/reports", json={"date": "2026-06-01", "fields": {"Offense ID": "OFN-999-A"}, "field_order": ["Offense ID"]})
    client.post("/api/reports", json={"date": "2026-06-10", "fields": {"Offense ID": "OFN-999-B"}, "field_order": ["Offense ID"]})
    r = client.get("/api/search?q=OFN-999&date_from=2026-06-05&date_to=2026-06-15")
    assert r.status_code == 200
    assert len(r.json()["reports"]) == 1

def test_search_date_range_no_keyword(client):
    client.post("/api/reports", json={"date": "2026-06-01", "fields": {"Offense ID": "A"}, "field_order": ["Offense ID"]})
    client.post("/api/reports", json={"date": "2026-06-10", "fields": {"Offense ID": "B"}, "field_order": ["Offense ID"]})
    r = client.get("/api/search?date_from=2026-06-01&date_to=2026-06-15")
    assert r.status_code == 200
    assert len(r.json()["reports"]) == 2


def test_create_report_duplicate_offense_id_returns_409(client):
    client.post("/api/reports", json={
        "date": "2026-06-06",
        "fields": {"Offense ID": "OFN-DUP"},
        "field_order": ["Offense ID"],
    })
    r = client.post("/api/reports", json={
        "date": "2026-06-07",
        "fields": {"Offense ID": "OFN-DUP"},
        "field_order": ["Offense ID"],
    })
    assert r.status_code == 409
    assert "Offense ID 已存在" in r.json()["detail"]

def test_update_report_duplicate_offense_id_returns_409(client):
    r1 = client.post("/api/reports", json={"date": "2026-06-06", "fields": {"Offense ID": "UPD-001"}, "field_order": ["Offense ID"]}).json()
    r2 = client.post("/api/reports", json={"date": "2026-06-06", "fields": {"Offense ID": "UPD-002"}, "field_order": ["Offense ID"]}).json()
    r = client.put(f"/api/reports/{r2['id']}", json={"fields": {"Offense ID": "UPD-001"}, "field_order": ["Offense ID"]})
    assert r.status_code == 409
