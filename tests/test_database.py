import pytest
from pathlib import Path

# DB_PATH is redirected to a temp file by the autouse fixture before each test
import database

@pytest.fixture(autouse=True)
def tmp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "test.db")
    database.init_db()
    yield

def test_init_db_creates_tables():
    import sqlite3
    conn = sqlite3.connect(database.DB_PATH)
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
    assert "reports" in tables
    assert "field_schema" in tables
    conn.close()

def test_init_db_seeds_default_schema():
    schema = database.get_schema()
    assert schema["fields"] == ["Offense ID", "時間", "方向", "來源IP", "目的IP", "目的port", "防火牆action", "事件總數"]

def test_update_schema():
    database.update_schema(["欄位A", "欄位B"])
    schema = database.get_schema()
    assert schema["fields"] == ["欄位A", "欄位B"]
    assert schema["updated_at"]

def test_create_and_get_report():
    report = database.create_report(
        date="2026-06-06",
        fields={"Offense ID": "OFN-001", "來源IP": "192.168.1.1"},
        field_order=["Offense ID", "來源IP"],
    )
    assert report["id"] is not None
    assert report["date"] == "2026-06-06"
    assert report["fields"]["Offense ID"] == "OFN-001"

def test_get_reports_by_date():
    database.create_report("2026-06-06", {"Offense ID": "A"}, ["Offense ID"])
    database.create_report("2026-06-06", {"Offense ID": "B"}, ["Offense ID"])
    database.create_report("2026-06-05", {"Offense ID": "C"}, ["Offense ID"])
    reports = database.get_reports_by_date("2026-06-06")
    assert len(reports) == 2

def test_get_dates():
    database.create_report("2026-06-06", {"x": "1"}, ["x"])
    database.create_report("2026-06-05", {"x": "2"}, ["x"])
    dates = database.get_dates()
    assert dates == ["2026-06-06", "2026-06-05"]

def test_update_report():
    report = database.create_report("2026-06-06", {"Offense ID": "OLD"}, ["Offense ID"])
    updated = database.update_report(report["id"], {"Offense ID": "NEW"}, ["Offense ID"])
    assert updated["fields"]["Offense ID"] == "NEW"

def test_delete_report():
    report = database.create_report("2026-06-06", {"x": "1"}, ["x"])
    database.delete_report(report["id"])
    reports = database.get_reports_by_date("2026-06-06")
    assert len(reports) == 0

def test_update_nonexistent_report_returns_none():
    result = database.update_report(9999, {"x": "1"}, ["x"])
    assert result is None
