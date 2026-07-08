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
    assert schema["fields"] == ["Offense ID", "觸發規則", "時間", "方向", "來源IP", "目的IP", "目的port", "防火牆action", "事件總數"]

def test_init_db_migrates_legacy_schema_missing_trigger_rule():
    import json
    legacy = ["Offense ID", "時間", "方向"]
    with database.get_conn() as conn:
        conn.execute(
            "UPDATE field_schema SET fields = ? WHERE id = 1",
            (json.dumps(legacy, ensure_ascii=False),),
        )
    database.init_db()
    schema = database.get_schema()
    assert schema["fields"] == ["Offense ID", "觸發規則", "時間", "方向"]

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
    # Test the get side: verify report appears in get_reports_by_date
    reports = database.get_reports_by_date("2026-06-06")
    assert len(reports) == 1
    assert reports[0]["id"] == report["id"]

def test_get_reports_by_date():
    database.create_report("2026-06-06", {"Offense ID": "A"}, ["Offense ID"])
    database.create_report("2026-06-06", {"Offense ID": "B"}, ["Offense ID"])
    database.create_report("2026-06-05", {"Offense ID": "C"}, ["Offense ID"])
    reports = database.get_reports_by_date("2026-06-06")
    assert len(reports) == 2
    # Verify ordering: reports come back in created_at ASC order
    assert reports[0]["fields"]["Offense ID"] == "A"
    assert reports[1]["fields"]["Offense ID"] == "B"

def test_get_dates():
    database.create_report("2026-06-06", {"x": "1"}, ["x"])
    database.create_report("2026-06-05", {"x": "2"}, ["x"])
    dates = database.get_dates()
    assert dates == ["2026-06-06", "2026-06-05"]

def test_update_report():
    report = database.create_report("2026-06-06", {"Offense ID": "OLD"}, ["Offense ID"])
    updated = database.update_report(report["id"], {"Offense ID": "NEW"}, ["Offense ID"])
    assert updated["fields"]["Offense ID"] == "NEW"
    # Verify updated_at advances
    assert updated["updated_at"] >= updated["created_at"]

def test_delete_report():
    report = database.create_report("2026-06-06", {"x": "1"}, ["x"])
    database.delete_report(report["id"])
    reports = database.get_reports_by_date("2026-06-06")
    assert len(reports) == 0

def test_update_nonexistent_report_returns_none():
    result = database.update_report(9999, {"x": "1"}, ["x"])
    assert result is None

def test_search_by_keyword_matches_values():
    database.create_report("2026-06-06", {"來源IP": "192.168.1.100", "Offense ID": "OFN-001"}, ["來源IP", "Offense ID"])
    database.create_report("2026-06-06", {"來源IP": "10.0.0.1", "Offense ID": "OFN-002"}, ["來源IP", "Offense ID"])
    results = database.search_reports("192.168")
    assert len(results) == 1
    assert results[0]["fields"]["來源IP"] == "192.168.1.100"

def test_search_case_insensitive():
    database.create_report("2026-06-06", {"Offense ID": "OFN-001"}, ["Offense ID"])
    results = database.search_reports("ofn-001")
    assert len(results) == 1

def test_search_does_not_match_keys():
    database.create_report("2026-06-06", {"來源IP": "1.2.3.4"}, ["來源IP"])
    results = database.search_reports("來源IP")
    assert len(results) == 0

def test_search_with_date_range():
    database.create_report("2026-06-01", {"Offense ID": "OFN-001-A"}, ["Offense ID"])
    database.create_report("2026-06-05", {"Offense ID": "OFN-001-B"}, ["Offense ID"])
    database.create_report("2026-06-10", {"Offense ID": "OFN-001-C"}, ["Offense ID"])
    results = database.search_reports("OFN-001", date_from="2026-06-02", date_to="2026-06-09")
    assert len(results) == 1
    assert results[0]["date"] == "2026-06-05"

def test_search_no_date_range_returns_all_dates():
    database.create_report("2026-06-01", {"Offense ID": "OFN-999-A"}, ["Offense ID"])
    database.create_report("2026-06-10", {"Offense ID": "OFN-999-B"}, ["Offense ID"])
    results = database.search_reports("OFN-999")
    assert len(results) == 2

def test_search_no_keyword_returns_all():
    database.create_report("2026-06-01", {"Offense ID": "A"}, ["Offense ID"])
    database.create_report("2026-06-10", {"Offense ID": "B"}, ["Offense ID"])
    results = database.search_reports(q=None)
    assert len(results) == 2

def test_search_no_keyword_with_date_range():
    database.create_report("2026-06-01", {"Offense ID": "A"}, ["Offense ID"])
    database.create_report("2026-06-05", {"Offense ID": "B"}, ["Offense ID"])
    database.create_report("2026-06-10", {"Offense ID": "C"}, ["Offense ID"])
    results = database.search_reports(q=None, date_from="2026-06-02", date_to="2026-06-09")
    assert len(results) == 1
    assert results[0]["fields"]["Offense ID"] == "B"


def test_create_report_duplicate_offense_id_raises():
    database.create_report(
        "2026-06-06",
        {"Offense ID": "OFN-999"},
        ["Offense ID"],
    )
    with pytest.raises(ValueError, match="Offense ID 已存在"):
        database.create_report(
            "2026-06-07",
            {"Offense ID": "OFN-999"},
            ["Offense ID"],
        )

def test_update_report_duplicate_offense_id_raises():
    r1 = database.create_report("2026-06-06", {"Offense ID": "EDIT-001"}, ["Offense ID"])
    r2 = database.create_report("2026-06-06", {"Offense ID": "EDIT-002"}, ["Offense ID"])
    with pytest.raises(ValueError, match="Offense ID 已存在"):
        database.update_report(r2["id"], {"Offense ID": "EDIT-001"}, ["Offense ID"])

def test_update_report_same_offense_id_allowed():
    r = database.create_report("2026-06-06", {"Offense ID": "SELF-001"}, ["Offense ID"])
    updated = database.update_report(r["id"], {"Offense ID": "SELF-001", "time": "new"}, ["Offense ID", "time"])
    assert updated["fields"]["time"] == "new"
