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
