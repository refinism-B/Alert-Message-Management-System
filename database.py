import sqlite3
import json
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path("data/reports.db")

DEFAULT_FIELDS = ["Offense ID", "時間", "方向", "來源IP", "目的IP", "目的port", "防火牆action", "事件總數"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                date TEXT NOT NULL,
                fields TEXT NOT NULL,
                field_order TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS schema (
                id INTEGER PRIMARY KEY,
                fields TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        exists = conn.execute("SELECT id FROM schema WHERE id = 1").fetchone()
        if not exists:
            conn.execute(
                "INSERT INTO schema (id, fields, updated_at) VALUES (1, ?, ?)",
                (json.dumps(DEFAULT_FIELDS, ensure_ascii=False), _now()),
            )


def get_schema() -> dict:
    with get_conn() as conn:
        row = conn.execute("SELECT fields, updated_at FROM schema WHERE id = 1").fetchone()
    return {"fields": json.loads(row["fields"]), "updated_at": row["updated_at"]}


def update_schema(fields: list[str]) -> dict:
    now = _now()
    with get_conn() as conn:
        conn.execute(
            "UPDATE schema SET fields = ?, updated_at = ? WHERE id = 1",
            (json.dumps(fields, ensure_ascii=False), now),
        )
    return {"fields": fields, "updated_at": now}
