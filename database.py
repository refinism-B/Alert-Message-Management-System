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
            CREATE TABLE IF NOT EXISTS field_schema (
                id INTEGER PRIMARY KEY,
                fields TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        exists = conn.execute("SELECT id FROM field_schema WHERE id = 1").fetchone()
        if not exists:
            conn.execute(
                "INSERT INTO field_schema (id, fields, updated_at) VALUES (1, ?, ?)",
                (json.dumps(DEFAULT_FIELDS, ensure_ascii=False), _now()),
            )


def get_schema() -> dict:
    with get_conn() as conn:
        row = conn.execute("SELECT fields, updated_at FROM field_schema WHERE id = 1").fetchone()
    if row is None:
        raise RuntimeError("Schema row missing — was init_db() called?")
    return {"fields": json.loads(row["fields"]), "updated_at": row["updated_at"]}


def update_schema(fields: list[str]) -> dict:
    now = _now()
    with get_conn() as conn:
        conn.execute(
            "UPDATE field_schema SET fields = ?, updated_at = ? WHERE id = 1",
            (json.dumps(fields, ensure_ascii=False), now),
        )
    return {"fields": fields, "updated_at": now}


def _row_to_report(row: sqlite3.Row) -> dict:
    return {
        "id": row["id"],
        "date": row["date"],
        "fields": json.loads(row["fields"]),
        "field_order": json.loads(row["field_order"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def create_report(date: str, fields: dict, field_order: list[str]) -> dict:
    now = _now()
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO reports (date, fields, field_order, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (date, json.dumps(fields, ensure_ascii=False), json.dumps(field_order, ensure_ascii=False), now, now),
        )
        row = conn.execute("SELECT * FROM reports WHERE id = ?", (cur.lastrowid,)).fetchone()
    return _row_to_report(row)


def get_reports_by_date(date: str) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM reports WHERE date = ? ORDER BY created_at ASC", (date,)
        ).fetchall()
    return [_row_to_report(r) for r in rows]


def get_dates() -> list[str]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT DISTINCT date FROM reports ORDER BY date DESC"
        ).fetchall()
    return [r["date"] for r in rows]


def update_report(report_id: int, fields: dict, field_order: list[str]) -> dict | None:
    now = _now()
    with get_conn() as conn:
        conn.execute(
            "UPDATE reports SET fields = ?, field_order = ?, updated_at = ? WHERE id = ?",
            (json.dumps(fields, ensure_ascii=False), json.dumps(field_order, ensure_ascii=False), now, report_id),
        )
        row = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    return _row_to_report(row) if row else None


def delete_report(report_id: int) -> None:
    with get_conn() as conn:
        conn.execute("DELETE FROM reports WHERE id = ?", (report_id,))


def search_reports(q: str, date_from: str | None = None, date_to: str | None = None) -> list[dict]:
    sql = "SELECT * FROM reports WHERE 1=1"
    params: list = []
    if date_from:
        sql += " AND date >= ?"
        params.append(date_from)
    if date_to:
        sql += " AND date <= ?"
        params.append(date_to)
    sql += " ORDER BY date DESC, created_at ASC"

    with get_conn() as conn:
        rows = conn.execute(sql, params).fetchall()

    q_lower = q.lower()
    results = []
    for row in rows:
        fields = json.loads(row["fields"])
        if any(q_lower in str(v).lower() for v in fields.values()):
            results.append(_row_to_report(row))
    return results
