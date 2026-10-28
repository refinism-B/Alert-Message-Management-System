import sqlite3
import json
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

import images

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "data" / "reports.db"

# Offense ID 去除空白後的值；索引與查詢必須用完全相同的運算式，SQLite 才會走索引
_OFFENSE_EXPR = "TRIM(json_extract(fields, '$.\"Offense ID\"'))"

DEFAULT_FIELDS = ["Offense ID", "觸發規則", "時間", "方向", "來源IP", "目的IP", "目的port", "防火牆action", "事件總數"]

DEFAULT_FIELDS_WAF = [
    "Offense ID", "觸發規則", "時間", "方向", "來源IP", "目的IP", "目的port",
    "防火牆action", "response code", "severity", "攻擊類型", "日誌總數", "事件描述",
]

TEMPLATE_IDS = {"general": 1, "waf": 2}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    """成功 commit、例外 rollback，並且一定會 close（sqlite3 的 with 本身不會 close）。"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        with conn:
            yield conn
    finally:
        conn.close()


def _normalize_existing_offense_ids(conn: sqlite3.Connection) -> None:
    """舊資料的 Offense ID 可能帶 Tab／全形空白（Python strip 會去、SQL TRIM 不會去）；
    建唯一索引前先用 strip() 回寫，重複才能被正確偵測。"""
    for row in conn.execute("SELECT id, fields FROM reports WHERE json_extract(fields, '$.\"Offense ID\"') IS NOT NULL").fetchall():
        fields = json.loads(row["fields"])
        value = fields.get("Offense ID")
        if isinstance(value, str) and value != value.strip():
            fields["Offense ID"] = value.strip()
            conn.execute("UPDATE reports SET fields = ? WHERE id = ?", (json.dumps(fields, ensure_ascii=False), row["id"]))


def _ensure_indexes(conn: sqlite3.Connection) -> None:
    _normalize_existing_offense_ids(conn)
    conn.execute("CREATE INDEX IF NOT EXISTS ix_reports_date ON reports(date, created_at)")

    dups = conn.execute(
        f"SELECT {_OFFENSE_EXPR} AS dup_id, COUNT(*) AS n FROM reports "
        f"WHERE {_OFFENSE_EXPR} <> '' GROUP BY dup_id HAVING n > 1"
    ).fetchall()
    existing = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type = 'index' AND name = 'ix_reports_offense'"
    ).fetchone()
    is_unique = bool(existing and existing["sql"].upper().startswith("CREATE UNIQUE"))

    if dups:
        print(
            "[警告] 既有資料中有重複的 Offense ID，無法建立唯一索引，改建非唯一索引："
            + "、".join(f"{r['dup_id']}（{r['n']} 筆）" for r in dups)
            + "。請手動處理重複資料後重新啟動。"
        )
    if existing and is_unique != (not dups):
        conn.execute("DROP INDEX ix_reports_offense")
        existing = None
    if not existing:
        unique = "" if dups else "UNIQUE "
        conn.execute(
            f"CREATE {unique}INDEX ix_reports_offense ON reports({_OFFENSE_EXPR}) "
            f"WHERE {_OFFENSE_EXPR} <> ''"
        )


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
        exists = conn.execute("SELECT id, fields FROM field_schema WHERE id = 1").fetchone()
        if not exists:
            conn.execute(
                "INSERT INTO field_schema (id, fields, updated_at) VALUES (1, ?, ?)",
                (json.dumps(DEFAULT_FIELDS, ensure_ascii=False), _now()),
            )
        else:
            # One-time migration: schemas seeded before 觸發規則 existed lack it
            fields = json.loads(exists["fields"])
            changed = False
            # 舊安裝的 schema 可能沒有 Offense ID，而 SchemaUpdate 強制要求它，
            # 不補回的話之後永遠存不了；補在最前面（與預設 schema 一致）。
            if "Offense ID" not in fields:
                fields.insert(0, "Offense ID")
                changed = True
            if "觸發規則" not in fields:
                anchor = fields.index("Offense ID") + 1
                fields.insert(anchor, "觸發規則")
                changed = True
            if changed:
                conn.execute(
                    "UPDATE field_schema SET fields = ?, updated_at = ? WHERE id = 1",
                    (json.dumps(fields, ensure_ascii=False), _now()),
                )

        waf_exists = conn.execute("SELECT id, fields FROM field_schema WHERE id = 2").fetchone()
        if not waf_exists:
            conn.execute(
                "INSERT INTO field_schema (id, fields, updated_at) VALUES (2, ?, ?)",
                (json.dumps(DEFAULT_FIELDS_WAF, ensure_ascii=False), _now()),
            )
        else:
            waf_fields = json.loads(waf_exists["fields"])
            if "Offense ID" not in waf_fields:
                waf_fields.insert(0, "Offense ID")
                conn.execute(
                    "UPDATE field_schema SET fields = ?, updated_at = ? WHERE id = 2",
                    (json.dumps(waf_fields, ensure_ascii=False), _now()),
                )

        _ensure_indexes(conn)


def get_schema(template: str = "general") -> dict:
    schema_id = TEMPLATE_IDS[template]
    with get_conn() as conn:
        row = conn.execute("SELECT fields, updated_at FROM field_schema WHERE id = ?", (schema_id,)).fetchone()
    if row is None:
        raise RuntimeError("Schema row missing — was init_db() called?")
    return {"fields": json.loads(row["fields"]), "updated_at": row["updated_at"]}


def update_schema(fields: list[str], template: str = "general") -> dict:
    schema_id = TEMPLATE_IDS[template]
    now = _now()
    with get_conn() as conn:
        conn.execute(
            "UPDATE field_schema SET fields = ?, updated_at = ? WHERE id = ?",
            (json.dumps(fields, ensure_ascii=False), now, schema_id),
        )
    return {"fields": fields, "updated_at": now}


def _row_to_report(row: sqlite3.Row) -> dict:
    fields = json.loads(row["fields"])
    return {
        "id": row["id"],
        "date": row["date"],
        "fields": fields,
        "images": images.list_images(row["date"], str(fields.get("Offense ID", "")).strip()),
        "field_order": json.loads(row["field_order"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def _offense_exists(conn: sqlite3.Connection, offense_id: str, exclude_id: int | None = None) -> bool:
    # 多帶 <> '' 才能讓 SQLite 推出部分索引的條件而走索引（否則全表掃描）
    sql = f"SELECT 1 FROM reports WHERE {_OFFENSE_EXPR} = ? AND {_OFFENSE_EXPR} <> ''"
    params: list = [offense_id]
    if exclude_id is not None:
        sql += " AND id != ?"
        params.append(exclude_id)
    return conn.execute(sql + " LIMIT 1", params).fetchone() is not None


def _offense_count_on_date(conn: sqlite3.Connection, date: str, offense_id: str) -> int:
    # 多帶 <> '' 讓 SQLite 走部分索引
    return conn.execute(
        f"SELECT COUNT(*) FROM reports WHERE date = ? AND {_OFFENSE_EXPR} = ? AND {_OFFENSE_EXPR} <> ''",
        (date, offense_id),
    ).fetchone()[0]


def offense_count_on_date(date: str, offense_id: str) -> int:
    with get_conn() as conn:
        return _offense_count_on_date(conn, date, offense_id)


def get_report(report_id: int) -> dict | None:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    return _row_to_report(row) if row else None


def _normalize_fields(fields: dict) -> tuple[dict, str]:
    """Offense ID 存入前去除前後空白，讓 Python 與 SQL TRIM 的判斷一致。"""
    offense_id = fields.get("Offense ID", "").strip()
    if "Offense ID" in fields:
        fields = {**fields, "Offense ID": offense_id}
    return fields, offense_id


def create_report(date: str, fields: dict, field_order: list[str]) -> dict:
    fields, offense_id = _normalize_fields(fields)
    now = _now()
    try:
        with get_conn() as conn:
            # 先取得寫入鎖再檢查，檢查與寫入之間才不會被其他連線插隊
            conn.execute("BEGIN IMMEDIATE")
            if offense_id and _offense_exists(conn, offense_id):
                raise ValueError("Offense ID 已存在")
            cur = conn.execute(
                "INSERT INTO reports (date, fields, field_order, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                (date, json.dumps(fields, ensure_ascii=False), json.dumps(field_order, ensure_ascii=False), now, now),
            )
            row = conn.execute("SELECT * FROM reports WHERE id = ?", (cur.lastrowid,)).fetchone()
    except sqlite3.IntegrityError:
        raise ValueError("Offense ID 已存在") from None
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
    fields, offense_id = _normalize_fields(fields)
    now = _now()
    try:
        with get_conn() as conn:
            conn.execute("BEGIN IMMEDIATE")
            # 先確認存在：不存在的 id 一律回 None（404），不論 Offense ID 是否撞到別人
            old = conn.execute("SELECT date, fields FROM reports WHERE id = ?", (report_id,)).fetchone()
            if old is None:
                return None
            if offense_id and _offense_exists(conn, offense_id, exclude_id=report_id):
                raise ValueError("Offense ID 已存在")
            date = old["date"]
            old_id = str(json.loads(old["fields"]).get("Offense ID", "")).strip()
            rename = old_id != offense_id and bool(images.list_images(date, old_id))
            if rename and _offense_count_on_date(conn, date, old_id) > 1:
                raise images.ImageError("此 Offense ID 在同日有重複通報，請先處理重複資料")
            conn.execute(
                "UPDATE reports SET fields = ?, field_order = ?, updated_at = ? WHERE id = ?",
                (json.dumps(fields, ensure_ascii=False), json.dumps(field_order, ensure_ascii=False), now, report_id),
            )
            if rename:
                # shortcut: rename 成功後若 commit 失敗，檔案已是新名；SQLite 本機 commit 幾乎不會失敗，真遇到再補反向改名
                images.rename_all(date, old_id, offense_id)
            row = conn.execute("SELECT * FROM reports WHERE id = ?", (report_id,)).fetchone()
    except sqlite3.IntegrityError:
        raise ValueError("Offense ID 已存在") from None
    return _row_to_report(row)


def delete_report(report_id: int) -> bool:
    """回傳是否真的刪到一筆。"""
    with get_conn() as conn:
        row = conn.execute("SELECT date, fields FROM reports WHERE id = ?", (report_id,)).fetchone()
        if row is None:
            return False
        conn.execute("DELETE FROM reports WHERE id = ?", (report_id,))
        offense_id = str(json.loads(row["fields"]).get("Offense ID", "")).strip()
        # 同日仍有同 ID 通報（舊資料重複）時圖片要留給它；刪圖失敗則例外讓交易回滾
        if offense_id and _offense_count_on_date(conn, row["date"], offense_id) == 0:
            images.delete_all(row["date"], offense_id)
        return True


def search_reports(q: str | None = None, date_from: str | None = None, date_to: str | None = None) -> list[dict]:
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

    if q is None:
        return [_row_to_report(r) for r in rows]

    # 關鍵字比對刻意留在 Python：SQLite 的 lower() 只處理 ASCII，下推到 SQL 會讓
    # 非 ASCII 字母的大小寫不敏感比對（如 É/é）語意改變。日期範圍已由 ix_reports_date
    # 在 SQL 端縮小，這裡只會掃描範圍內的資料。
    q_lower = q.lower()
    results = []
    for row in rows:
        fields = json.loads(row["fields"])
        if any(q_lower in str(v).lower() for v in fields.values()):
            results.append(_row_to_report(row))
    return results
