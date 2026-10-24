import json
import sqlite3
import threading

import pytest

import database


@pytest.fixture(autouse=True)
def tmp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "test.db")
    database.init_db()
    yield


def _index_sql() -> str:
    with database.get_conn() as conn:
        return conn.execute("SELECT sql FROM sqlite_master WHERE name='ix_reports_offense'").fetchone()["sql"]


def test_get_conn_closes_connection():
    with database.get_conn() as conn:
        conn.execute("SELECT 1")
    with pytest.raises(sqlite3.ProgrammingError):
        conn.execute("SELECT 1")


def test_get_conn_closes_on_exception():
    with pytest.raises(RuntimeError):
        with database.get_conn() as conn:
            raise RuntimeError("boom")
    with pytest.raises(sqlite3.ProgrammingError):
        conn.execute("SELECT 1")


def test_indexes_created():
    with database.get_conn() as conn:
        names = {r["name"] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}
    assert "ix_reports_date" in names
    assert _index_sql().upper().startswith("CREATE UNIQUE")


def test_offense_id_duplicate_ignores_surrounding_whitespace():
    database.create_report("2026-06-06", {"Offense ID": "DUP"}, ["Offense ID"])
    with pytest.raises(ValueError, match="Offense ID 已存在"):
        database.create_report("2026-06-07", {"Offense ID": "  DUP "}, ["Offense ID"])


def test_blank_offense_ids_may_repeat():
    database.create_report("2026-06-06", {"Offense ID": ""}, ["Offense ID"])
    database.create_report("2026-06-06", {"Offense ID": "   "}, ["Offense ID"])
    database.create_report("2026-06-06", {"x": "1"}, ["x"])
    database.create_report("2026-06-06", {"x": "2"}, ["x"])
    assert len(database.get_reports_by_date("2026-06-06")) == 4


def test_update_to_duplicate_offense_id_rejected():
    database.create_report("2026-06-06", {"Offense ID": "A"}, ["Offense ID"])
    b = database.create_report("2026-06-06", {"Offense ID": "B"}, ["Offense ID"])
    with pytest.raises(ValueError, match="Offense ID 已存在"):
        database.update_report(b["id"], {"Offense ID": "A"}, ["Offense ID"])


def test_update_missing_report_returns_none_even_if_offense_id_taken():
    database.create_report("2026-06-06", {"Offense ID": "TAKEN"}, ["Offense ID"])
    assert database.update_report(9999, {"Offense ID": "TAKEN"}, ["Offense ID"]) is None


def test_delete_report_returns_whether_deleted():
    r = database.create_report("2026-06-06", {"Offense ID": "D"}, ["Offense ID"])
    assert database.delete_report(r["id"]) is True
    assert database.delete_report(r["id"]) is False


def test_integrity_error_mapped_to_value_error(monkeypatch):
    """即使應用層檢查被繞過，唯一索引的違反也要轉成 ValueError。"""
    database.create_report("2026-06-06", {"Offense ID": "RACE"}, ["Offense ID"])
    monkeypatch.setattr(database, "_offense_exists", lambda *a, **k: False)
    with pytest.raises(ValueError, match="Offense ID 已存在"):
        database.create_report("2026-06-07", {"Offense ID": "RACE"}, ["Offense ID"])
    r = database.create_report("2026-06-07", {"Offense ID": "OTHER"}, ["Offense ID"])
    with pytest.raises(ValueError, match="Offense ID 已存在"):
        database.update_report(r["id"], {"Offense ID": "RACE"}, ["Offense ID"])


@pytest.mark.parametrize("unique_index", [True, False])
def test_concurrent_create_same_offense_id_only_one_wins(monkeypatch, unique_index):
    if not unique_index:
        # 沒有唯一索引兜底時，只靠 BEGIN IMMEDIATE 的寫入鎖也必須擋住競態
        with database.get_conn() as conn:
            conn.execute("DROP INDEX ix_reports_offense")
    barrier = threading.Barrier(2)
    orig = database._offense_exists

    def synced(*a, **k):
        res = orig(*a, **k)
        try:
            # 若沒有寫入鎖，兩個執行緒會在檢查後同時到這裡再一起 INSERT
            barrier.wait(timeout=1)
        except threading.BrokenBarrierError:
            pass
        return res

    monkeypatch.setattr(database, "_offense_exists", synced)
    results = []

    def worker():
        try:
            database.create_report("2026-06-06", {"Offense ID": "CONC"}, ["Offense ID"])
            results.append("ok")
        except ValueError:
            results.append("dup")

    ts = [threading.Thread(target=worker) for _ in range(2)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert sorted(results) == ["dup", "ok"]
    assert len(database.get_reports_by_date("2026-06-06")) == 1


def test_init_db_with_existing_duplicates_warns_and_builds_non_unique_index(capsys):
    with database.get_conn() as conn:
        conn.execute("DROP INDEX ix_reports_offense")
        for d in ("2026-06-06", "2026-06-07"):
            conn.execute(
                "INSERT INTO reports (date, fields, field_order, created_at, updated_at) VALUES (?, ?, '[]', 'x', 'x')",
                (d, '{"Offense ID": " DUPX "}'),
            )
    database.init_db()  # 不可拋例外
    out = capsys.readouterr().out
    assert "DUPX" in out and "警告" in out
    assert not _index_sql().upper().startswith("CREATE UNIQUE")
    # 重複解除後再啟動，升級回唯一索引
    with database.get_conn() as conn:
        conn.execute("DELETE FROM reports WHERE date = '2026-06-07'")
    database.init_db()
    assert _index_sql().upper().startswith("CREATE UNIQUE")


def test_search_unicode_case_insensitive_and_special_chars():
    database.create_report("2026-06-06", {"Offense ID": "U1", "note": "Émile 100%_done"}, ["Offense ID", "note"])
    database.create_report("2026-06-06", {"Offense ID": "U2", "note": "中文告警"}, ["Offense ID", "note"])
    assert len(database.search_reports(q="émile")) == 1
    assert len(database.search_reports(q="100%_")) == 1
    assert len(database.search_reports(q="中文")) == 1
    assert len(database.search_reports(q="%")) == 1


def test_paths_are_absolute():
    assert database.BASE_DIR.is_absolute()
    assert (database.BASE_DIR / "static").is_dir()


def test_offense_lookup_uses_index():
    with database.get_conn() as conn:
        for sql, params in (
            (f"SELECT 1 FROM reports WHERE {database._OFFENSE_EXPR} = ? AND {database._OFFENSE_EXPR} <> '' LIMIT 1", ["x"]),
        ):
            plan = " ".join(r["detail"] for r in conn.execute("EXPLAIN QUERY PLAN " + sql, params))
            assert "ix_reports_offense" in plan and "SCAN" not in plan


def test_exists_query_text_matches_index_plan():
    import inspect
    assert "<> ''" in inspect.getsource(database._offense_exists)


def test_init_db_normalizes_legacy_unicode_whitespace_ids():
    with database.get_conn() as conn:
        conn.execute("DROP INDEX ix_reports_offense")
        for i, v in enumerate(["111\t", "222\u3000", "333 ", "111"]):
            conn.execute(
                "INSERT INTO reports (date, fields, field_order, created_at, updated_at) VALUES (?, ?, '[]', 'x', 'x')",
                (f"2026-06-0{i + 1}", json.dumps({"Offense ID": v})),
            )
    database.init_db()
    ids = sorted(r["fields"]["Offense ID"] for d in ("2026-06-01", "2026-06-02", "2026-06-03", "2026-06-04")
                 for r in database.get_reports_by_date(d))
    assert ids == ["111", "111", "222", "333"]
    # 正規化後 111 重複 -> 走非唯一索引並警告；222 / 333 已被保護
    assert not _index_sql().upper().startswith("CREATE UNIQUE")
    for oid in ("222", "333", "111"):
        with pytest.raises(ValueError, match="Offense ID 已存在"):
            database.create_report("2026-07-01", {"Offense ID": oid}, ["Offense ID"])
