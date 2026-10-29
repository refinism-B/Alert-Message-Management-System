import pytest
from fastapi.testclient import TestClient

import database
import images
import main

PNG = b"\x89PNG\r\n\x1a\n" + b"x"
OLD, NEW = "2026-10-19", "2026-10-29"
FIELDS = ["Offense ID", "時間"]


@pytest.fixture(autouse=True)
def tmp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "test.db")
    database.init_db()


def _misfiled(n_images=2, offense="8267"):
    """重現 bug：時間寫 10月29日，卻存在 10-19。"""
    r = database.create_report(OLD, {"Offense ID": offense, "時間": "10月29日"}, FIELDS)
    for _ in range(n_images):
        images.add_image(OLD, offense, PNG)
    return r


def test_create_uses_given_date_not_time_field():
    # 早上補記昨晚的事件：歸屬仍是存檔當天
    r = database.create_report(NEW, {"Offense ID": "8267", "時間": "10月28日"}, FIELDS)
    assert r["date"] == NEW


def test_edit_never_changes_date():
    r = _misfiled(1)
    out = database.update_report(r["id"], {"Offense ID": "8267", "時間": "10月1日"}, FIELDS)
    assert out["date"] == OLD
    assert out["images"] == ["8267-1.png"]


def test_change_date_moves_report_and_images_keeps_fields():
    r = _misfiled()
    out = database.update_report(r["id"], date=NEW)
    assert out["date"] == NEW
    assert out["fields"] == r["fields"] and out["field_order"] == r["field_order"]
    assert out["images"] == ["8267-1.png", "8267-2.png"]
    assert images.list_images(OLD, "8267") == []
    assert [x["id"] for x in database.get_reports_by_date(NEW)] == [r["id"]]
    assert database.get_reports_by_date(OLD) == []


def test_change_date_without_images():
    r = _misfiled(0)
    assert database.update_report(r["id"], date=NEW)["date"] == NEW


def test_edit_fields_and_date_together_moves_and_renames():
    r = _misfiled(1)
    out = database.update_report(r["id"], {"Offense ID": "9000"}, ["Offense ID"], date=NEW)
    assert out["date"] == NEW and out["images"] == ["9000-1.png"]
    assert images.list_images(OLD, "8267") == []


def test_change_date_conflict_rolls_back_everything():
    r = _misfiled(1)
    images.day_dir(NEW).mkdir(parents=True)
    (images.day_dir(NEW) / "8267-1.png").write_bytes(PNG)
    with pytest.raises(ValueError):
        database.update_report(r["id"], date=NEW)
    assert database.get_report(r["id"])["date"] == OLD
    assert images.list_images(OLD, "8267") == ["8267-1.png"]


def test_change_date_missing_report_returns_none():
    assert database.update_report(999, date=NEW) is None


def test_change_date_api():
    r = _misfiled(1)
    c = TestClient(main.app)
    res = c.put(f"/api/reports/{r['id']}/date", json={"date": NEW})
    assert res.status_code == 200 and res.json()["date"] == NEW and res.json()["images"] == ["8267-1.png"]
    assert c.put("/api/reports/999/date", json={"date": NEW}).status_code == 404
    assert c.put(f"/api/reports/{r['id']}/date", json={"date": "2026-02-30"}).status_code == 422
    assert c.put(f"/api/reports/{r['id']}/date", json={"date": "20261029"}).status_code == 422


def test_change_date_api_conflict_is_409():
    r = _misfiled(1)
    images.day_dir(NEW).mkdir(parents=True)
    (images.day_dir(NEW) / "8267-1.png").write_bytes(PNG)
    res = TestClient(main.app).put(f"/api/reports/{r['id']}/date", json={"date": NEW})
    assert res.status_code == 409 and "8267-1.png" in res.json()["detail"]


def test_rename_all_across_dates_creates_target_dir():
    images.add_image("2026-10-19", "8267", PNG)
    images.rename_all("2026-10-19", "8267", "8267", new_date="2026-10-29")
    assert images.list_images("2026-10-29", "8267") == ["8267-1.png"]
    assert images.list_images("2026-10-19", "8267") == []


# ── 手動放進 image/ 的檔案 ─────────────────────────────────

def test_add_image_skips_unlisted_name_taken_on_case_insensitive_fs():
    D = "2026-10-29"
    images.add_image(D, "8267", PNG)
    images.day_dir(D).joinpath("8267-2.PNG").write_bytes(PNG)  # 不列出；Windows 上與 8267-2.png 同名
    images.add_image(D, "8267", PNG)
    names = images.list_images(D, "8267")
    assert names[0] == "8267-1.png" and len(names) == 2  # 不分大小寫的 FS 跳到 3，分大小寫的 FS 拿到 2


def test_add_image_retry_does_not_overwrite(monkeypatch):
    D = "2026-10-29"
    images.add_image(D, "8267", PNG)
    monkeypatch.setattr(images, "list_images", lambda *a: [])  # 模擬列不出既有檔
    assert images.add_image(D, "8267", PNG + b"new") == "8267-2.png"
    assert images.day_dir(D).joinpath("8267-1.png").read_bytes() == PNG


def test_unreadable_day_dir_does_not_break_listing(monkeypatch):
    D = "2026-10-29"
    database.create_report(D, {"Offense ID": "8267"}, ["Offense ID"])
    images.add_image(D, "8267", PNG)

    def boom(*a, **k):
        raise PermissionError(13, "denied")

    monkeypatch.setattr(images, "list_images", boom)
    assert database.get_reports_by_date(D)[0]["images"] == []
    assert database.search_reports("8267")[0]["images"] == []


def test_add_image_skips_directory_with_image_name():
    D = "2026-10-29"
    images.day_dir(D).joinpath("8267-1.png").mkdir(parents=True)
    assert images.add_image(D, "8267", PNG) == "8267-2.png"


# ── 收尾審查的修正 ─────────────────────────────────────────

def test_add_image_write_failure_leaves_no_partial_files(monkeypatch):
    D = "2026-10-29"
    real_open = open

    class FailingWrite:
        def __init__(self, f): self.f = f
        def __enter__(self): return self
        def __exit__(self, *a): self.f.close()
        def write(self, _): raise OSError(28, "No space left on device")

    monkeypatch.setattr("builtins.open", lambda p, m="r", *a, **k: FailingWrite(real_open(p, m, *a, **k)) if m == "xb" else real_open(p, m, *a, **k))
    with pytest.raises(images.ImageError):
        images.add_image(D, "8267", PNG)
    assert list(images.day_dir(D).iterdir()) == []


def _legacy_dup(date_a, date_b):
    """舊資料：唯一索引建立前就存在的重複 Offense ID。"""
    import sqlite3
    a = database.create_report(date_a, {"Offense ID": "8267"}, ["Offense ID"])
    from contextlib import closing
    with closing(sqlite3.connect(database.DB_PATH)) as c, c:
        c.execute("DROP INDEX ix_reports_offense")
        c.execute(
            "INSERT INTO reports (date, fields, field_order, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            (date_b, '{"Offense ID": "8267"}', '["Offense ID"]', "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00"),
        )
    return a


def test_change_date_allowed_for_legacy_duplicate_offense_id():
    a = _legacy_dup(OLD, "2026-10-01")
    assert database.update_report(a["id"], date=NEW)["date"] == NEW


def test_change_date_blocked_when_target_day_has_same_offense_id():
    a = _legacy_dup(OLD, NEW)  # 搬過去會跟另一筆共用同一組截圖檔名
    with pytest.raises(ValueError):
        database.update_report(a["id"], date=NEW)
    assert database.get_report(a["id"])["date"] == OLD


def test_rollback_failure_keeps_original_error(monkeypatch, caplog):
    r = _misfiled(1)
    real = images.rename_all
    calls = []

    def flaky(*a, **k):
        calls.append(1)
        if len(calls) == 1:
            return real(*a, **k)
        raise images.ImageError("還原失敗")

    monkeypatch.setattr(images, "rename_all", flaky)
    # 搬檔成功後交易 commit 失敗，接著還原搬檔也失敗
    import sqlite3
    real_conn = database.get_conn

    from contextlib import contextmanager

    @contextmanager
    def failing_commit():
        with real_conn() as conn:
            yield conn
            raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(database, "get_conn", failing_commit)
    with pytest.raises(sqlite3.OperationalError):
        database.update_report(r["id"], date=NEW)
    assert "還原失敗" in caplog.text


def test_rename_all_error_does_not_leak_full_path(monkeypatch):
    images.add_image(OLD, "8267", PNG)
    monkeypatch.setattr(type(images.day_dir(NEW)), "mkdir", lambda *a, **k: (_ for _ in ()).throw(OSError(13, "Permission denied", str(images.day_dir(NEW)))))
    with pytest.raises(images.ImageError) as e:
        images.rename_all(OLD, "8267", "8267", new_date=NEW)
    assert "\\" not in str(e.value)  # 不帶 Windows 絕對路徑
