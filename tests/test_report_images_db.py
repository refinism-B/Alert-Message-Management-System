import pytest

import database
import images

PNG = b"\x89PNG\r\n\x1a\n" + b"x"
D = "2026-10-28"


@pytest.fixture(autouse=True)
def tmp_db(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "test.db")
    database.init_db()


def _mk(offense="8267", **extra):
    return database.create_report(D, {"Offense ID": offense, **extra}, ["Offense ID", *extra])


def test_report_includes_images():
    _mk()
    images.add_image(D, "8267", PNG)
    assert database.get_reports_by_date(D)[0]["images"] == ["8267-1.png"]


def test_update_offense_id_renames_images():
    r = _mk()
    images.add_image(D, "8267", PNG)
    images.add_image(D, "8267", PNG)
    out = database.update_report(r["id"], {"Offense ID": "9000"}, ["Offense ID"])
    assert out["images"] == ["9000-1.png", "9000-2.png"]
    assert images.list_images(D, "8267") == []


def test_update_rename_conflict_rolls_back():
    r = _mk()
    images.add_image(D, "8267", PNG)
    (images.day_dir(D) / "9000-1.png").write_bytes(PNG)
    with pytest.raises(ValueError):
        database.update_report(r["id"], {"Offense ID": "9000"}, ["Offense ID"])
    assert database.get_report(r["id"])["fields"]["Offense ID"] == "8267"
    assert images.list_images(D, "8267") == ["8267-1.png"]


def test_update_same_offense_id_does_not_touch_files():
    r = _mk(note="a")
    images.add_image(D, "8267", PNG)
    out = database.update_report(r["id"], {"Offense ID": "8267", "note": "b"}, ["Offense ID", "note"])
    assert out["images"] == ["8267-1.png"]
    assert out["fields"]["note"] == "b"


def test_update_to_invalid_id_without_images_succeeds():
    r = _mk()
    out = database.update_report(r["id"], {"Offense ID": "a b"}, ["Offense ID"])
    assert out["fields"]["Offense ID"] == "a b"


def test_update_to_invalid_id_with_images_fails():
    r = _mk()
    images.add_image(D, "8267", PNG)
    with pytest.raises(ValueError):
        database.update_report(r["id"], {"Offense ID": "a b"}, ["Offense ID"])
    assert database.get_report(r["id"])["fields"]["Offense ID"] == "8267"
    assert images.list_images(D, "8267") == ["8267-1.png"]


def test_delete_report_removes_images():
    r = _mk()
    images.add_image(D, "8267", PNG)
    assert database.delete_report(r["id"]) is True
    assert images.list_images(D, "8267") == []


def _make_duplicates():
    a = _mk()
    with database.get_conn() as conn:
        conn.execute("DROP INDEX ix_reports_offense")
        # 繞過 create_report 的重複檢查，模擬舊資料
        conn.execute(
            "INSERT INTO reports (date, fields, field_order, created_at, updated_at) "
            "SELECT date, fields, field_order, created_at, updated_at FROM reports WHERE id = ?", (a["id"],))
    return a, None


def test_delete_report_keeps_images_when_duplicate_offense():
    a, b = _make_duplicates()
    images.add_image(D, "8267", PNG)
    database.delete_report(a["id"])
    assert images.list_images(D, "8267") == ["8267-1.png"]


def test_rename_blocked_when_duplicate_offense():
    a, b = _make_duplicates()
    images.add_image(D, "8267", PNG)
    with pytest.raises(ValueError):
        database.update_report(a["id"], {"Offense ID": "9000"}, ["Offense ID"])
    assert images.list_images(D, "8267") == ["8267-1.png"]


def test_delete_report_image_failure_rolls_back(monkeypatch):
    r = _mk()

    def boom(*a):
        raise images.ImageError("x")

    monkeypatch.setattr(images, "delete_all", boom)
    with pytest.raises(images.ImageError):
        database.delete_report(r["id"])
    assert database.get_report(r["id"]) is not None


def test_offense_count_on_date():
    _mk()
    assert database.offense_count_on_date(D, "8267") == 1
    assert database.offense_count_on_date("2026-10-27", "8267") == 0
