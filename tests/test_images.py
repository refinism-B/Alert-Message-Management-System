from pathlib import Path

import pytest

import images

PNG = b"\x89PNG\r\n\x1a\n" + b"x" * 10
D = "2026-10-28"


def test_day_dir_uses_compact_date():
    assert images.day_dir(D) == images.IMAGE_DIR / "20261028"


def test_add_image_numbers_from_one():
    assert images.add_image(D, "8267", PNG) == "8267-1.png"
    assert images.add_image(D, "8267", PNG) == "8267-2.png"
    assert images.list_images(D, "8267") == ["8267-1.png", "8267-2.png"]
    assert (images.day_dir(D) / "8267-1.png").read_bytes() == PNG


def test_add_after_delete_middle_uses_max_plus_one():
    for _ in range(3):
        images.add_image(D, "8267", PNG)
    assert images.delete_image(D, "8267", 2) is True
    assert images.add_image(D, "8267", PNG) == "8267-4.png"
    assert images.list_images(D, "8267") == ["8267-1.png", "8267-3.png", "8267-4.png"]


def test_list_images_sorted_numerically():
    for _ in range(10):
        images.add_image(D, "8267", PNG)
    assert images.list_images(D, "8267")[-1] == "8267-10.png"


def test_list_images_does_not_mix_prefix_ids():
    images.add_image(D, "8267", PNG)
    images.add_image(D, "8267-1", PNG)
    assert images.list_images(D, "8267") == ["8267-1.png"]
    assert images.list_images(D, "8267-1") == ["8267-1-1.png"]


def test_add_rejects_non_png():
    with pytest.raises(images.ImageError):
        images.add_image(D, "8267", b"GIF89a" + b"x" * 10)
    assert images.list_images(D, "8267") == []


def test_add_rejects_oversize():
    with pytest.raises(images.ImageError):
        images.add_image(D, "8267", PNG + b"0" * images.MAX_IMAGE_BYTES)


@pytest.mark.parametrize("bad", ["", "../x", "a/b", "8267 ", "8267\n", "中文"])
def test_add_rejects_bad_offense_id(bad):
    with pytest.raises(images.ImageError):
        images.add_image(D, bad, PNG)


def test_add_never_overwrites():
    d = images.day_dir(D)
    d.mkdir(parents=True)
    (d / "8267-1.png").write_bytes(b"old")
    assert images.add_image(D, "8267", PNG) == "8267-2.png"
    assert (d / "8267-1.png").read_bytes() == b"old"


def test_list_images_invalid_id_or_missing_dir_is_empty():
    assert images.list_images(D, "../x") == []
    assert images.list_images(D, "8267\n") == []
    assert images.list_images(D, "8267") == []


def test_image_path_only_returns_listed():
    images.add_image(D, "8267", PNG)
    assert images.image_path(D, "8267", 1) == images.day_dir(D) / "8267-1.png"
    assert images.image_path(D, "8267", 99) is None


def test_delete_all_removes_only_that_id():
    images.add_image(D, "8267", PNG)
    images.add_image(D, "8267", PNG)
    images.add_image(D, "8268", PNG)
    images.delete_all(D, "8267")
    assert images.list_images(D, "8267") == []
    assert images.list_images(D, "8268") == ["8268-1.png"]


def test_rename_all_keeps_seq():
    for _ in range(3):
        images.add_image(D, "8267", PNG)
    images.delete_image(D, "8267", 2)
    images.rename_all(D, "8267", "9000")
    assert images.list_images(D, "9000") == ["9000-1.png", "9000-3.png"]
    assert images.list_images(D, "8267") == []


def test_rename_all_noop_without_images():
    images.rename_all(D, "8267", "bad id")


def test_rename_all_conflict_changes_nothing():
    images.add_image(D, "8267", PNG)
    (images.day_dir(D) / "9000-1.png").write_bytes(b"x")
    with pytest.raises(images.ImageError):
        images.rename_all(D, "8267", "9000")
    assert images.list_images(D, "8267") == ["8267-1.png"]


def test_rename_all_rolls_back_on_oserror(monkeypatch):
    images.add_image(D, "8267", PNG)
    images.add_image(D, "8267", PNG)
    real = Path.rename
    calls = []

    def flaky(self, target):
        calls.append(1)
        if len(calls) == 2:
            raise OSError("boom")
        return real(self, target)

    monkeypatch.setattr(Path, "rename", flaky)
    with pytest.raises(images.ImageError):
        images.rename_all(D, "8267", "9000")
    monkeypatch.setattr(Path, "rename", real)
    assert images.list_images(D, "8267") == ["8267-1.png", "8267-2.png"]
    assert images.list_images(D, "9000") == []


def test_delete_all_is_atomic_when_rename_fails(monkeypatch):
    images.add_image(D, "8267", PNG)
    images.add_image(D, "8267", PNG)
    real, calls = Path.rename, []

    def flaky(self, target):
        calls.append(self)
        if len(calls) == 2:
            raise OSError("locked")
        return real(self, target)

    with monkeypatch.context() as m:
        m.setattr(Path, "rename", flaky)
        with pytest.raises(images.ImageError):
            images.delete_all(D, "8267")
    assert images.list_images(D, "8267") == ["8267-1.png", "8267-2.png"]


def test_add_image_retries_on_seq_collision(monkeypatch):
    images.add_image(D, "8267", PNG)
    real = images.list_images
    calls = []

    def stale(date, oid):
        calls.append(1)
        return [] if len(calls) == 1 else real(date, oid)  # 第一次看到過期清單，模擬並行

    monkeypatch.setattr(images, "list_images", stale)
    assert images.add_image(D, "8267", PNG) == "8267-2.png"
    assert (images.day_dir(D) / "8267-1.png").read_bytes() == PNG


def test_add_image_oserror_becomes_image_error(monkeypatch):
    def boom(self, *a, **k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Path, "mkdir", boom)
    with pytest.raises(images.ImageError, match="儲存截圖失敗"):
        images.add_image(D, "8267", PNG)


def test_delete_image_oserror_becomes_image_error(monkeypatch):
    images.add_image(D, "8267", PNG)

    def boom(self, *a, **k):
        raise PermissionError("locked")

    monkeypatch.setattr(Path, "unlink", boom)
    with pytest.raises(images.ImageError, match="8267-1.png"):
        images.delete_image(D, "8267", 1)


def test_list_images_ignores_leading_zero_and_unicode_digits():
    d = images.day_dir(D)
    d.mkdir(parents=True)
    for n in ("8267-1.png", "8267-01.png", "8267-\u0661.png"):
        (d / n).write_bytes(PNG)
    assert images.list_images(D, "8267") == ["8267-1.png"]


@pytest.mark.parametrize("bad", ["2026-10-28/../x", "../../etc", "２０２６-10-28", "2026-10-28\n"])
def test_day_dir_rejects_malformed_date(bad):
    with pytest.raises(images.ImageError):
        images.day_dir(bad)
    assert images.list_images(bad, "8267") == []


def _fail_rename_of(monkeypatch, name):
    real = Path.rename

    def rename(self, target):
        if self.name == name:
            raise OSError("boom")
        return real(self, target)

    monkeypatch.setattr(Path, "rename", rename)


def test_rename_all_rollback_failure_reports_unrestored(monkeypatch):
    for _ in range(3):
        images.add_image(D, "8267", PNG)
    d = images.day_dir(D)
    real = Path.rename

    def rename(self, target):
        # 第三張改名失敗觸發回滾；回滾時 9000-1.png 還原也失敗
        if self.name == "8267-3.png" or self.name == "9000-1.png":
            raise OSError("boom")
        return real(self, target)

    monkeypatch.setattr(Path, "rename", rename)
    with pytest.raises(images.ImageError) as ei:
        images.rename_all(D, "8267", "9000")
    assert "8267-1.png" in str(ei.value)
    assert (d / "8267-2.png").exists() and (d / "9000-1.png").exists()


def test_stage_delete_partial_failure_restores_others(monkeypatch):
    for _ in range(3):
        images.add_image(D, "8267", PNG)
    real_rename = Path.rename
    _fail_rename_of(monkeypatch, "8267-3.png")
    with pytest.raises(images.ImageError):
        images.stage_delete(D, "8267")
    monkeypatch.setattr(Path, "rename", real_rename)
    assert images.list_images(D, "8267") == ["8267-1.png", "8267-2.png", "8267-3.png"]


def test_stage_delete_restore_failure_names_file(monkeypatch):
    for _ in range(3):
        images.add_image(D, "8267", PNG)
    real = Path.rename

    def rename(self, target):
        if self.name == "8267-3.png" or self.name == "8267-1.png.deleting":
            raise OSError("boom")
        return real(self, target)

    monkeypatch.setattr(Path, "rename", rename)
    with pytest.raises(images.ImageError) as ei:
        images.stage_delete(D, "8267")
    assert "無法還原：8267-1.png" in str(ei.value)
    monkeypatch.setattr(Path, "rename", real)
    assert images.list_images(D, "8267") == ["8267-2.png", "8267-3.png"]


def test_image_lock_exists_and_is_plain_lock():
    assert not images.IMAGE_LOCK.locked()
