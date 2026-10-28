import base64
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import database
import main
from tests.test_api import tmp_db, client  # noqa: F401

D = "2026-10-28"
PNG = b"\x89PNG\r\n\x1a\n" + b"0" * 32


def _mk(offense="8267"):
    r = database.create_report(D, {"Offense ID": offense}, ["Offense ID"])
    return r["id"]


def _up(client, rid, data=PNG):
    return client.post(f"/api/reports/{rid}/images",
                       json={"data": base64.b64encode(data).decode()})


def test_upload_and_list(client):
    rid = _mk()
    r = _up(client, rid)
    assert r.status_code == 201
    assert r.json()["filename"] == "8267-1.png"
    reports = client.get(f"/api/reports?date={D}").json()
    assert reports[0]["images"] == ["8267-1.png"]


def test_get_image_returns_png(client):
    rid = _mk()
    _up(client, rid)
    r = client.get(f"/api/reports/{rid}/images/1")
    assert r.status_code == 200
    assert r.headers["content-type"] == "image/png"
    assert "no-cache" in r.headers["cache-control"]
    assert r.content == PNG


def test_get_missing_image_404(client):
    rid = _mk()
    assert client.get(f"/api/reports/{rid}/images/99").status_code == 404


def test_delete_image(client):
    rid = _mk()
    _up(client, rid)
    r = client.delete(f"/api/reports/{rid}/images/1")
    assert r.status_code == 200
    assert r.json()["images"] == []
    assert client.delete(f"/api/reports/{rid}/images/1").status_code == 404


def test_upload_unknown_report_404(client):
    assert _up(client, 9999).status_code == 404


def test_upload_invalid_base64_400(client):
    rid = _mk()
    r = client.post(f"/api/reports/{rid}/images", json={"data": "!!!"})
    assert r.status_code == 400
    assert r.json()["detail"] == "圖片資料格式錯誤"


def test_upload_non_png_400(client):
    rid = _mk()
    assert _up(client, rid, b"not a png").status_code == 400


def test_upload_requires_offense_id_400(client):
    rid = _mk("")
    r = _up(client, rid)
    assert r.status_code == 400
    assert r.json()["detail"] == "請先填寫 Offense ID"


def test_upload_rejected_for_duplicate_offense(client):
    rid = _mk()
    with database.get_conn() as conn:
        conn.execute("DROP INDEX ix_reports_offense")
        # 繞過 create_report 的重複檢查，模擬舊資料
        conn.execute(
            "INSERT INTO reports (date, fields, field_order, created_at, updated_at) "
            "SELECT date, fields, field_order, created_at, updated_at FROM reports WHERE id = ?", (rid,))
    r = _up(client, rid)
    assert r.status_code == 409
    assert "重複" in r.json()["detail"]


def test_delete_image_unlink_failure_409(client, monkeypatch):
    rid = _mk()
    _up(client, rid)

    def boom(self, *a, **k):
        raise PermissionError("locked")

    monkeypatch.setattr(Path, "unlink", boom)
    r = client.delete(f"/api/reports/{rid}/images/1")
    assert r.status_code == 409
    assert "8267-1.png" in r.json()["detail"]


def test_upload_storage_failure_400(client, monkeypatch):
    rid = _mk()

    def boom(self, *a, **k):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(Path, "mkdir", boom)
    assert _up(client, rid).status_code == 400


def test_upload_requires_json_content_type(client):
    rid = _mk()
    r = client.post(f"/api/reports/{rid}/images", files={"data": ("a.png", PNG)})
    assert r.status_code == 415


def test_upload_body_too_large_413(client):
    rid = _mk()
    r = client.post(f"/api/reports/{rid}/images",
                    content=b"x" * (main.MAX_IMAGE_BODY_BYTES + 1),
                    headers={"content-type": "application/json"})
    assert r.status_code == 413


def test_lookup_body_limit_unchanged(client):
    r = client.post("/api/lookup/compare",
                    content=b"x" * (main.MAX_LOOKUP_BODY_BYTES + 1),
                    headers={"content-type": "application/json"})
    assert r.status_code == 413
