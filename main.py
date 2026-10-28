from dotenv import load_dotenv

load_dotenv()

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exception_handlers import request_validation_exception_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.staticfiles import StaticFiles
from typing import Literal, Optional
import base64
import binascii
import ipaddress
import json
import os
import re

import database
import images
import lookup
import models
import postprocess
import settings_store



@asynccontextmanager
async def lifespan(_: FastAPI):
    database.init_db()
    yield


# 關閉 /docs、/redoc、/openapi.json：Swagger UI 從 CDN 載入腳本，會在同源下執行
app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)

# 服務無認證、只綁本機；限制 Host 以防 DNS rebinding。
# 測試以 ALLOWED_HOSTS 環境變數（逗號分隔）追加 testserver，正式環境不帶。
_extra_hosts = [h.strip() for h in os.environ.get("ALLOWED_HOSTS", "").split(",") if h.strip()]
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", *_extra_hosts])

# 瀏覽器發出的跨站請求會帶 Sec-Fetch-Site: cross-site／same-site；curl 等非瀏覽器
# 用戶端不帶此標頭。擋下跨站請求，避免其他網站用使用者的金鑰刷 VT 配額或 LLM 費用。
_ALLOWED_FETCH_SITES = {"same-origin", "none"}


def _is_loopback(host) -> bool:
    """用 ipaddress 判斷：IPv4-mapped IPv6 先還原成 IPv4，再看 is_loopback。
    無法解析的 host（例如 testclient）一律拒絕。"""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_loopback


CSP = ("frame-ancestors 'none'; object-src 'none'; base-uri 'none'; "
       "form-action 'self'; connect-src 'self'")


def _cross_site_rejection(request: Request) -> Optional[JSONResponse]:
    path = request.url.path
    if not path.startswith("/api/"):
        return None
    site = request.headers.get("sec-fetch-site")
    if site is not None and site.lower() not in _ALLOWED_FETCH_SITES:
        return JSONResponse({"detail": "不允許跨站請求"}, status_code=403)
    # 舊瀏覽器不送 Sec-Fetch-Site；跨站 no-cors POST 可不帶/帶 text/plain 的 Content-Type 繞過，
    # 所以有 body 的方法一律要求 application/json（跨站帶它會觸發 preflight）
    if request.method in ("POST", "PUT", "PATCH"):
        media = request.headers.get("content-type", "").split(";")[0].strip().lower()
        if media != "application/json":
            return JSONResponse({"detail": "只接受 application/json"}, status_code=415)
    # 寫入設定的端點另外限定來源為本機，即使有人把 host 改成 0.0.0.0 區網也不能改
    if path.startswith("/api/settings") and request.method not in ("GET", "HEAD", "OPTIONS"):
        host = request.client.host if request.client else None
        if not _is_loopback(host):
            return JSONResponse({"detail": "設定只能從本機修改"}, status_code=403)
    return None


@app.middleware("http")
async def block_cross_site(request: Request, call_next):
    response = _cross_site_rejection(request) or await call_next(request)
    # 防 clickjacking 並收斂外連（含 403 與靜態檔）。刻意不加 default-src/script-src/style-src：
    # 頁面大量使用 inline onclick 與 inline style，加了會整頁壞掉
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = CSP
    return response


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    """設定端點的 422 預設會在 detail[].input 原樣回傳送出的值（即金鑰），
    前端又會顯示在 DOM 上。該路徑下移除 input、ctx；其他路徑維持 FastAPI 預設格式。"""
    if request.url.path.startswith("/api/settings/"):
        errors = [{k: v for k, v in e.items() if k not in ("input", "ctx")} for e in exc.errors()]
        return JSONResponse({"detail": jsonable_encoder(errors)}, status_code=422)
    return await request_validation_exception_handler(request, exc)


@app.get("/api/dates")
def get_dates() -> list[str]:
    return database.get_dates()


@app.get("/api/reports")
def get_reports(date: models.DateStr) -> list[models.ReportResponse]:
    return database.get_reports_by_date(date)


@app.post("/api/reports")
def create_report(body: models.ReportCreate) -> models.ReportResponse:
    try:
        return database.create_report(body.date, body.fields, body.field_order)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))


@app.put("/api/reports/{report_id}")
def update_report(report_id: int, body: models.ReportUpdate) -> models.ReportResponse:
    try:
        result = database.update_report(report_id, body.fields, body.field_order)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    if result is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return result


@app.delete("/api/reports/{report_id}")
def delete_report(report_id: int) -> dict:
    try:
        deleted = database.delete_report(report_id)
    except images.ImageError as e:
        raise HTTPException(status_code=409, detail=str(e))
    if not deleted:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"ok": True}


def _report_or_404(report_id: int) -> dict:
    report = database.get_report(report_id)
    if report is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


@app.post("/api/reports/{report_id}/images", status_code=201)
def upload_image(report_id: int, body: models.ImageUpload) -> models.ImageUploadResponse:
    report = _report_or_404(report_id)
    offense_id = report["fields"].get("Offense ID", "").strip()
    try:
        images.check_offense_id(offense_id)
        # 同日重複的 Offense ID 會共用檔名前綴，圖會張冠李戴
        if database.offense_count_on_date(report["date"], offense_id) > 1:
            raise HTTPException(status_code=409, detail="此 Offense ID 在同日有重複通報，請先處理重複資料")
        try:
            data = base64.b64decode(body.data, validate=True)
        except (binascii.Error, ValueError):
            raise HTTPException(status_code=400, detail="圖片資料格式錯誤")
        # date 一律取 DB 內的值，不用請求帶的
        filename = images.add_image(report["date"], offense_id, data)
    except images.ImageError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return {"filename": filename, "images": images.list_images(report["date"], offense_id)}


def _image_file_or_404(report: dict, seq: int):
    offense_id = report["fields"].get("Offense ID", "").strip()
    path = images.image_path(report["date"], offense_id, seq)
    if path is None:
        raise HTTPException(status_code=404, detail="Image not found")
    return offense_id, path


@app.get("/api/reports/{report_id}/images/{seq}")
def get_image(report_id: int, seq: int):
    _, path = _image_file_or_404(_report_or_404(report_id), seq)
    return FileResponse(path, media_type="image/png", headers={"Cache-Control": "no-cache"})


@app.delete("/api/reports/{report_id}/images/{seq}")
def delete_image(report_id: int, seq: int) -> models.ImageListResponse:
    report = _report_or_404(report_id)
    offense_id, _ = _image_file_or_404(report, seq)
    images.delete_image(report["date"], offense_id, seq)
    return {"images": images.list_images(report["date"], offense_id)}


@app.get("/api/schema")
def get_schema(template: Literal["general", "waf"] = "general") -> models.SchemaResponse:
    return database.get_schema(template)


@app.put("/api/schema")
def update_schema(body: models.SchemaUpdate, template: Literal["general", "waf"] = "general") -> models.SchemaResponse:
    return database.update_schema(body.fields, template)


@app.get("/api/search")
def search(
    q: Optional[str] = None,
    date_from: Optional[models.DateStr] = None,
    date_to: Optional[models.DateStr] = None,
) -> models.SearchResult:
    reports = database.search_reports(q, date_from, date_to)
    return {"reports": reports}


def _with_view(result: dict) -> dict:
    """附上後處理視圖。原始 data 不動，後處理失敗也不影響查詢結果本身。"""
    processed = postprocess.process(result)
    return {**result, "view": processed["view"], "warnings": processed["warnings"]}


@app.get("/api/lookup/rdap")
def lookup_rdap(target: str) -> models.RdapLookupResponse:
    try:
        return _with_view(lookup.query_rdap_whois(target))
    except lookup.UnsupportedTargetError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except lookup.LookupFailedError as e:
        raise HTTPException(status_code=502, detail=str(e))


def _resolve_key(kind: str) -> Optional[str]:
    try:
        return settings_store.get_key(kind)
    except settings_store.KeyringUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.get("/api/lookup/vt")
def lookup_vt(target: str) -> models.VtLookupResponse:
    api_key = _resolve_key("vt")
    if not api_key:
        raise HTTPException(status_code=503, detail="請設定 VT_API_KEY（.env 或於設定頁輸入）")
    try:
        return _with_view(lookup.query_virustotal(target, api_key))
    except lookup.UnsupportedTargetError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except lookup.VtQueryError as e:
        raise HTTPException(status_code=e.status_code, detail=str(e))


# 實測完整的 VT 回應約 100KB，2MB 是寬鬆的上限。rdap／vt 是任意 dict，不設限的話
# 一個大 payload 就會變成大量 input tokens（花使用者的額度）或拖慢後處理。
MAX_LOOKUP_PAYLOAD_BYTES = 2 * 1024 * 1024


def _check_payload_size(**payloads: Optional[dict]) -> None:
    for name, payload in payloads.items():
        if payload is None:
            continue
        size = len(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
        if size > MAX_LOOKUP_PAYLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"{name} 資料過大（{size:,} bytes，上限 {MAX_LOOKUP_PAYLOAD_BYTES:,} bytes）")


# 整個 request body 的上限：rdap 與 vt 兩份各可到 MAX_LOOKUP_PAYLOAD_BYTES，
# 再加 target 與 JSON 外層結構的餘裕。這道關卡在 JSON 解析「之前」，擋住記憶體與解析成本；
# 上面逐欄位的檢查保留，用來擋單一來源過大。
MAX_LOOKUP_BODY_BYTES = 2 * MAX_LOOKUP_PAYLOAD_BYTES + 64 * 1024
# 截圖以 base64 上傳（膨脹 4/3），上限依單張圖片上限推算
MAX_IMAGE_BODY_BYTES = (images.MAX_IMAGE_BYTES * 4) // 3 + 64 * 1024


def _body_limit(path: str) -> Optional[int]:
    if path in ("/api/lookup/compare", "/api/lookup/analyze"):
        return MAX_LOOKUP_BODY_BYTES
    if re.fullmatch(r"/api/reports/\d+/images", path):
        return MAX_IMAGE_BODY_BYTES
    return None


class BodySizeLimitMiddleware:
    """純 ASGI middleware：先看 Content-Length，超過直接 413；沒有（chunked）時
    邊讀邊計數，超過就停止讀取並回 413。未超限才把已讀的內容重放給後面的 app。"""

    def __init__(self, app):
        self.app = app

    async def _reject(self, send, max_bytes: int) -> None:
        body = json.dumps(
            {"detail": f"請求內容過大（上限 {max_bytes:,} bytes）"}, ensure_ascii=False
        ).encode("utf-8")
        await send({"type": "http.response.start", "status": 413,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})

    async def __call__(self, scope, receive, send):
        max_bytes = (_body_limit(scope["path"])
                     if scope["type"] == "http" and scope["method"] == "POST" else None)
        if max_bytes is None:
            await self.app(scope, receive, send)
            return

        for name, value in scope["headers"]:
            if name == b"content-length":
                try:
                    declared = int(value)
                except ValueError:
                    break  # 無效值：退回逐塊計數
                if declared > max_bytes:
                    await self._reject(send, max_bytes)
                    return
                break

        messages, total = [], 0
        while True:
            message = await receive()
            messages.append(message)
            if message["type"] == "http.disconnect":
                return
            total += len(message.get("body", b""))
            if total > max_bytes:
                await self._reject(send, max_bytes)
                return
            if not message.get("more_body", False):
                break

        replay = iter(messages)

        async def replay_receive():
            try:
                return next(replay)
            except StopIteration:
                return await receive()

        await self.app(scope, replay_receive, send)


app.add_middleware(BodySizeLimitMiddleware)


@app.post("/api/lookup/compare")
def lookup_compare(body: models.CompareRequest) -> models.CompareResponse:
    """跨來源比對。比對的是正規化後的語意事實，不是欄位路徑——RDAP、WHOIS 備援、
    VirusTotal 屬性與其內嵌的 raw RDAP 四者結構差異太大，路徑映射表撐不住。"""
    _check_payload_size(rdap=body.rdap, vt=body.vt)
    return postprocess.compare_sources(body.rdap, body.vt)




@app.post("/api/lookup/analyze")
def lookup_analyze(body: models.AnalyzeRequest) -> models.AnalyzeResponse:
    _check_payload_size(rdap=body.rdap, vt=body.vt)
    api_key = _resolve_key("llm")
    if not api_key:
        raise HTTPException(status_code=503, detail="請設定 LLM_API_KEY（.env 或於設定頁輸入）")
    model, _ = settings_store.get_model()
    try:
        return lookup.analyze_with_llm(body.target, body.rdap, body.vt, api_key, model)
    except lookup.UnsupportedTargetError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except lookup.LlmQueryError as e:
        raise HTTPException(status_code=e.status_code, detail=str(e))


def _kind_or_404(kind: str) -> str:
    if kind not in settings_store.KEY_NAMES:
        raise HTTPException(status_code=404, detail="未知的金鑰類型")
    return kind


def _settings_call(fn, *args):
    """把 settings_store 的例外對應成 HTTP 狀態；訊息本身已不含金鑰。"""
    try:
        return fn(*args)
    except settings_store.SourceLockedError as e:
        raise HTTPException(status_code=409, detail=str(e))
    except settings_store.ValidationFailedError as e:
        raise HTTPException(status_code=e.status_code, detail=str(e))
    except settings_store.KeyringUnavailableError as e:
        raise HTTPException(status_code=503, detail=str(e))


@app.get("/api/settings")
def get_settings() -> models.SettingsResponse:
    return settings_store.get_status()


@app.put("/api/settings/keys/{kind}")
def put_key(kind: str, body: models.KeyUpdate) -> models.KeyStatus:
    return _settings_call(settings_store.set_key, _kind_or_404(kind), body.value)


@app.delete("/api/settings/keys/{kind}")
def delete_key(kind: str) -> models.KeyStatus:
    return _settings_call(settings_store.delete_key, _kind_or_404(kind))


@app.put("/api/settings/model")
def put_model(body: models.ModelUpdate) -> models.ModelStatus:
    if body.model not in settings_store.ALLOWED_MODELS:
        raise HTTPException(status_code=422, detail="不支援的模型")
    return _settings_call(settings_store.set_model, body.model)


class NoCacheStaticFiles(StaticFiles):
    """靜態檔案（尤其 index.html／ip-lookup.js）開發中頻繁變動，瀏覽器的
    啟發式快取常導致重新整理後仍看到舊版。強制每次請求都向伺服器驗證，
    避免「明明改好了但畫面沒更新」的困惑。"""

    def file_response(self, *args, **kwargs):
        response = super().file_response(*args, **kwargs)
        response.headers["Cache-Control"] = "no-cache"
        return response


app.mount("/", NoCacheStaticFiles(directory=database.BASE_DIR / "static", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    import threading
    import time
    import webbrowser

    # 定義一個要在背景執行的函式
    def open_browser():
        # 稍微等待 1.5 秒，確保 Uvicorn 伺服器已經完全啟動並開始監聽
        time.sleep(1.5)
        webbrowser.open_new_tab("http://127.0.0.1:8000")

    # 啟動背景執行緒去開瀏覽器，主程式會繼續往下走
    threading.Thread(target=open_browser, daemon=True).start()

    # 執行 Uvicorn（此處會阻塞主執行緒）
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
