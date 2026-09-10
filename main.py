from dotenv import load_dotenv

load_dotenv()

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from typing import Literal, Optional
import os

import database
import lookup
import models

app = FastAPI()

database.init_db()


@app.get("/api/dates")
def get_dates() -> list[str]:
    return database.get_dates()


@app.get("/api/reports")
def get_reports(date: str) -> list[models.ReportResponse]:
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
    database.delete_report(report_id)
    return {"ok": True}


@app.get("/api/schema")
def get_schema(template: Literal["general", "waf"] = "general") -> models.SchemaResponse:
    return database.get_schema(template)


@app.put("/api/schema")
def update_schema(body: models.SchemaUpdate, template: Literal["general", "waf"] = "general") -> models.SchemaResponse:
    return database.update_schema(body.fields, template)


@app.get("/api/search")
def search(
    q: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
) -> models.SearchResult:
    reports = database.search_reports(q, date_from, date_to)
    return {"reports": reports}


@app.get("/api/lookup/rdap")
def lookup_rdap(target: str) -> models.RdapLookupResponse:
    try:
        return lookup.query_rdap_whois(target)
    except lookup.LookupFailedError as e:
        raise HTTPException(status_code=502, detail=str(e))


@app.get("/api/lookup/vt")
def lookup_vt(target: str) -> models.VtLookupResponse:
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        raise HTTPException(status_code=503, detail="請設定 VT_API_KEY")
    try:
        return lookup.query_virustotal(target, api_key)
    except lookup.VtQueryError as e:
        raise HTTPException(status_code=e.status_code, detail=str(e))


@app.post("/api/lookup/analyze")
def lookup_analyze(body: models.AnalyzeRequest) -> models.AnalyzeResponse:
    api_key = os.environ.get("LLM_API_KEY")
    if not api_key:
        raise HTTPException(status_code=503, detail="請設定 LLM_API_KEY")
    model = os.environ.get("LLM_MODEL", "claude-sonnet-5")
    try:
        return lookup.analyze_with_llm(body.target, body.rdap, body.vt, api_key, model)
    except lookup.LlmQueryError as e:
        raise HTTPException(status_code=e.status_code, detail=str(e))


app.mount("/", StaticFiles(directory="static", html=True), name="static")

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
