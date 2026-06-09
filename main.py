from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from typing import Optional
import database
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
    return database.create_report(body.date, body.fields, body.field_order)


@app.put("/api/reports/{report_id}")
def update_report(report_id: int, body: models.ReportUpdate) -> models.ReportResponse:
    result = database.update_report(report_id, body.fields, body.field_order)
    if result is None:
        raise HTTPException(status_code=404, detail="Report not found")
    return result


@app.delete("/api/reports/{report_id}")
def delete_report(report_id: int) -> dict:
    database.delete_report(report_id)
    return {"ok": True}


@app.get("/api/schema")
def get_schema() -> models.SchemaResponse:
    return database.get_schema()


@app.put("/api/schema")
def update_schema(body: models.SchemaUpdate) -> models.SchemaResponse:
    return database.update_schema(body.fields)


@app.get("/api/search")
def search(
    q: Optional[str] = None,
    date_from: Optional[str] = None,
    date_to: Optional[str] = None,
) -> models.SearchResult:
    reports = database.search_reports(q, date_from, date_to)
    return {"reports": reports}


app.mount("/", StaticFiles(directory="static", html=True), name="static")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
