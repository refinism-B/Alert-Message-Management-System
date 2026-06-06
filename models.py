from pydantic import BaseModel


class ReportCreate(BaseModel):
    date: str
    fields: dict[str, str]
    field_order: list[str]


class ReportUpdate(BaseModel):
    fields: dict[str, str]
    field_order: list[str]


class ReportResponse(BaseModel):
    id: int
    date: str
    fields: dict[str, str]
    field_order: list[str]
    created_at: str
    updated_at: str


class SchemaUpdate(BaseModel):
    fields: list[str]


class SchemaResponse(BaseModel):
    fields: list[str]
    updated_at: str


class SearchResult(BaseModel):
    reports: list[ReportResponse]
