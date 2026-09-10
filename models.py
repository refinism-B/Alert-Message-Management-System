from typing import Literal, Optional

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


class RdapLookupResponse(BaseModel):
    target: str
    type: Literal["ip", "domain"]
    source: str
    queried_at: str
    data: dict


class VtLookupResponse(BaseModel):
    target: str
    type: Literal["ip", "domain"]
    source: str
    queried_at: str
    data: dict


class AnalyzeRequest(BaseModel):
    target: str
    rdap: Optional[dict] = None
    vt: Optional[dict] = None


class AnalyzeResponse(BaseModel):
    content: str
    analyzed_at: str
    target: str
    model: str
