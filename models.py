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


class LookupResponseBase(BaseModel):
    target: str
    type: Literal["ip", "domain"]
    source: str
    queried_at: str
    # data 永遠是未經加工的原始回應；view 是後處理產出的摘要視圖。
    # 兩者並存，任何後處理規則都不會成為資料的唯一出口。
    data: dict
    view: Optional[dict] = None
    warnings: list[str] = []


class RdapLookupResponse(LookupResponseBase):
    pass


class VtLookupResponse(LookupResponseBase):
    pass


class CompareRequest(BaseModel):
    # 兩邊都可為 None：任一來源查詢失敗時仍要能比對剩下的那一份
    rdap: Optional[dict] = None
    vt: Optional[dict] = None


class CompareResponse(BaseModel):
    target: str
    sources: list[dict]
    rows: list[dict]
    headline: Optional[str] = None
    summary: dict
    warnings: list[str] = []


class AnalyzeRequest(BaseModel):
    target: str
    rdap: Optional[dict] = None
    vt: Optional[dict] = None


class AnalyzeResponse(BaseModel):
    content: str
    analyzed_at: str
    target: str
    model: str
    # token 用量。重試時是兩次呼叫的總和，calls 記錄實際呼叫次數。
    usage: dict = {}
