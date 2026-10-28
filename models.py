import re
from datetime import date as _date
from typing import Annotated, Literal, Optional

from pydantic import AfterValidator, BaseModel, Field, field_validator


def validate_date_str(value: str) -> str:
    """YYYY-MM-DD 且是真實存在的日期；搜尋的日期範圍靠字串比較，格式必須固定。"""
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", value):
        raise ValueError("日期格式必須為 YYYY-MM-DD")
    try:
        _date.fromisoformat(value)
    except ValueError:
        raise ValueError("日期不存在") from None
    return value


DateStr = Annotated[str, AfterValidator(validate_date_str)]

REQUIRED_SCHEMA_FIELDS = ("Offense ID",)


class ReportCreate(BaseModel):
    date: DateStr
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
    images: list[str] = []


class ImageUpload(BaseModel):
    data: str  # 純 base64，無 data: 前綴


class ImageListResponse(BaseModel):
    images: list[str]


class ImageUploadResponse(ImageListResponse):
    filename: str


class SchemaUpdate(BaseModel):
    fields: list[str]

    @field_validator("fields")
    @classmethod
    def _check_fields(cls, v: list[str]) -> list[str]:
        cleaned = [f.strip() for f in v]
        if not cleaned:
            raise ValueError("欄位清單不可為空")
        if any(not f for f in cleaned):
            raise ValueError("欄位名稱不可為空白")
        if len(set(cleaned)) != len(cleaned):
            raise ValueError("欄位名稱不可重複")
        for required in REQUIRED_SCHEMA_FIELDS:
            if required not in cleaned:
                raise ValueError(f"必須保留「{required}」欄位")
        return cleaned


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
    # target 是正規化後實際拿去查詢的值（IDN 會是 punycode）；與使用者輸入不同時
    # 保留原輸入供顯示，相同時為 None。
    input_target: Optional[str] = None


class RdapLookupResponse(LookupResponseBase):
    pass


class VtLookupResponse(LookupResponseBase):
    # 6 小時內查過的目標回快取。cached_at 是寫入快取的時間（ISO 8601，含時區），
    # queried_at 仍是當初向 VirusTotal 取得資料的時間。
    cached: bool = False
    cached_at: Optional[str] = None


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


class KeyUpdate(BaseModel):
    value: str = Field(max_length=1024, repr=False)


class ModelUpdate(BaseModel):
    model: str = Field(max_length=200)


class KeyStatus(BaseModel):
    configured: bool
    source: Literal["env", "ui", "none"]
    hint: Optional[str] = None
    updated_at: Optional[str] = None


class ModelStatus(BaseModel):
    value: str
    source: Literal["env", "ui", "default"]
    options: list[str]


class SettingsResponse(BaseModel):
    keys: dict[str, KeyStatus]
    keyring_error: Optional[str] = None
    model: ModelStatus
