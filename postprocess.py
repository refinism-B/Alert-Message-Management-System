"""RDAP / WHOIS / VirusTotal 查詢結果的後處理。

設計原則（詳見 docs/RDAP_VT_後處理_可行性評估.md）：

1. **原始資料永不丟失**：本模組只產生 `view`（給人看的摘要視圖），呼叫端保留的
   `data`（原始回應）完全不動。每一個攤平後的欄位路徑都會被分配到某個區塊、
   或進「其他欄位」、或進 `hidden`，不會有欄位憑空消失。
2. **三套 schema 分開處理**：whoisit（RDAP 成功）、python-whois（TCP 43 備援）、
   VirusTotal API v3 的欄位名稱與型別完全不同，依 `source` 分派到不同 profile。
3. **「查無資料」與「無異常」嚴格區分**：缺資料一律顯示「資料未提供」，
   絕不顯示 0 或空白——把「不知道」呈現成「沒問題」是本模組最危險的失敗模式。
4. **Fail-soft**：任何一條規則出錯都不得讓查詢失敗，退回原始顯示並記入 warnings。
"""

import hashlib
import ipaddress
import re
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

TW_TZ = timezone(timedelta(hours=8))

# 時間戳合理範圍：早於 1990 或晚於「現在 + 10 年」的值視為髒資料或單位錯誤
# （例如毫秒級時間戳），原樣顯示並告警，不硬轉。
_MIN_EPOCH = 631152000  # 1990-01-01Z
_MAX_EPOCH_AHEAD_DAYS = 3653  # ~10 年

# VirusTotal 引擎判定的官方列舉值。分三類而非二分法：timeout / type-unsupported
# 這類「引擎沒跑成功」的結果若算成異常，每次查詢都會噴出一堆假警報。
_VT_NORMAL = {"harmless", "undetected"}
_VT_ABNORMAL = {"malicious", "suspicious"}

# 已知的 epoch 欄位白名單。刻意不用「10 位數整數就當成時間戳」這種啟發式——
# VT 的 asn、popularity rank 等數值都可能落在該範圍內而被誤轉。
_VT_EPOCH_FIELDS = {
    "first_seen_date", "last_analysis_date", "last_modification_date",
    "whois_date", "creation_date", "expiration_date", "last_update_date",
    "last_dns_records_date", "last_https_certificate_date", "timestamp",
    "not_after", "not_before",
}

_EMPTY_VALUES = (None, "", [], {})


# ---------------------------------------------------------------------------
# 攤平
# ---------------------------------------------------------------------------

def flatten(data: Any, prefix: str = "") -> dict[str, Any]:
    """把巢狀結構攤平成 {路徑: 純量值}。

    深度上限與走訪記錄用來防止 RDAP entities 的深層巢狀（實測 VT 內嵌的 RDAP
    確實有 entity 內再包 entity）把遞迴撐爆，以及理論上的循環參照。
    """
    return _flatten(data, prefix, depth=0, seen=set())


# 實測 VT 內嵌 RDAP 的 vcard_array 最深到第 13 層，設 6 會截掉真實資料。
# 上限的用途是擋失控遞迴，不是壓縮資料——循環參照另有 seen 集合把關。
_MAX_DEPTH = 14


def _flatten(data: Any, prefix: str, depth: int, seen: set) -> dict[str, Any]:
    out: dict[str, Any] = {}
    if depth > _MAX_DEPTH:
        out[prefix or "(root)"] = "（巢狀層數超過上限，已截斷；完整內容請見原始資料）"
        return out
    if isinstance(data, (dict, list)) and id(data) in seen:
        out[prefix or "(root)"] = "（循環參照，已截斷）"
        return out

    if isinstance(data, dict):
        if not data:
            out[prefix] = {}
            return out
        seen = seen | {id(data)}
        for key, value in data.items():
            label = f"{prefix}.{key}" if prefix else str(key)
            out.update(_flatten(value, label, depth + 1, seen))
    elif isinstance(data, list):
        if not data:
            out[prefix] = []
            return out
        seen = seen | {id(data)}
        for i, item in enumerate(data):
            out.update(_flatten(item, f"{prefix}[{i}]", depth + 1, seen))
    else:
        out[prefix] = data
    return out


def is_empty(value: Any) -> bool:
    if isinstance(value, bool) or isinstance(value, (int, float)):
        return False
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    if isinstance(value, (list, dict, tuple)):
        return len(value) == 0
    return False


def to_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "是" if value else "否"
    if isinstance(value, (list, tuple)):
        return "; ".join(to_text(v) for v in value)
    if isinstance(value, dict):
        return "; ".join(f"{k}={to_text(v)}" for k, v in value.items())
    return str(value)


# ---------------------------------------------------------------------------
# 時間
# ---------------------------------------------------------------------------

def parse_time(value: Any, field_name: str = "") -> Optional[datetime]:
    """把 epoch 整數或 ISO 字串轉成 datetime（UTC+8）。無法判讀回 None。

    epoch 只在欄位名稱屬於白名單時才嘗試轉換（見 _VT_EPOCH_FIELDS 的說明）。
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        base = field_name.rsplit(".", 1)[-1].split("[")[0]
        if base not in _VT_EPOCH_FIELDS:
            return None
        if not _epoch_in_range(value):
            return None
        return datetime.fromtimestamp(value, TW_TZ)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        try:
            dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(TW_TZ)
    return None


def _epoch_in_range(value: float) -> bool:
    max_epoch = (datetime.now(TW_TZ) + timedelta(days=_MAX_EPOCH_AHEAD_DAYS)).timestamp()
    return _MIN_EPOCH <= value <= max_epoch


def format_time(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S (UTC+8)")


def relative_time(dt: datetime, now: Optional[datetime] = None, *, is_expiry: bool = False) -> str:
    """人類可讀的相對時間。未來時間與過期時間的措辭不同——「已過期 N 天」本身
    就是一個風險訊號，不能跟「N 天前」混為一談。"""
    now = now or datetime.now(TW_TZ)
    delta = dt - now
    seconds = delta.total_seconds()
    magnitude = _humanize(abs(seconds))
    if seconds >= 0:
        return f"還有 {magnitude}" if is_expiry else f"{magnitude}後"
    return f"已過期 {magnitude}" if is_expiry else f"{magnitude}前"


def _humanize(seconds: float) -> str:
    if seconds < 3600:
        return f"{int(seconds // 60)} 分鐘"
    if seconds < 86400:
        return f"{int(seconds // 3600)} 小時"
    days = int(seconds // 86400)
    if days < 365:
        return f"{days} 天"
    return f"{days // 365} 年 {days % 365} 天"


def describe_time(value: Any, field_name: str = "", *, is_expiry: bool = False,
                  now: Optional[datetime] = None) -> Optional[str]:
    dt = parse_time(value, field_name)
    if dt is None:
        return None
    return f"{format_time(dt)}（{relative_time(dt, now, is_expiry=is_expiry)}）"


# ---------------------------------------------------------------------------
# entity 指紋（去重用）
# ---------------------------------------------------------------------------

_ENTITY_CORE_FIELDS = ("handle", "name", "email", "url")


def entity_fingerprint(entity: dict) -> Optional[str]:
    """對 entity 的核心欄位取指紋。核心欄位全空時回 None。

    回 None 的情形**一律不合併**：兩個什麼都沒填的 entity 指紋當然相同，
    但那不足以證明它們是同一個實體，合併會造成事實上的錯誤。
    """
    parts = []
    for field in _ENTITY_CORE_FIELDS:
        raw = entity.get(field)
        text = to_text(raw).strip().lower()
        parts.append(text)
    if not any(parts):
        return None
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()[:16]


# ---------------------------------------------------------------------------
# 陣列壓縮
# ---------------------------------------------------------------------------

def collapse_records(records: list[dict]) -> dict:
    """把同形狀的字典陣列壓成「恆定欄位 + 變動欄位表」。

    n == 1 時不判斷「全部相同」——單一元素的所有欄位當然都相同，說它們恆定是
    誤導。這時直接全部當成變動欄位輸出。
    """
    records = [r for r in records if isinstance(r, dict)]
    if not records:
        return {"constant": {}, "columns": [], "rows": [], "empty_columns": []}

    columns: list[str] = []
    for record in records:
        for key in record:
            if key not in columns:
                columns.append(key)

    empty_columns = [c for c in columns if all(is_empty(r.get(c)) for r in records)]
    remaining = [c for c in columns if c not in empty_columns]

    constant: dict[str, Any] = {}
    if len(records) >= 2:
        for column in list(remaining):
            values = {to_text(r.get(column)) for r in records}
            if len(values) == 1:
                constant[column] = records[0].get(column)
                remaining.remove(column)

    rows = [[r.get(c) for c in remaining] for r in records]
    return {"constant": constant, "columns": remaining, "rows": rows,
            "empty_columns": empty_columns}


# ---------------------------------------------------------------------------
# 視圖建構器
# ---------------------------------------------------------------------------

class ViewBuilder:
    """累積 summary / sections / hidden / warnings，並追蹤哪些原始路徑已被消化。

    `consumed` 的用途是自我稽核：所有攤平路徑扣掉已消化的，剩下的就是這份
    profile 沒認得的欄位，會被放進「其他欄位」區塊而不是被靜默丟掉。
    """

    def __init__(self, flat: dict[str, Any]):
        self.flat = flat
        self.summary: list[dict] = []
        self.sections: list[dict] = []
        self.hidden_fields: list[dict] = []
        self.warnings: list[str] = []
        self.unknown_fields: list[str] = []
        self.consumed: set[str] = set()

    # -- summary ------------------------------------------------------------

    def add_summary(self, label: str, value: Any, *, path: Optional[str] = None,
                    note: Optional[str] = None, tone: Optional[str] = None,
                    text: Optional[str] = None) -> None:
        """加一列摘要。value 為空時顯示「資料未提供」而不是空白或 0。"""
        missing = is_empty(value) and text is None
        self.summary.append({
            "label": label,
            "value": "資料未提供" if missing else (text if text is not None else to_text(value)),
            "path": path,
            "note": note,
            "tone": tone,
            "missing": missing,
        })
        if path:
            self.consume(path)

    # -- 路徑消化 ------------------------------------------------------------

    def consume(self, *paths: str) -> None:
        for path in paths:
            self.consumed.add(path)

    def consume_prefix(self, prefix: str) -> list[str]:
        matched = [p for p in self.flat
                   if p == prefix or p.startswith(prefix + ".") or p.startswith(prefix + "[")]
        self.consumed.update(matched)
        return matched

    def get(self, path: str, default: Any = None) -> Any:
        return self.flat.get(path, default)

    # -- sections -----------------------------------------------------------

    def add_section(self, section_id: str, title: str, kind: str, payload: dict, *,
                    collapsed: bool = False, note: Optional[str] = None) -> None:
        section = {"id": section_id, "title": title, "kind": kind,
                   "collapsed": collapsed, "note": note}
        section.update(payload)
        self.sections.append(section)

    def add_fields_section(self, section_id: str, title: str, rows: list[dict], *,
                           collapsed: bool = False, note: Optional[str] = None) -> None:
        rows = [r for r in rows if r]
        if not rows:
            return
        self.add_section(section_id, title, "fields", {"rows": rows},
                         collapsed=collapsed, note=note)

    def hide(self, label: str, path: str, reason: str) -> None:
        self.hidden_fields.append({"label": label, "path": path, "reason": reason})
        self.consume(path)

    def warn(self, message: str) -> None:
        if message not in self.warnings:
            self.warnings.append(message)

    # -- 收尾 ---------------------------------------------------------------

    def finish(self, labeller) -> dict:
        """把沒被任何規則消化的欄位收進「其他欄位」，確保零遺漏。"""
        leftovers = [p for p in self.flat if p not in self.consumed]
        rows = []
        for path in leftovers:
            value = self.flat[path]
            if is_empty(value):
                self.hide(labeller(path), path, "空值")
                continue
            self.unknown_fields.append(path)
            rows.append({"label": labeller(path), "path": path, "value": to_text(value)})
        if rows:
            self.add_fields_section(
                "other", "其他欄位", rows, collapsed=True,
                note="這些欄位尚未納入翻譯字典，以原始路徑顯示。",
            )
        self.consumed.update(leftovers)
        return {
            "summary": self.summary,
            "sections": self.sections,
            "hidden": {
                "count": len(self.hidden_fields),
                "empty_count": sum(1 for f in self.hidden_fields if f["reason"] == "空值"),
                "fields": self.hidden_fields,
            },
            "unknown_fields": self.unknown_fields,
        }


# ---------------------------------------------------------------------------
# 欄位字典
# ---------------------------------------------------------------------------

# whoisit（RDAP 查詢成功時）的正規化 schema。刻意不對照 RFC 9083——whoisit
# 已經把 events/vcardArray 等結構轉成自己的欄位名，RFC 的路徑對不上。
WHOISIT_LABELS = {
    "handle": "物件代碼",
    "parent_handle": "上層物件代碼",
    "name": "名稱",
    "unicode_name": "名稱（Unicode）",
    "whois_server": "WHOIS 伺服器",
    "type": "物件類型",
    "terms_of_service_url": "服務條款網址",
    "copyright_notice": "版權聲明",
    "description": "描述",
    "last_changed_date": "最後異動時間",
    "registration_date": "註冊／分配時間",
    "expiration_date": "到期時間",
    "url": "RDAP 查詢網址",
    "rir": "所屬 RIR",
    "country": "國家／地區",
    "ip_version": "IP 版本",
    "assignment_type": "分配類型",
    "network": "網段",
    "asn_range": "ASN 範圍",
    "status": "狀態",
    "nameservers": "名稱伺服器",
    "dnssec": "DNSSEC",
    "raw": "原始回應",
    "entities.*.handle": "聯絡人代碼",
    "entities.*.name": "聯絡人名稱",
    "entities.*.email": "聯絡人 Email",
    "entities.*.url": "聯絡人 RDAP 網址",
    "entities.*.type": "聯絡人物件類型",
    "entities.*.rir": "聯絡人所屬 RIR",
    "entities.*.address.po_box": "郵政信箱",
    "entities.*.address.ext_address": "地址（延伸）",
    "entities.*.address.street_address": "街道地址",
    "entities.*.address.locality": "城市",
    "entities.*.address.region": "行政區",
    "entities.*.address.postal_code": "郵遞區號",
    "entities.*.address.country": "國家",
    "entities.*.phone": "聯絡電話",
}

ENTITY_ROLE_LABELS = {
    "registrant": "註冊人",
    "registrar": "註冊商",
    "administrative": "行政聯絡人",
    "technical": "技術聯絡人",
    "abuse": "濫用檢舉窗口",
    "billing": "帳務聯絡人",
    "noc": "網路維運中心",
    "reseller": "經銷商",
    "sponsor": "贊助註冊商",
    "proxy": "代理人",
    "notifications": "通知窗口",
}

# python-whois 備援。實測 .tw 的解析會錯位（registrant_country 出現
# "Administrative Contact:"），所以這個 profile 的所有欄位都附可信度警示。
PYWHOIS_LABELS = {
    "domain_name": "網域名稱",
    "registrar": "註冊商",
    "registrar_url": "註冊商網址",
    "whois_server": "WHOIS 伺服器",
    "creation_date": "建立時間",
    "expiration_date": "到期時間",
    "updated_date": "最後異動時間",
    "name_servers": "名稱伺服器",
    "status": "狀態",
    "dnssec": "DNSSEC",
    "emails": "聯絡 Email",
    "org": "組織",
    "registrant_name": "註冊人姓名",
    "registrant_organization": "註冊人組織",
    "registrant_street": "註冊人地址",
    "registrant_city": "註冊人城市",
    "registrant_state_province": "註冊人行政區",
    "registrant_postal_code": "註冊人郵遞區號",
    "registrant_country": "註冊人國家",
    "registrant_phone": "註冊人電話",
    "registrant_fax": "註冊人傳真",
    "registrant_email": "註冊人 Email",
    "admin": "行政聯絡人",
    "admin_email": "行政聯絡人 Email",
    "admin_phone": "行政聯絡人電話",
    "admin_fax": "行政聯絡人傳真",
    "tech": "技術聯絡人",
    "tech_email": "技術聯絡人 Email",
    "tech_phone": "技術聯絡人電話",
    "tech_fax": "技術聯絡人傳真",
}

VT_LABELS = {
    "data.id": "查詢物件 ID",
    "data.type": "物件類型",
    "data.links.self": "VirusTotal API 連結",
    "as_owner": "ASN 持有者",
    "asn": "ASN",
    "network": "網段",
    "country": "國家／地區",
    "continent": "所屬洲",
    "regional_internet_registry": "所屬 RIR",
    "reputation": "社群信譽分數",
    "tags": "標籤",
    "jarm": "JARM（TLS 指紋）",
    "tld": "頂級網域",
    "registrar": "註冊商",
    "first_seen_date": "VT 首次觀察時間",
    "last_analysis_date": "最後掃描時間",
    "last_modification_date": "VT 資料最後更新時間",
    "whois_date": "WHOIS 取得時間",
    "creation_date": "建立時間",
    "expiration_date": "到期時間",
    "last_update_date": "最後異動時間",
    "last_dns_records_date": "DNS 紀錄取得時間",
    "last_https_certificate": "HTTPS 憑證",
    "last_https_certificate_date": "HTTPS 憑證取得時間",
    "last_dns_records": "DNS 紀錄",
    "crowdsourced_context": "社群情資",
    "popularity_ranks": "熱門度排名",
    "categories": "廠商分類",
    "whois": "WHOIS 原文",
    "rdap": "RDAP 快照",
    "total_votes.harmless": "社群投票：無害",
    "total_votes.malicious": "社群投票：惡意",
    "last_analysis_stats.malicious": "判定惡意的引擎數",
    "last_analysis_stats.suspicious": "判定可疑的引擎數",
    "last_analysis_stats.undetected": "未偵測的引擎數",
    "last_analysis_stats.harmless": "判定無害的引擎數",
    "last_analysis_stats.timeout": "逾時的引擎數",
}

# 註冊局／RIR 的 RDAP 擴充欄位前綴（RFC 7480 §6 的 extension 機制）。
# 這類欄位每家不同、且會隨時間增加，不可能用字典窮舉，統一歸到收合區塊比
# 逐一標「待補充翻譯」有意義。
_RDAP_EXTENSION_RE = re.compile(r"(^|\.)[a-z][a-z0-9]*[0-9]_[a-z0-9_]+")

# 法律／協定樣板欄位：內容每筆都不同且都不空，靠空值或恆定值判斷抓不出來，
# 用欄位名白名單直接歸類。
_LEGAL_KEYS = {"notices", "remarks", "copyright_notice", "terms_of_service_url",
               "rdap_conformance", "lang", "object_class_name", "port43"}


def _label_from_dict(path: str, table: dict[str, str]) -> str:
    """字典查找：先試完整路徑，再試把陣列索引與 entity 角色換成萬用字元。"""
    if path in table:
        return table[path]
    generic = re.sub(r"\[\d+\]", "", path)
    if generic in table:
        return table[generic]
    parts = generic.split(".")
    if len(parts) >= 2:
        wildcarded = ".".join([parts[0], "*"] + parts[2:])
        if wildcarded in table:
            return table[wildcarded]
    tail = parts[-1]
    if tail in table:
        return table[tail]
    return path


def make_labeller(table: dict[str, str]):
    def labeller(path: str) -> str:
        label = _label_from_dict(path, table)
        return label if label != path else path
    return labeller


def label_with_path(path: str, table: dict[str, str]) -> dict:
    """翻譯只加不取代：同時保留原始路徑，讓分析師能回頭核對原始資料
    （lookup.py 的 SYSTEM_PROMPT 也要求 LLM 標註欄位路徑）。"""
    return {"label": _label_from_dict(path, table), "path": path}


# ---------------------------------------------------------------------------
# Profile：whoisit（RDAP 查詢成功）
# ---------------------------------------------------------------------------

_ENTITY_ROLE_ORDER = ["registrant", "registrar", "administrative", "technical",
                      "abuse", "billing", "noc", "reseller", "sponsor"]


def _collect_entities(entities: Any) -> list[dict]:
    """把 {角色: [entity]} 攤成清單，內容相同的 entity 依指紋合併並保留所有角色。

    指紋為 None（核心欄位全空）者一律不合併——無法證明是同一實體。
    """
    if not isinstance(entities, dict):
        return []
    ordered_roles = [r for r in _ENTITY_ROLE_ORDER if r in entities]
    ordered_roles += [r for r in entities if r not in ordered_roles]

    merged: list[dict] = []
    by_fingerprint: dict[str, dict] = {}
    for role in ordered_roles:
        items = entities.get(role)
        if not isinstance(items, list):
            continue
        for index, entity in enumerate(items):
            if not isinstance(entity, dict):
                continue
            role_label = ENTITY_ROLE_LABELS.get(role, role)
            fingerprint = entity_fingerprint(entity)
            if fingerprint and fingerprint in by_fingerprint:
                by_fingerprint[fingerprint]["roles"].append(role_label)
                by_fingerprint[fingerprint]["paths"].append(f"entities.{role}[{index}]")
                continue
            record = {"roles": [role_label], "entity": entity,
                      "paths": [f"entities.{role}[{index}]"],
                      "mergeable": fingerprint is not None}
            merged.append(record)
            if fingerprint:
                by_fingerprint[fingerprint] = record
    return merged


def _entity_rows(builder: "ViewBuilder", record: dict, table: dict[str, str]) -> list[dict]:
    """空欄位不直接丟棄，記入 hidden。分析師需要能分辨「這欄是空的」與
    「這個來源根本沒有這個欄位」——兩者的判讀意義不同。"""
    rows = []
    for base_path in record["paths"]:
        for key, value in record["entity"].items():
            pairs = value.items() if isinstance(value, dict) else [(None, value)]
            for sub_key, sub_value in pairs:
                generic = f"entities.*.{key}.{sub_key}" if sub_key else f"entities.*.{key}"
                path = f"{base_path}.{key}.{sub_key}" if sub_key else f"{base_path}.{key}"
                label = _label_from_dict(generic, table)
                if is_empty(sub_value):
                    builder.hide(label, path, "空值")
                    continue
                if base_path != record["paths"][0]:
                    continue  # 合併顯示的重複角色不重覆列出內容
                rows.append({"label": label, "path": path, "value": to_text(sub_value)})
    return rows


def _build_whoisit_view(result: dict, builder: ViewBuilder, now: Optional[datetime]) -> None:
    data = result.get("data") or {}
    target_type = result.get("type")

    name = builder.get("name")
    unicode_name = builder.get("unicode_name")
    builder.consume("unicode_name")
    if not is_empty(unicode_name) and to_text(unicode_name).lower() != to_text(name).lower():
        # IDN：只顯示好看的 Unicode 名稱會掩蓋 homograph 攻擊，兩種寫法都要在
        builder.add_summary(
            "名稱", name, path="name",
            text=f"{to_text(unicode_name)}（A-label：{to_text(name)}）",
            note="此為國際化網域名稱（IDN），請確認 Unicode 寫法與 A-label 相符，慎防相似字元攻擊。",
            tone="warn")
    else:
        builder.add_summary("名稱", name, path="name")

    if target_type == "ip":
        builder.add_summary("網段", builder.get("network"), path="network")
        builder.add_summary("分配類型", builder.get("assignment_type"), path="assignment_type")
        builder.add_summary("IP 版本", builder.get("ip_version"), path="ip_version")
    else:
        builder.add_summary("註冊商", builder.get("entities.registrar[0].name"),
                            path="entities.registrar[0].name")

    builder.add_summary("所屬 RIR", builder.get("rir"), path="rir")
    builder.add_summary("國家／地區", builder.get("country"), path="country")

    for label, key, is_expiry in (("註冊／分配時間", "registration_date", False),
                                  ("最後異動時間", "last_changed_date", False),
                                  ("到期時間", "expiration_date", True)):
        raw_value = builder.get(key)
        described = describe_time(raw_value, key, is_expiry=is_expiry, now=now)
        tone = "risk" if (is_expiry and described and "已過期" in described) else None
        builder.add_summary(label, raw_value, path=key, text=described, tone=tone)

    if target_type != "ip":
        nameservers = data.get("nameservers")
        builder.add_summary("DNSSEC", builder.get("dnssec"), path="dnssec")
        builder.add_summary(
            "名稱伺服器", nameservers,
            text=f"{len(nameservers)} 台：{to_text(nameservers)}"
            if isinstance(nameservers, list) and nameservers else None)
        builder.consume_prefix("nameservers")

    builder.add_summary("濫用檢舉窗口", builder.get("entities.abuse[0].email"),
                        path="entities.abuse[0].email")

    # -- 聯絡窗口：內容相同者合併，但保留全部角色名 --
    records = _collect_entities(data.get("entities"))
    builder.consume_prefix("entities")
    for i, record in enumerate(records):
        note = None
        if len(record["roles"]) > 1:
            note = "以下角色的聯絡資料內容完全相同，已合併顯示。"
        elif not record["mergeable"]:
            note = "此聯絡人的代碼／名稱／Email 皆為空，無法比對是否與其他聯絡人重複，故獨立列出。"
        builder.add_fields_section(f"entity_{i}", "、".join(record["roles"]),
                                   _entity_rows(builder, record, WHOISIT_LABELS), note=note)

    # -- 物件明細 --
    detail_rows = []
    for key in ["handle", "parent_handle", "type", "status", "url", "whois_server",
                "description", "asn_range"]:
        value = data.get(key)
        if is_empty(value):
            builder.hide(_label_from_dict(key, WHOISIT_LABELS), key, "空值")
            continue
        detail_rows.append({"label": _label_from_dict(key, WHOISIT_LABELS),
                            "path": key, "value": to_text(value)})
        builder.consume_prefix(key)
    builder.add_fields_section("object_detail", "物件明細", detail_rows)

    _add_legal_section(builder, WHOISIT_LABELS, prefix="")

    if not is_empty(data.get("raw")):
        raw_paths = builder.consume_prefix("raw")
        rows = []
        for p in raw_paths:
            if is_empty(builder.flat[p]):
                builder.hide(_label_from_dict(p, WHOISIT_LABELS), p, "空值")
                continue
            rows.append({"label": _label_from_dict(p, WHOISIT_LABELS), "path": p,
                         "value": to_text(builder.flat[p])})
        builder.add_section("raw_rdap", "RDAP 原始回應", "fields", {"rows": rows}, collapsed=True)


def _add_legal_section(builder: "ViewBuilder", table: dict[str, str], prefix: str) -> None:
    """法律聲明／協定樣板：內容每筆都不同且都不空，靠空值或恆定值判斷抓不出來，
    用欄位名白名單直接歸類並預設收合。"""
    rows = []
    for key in _LEGAL_KEYS:
        path = f"{prefix}{key}" if prefix else key
        for p in [p for p in builder.flat
                  if p == path or p.startswith(path + ".") or p.startswith(path + "[")]:
            value = builder.flat[p]
            if is_empty(value):
                builder.hide(_label_from_dict(p, table), p, "空值")
                continue
            rows.append({"label": _label_from_dict(p, table), "path": p, "value": to_text(value)})
            builder.consume(p)
    builder.add_fields_section(
        "legal", "法律聲明與服務條款", rows, collapsed=True,
        note="註冊局的固定樣板文字，與本次查詢目標的判讀無關。")


# ---------------------------------------------------------------------------
# Profile：python-whois（TCP 43 備援）
# ---------------------------------------------------------------------------

_PYWHOIS_RELIABILITY_WARNING = (
    "本次為 WHOIS 備援（TCP 43）。欄位由 python-whois 從各註冊局的純文字輸出解析而來，"
    "不同註冊局格式不一，實測存在欄位錯位的情形（例如國家欄位出現聯絡人標題文字）。"
    "所有欄位僅供參考，判讀前請對照原始資料。"
)


def _build_pywhois_view(result: dict, builder: ViewBuilder, now: Optional[datetime]) -> None:
    builder.warn(_PYWHOIS_RELIABILITY_WARNING)

    builder.add_summary("網域名稱", builder.get("domain_name"), path="domain_name",
                        note="WHOIS 備援解析結果，可信度低於 RDAP。", tone="warn")
    builder.add_summary("註冊商", builder.get("registrar"), path="registrar")
    for label, key, is_expiry in (("建立時間", "creation_date", False),
                                  ("最後異動時間", "updated_date", False),
                                  ("到期時間", "expiration_date", True)):
        raw_value = builder.get(key)
        described = describe_time(raw_value, key, is_expiry=is_expiry, now=now)
        tone = "risk" if (is_expiry and described and "已過期" in described) else None
        builder.add_summary(label, raw_value, path=key, text=described, tone=tone)
    builder.add_summary("註冊人組織", builder.get("registrant_organization"),
                        path="registrant_organization")
    builder.add_summary("註冊人國家", builder.get("registrant_country"),
                        path="registrant_country")

    name_servers = (result.get("data") or {}).get("name_servers")
    builder.add_summary(
        "名稱伺服器", name_servers,
        text=f"{len(name_servers)} 台：{to_text(name_servers)}"
        if isinstance(name_servers, list) and name_servers else None)
    builder.consume_prefix("name_servers")

    rows = []
    for path in list(builder.flat):
        if path in builder.consumed:
            continue
        value = builder.flat[path]
        if is_empty(value):
            builder.hide(_label_from_dict(path, PYWHOIS_LABELS), path, "空值")
            continue
        label = _label_from_dict(path, PYWHOIS_LABELS)
        if label == path:
            continue  # 字典未命中，交給 finish() 統一收進「其他欄位」
        rows.append({"label": label, "path": path, "value": to_text(value)})
        builder.consume(path)
    builder.add_fields_section("whois_detail", "WHOIS 欄位明細", rows,
                               note=_PYWHOIS_RELIABILITY_WARNING)


# ---------------------------------------------------------------------------
# Profile：VirusTotal API v3
# ---------------------------------------------------------------------------

_VT_ATTR = "data.attributes."

# 這些 VT 欄位體積大、判讀價值低，直接歸到收合區塊；不靠空值/恆定值判斷。
_VT_BULKY_KEYS = ("last_https_certificate",)


def _vt_engine_summary(results: Any, stats: Any) -> dict:
    """引擎判定三分類。

    刻意不用「不是 harmless/undetected 就是異常」——timeout、type-unsupported
    這類「引擎沒跑成功」若算成異常，幾乎每次查詢都會噴出假警報。
    判定依據是 category（官方列舉），result 只當成給人看的細節。
    """
    if not isinstance(results, dict) or not results:
        return {
            "available": False,
            "reason": "VirusTotal 對此目標尚無掃描結果（並非「掃描後判定無異常」）。",
            "stats": stats if isinstance(stats, dict) else None,
        }

    abnormal, inconclusive, unknown_categories = [], [], []
    normal_count = 0
    for engine, record in results.items():
        if not isinstance(record, dict):
            continue
        category = to_text(record.get("category")).strip().lower()
        entry = {"engine": record.get("engine_name") or engine,
                 "category": category,
                 "result": to_text(record.get("result")),
                 "method": to_text(record.get("method"))}
        if category in _VT_ABNORMAL:
            abnormal.append(entry)
        elif category in _VT_NORMAL:
            normal_count += 1
        else:
            inconclusive.append(entry)
            if category not in unknown_categories:
                unknown_categories.append(category)

    abnormal.sort(key=lambda e: (e["category"] != "malicious", e["engine"].lower()))
    total = len(results)

    mismatch = None
    if isinstance(stats, dict):
        claimed = sum(int(stats.get(k) or 0) for k in ("malicious", "suspicious"))
        if claimed != len(abnormal):
            mismatch = (f"last_analysis_stats 宣稱異常 {claimed} 家，"
                        f"逐筆統計為 {len(abnormal)} 家；兩者不一致，已同時列出。")

    return {
        "available": True,
        "total": total,
        "stats": stats if isinstance(stats, dict) else None,
        "counts": {"abnormal": len(abnormal), "normal": normal_count,
                   "inconclusive": len(inconclusive)},
        "abnormal": abnormal,
        "inconclusive": inconclusive,
        "unknown_categories": unknown_categories,
        "mismatch": mismatch,
        "all_clear_text": (f"{normal_count}/{total} 家引擎判定為無害或未偵測，無異常判定"
                           if not abnormal else None),
    }


def _build_vt_view(result: dict, builder: ViewBuilder, now: Optional[datetime]) -> None:
    payload = (result.get("data") or {}).get("data") or {}
    attributes = payload.get("attributes") or {}
    target_type = result.get("type")

    def attr(key: str) -> Any:
        return builder.get(_VT_ATTR + key)

    def summarize(label: str, key: str, **kwargs) -> None:
        builder.add_summary(label, attr(key), path=_VT_ATTR + key, **kwargs)

    if target_type == "ip":
        summarize("ASN 持有者", "as_owner")
        summarize("ASN", "asn")
        summarize("網段", "network")
        summarize("所屬 RIR", "regional_internet_registry")
    else:
        summarize("註冊商", "registrar")
        summarize("頂級網域", "tld")
    if target_type == "ip":
        # VT 的 domain 物件沒有 country/continent，列出來只會是一排「資料未提供」
        summarize("國家／地區", "country")
        summarize("所屬洲", "continent")

    # -- 偵測比例：查無資料與無異常必須分開呈現 --
    engines = _vt_engine_summary(attributes.get("last_analysis_results"),
                                 attributes.get("last_analysis_stats"))
    builder.consume_prefix(_VT_ATTR + "last_analysis_results")
    builder.consume_prefix(_VT_ATTR + "last_analysis_stats")
    if engines["available"]:
        counts = engines["counts"]
        stats = engines["stats"] or {}
        tone = "risk" if int(stats.get("malicious") or 0) else (
            "warn" if int(stats.get("suspicious") or 0) else "ok")
        builder.add_summary(
            "引擎偵測結果", counts,
            path=_VT_ATTR + "last_analysis_stats",
            text=(f"惡意 {stats.get('malicious', 0)}／可疑 {stats.get('suspicious', 0)}／"
                  f"無害 {stats.get('harmless', 0)}／未偵測 {stats.get('undetected', 0)}"
                  f"（共 {engines['total']} 家）"),
            tone=tone)
    else:
        builder.add_summary("引擎偵測結果", None, path=_VT_ATTR + "last_analysis_stats",
                            note=engines["reason"], tone="warn")

    reputation = attr("reputation")
    builder.add_summary(
        "社群信譽分數", reputation, path=_VT_ATTR + "reputation",
        tone="warn" if isinstance(reputation, int) and reputation < 0 else None,
        note="負值代表社群傾向認為此目標有問題。" if isinstance(reputation, int) and reputation < 0 else None)

    votes = attributes.get("total_votes")
    builder.consume_prefix(_VT_ATTR + "total_votes")
    if isinstance(votes, dict):
        builder.add_summary("社群投票", votes,
                            text=f"無害 {votes.get('harmless', 0)}／惡意 {votes.get('malicious', 0)}",
                            tone="warn" if int(votes.get("malicious") or 0) else None)
    else:
        builder.add_summary("社群投票", None)

    tags = attributes.get("tags")
    builder.consume_prefix(_VT_ATTR + "tags")
    builder.add_summary("標籤", tags, text=to_text(tags) if tags else None,
                        tone="warn" if tags else None)

    # -- 社群情資：高價值風險訊號，必須進摘要 --
    context = attributes.get("crowdsourced_context")
    builder.consume_prefix(_VT_ATTR + "crowdsourced_context")
    if isinstance(context, list) and context:
        severities = [to_text(c.get("severity")) for c in context if isinstance(c, dict)]
        builder.add_summary(
            "社群情資", context,
            text=f"{len(context)} 筆" + (f"（最高嚴重度：{_max_severity(severities)}）" if severities else ""),
            tone="warn")
        collapsed = _humanize_table(
            collapse_records([c for c in context if isinstance(c, dict)]), now)
        builder.add_section("crowdsourced", "社群情資", "table",
                            {"table": collapsed, "count": len(context)})
    else:
        builder.add_summary("社群情資", None)

    time_fields = [("VT 首次觀察時間", "first_seen_date", False),
                   ("最後掃描時間", "last_analysis_date", False)]
    if target_type != "ip":
        # 建立／到期是網域才有的概念，對 IP 顯示「資料未提供」只是徒增噪音
        time_fields = [("建立時間", "creation_date", False),
                       ("到期時間", "expiration_date", True)] + time_fields
    for label, key, is_expiry in time_fields:
        raw_value = attr(key)
        described = describe_time(raw_value, key, is_expiry=is_expiry, now=now)
        tone = "risk" if (is_expiry and described and "已過期" in described) else None
        builder.add_summary(label, raw_value, path=_VT_ATTR + key, text=described, tone=tone)

    _add_vt_derived_checks(builder, attributes, now)

    # -- 引擎明細 --
    builder.add_section("vt_engines", "掃描引擎判定", "engines", {"engines": engines})

    # -- DNS 紀錄 / 熱門度 / 分類 --
    dns_records = attributes.get("last_dns_records")
    builder.consume_prefix(_VT_ATTR + "last_dns_records")
    if isinstance(dns_records, list) and dns_records:
        builder.add_section("dns_records", "最近 DNS 紀錄", "table",
                            {"table": _humanize_table(collapse_records(
                                [r for r in dns_records if isinstance(r, dict)]), now),
                             "count": len(dns_records)})

    ranks = attributes.get("popularity_ranks")
    builder.consume_prefix(_VT_ATTR + "popularity_ranks")
    if isinstance(ranks, dict) and ranks:
        rows = []
        for provider, info in ranks.items():
            if not isinstance(info, dict):
                continue
            described = describe_time(info.get("timestamp"), "timestamp", now=now)
            rows.append({"label": provider, "path": f"{_VT_ATTR}popularity_ranks.{provider}",
                         "value": f"第 {info.get('rank')} 名" + (f"（{described}）" if described else "")})
        builder.add_fields_section("popularity", "熱門度排名", rows)

    categories = attributes.get("categories")
    builder.consume_prefix(_VT_ATTR + "categories")
    if isinstance(categories, dict) and categories:
        builder.add_fields_section(
            "categories", "廠商分類",
            [{"label": k, "path": f"{_VT_ATTR}categories.{k}", "value": to_text(v)}
             for k, v in categories.items()])

    # -- 體積大、判讀價值低者一律收合 --
    for key in _VT_BULKY_KEYS:
        paths = builder.consume_prefix(_VT_ATTR + key)
        rows = []
        for p in paths:
            if is_empty(builder.flat[p]):
                builder.hide(_label_from_dict(p, VT_LABELS), p, "空值")
                continue
            rows.append({"label": _label_from_dict(p, VT_LABELS), "path": p,
                         "value": to_text(builder.flat[p])})
        builder.add_fields_section(f"vt_{key}", _label_from_dict(key, VT_LABELS) or key,
                                   rows, collapsed=True,
                                   note="體積大且多為憑證原始欄位，預設收合。")

    # -- VT 內嵌的 RDAP 快照：與獨立 RDAP 查詢高度重複，預設收合 --
    rdap_paths = builder.consume_prefix(_VT_ATTR + "rdap")
    if rdap_paths:
        rows = []
        for p in rdap_paths:
            if is_empty(builder.flat[p]):
                builder.hide(p.split(".", 2)[-1], p, "空值")
                continue
            rows.append({"label": p.split(".", 2)[-1], "path": p,
                         "value": to_text(builder.flat[p])})
        builder.add_fields_section(
            "vt_rdap", "VirusTotal 內嵌的 RDAP 快照", rows, collapsed=True,
            note=("此為 VirusTotal 自行留存的 RDAP 快照，與「RDAP／WHOIS」分頁的獨立查詢"
                  "描述同一個物件，內容高度重複，且可能因快取而與即時查詢結果不同步。"))

    # -- whois 自由文字：原文保留 --
    whois_text = attributes.get("whois")
    builder.consume_prefix(_VT_ATTR + "whois")
    if isinstance(whois_text, str) and whois_text.strip():
        builder.add_section(
            "vt_whois", "WHOIS 原文", "text", {"text": whois_text}, collapsed=True,
            note="註冊局的 WHOIS 純文字輸出，未經解析，原樣保留。")

    _add_legal_section(builder, VT_LABELS, prefix=_VT_ATTR)

    # 剩下的 VT 屬性用字典翻譯後列成明細
    rows = []
    for path in list(builder.flat):
        if path in builder.consumed:
            continue
        value = builder.flat[path]
        if is_empty(value):
            builder.hide(_label_from_dict(path, VT_LABELS), path, "空值")
            continue
        if _RDAP_EXTENSION_RE.search(path):
            continue  # 註冊局擴充欄位，下面另外收合
        label = _label_from_dict(path, VT_LABELS)
        if label == path:
            continue
        described = describe_time(value, path, now=now)
        rows.append({"label": label, "path": path, "value": described or to_text(value)})
        builder.consume(path)
    builder.add_fields_section("vt_detail", "VirusTotal 欄位明細", rows)

    ext_rows = [{"label": p, "path": p, "value": to_text(builder.flat[p])}
                for p in list(builder.flat)
                if p not in builder.consumed and _RDAP_EXTENSION_RE.search(p)
                and not is_empty(builder.flat[p])]
    for row in ext_rows:
        builder.consume(row["path"])
    builder.add_fields_section(
        "registry_ext", "註冊局擴充欄位", ext_rows, collapsed=True,
        note="各註冊局自訂的 RDAP 擴充欄位（RFC 7480 §6），欄位名每家不同，以原始路徑顯示。")


TABLE_COLUMN_LABELS = {
    "title": "標題", "severity": "嚴重度", "details": "內容", "source": "來源",
    "timestamp": "時間", "type": "類型", "ttl": "TTL", "value": "值",
    "rname": "負責人", "serial": "序號", "refresh": "重新整理間隔",
    "retry": "重試間隔", "expire": "逾期時間", "minimum": "最小 TTL",
    "priority": "優先序", "rel": "用途", "href": "網址",
}


def _humanize_table(table: dict, now: Optional[datetime]) -> dict:
    """表格欄位同樣要套時間轉換與欄名翻譯——摘要卡片轉了、表格沒轉，
    使用者一樣要面對 1692891969 這種讀不出來的值。"""
    columns = table.get("columns") or []
    rows = []
    for row in table.get("rows") or []:
        new_row = []
        for column, value in zip(columns, row):
            described = describe_time(value, column, now=now)
            new_row.append(described or value)
        rows.append(new_row)
    constant = {}
    for column, value in (table.get("constant") or {}).items():
        described = describe_time(value, column, now=now)
        constant[TABLE_COLUMN_LABELS.get(column, column)] = described or value
    return {
        "columns": [TABLE_COLUMN_LABELS.get(c, c) for c in columns],
        "rows": rows,
        "constant": constant,
        "empty_columns": [TABLE_COLUMN_LABELS.get(c, c) for c in table.get("empty_columns") or []],
    }


_SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def _max_severity(severities: list[str]) -> str:
    ranked = [s.lower() for s in severities if s]
    if not ranked:
        return "未標示"
    ranked.sort(key=lambda s: _SEVERITY_ORDER.index(s) if s in _SEVERITY_ORDER else -1)
    return ranked[-1]


def _add_vt_derived_checks(builder: ViewBuilder, attributes: dict,
                           now: Optional[datetime]) -> None:
    """衍生指標：只做幾組有明確判讀意義的比較。

    刻意不做「任兩個日期都比一比」——那會產生 N² 條無意義的差值，
    等於用新的雜訊取代舊的雜訊。
    """
    now = now or datetime.now(TW_TZ)
    last_analysis = parse_time(attributes.get("last_analysis_date"), "last_analysis_date")
    if last_analysis is not None:
        stale_days = (now - last_analysis).days
        if stale_days >= 30:
            builder.add_summary(
                "掃描資料時效", stale_days,
                text=f"最後一次掃描在 {stale_days} 天前",
                note="掃描結果已有一段時間未更新，判讀時請把時效納入考量。",
                tone="warn")

    first_seen = parse_time(attributes.get("first_seen_date"), "first_seen_date")
    creation = parse_time(attributes.get("creation_date"), "creation_date")
    if first_seen is not None and creation is not None and first_seen < creation:
        # 只有「VT 比註冊時間更早就看到這個目標」才是異常。
        # 反過來（老網域最近才被 VT 收錄）是常態，拿差值來報會製造大量假訊號：
        # 實測 example.com 註冊於 1995 年、VT 2023 年首次觀察，差 10272 天但毫無意義。
        gap_days = (creation - first_seen).days
        builder.add_summary(
            "首次觀察早於建立時間", gap_days,
            text=f"VirusTotal 早於註冊建立時間 {gap_days} 天就已觀察到此目標",
            note="可能代表此目標曾被註冊、釋出後再重新註冊，或其中一方的時間資料有誤。",
            tone="warn")


# ---------------------------------------------------------------------------
# 進入點
# ---------------------------------------------------------------------------

_PROFILES = {
    "whoisit": (_build_whoisit_view, WHOISIT_LABELS),
    "pywhois": (_build_pywhois_view, PYWHOIS_LABELS),
    "vt": (_build_vt_view, VT_LABELS),
}


def detect_profile(result: dict) -> str:
    """依 source 字串分派。三個來源的 schema 完全不同，不能共用一套規則。"""
    source = to_text(result.get("source"))
    if source.startswith("VirusTotal"):
        return "vt"
    if source.startswith("WHOIS"):
        return "pywhois"
    return "whoisit"


def process(result: dict, now: Optional[datetime] = None) -> dict:
    """產生 view 與 warnings。原始 result["data"] 不動。

    任何規則出錯都不得讓查詢失敗——查得到資料本身比版面重要，因此整段包在
    try/except 內，失敗時退回「全欄位攤平」的原始呈現並附上告警。
    """
    profile_name = detect_profile(result)
    builder_fn, table = _PROFILES[profile_name]
    flat = flatten(result.get("data") or {})
    builder = ViewBuilder(flat)
    try:
        builder_fn(result, builder, now)
        view = builder.finish(make_labeller(table))
    except Exception as e:  # noqa: BLE001 - fail-soft 是刻意的
        view = _fallback_view(flat, table)
        view["warnings"] = [f"後處理失敗，已退回原始欄位呈現：{type(e).__name__}: {e}"]
        view["profile"] = profile_name
        return {"view": view, "warnings": view["warnings"]}

    view["profile"] = profile_name
    view["warnings"] = builder.warnings
    return {"view": view, "warnings": builder.warnings}


def _fallback_view(flat: dict[str, Any], table: dict[str, str]) -> dict:
    rows = [{"label": _label_from_dict(p, table), "path": p, "value": to_text(v)}
            for p, v in flat.items()]
    return {
        "summary": [],
        "sections": [{"id": "fallback", "title": "全部欄位", "kind": "fields",
                      "collapsed": False, "note": None, "rows": rows}],
        "hidden": {"count": 0, "empty_count": 0, "fields": []},
        "unknown_fields": [],
    }


def flatten_for_export(data: Any) -> dict[str, str]:
    """匯出用的完整攤平。匯出檔常被拿去當工單附件或存證，一欄都不能少，
    因此不套用任何摘要或摺疊規則。"""
    return {path: to_text(value) for path, value in flatten(data).items()}


def summarize_for_llm(result: Optional[dict]) -> str:
    """給 LLM 的精簡輸入：只給摘要與各區塊的非空欄位，省掉大量空欄位、
    重複 entity 與 89 家引擎的原始字串。"""
    if not result:
        return "（無資料）"
    processed = process(result)
    view = processed["view"]
    lines = []
    for item in view["summary"]:
        path = f"（{item['path']}）" if item.get("path") else ""
        lines.append(f"{item['label']}{path}: {item['value']}")
    for section in view["sections"]:
        if section["kind"] == "engines":
            engines = section.get("engines") or {}
            if not engines.get("available"):
                lines.append(f"[{section['title']}] {engines.get('reason', '')}")
                continue
            lines.append(f"[{section['title']}] 共 {engines['total']} 家；"
                         f"異常 {engines['counts']['abnormal']} 家")
            for entry in engines["abnormal"]:
                lines.append(f"  - {entry['engine']}: {entry['category']} / {entry['result']}")
            continue
        if section["kind"] == "text":
            lines.append(f"[{section['title']}]\n{section.get('text', '')}")
            continue
        if section["kind"] == "table":
            table = section.get("table") or {}
            lines.append(f"[{section['title']}] 欄位: {', '.join(table.get('columns', []))}")
            for row in table.get("rows", []):
                lines.append("  - " + "; ".join(to_text(c) for c in row))
            continue
        for row in section.get("rows", []):
            lines.append(f"[{section['title']}] {row['label']}（{row['path']}）: {row['value']}")
    for warning in view.get("warnings", []):
        lines.append(f"[注意] {warning}")
    return "\n".join(lines) if lines else "（無資料）"
