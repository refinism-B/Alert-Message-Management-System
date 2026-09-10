import ipaddress
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional
from urllib.parse import urlparse

import httpx
import whois
import whoisit
from whoisit import errors as whoisit_errors

TW_TZ = timezone(timedelta(hours=8))


def classify_target(value: str) -> Literal["ip", "domain"]:
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        return "domain"


class LookupFailedError(Exception):
    """RDAP 與 WHOIS 皆查詢失敗"""


def _now_tw() -> str:
    return datetime.now(TW_TZ).strftime("%Y-%m-%d %H:%M:%S (UTC+8)")


def _extract_rdap_host(raw: dict) -> Optional[str]:
    for link in raw.get("links", []) or []:
        href = link.get("href", "")
        if href.startswith("http"):
            return urlparse(href).netloc
    return None


def query_rdap_whois(target: str) -> dict:
    target_type = classify_target(target)
    queried_at = _now_tw()

    raw = None
    try:
        whoisit.bootstrap()
        raw = whoisit.ip(target) if target_type == "ip" else whoisit.domain(target)
    except whoisit_errors.WhoisItError:
        raw = None

    if raw is not None:
        host = _extract_rdap_host(raw)
        source = f"RDAP（IANA bootstrap → {host}）" if host else "RDAP（IANA bootstrap）"
        return {"target": target, "type": target_type, "source": source, "queried_at": queried_at, "data": raw}

    try:
        w = whois.whois(target)
    except Exception as e:
        raise LookupFailedError(f"RDAP 與 WHOIS 查詢皆失敗：{e}") from e

    data = dict(w) if w else {}
    if target_type == "domain":
        if not data or not data.get("domain_name"):
            raise LookupFailedError("RDAP 與 WHOIS 查詢皆失敗：查無資料")
    else:
        if not data:
            raise LookupFailedError("RDAP 與 WHOIS 查詢皆失敗：查無資料")

    return {"target": target, "type": target_type, "source": "WHOIS 備援（TCP 43）", "queried_at": queried_at, "data": data}


VT_BASE_URL = "https://www.virustotal.com/api/v3"


class VtQueryError(Exception):
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        super().__init__(message)


def _vt_path(target: str, target_type: str) -> str:
    kind = "ip_addresses" if target_type == "ip" else "domains"
    return f"{VT_BASE_URL}/{kind}/{target}"


def query_virustotal(target: str, api_key: str) -> dict:
    target_type = classify_target(target)
    queried_at = _now_tw()
    response = httpx.get(_vt_path(target, target_type), headers={"x-apikey": api_key}, timeout=10.0)
    if response.status_code != 200:
        raise VtQueryError(
            response.status_code,
            f"VirusTotal 查詢失敗：{response.status_code} {response.reason_phrase}",
        )
    return {
        "target": target,
        "type": target_type,
        "source": "VirusTotal Public API v3",
        "queried_at": queried_at,
        "data": response.json(),
    }
