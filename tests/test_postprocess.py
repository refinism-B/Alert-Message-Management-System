"""後處理規則的測試。

fixture 皆為 2026-09-12 對真實 API 取得的回應（tests/fixtures/），
只有 vt_no_analysis 是從 vt_domain_full 衍生而來（見 _vt_without_analysis）。
"""

import copy
import json
import pathlib
from datetime import datetime, timedelta

import pytest

import lookup
import postprocess

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
NOW = datetime(2026, 9, 12, 12, 0, 0, tzinfo=postprocess.TW_TZ)


def load(name: str) -> dict:
    return json.loads((FIXTURES / f"{name}.json").read_text(encoding="utf-8"))


@pytest.fixture
def rdap_ip():
    return load("rdap_ip_whoisit")


@pytest.fixture
def rdap_domain():
    return load("rdap_domain_whoisit")


@pytest.fixture
def whois_fallback():
    return load("whois_fallback")


@pytest.fixture
def vt_ip():
    return load("vt_ip_full")


@pytest.fixture
def vt_domain():
    return load("vt_domain_full")


def summary_of(view: dict, label: str) -> dict:
    for item in view["summary"]:
        if item["label"] == label:
            return item
    raise AssertionError(f"摘要中找不到「{label}」，實際有：{[i['label'] for i in view['summary']]}")


def section_of(view: dict, section_id: str) -> dict:
    for section in view["sections"]:
        if section["id"] == section_id:
            return section
    raise AssertionError(f"找不到區塊 {section_id}，實際有：{[s['id'] for s in view['sections']]}")


def has_section(view: dict, section_id: str) -> bool:
    return any(s["id"] == section_id for s in view["sections"])


# ---------------------------------------------------------------------------
# 攤平與基礎工具
# ---------------------------------------------------------------------------

def test_flatten_truncates_deep_nesting():
    data = {"leaf": "太深了"}
    for _ in range(postprocess._MAX_DEPTH + 2):
        data = {"nest": data}
    flat = postprocess.flatten(data)
    assert any("截斷" in str(v) for v in flat.values())


def test_flatten_does_not_truncate_real_vt_nesting():
    """實測 VT 內嵌 RDAP 的 vcard_array 巢狀很深，深度上限不得截到真實資料。"""
    flat = postprocess.flatten(load("vt_ip_full")["data"])
    assert not any("截斷" in str(v) for v in flat.values())


def test_flatten_handles_cycles():
    node = {"name": "x"}
    node["self"] = node
    flat = postprocess.flatten(node)
    assert any("循環參照" in str(v) or "截斷" in str(v) for v in flat.values())


def test_flatten_keeps_empty_containers_as_paths():
    flat = postprocess.flatten({"description": [], "address": {}})
    assert flat["description"] == []
    assert flat["address"] == {}


def test_zero_is_not_empty():
    # 0 與 False 是有意義的值，不能被當成「沒資料」摺疊掉
    assert postprocess.is_empty(0) is False
    assert postprocess.is_empty(False) is False
    assert postprocess.is_empty("") is True
    assert postprocess.is_empty([]) is True


# ---------------------------------------------------------------------------
# 時間
# ---------------------------------------------------------------------------

def test_epoch_only_converted_for_whitelisted_fields():
    # VT 的 asn 是 6 位數整數，若用「數值特徵」猜時間戳就會被誤轉
    assert postprocess.parse_time(60068, "data.attributes.asn") is None
    assert postprocess.parse_time(1742568139, "data.attributes.first_seen_date") is not None


def test_epoch_out_of_range_rejected():
    # 毫秒級時間戳（13 位數）不硬轉成西元 57000 年
    assert postprocess.parse_time(1742568139000, "first_seen_date") is None
    assert postprocess.parse_time(1, "first_seen_date") is None


def test_iso_string_parsed_and_converted_to_tw():
    dt = postprocess.parse_time("2024-05-17 13:12:02+00:00")
    assert postprocess.format_time(dt) == "2024-05-17 21:12:02 (UTC+8)"


def test_expiry_wording_differs_from_plain_past():
    past = NOW - timedelta(days=10)
    assert postprocess.relative_time(past, NOW) == "10 天前"
    assert postprocess.relative_time(past, NOW, is_expiry=True) == "已過期 10 天"
    future = NOW + timedelta(days=10)
    assert postprocess.relative_time(future, NOW, is_expiry=True) == "還有 10 天"


# ---------------------------------------------------------------------------
# entity 去重
# ---------------------------------------------------------------------------

def test_identical_roles_are_merged_and_keep_all_role_names(rdap_ip):
    # 實測資料中 administrative 與 technical 指向同一個 DLTS1-RIPE
    view = postprocess.process(rdap_ip, now=NOW)["view"]
    titles = [s["title"] for s in view["sections"] if s["id"].startswith("entity_")]
    assert "行政聯絡人、技術聯絡人" in titles
    merged = next(s for s in view["sections"] if s["title"] == "行政聯絡人、技術聯絡人")
    assert "已合併顯示" in merged["note"]


def test_entities_with_all_core_fields_empty_are_never_merged():
    empty_entity = {"type": "entity", "address": {"country": ""}}
    records = postprocess._collect_entities({
        "administrative": [copy.deepcopy(empty_entity)],
        "technical": [copy.deepcopy(empty_entity)],
    })
    assert len(records) == 2, "核心欄位全空無法證明是同一實體，不得合併"
    assert all(r["mergeable"] is False for r in records)


def test_fingerprint_normalizes_case_and_whitespace():
    a = {"handle": "X1", "email": "Abuse@Example.COM ", "name": "Ops"}
    b = {"handle": "x1", "email": "abuse@example.com", "name": "ops"}
    assert postprocess.entity_fingerprint(a) == postprocess.entity_fingerprint(b)


# ---------------------------------------------------------------------------
# 陣列壓縮
# ---------------------------------------------------------------------------

def test_single_record_has_no_constant_columns():
    # n==1 時所有欄位當然「相同」，宣稱它們恆定是誤導
    collapsed = postprocess.collapse_records([{"rel": "self", "href": "http://a"}])
    assert collapsed["constant"] == {}
    assert collapsed["columns"] == ["rel", "href"]


def test_constant_columns_lifted_and_empty_columns_dropped():
    records = [
        {"rel": "self", "href": "http://a", "type": "application/rdap+json", "title": ""},
        {"rel": "up", "href": "http://b", "type": "application/rdap+json", "title": ""},
    ]
    collapsed = postprocess.collapse_records(records)
    assert collapsed["constant"] == {"type": "application/rdap+json"}
    assert collapsed["empty_columns"] == ["title"]
    # href 每筆都不同，是唯一有資訊量的欄位，必須逐筆保留
    assert collapsed["columns"] == ["rel", "href"]
    assert collapsed["rows"] == [["self", "http://a"], ["up", "http://b"]]


# ---------------------------------------------------------------------------
# VirusTotal 引擎判定
# ---------------------------------------------------------------------------

def test_engines_three_way_classification(vt_ip):
    view = postprocess.process(vt_ip, now=NOW)["view"]
    engines = section_of(view, "vt_engines")["engines"]
    assert engines["available"] is True
    assert engines["total"] == 89
    # 實測 stats: malicious=3, suspicious=3
    assert engines["counts"]["abnormal"] == 6
    assert engines["counts"]["normal"] == 83
    assert engines["mismatch"] is None
    assert engines["abnormal"][0]["category"] == "malicious"


def test_timeout_and_unsupported_are_inconclusive_not_abnormal():
    results = {
        "A": {"category": "timeout", "result": None, "engine_name": "A"},
        "B": {"category": "type-unsupported", "result": None, "engine_name": "B"},
        "C": {"category": "harmless", "result": "clean", "engine_name": "C"},
    }
    stats = {"malicious": 0, "suspicious": 0, "harmless": 1, "undetected": 0, "timeout": 1}
    engines = postprocess._vt_engine_summary(results, stats)
    assert engines["counts"]["abnormal"] == 0
    assert engines["counts"]["inconclusive"] == 2
    assert engines["mismatch"] is None


def test_unknown_verdict_is_not_treated_as_normal():
    results = {"A": {"category": "brand-new-verdict", "engine_name": "A"}}
    engines = postprocess._vt_engine_summary(results, None)
    assert engines["counts"]["normal"] == 0
    assert "brand-new-verdict" in engines["unknown_categories"]


def test_stats_and_results_mismatch_is_reported():
    results = {"A": {"category": "malicious", "engine_name": "A"}}
    stats = {"malicious": 3, "suspicious": 0}
    engines = postprocess._vt_engine_summary(results, stats)
    assert engines["mismatch"] is not None
    assert "3" in engines["mismatch"] and "1" in engines["mismatch"]


def _vt_without_analysis(vt_domain: dict) -> dict:
    """衍生 fixture：VirusTotal 對此目標尚無掃描結果。"""
    derived = copy.deepcopy(vt_domain)
    attrs = derived["data"]["data"]["attributes"]
    attrs.pop("last_analysis_results", None)
    attrs.pop("last_analysis_stats", None)
    return derived


def test_no_scan_data_is_not_presented_as_clean(vt_domain):
    """最關鍵的安全性規則：把「沒掃過」畫成「沒問題」是本模組最危險的失敗模式。"""
    view = postprocess.process(_vt_without_analysis(vt_domain), now=NOW)["view"]
    engines = section_of(view, "vt_engines")["engines"]
    assert engines["available"] is False
    assert "尚無掃描結果" in engines["reason"]

    row = summary_of(view, "引擎偵測結果")
    assert row["missing"] is True
    assert row["value"] == "資料未提供"
    assert "0" not in row["value"], "缺資料不得顯示為 0"
    assert "並非" in row["note"]


def test_all_clear_reports_dynamic_engine_count(vt_domain):
    view = postprocess.process(vt_domain, now=NOW)["view"]
    engines = section_of(view, "vt_engines")["engines"]
    # 實測 example.com：malicious=0, suspicious=0
    assert engines["counts"]["abnormal"] == 0
    assert engines["all_clear_text"] is not None
    assert str(engines["total"]) in engines["all_clear_text"]
    assert "89" == str(engines["total"])


# ---------------------------------------------------------------------------
# 摘要卡片
# ---------------------------------------------------------------------------

def test_missing_summary_value_says_not_provided(rdap_ip):
    view = postprocess.process(rdap_ip, now=NOW)["view"]
    # 實測 IP 的 expiration_date 為 None
    row = summary_of(view, "到期時間")
    assert row["value"] == "資料未提供"
    assert row["missing"] is True


def test_summary_order_is_fixed_not_api_order(rdap_ip):
    view = postprocess.process(rdap_ip, now=NOW)["view"]
    labels = [i["label"] for i in view["summary"]]
    assert labels.index("名稱") < labels.index("網段") < labels.index("所屬 RIR")
    assert labels.index("註冊／分配時間") < labels.index("濫用檢舉窗口")


def test_summary_carries_original_path_for_cross_checking(rdap_ip):
    view = postprocess.process(rdap_ip, now=NOW)["view"]
    assert summary_of(view, "網段")["path"] == "network"
    assert summary_of(view, "濫用檢舉窗口")["path"] == "entities.abuse[0].email"


def test_abuse_contact_surfaced_to_summary(rdap_ip):
    view = postprocess.process(rdap_ip, now=NOW)["view"]
    assert summary_of(view, "濫用檢舉窗口")["value"] == "abuse@datacamp.co.uk"


def test_vt_tags_and_reputation_surfaced(vt_ip):
    view = postprocess.process(vt_ip, now=NOW)["view"]
    # 原文件問題三提到的 vpn 標籤，實測確實在 tags
    assert summary_of(view, "標籤")["value"] == "vpn"
    assert summary_of(view, "社群信譽分數")["value"] == "0"


def test_vt_ip_does_not_show_domain_only_fields(vt_ip):
    view = postprocess.process(vt_ip, now=NOW)["view"]
    labels = [i["label"] for i in view["summary"]]
    assert "建立時間" not in labels, "IP 沒有建立/到期的概念，不該列成「資料未提供」"
    assert "到期時間" not in labels


def test_table_columns_are_translated_and_epochs_converted(vt_domain):
    """摘要卡片轉了時間、表格沒轉的話，使用者一樣要面對 1692891969。"""
    view = postprocess.process(vt_domain, now=NOW)["view"]
    table = section_of(view, "crowdsourced")["table"]
    assert "時間" in table["columns"] and "timestamp" not in table["columns"]
    time_col = table["columns"].index("時間")
    assert "(UTC+8)" in table["rows"][0][time_col]


def test_old_domain_does_not_trigger_first_seen_gap_noise(vt_domain):
    """example.com 註冊於 1995、VT 2023 才首次觀察，差 10272 天但毫無判讀意義。"""
    view = postprocess.process(vt_domain, now=NOW)["view"]
    labels = [i["label"] for i in view["summary"]]
    assert not any("首次觀察" in l and "建立" in l for l in labels)


def test_first_seen_before_creation_is_flagged():
    result = {"target": "x.test", "type": "domain", "source": "VirusTotal Public API v3",
              "queried_at": "", "data": {"data": {"attributes": {
                  "first_seen_date": 1600000000, "creation_date": 1700000000}}}}
    view = postprocess.process(result, now=NOW)["view"]
    row = summary_of(view, "首次觀察早於建立時間")
    assert row["tone"] == "warn"


def test_vt_domain_does_not_show_ip_only_fields(vt_domain):
    view = postprocess.process(vt_domain, now=NOW)["view"]
    labels = [i["label"] for i in view["summary"]]
    assert "所屬洲" not in labels, "VT 的 domain 物件沒有 country/continent"
    assert "國家／地區" not in labels


def test_crowdsourced_context_surfaced_as_risk_signal(vt_domain):
    view = postprocess.process(vt_domain, now=NOW)["view"]
    row = summary_of(view, "社群情資")
    assert row["missing"] is False
    assert "筆" in row["value"]
    assert has_section(view, "crowdsourced")


def test_negative_reputation_flagged():
    result = {"target": "x.test", "type": "domain", "source": "VirusTotal Public API v3",
              "queried_at": "", "data": {"data": {"attributes": {"reputation": -42}}}}
    view = postprocess.process(result, now=NOW)["view"]
    row = summary_of(view, "社群信譽分數")
    assert row["tone"] == "warn"
    assert "負值" in row["note"]


def test_expired_domain_flagged_as_risk():
    result = {"target": "x.test", "type": "domain", "source": "RDAP（IANA bootstrap）",
              "queried_at": "", "data": {"name": "X.TEST", "expiration_date": "2020-01-01 00:00:00+00:00"}}
    view = postprocess.process(result, now=NOW)["view"]
    row = summary_of(view, "到期時間")
    assert row["tone"] == "risk"
    assert "已過期" in row["value"]


# ---------------------------------------------------------------------------
# IDN
# ---------------------------------------------------------------------------

def test_idn_shows_both_unicode_and_a_label():
    result = {"target": "xn--fsq.test", "type": "domain", "source": "RDAP（IANA bootstrap）",
              "queried_at": "", "data": {"name": "XN--FSQ.TEST", "unicode_name": "例.test"}}
    view = postprocess.process(result, now=NOW)["view"]
    row = summary_of(view, "名稱")
    assert "例.test" in row["value"]
    assert "XN--FSQ.TEST" in row["value"]
    assert row["tone"] == "warn"
    assert "相似字元" in row["note"]


def test_non_idn_domain_shows_name_plainly(rdap_domain):
    view = postprocess.process(rdap_domain, now=NOW)["view"]
    row = summary_of(view, "名稱")
    assert row["value"] == "EXAMPLE.COM"
    assert row["tone"] is None


# ---------------------------------------------------------------------------
# 摺疊與零遺漏
# ---------------------------------------------------------------------------

def test_empty_fields_are_hidden_but_counted(rdap_ip):
    view = postprocess.process(rdap_ip, now=NOW)["view"]
    # 原文件問題一：entities.*.address 的 7 個子欄位在實測資料中全為空
    assert view["hidden"]["empty_count"] > 0
    hidden_paths = [f["path"] for f in view["hidden"]["fields"]]
    assert any("address" in p for p in hidden_paths)


def test_legal_boilerplate_collapsed_by_default(rdap_ip):
    view = postprocess.process(rdap_ip, now=NOW)["view"]
    assert section_of(view, "legal")["collapsed"] is True


def test_vt_embedded_rdap_snapshot_collapsed(vt_ip):
    """原文件問題四：VT 內嵌的 RDAP 快照與獨立 RDAP 查詢高度重複。"""
    view = postprocess.process(vt_ip, now=NOW)["view"]
    section = section_of(view, "vt_rdap")
    assert section["collapsed"] is True
    assert "重複" in section["note"]


def test_bulky_certificate_collapsed(vt_domain):
    view = postprocess.process(vt_domain, now=NOW)["view"]
    assert section_of(view, "vt_last_https_certificate")["collapsed"] is True


def test_whois_free_text_preserved_verbatim(vt_ip):
    """whois 原文一律保留，不得被解析結果取代。"""
    view = postprocess.process(vt_ip, now=NOW)["view"]
    section = section_of(view, "vt_whois")
    raw = vt_ip["data"]["data"]["attributes"]["whois"]
    assert section["text"] == raw


@pytest.mark.parametrize("name", ["rdap_ip_whoisit", "rdap_domain_whoisit", "whois_fallback",
                                  "vt_ip_full", "vt_domain_full"])
def test_no_field_is_silently_dropped(name):
    """零遺漏稽核：每個攤平路徑都必須被某條規則消化，不得憑空消失。"""
    result = load(name)
    flat = postprocess.flatten(result.get("data") or {})
    builder = postprocess.ViewBuilder(flat)
    profile = postprocess.detect_profile(result)
    builder_fn, table = postprocess._PROFILES[profile]
    builder_fn(result, builder, NOW)
    builder.finish(postprocess.make_labeller(table))
    assert set(flat) - builder.consumed == set()


# ---------------------------------------------------------------------------
# Profile 分派與 fail-soft
# ---------------------------------------------------------------------------

def test_profile_detection(rdap_ip, whois_fallback, vt_ip):
    assert postprocess.detect_profile(rdap_ip) == "whoisit"
    assert postprocess.detect_profile(whois_fallback) == "pywhois"
    assert postprocess.detect_profile(vt_ip) == "vt"


def test_whois_fallback_carries_reliability_warning(whois_fallback):
    processed = postprocess.process(whois_fallback, now=NOW)
    assert processed["warnings"], "WHOIS 備援必須附可信度警示"
    assert "欄位錯位" in processed["warnings"][0]


def test_postprocess_failure_falls_back_to_raw_fields(rdap_ip, monkeypatch):
    def boom(*args, **kwargs):
        raise RuntimeError("模擬規則出錯")

    monkeypatch.setitem(postprocess._PROFILES, "whoisit", (boom, postprocess.WHOISIT_LABELS))
    processed = postprocess.process(rdap_ip, now=NOW)
    assert processed["warnings"]
    assert "後處理失敗" in processed["warnings"][0]
    # 查詢結果本身不能因為版面規則出錯就消失
    rows = section_of(processed["view"], "fallback")["rows"]
    assert len(rows) == len(postprocess.flatten(rdap_ip["data"]))


# ---------------------------------------------------------------------------
# 匯出完整性
# ---------------------------------------------------------------------------

def test_export_flatten_keeps_every_field(vt_ip):
    """匯出檔常作為工單附件或存證，不得套用任何摘要或摺疊規則。"""
    exported = postprocess.flatten_for_export(vt_ip["data"])
    assert len(exported) == len(postprocess.flatten(vt_ip["data"]))
    assert "data.attributes.last_analysis_results.Acronis.category" in exported


def test_llm_summary_is_smaller_than_raw_flatten(vt_ip):
    raw_lines = len(postprocess.flatten(vt_ip["data"]))
    summary_lines = len(postprocess.summarize_for_llm(vt_ip).splitlines())
    assert summary_lines < raw_lines / 2


# ---------------------------------------------------------------------------
# CIDR
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("target", ["79.0.0.0/8", "192.168.1.0/24", "2001:db8::/32"])
def test_cidr_rejected_with_actionable_message(target):
    with pytest.raises(lookup.UnsupportedTargetError) as excinfo:
        lookup.classify_target(target)
    assert "不支援網段查詢" in str(excinfo.value)


def test_plain_ip_and_domain_still_classified():
    assert lookup.classify_target("79.127.254.133") == "ip"
    assert lookup.classify_target("example.com") == "domain"
