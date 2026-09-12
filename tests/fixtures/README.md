# 測試 fixture

`postprocess.py` 的規則全都是「對特定資料形狀的判斷」，沒有真實樣本就驗不出對錯。
這裡的 JSON 都是**真實 API 回應**，不是手寫的。

| 檔案 | 查詢目標 | 涵蓋情境 |
|---|---|---|
| `rdap_ip_whoisit.json` | `79.127.254.133` | RDAP 查 IP 成功（whoisit schema）。administrative 與 technical 指向同一個 entity，`address.*` 七個子欄位全空 |
| `rdap_domain_whoisit.json` | `example.com` | RDAP 查網域成功。含 `nameservers`、`dnssec`、`entities.registrar` |
| `whois_fallback.json` | `nic.tw` | RDAP 失敗、落到 python-whois 備援。**欄位是錯位的**（`registrant_country` 值為 `"Administrative Contact:"`），這是刻意保留的真實髒資料 |
| `vt_ip_full.json` | `79.127.254.133` | VirusTotal 查 IP。89 家引擎、內嵌 RDAP 快照（`entities[2].entities[0]` 與 `entities[0]` 重複）、`whois` 原文描述的是上層委派區塊 `79.0.0.0/8`、`tags: ["vpn"]` |
| `vt_domain_full.json` | `example.com` | VirusTotal 查網域。含 `crowdsourced_context`、`last_dns_records`、`popularity_ranks`、`last_https_certificate` |

**取得日期：2026-09-12**

## 為什麼要定期重抓

fixture 是**凍結快照**。RDAP 或 VirusTotal 的回應結構若有變動，這裡的測試仍會全綠，
但線上會壞——測試驗的是「對這份快照的處理正確」，不是「對現在的 API 正確」。

建議每季或改動 `postprocess.py` 的 profile 時重抓一次，並檢查 diff：
結構性的差異（多了欄位、少了欄位、型別改變）就是要跟進的訊號。

## 怎麼重抓

```bash
python tests/fixtures/refresh.py          # 只重抓 RDAP/WHOIS，不呼叫 VirusTotal
python tests/fixtures/refresh.py --vt     # 一併重抓 VirusTotal（會消耗 API 配額）
```

`--vt` 需要 `.env` 內的 `VT_API_KEY`。VirusTotal 公開 API 限速 4 次/分鐘，
腳本會自行間隔。重抓後務必跑 `python -m pytest -q` 確認規則仍成立。

## 注意

- 這些檔案含真實的公開註冊資料（組織名稱、abuse 信箱）。都是 RDAP/WHOIS 本來就公開的內容，
  但重抓時請確認沒有把 API 金鑰之類的東西寫進去。
- `whois_fallback.json` 的欄位錯位是**特意保留的**。不要「修正」它——
  那正是 `postprocess.py` 把 python-whois 標為參考來源、並附可信度警示的原因。
