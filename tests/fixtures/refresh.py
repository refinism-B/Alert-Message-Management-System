"""重抓測試 fixture。

fixture 是凍結快照：RDAP 或 VirusTotal 的回應結構變了，測試仍會全綠但線上會壞。
用法與重抓時機見同目錄的 README.md。

    python tests/fixtures/refresh.py          # 只重抓 RDAP/WHOIS
    python tests/fixtures/refresh.py --vt     # 一併重抓 VirusTotal（消耗 API 配額）
"""

import argparse
import json
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv  # noqa: E402

load_dotenv(ROOT / ".env")

import os  # noqa: E402

import lookup  # noqa: E402

OUT = pathlib.Path(__file__).parent

# 目標與檔名對照。換目標的話 README 的說明也要跟著改，否則下一個人不知道
# 每份 fixture 原本是要涵蓋哪個情境。
RDAP_TARGETS = [
    ("rdap_ip_whoisit.json", "79.127.254.133", "RDAP"),
    ("rdap_domain_whoisit.json", "example.com", "RDAP"),
    ("whois_fallback.json", "nic.tw", "WHOIS"),
]
VT_TARGETS = [
    ("vt_ip_full.json", "79.127.254.133"),
    ("vt_domain_full.json", "example.com"),
]

VT_RATE_LIMIT_SECONDS = 20  # 公開 API 限速 4 次/分鐘


def save(name: str, payload: dict) -> None:
    path = OUT / name
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"  已寫入 {path.name}（{path.stat().st_size:,} bytes）")


def refresh_rdap() -> int:
    failures = 0
    for name, target, expected in RDAP_TARGETS:
        print(f"[RDAP] {target}")
        try:
            result = lookup.query_rdap_whois(target)
        except lookup.LookupFailedError as e:
            print(f"  失敗：{e}")
            failures += 1
            continue
        if expected not in result["source"]:
            # 例如原本會落到 WHOIS 備援的目標，現在 RDAP 查得到了。
            # 這代表該 fixture 已經不再涵蓋原本的情境，要換目標而不是照存。
            print(f"  ⚠️ 來源與預期不符：得到「{result['source']}」，預期含「{expected}」。")
            print("     這份 fixture 已不再涵蓋原本的情境，請改用別的查詢目標並更新 README。")
            failures += 1
            continue
        print(f"  來源：{result['source']}")
        save(name, result)
    return failures


def refresh_vt() -> int:
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        print("略過 VirusTotal：未設定 VT_API_KEY")
        return 1
    failures = 0
    for index, (name, target) in enumerate(VT_TARGETS):
        if index:
            time.sleep(VT_RATE_LIMIT_SECONDS)
        print(f"[VirusTotal] {target}")
        try:
            result = lookup.query_virustotal(target, api_key)
        except (lookup.LookupFailedError, lookup.VtQueryError) as e:
            print(f"  失敗：{e}")
            failures += 1
            continue
        attributes = (result["data"].get("data") or {}).get("attributes") or {}
        print(f"  引擎數：{len(attributes.get('last_analysis_results') or {})}"
              f"／內嵌 rdap：{'rdap' in attributes}"
              f"／whois 原文：{'whois' in attributes}")
        save(name, result)
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description="重抓測試 fixture")
    parser.add_argument("--vt", action="store_true",
                        help="一併重抓 VirusTotal（會消耗 API 配額）")
    args = parser.parse_args()

    failures = refresh_rdap()
    if args.vt:
        failures += refresh_vt()
    else:
        print("未加 --vt，略過 VirusTotal")

    print()
    if failures:
        print(f"完成，但有 {failures} 項未更新（見上方訊息）。")
    else:
        print("完成。請接著跑 `python -m pytest -q` 確認規則仍成立；")
        print("若有測試失敗，先看 git diff 判斷是 API 結構變了還是規則寫錯了。")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
