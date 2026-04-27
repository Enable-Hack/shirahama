#!/usr/bin/env python3
"""
NVD JSON Feed / CISA KEV から白浜環境関連製品の CVE を取得。

使い方:
    python scripts/feed/fetch_cve.py --output data/cve/

データソース:
    - CISA KEV: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
    - NVD CVE 2.0: https://services.nvd.nist.gov/rest/json/cves/2.0
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# 白浜環境関連製品（vendor or product 名で部分一致）
WATCH_PRODUCTS = [
    "wordpress",
    "rainloop",
    "snappymail",
    "php",
    "bind",
    "openssh",
    "apache",
    "httpd",
    "sendmail",
    "postfix",
    "dovecot",
    "courier",
    "polkit",      # PwnKit (CVE-2021-4034)
    "pkexec",
    "isc-dhcp",
    "yamaha",
    "rtx1200",
    "rtx1210",
    "cisco",
]

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev(output_dir: Path) -> int:
    """CISA KEV を取得して関連製品だけ抽出"""
    print(f"[fetch] {KEV_URL}", file=sys.stderr)
    try:
        with urllib.request.urlopen(KEV_URL, timeout=30) as resp:
            data = json.load(resp)
    except Exception as e:
        print(f"[error] KEV fetch failed: {e}", file=sys.stderr)
        return 0

    relevant = []
    for vuln in data.get("vulnerabilities", []):
        text = (
            vuln.get("vendorProject", "")
            + " "
            + vuln.get("product", "")
            + " "
            + vuln.get("vulnerabilityName", "")
            + " "
            + vuln.get("shortDescription", "")
        ).lower()
        if any(p in text for p in WATCH_PRODUCTS):
            relevant.append(vuln)

    output_dir.mkdir(parents=True, exist_ok=True)
    out = output_dir / f"kev_{datetime.now(timezone.utc).strftime('%Y%m%d')}.json"
    out.write_text(json.dumps({"fetched_at": datetime.now(timezone.utc).isoformat(),
                               "count": len(relevant),
                               "vulnerabilities": relevant}, indent=2, ensure_ascii=False))
    print(f"[ok] saved {len(relevant)} CVE to {out}", file=sys.stderr)
    return len(relevant)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--output", default="data/cve/", help="出力ディレクトリ")
    args = ap.parse_args()

    output_dir = Path(args.output)
    n = fetch_kev(output_dir)
    print(f"Total relevant CVEs: {n}")


if __name__ == "__main__":
    main()
