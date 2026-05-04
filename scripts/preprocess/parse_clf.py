#!/usr/bin/env python3
"""
Apache CLF (Common Log Format / Combined Log Format) → JSONL

使い方:
    python parse_clf.py /var/log/httpd/access_log | jq .
    cat access_log | python parse_clf.py - | jq -r '.status' | sort | uniq -c

CLF 例:
    192.168.1.1 - - [27/Apr/2026:13:00:00 +0900] "GET /index.html HTTP/1.1" 200 1234 "-" "curl/8.7"
"""
from __future__ import annotations

import re
import sys
from datetime import datetime, timezone, timedelta
from typing import Optional

from _common import emit, stream_lines

JST = timezone(timedelta(hours=9))


# Combined Log Format
CLF_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+(?P<proto>[^"]+)"\s+'
    r'(?P<status>\d+)\s+(?P<bytes>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<ua>[^"]*)")?'
)


def parse_apache_ts(ts: str) -> Optional[str]:
    """27/Apr/2026:13:00:00 +0900 → 2026-04-27T13:00:00+09:00 (ISO8601, JST 正規化)

    Apache 側の TZ が +0000 (UTC) でも +0900 (JST) でも、必ず JST へ変換して emit する。
    こうしないと jq の lex 比較で `/incident §2` の JST 窓 (+09:00) と一致しなくなる。
    例: UTC ログ `2026-04-27T04:00:00+00:00` → JST 窓 `13:00-13:30+09:00` と
        文字列比較すると "04:00" < "13:00" になって誤って drop される。
    """
    try:
        dt = datetime.strptime(ts, "%d/%b/%Y:%H:%M:%S %z")
        return dt.astimezone(JST).isoformat()
    except ValueError:
        return None


def parse_line(line: str) -> Optional[dict]:
    m = CLF_RE.match(line)
    if not m:
        return None
    g = m.groupdict()
    return {
        "src_ip": g["ip"],
        "timestamp": parse_apache_ts(g["ts"]),
        "method": g["method"],
        "path": g["path"],
        "protocol": g["proto"],
        "status": int(g["status"]),
        "body_bytes": int(g["bytes"]) if g["bytes"].isdigit() else 0,
        "referer": g.get("referer") or "",
        "ua": g.get("ua") or "",
        "log_source": "apache_access",
    }


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "-"
    for line in stream_lines(path):
        if not line.strip():
            continue
        record = parse_line(line)
        if record:
            emit(record)
        else:
            # パース失敗は debug 用に stderr へ
            print(f"[parse_clf] unmatched: {line[:120]}", file=sys.stderr)


if __name__ == "__main__":
    main()
