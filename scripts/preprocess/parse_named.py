#!/usr/bin/env python3
"""
BIND の named.log → JSONL
クエリ / update 試行 / AXFR を抽出。

使い方:
    python parse_named.py /var/log/named.log | jq 'select(.action == "update")'
"""
from __future__ import annotations

import re
import sys
from datetime import datetime
from typing import Optional

from _common import emit, stream_lines


# BIND の queries category 例:
# 27-Apr-2026 13:00:00.123 client @0x... 192.168.1.1#54321 (example.com): query: example.com IN A +E(0)K (10.0.0.1)
QUERY_RE = re.compile(
    r'(?P<ts>\d{2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2}\.\d+)\s+'
    r'client\s+(?:@\S+\s+)?(?P<src>[\d\.:a-fA-F]+)#(?P<port>\d+)\s+'
    r'(?:\([^)]+\):\s+)?'
    r'query:\s+(?P<qname>\S+)\s+\S+\s+(?P<qtype>\S+)'
)

# update-security category
UPDATE_RE = re.compile(
    r'(?P<ts>\d{2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2}\.\d+)\s+'
    r'client\s+(?:@\S+\s+)?(?P<src>[\d\.:a-fA-F]+)#(?P<port>\d+).*?'
    r'update\s+(?:\'(?P<zone>\S+)\'\s+)?(?P<verdict>denied|approved|rejected)'
)

# AXFR
AXFR_RE = re.compile(
    r'(?P<ts>\d{2}-\w{3}-\d{4} \d{2}:\d{2}:\d{2}\.\d+)\s+'
    r'client\s+(?:@\S+\s+)?(?P<src>[\d\.:a-fA-F]+)#(?P<port>\d+).*?'
    r'transfer.*?(?P<verdict>denied|approved)'
)


def parse_bind_ts(ts: str) -> Optional[str]:
    """27-Apr-2026 13:00:00.123 → 2026-04-27T13:00:00.123"""
    try:
        dt = datetime.strptime(ts, "%d-%b-%Y %H:%M:%S.%f")
        return dt.isoformat()
    except ValueError:
        return None


def parse_line(line: str) -> Optional[dict]:
    if m := UPDATE_RE.search(line):
        return {
            "timestamp": parse_bind_ts(m["ts"]),
            "client_ip": m["src"],
            "client_port": int(m["port"]),
            "action": "update",
            "verdict": m["verdict"],
            "zone": m.group("zone") or None,
            "log_source": "named",
            "raw": line[:200],
        }
    if m := AXFR_RE.search(line):
        return {
            "timestamp": parse_bind_ts(m["ts"]),
            "client_ip": m["src"],
            "client_port": int(m["port"]),
            "action": "transfer",
            "verdict": m["verdict"],
            "log_source": "named",
            "raw": line[:200],
        }
    if m := QUERY_RE.search(line):
        return {
            "timestamp": parse_bind_ts(m["ts"]),
            "client_ip": m["src"],
            "client_port": int(m["port"]),
            "action": "query",
            "qname": m["qname"],
            "qtype": m["qtype"],
            "log_source": "named",
        }
    return None


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "-"
    for line in stream_lines(path):
        if not line.strip():
            continue
        record = parse_line(line)
        if record:
            emit(record)


if __name__ == "__main__":
    main()
