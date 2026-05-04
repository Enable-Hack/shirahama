#!/usr/bin/env python3
"""
汎用 syslog (BSD/Linux) → JSONL
プログラム別に振り分ける前の最後の砦。
"""
from __future__ import annotations

import re
import sys
from datetime import datetime
from typing import Optional

from _common import emit, stream_lines, to_jst_iso


SYSLOG_RE = re.compile(
    r'^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<prog>[^\[\:]+)'
    r'(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<msg>.*)$'
)


def parse_line(line: str) -> Optional[dict]:
    m = SYSLOG_RE.match(line)
    if not m:
        return None
    g = m.groupdict()
    try:
        year = datetime.now().year
        ts_iso = to_jst_iso(datetime.strptime(f"{year} {g['ts']}", "%Y %b %d %H:%M:%S"))
    except ValueError:
        ts_iso = None

    return {
        "timestamp": ts_iso,
        "host": g["host"],
        "prog": g["prog"],
        "pid": int(g["pid"]) if g["pid"] else None,
        "msg": g["msg"],
        "log_source": "syslog",
    }


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
