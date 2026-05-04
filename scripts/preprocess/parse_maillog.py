#!/usr/bin/env python3
"""
postfix / sendmail の maillog → JSONL
送信者・受信者・SPF/DKIM 結果・接続元 IP を抽出。

使い方:
    python parse_maillog.py /var/log/maillog | jq 'select(.event == "from_to")'
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
    r'(?:(?P<qid>[A-F0-9]{8,}):\s+)?'
    r'(?P<msg>.*)$'
)

FROM_RE = re.compile(r'from=<(?P<from_addr>[^>]*)>')
TO_RE = re.compile(r'to=<(?P<to_addr>[^>]*)>')
CLIENT_RE = re.compile(r'client=(?P<client>\S+?)\[(?P<client_ip>[^\]]+)\]')
HELO_RE = re.compile(r'helo=<(?P<helo>[^>]+)>')
STATUS_RE = re.compile(r'status=(?P<status>\w+)')
SPF_RE = re.compile(r'spf=(?P<spf>\w+)', re.IGNORECASE)
DKIM_RE = re.compile(r'dkim=(?P<dkim>\w+)', re.IGNORECASE)
DMARC_RE = re.compile(r'dmarc=(?P<dmarc>\w+)', re.IGNORECASE)


def parse_syslog_ts(ts: str) -> Optional[str]:
    try:
        year = datetime.now().year
        return to_jst_iso(datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S"))
    except ValueError:
        return None


def parse_line(line: str) -> Optional[dict]:
    m = SYSLOG_RE.match(line)
    if not m:
        return None
    g = m.groupdict()
    record = {
        "timestamp": parse_syslog_ts(g["ts"]),
        "host": g["host"],
        "prog": g["prog"],
        "qid": g["qid"],
        "msg": g["msg"],
        "log_source": "maillog",
    }

    msg = g["msg"]
    found = {}
    for rx, key in [
        (FROM_RE, "from_addr"),
        (TO_RE, "to_addr"),
        (CLIENT_RE, None),  # 2 fields
        (HELO_RE, "helo"),
        (STATUS_RE, "status"),
        (SPF_RE, "spf"),
        (DKIM_RE, "dkim"),
        (DMARC_RE, "dmarc"),
    ]:
        if mm := rx.search(msg):
            if key:
                found[key] = mm[key]
            else:
                found.update(client=mm["client"], client_ip=mm["client_ip"])

    record.update(found)

    if "from_addr" in found and "to_addr" in found:
        record["event"] = "from_to"
    elif "client_ip" in found:
        record["event"] = "client_connect"
    else:
        record["event"] = "other"

    return record


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
