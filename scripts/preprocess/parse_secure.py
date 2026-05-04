#!/usr/bin/env python3
"""
/var/log/secure (Linux) → JSONL
SSH ログイン失敗 / sudo 認証失敗 / pkexec 等を抽出。

使い方:
    python parse_secure.py /var/log/secure | jq 'select(.event == "login_fail")'
"""
from __future__ import annotations

import re
import sys
from datetime import datetime
from typing import Optional

from _common import emit, stream_lines, to_jst_iso


# 標準 syslog 形式: "Apr 27 13:00:00 host prog[pid]: msg"
SYSLOG_RE = re.compile(
    r'^(?P<ts>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<prog>[^\[\:]+)'
    r'(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<msg>.*)$'
)

# sshd 失敗
SSHD_FAIL_RE = re.compile(
    r'Failed password for (?:invalid user )?(?P<user>\S+) from (?P<src>\S+) port (?P<port>\d+)'
)
SSHD_INVALID_RE = re.compile(r'Invalid user (?P<user>\S+) from (?P<src>\S+)')
SSHD_OK_RE = re.compile(
    r'Accepted (?:password|publickey) for (?P<user>\S+) from (?P<src>\S+)'
)

# sudo
SUDO_FAIL_RE = re.compile(r'authentication failure;.*user=(?P<user>\S+)')

# pkexec
PKEXEC_RE = re.compile(r'pkexec.*(GCONV_PATH|exploit)', re.IGNORECASE)


def parse_syslog_ts(ts: str) -> Optional[str]:
    """Apr 27 13:00:00 → 2026-04-27T13:00:00+09:00 (年は実行時の現在年 / JST 付与)"""
    try:
        year = datetime.now().year
        dt = datetime.strptime(f"{year} {ts}", "%Y %b %d %H:%M:%S")
        return to_jst_iso(dt)
    except ValueError:
        return None


def classify(prog: str, msg: str) -> dict:
    """msg からイベント種別を判定"""
    out = {"event": "other"}

    if "ssh" in prog.lower():
        if m := SSHD_FAIL_RE.search(msg):
            out.update(event="login_fail", user=m["user"], src_ip=m["src"], src_port=int(m["port"]))
        elif m := SSHD_INVALID_RE.search(msg):
            out.update(event="login_invalid_user", user=m["user"], src_ip=m["src"])
        elif m := SSHD_OK_RE.search(msg):
            out.update(event="login_ok", user=m["user"], src_ip=m["src"])

    if "sudo" in prog.lower():
        if m := SUDO_FAIL_RE.search(msg):
            out.update(event="sudo_fail", user=m["user"])

    if PKEXEC_RE.search(msg):
        out.update(event="pkexec_attempt", severity="critical")

    return out


def parse_line(line: str) -> Optional[dict]:
    m = SYSLOG_RE.match(line)
    if not m:
        return None
    g = m.groupdict()
    record = {
        "timestamp": parse_syslog_ts(g["ts"]),
        "host": g["host"],
        "prog": g["prog"],
        "pid": int(g["pid"]) if g["pid"] else None,
        "msg": g["msg"],
        "log_source": "secure",
    }
    record.update(classify(g["prog"], g["msg"]))
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
