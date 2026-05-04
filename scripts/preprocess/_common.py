"""
preprocess の共通ユーティリティ。
security-day2/dns2/src/main.rs の serde_json + chrono パターンを Python 移植。
1 record = 1 line JSONL を stdout に吐く。`tee | jq` で可読化できる。
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone, timedelta
from typing import Iterator

JST = timezone(timedelta(hours=9))


def to_jst_iso(dt: datetime) -> str:
    """datetime を JST に正規化して ISO8601 で返す。

    syslog 系 (年なし / TZ なし) は naive datetime → サーバ clock = JST 前提で
    そのまま JST tag を付与する。Apache 系のように TZ-aware なら astimezone で変換。
    /incident §2 の jq lex 比較が JST 窓で動くためには全 parser が +09:00 を吐く必要がある。
    """
    if dt.tzinfo is None:
        return dt.replace(tzinfo=JST).isoformat()
    return dt.astimezone(JST).isoformat()


def emit(record: dict) -> None:
    """1 行 1 JSON で stdout に出力。jq で読める形式。"""
    record.setdefault("parsed_at", datetime.now(JST).isoformat())
    print(json.dumps(record, ensure_ascii=False))


def stream_lines(path: str) -> Iterator[str]:
    """ファイルを 1 行ずつ。'-' なら stdin から読む。"""
    if path == "-":
        for line in sys.stdin:
            yield line.rstrip("\n")
    else:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                yield line.rstrip("\n")
