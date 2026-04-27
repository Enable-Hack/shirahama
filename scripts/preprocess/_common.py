"""
preprocess の共通ユーティリティ。
security-day2/dns2/src/main.rs の serde_json + chrono パターンを Python 移植。
1 record = 1 line JSONL を stdout に吐く。`tee | jq` で可読化できる。
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from typing import Iterator


def emit(record: dict) -> None:
    """1 行 1 JSON で stdout に出力。jq で読める形式。"""
    record.setdefault("parsed_at", datetime.now(timezone.utc).isoformat())
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
