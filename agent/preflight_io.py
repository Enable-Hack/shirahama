"""/preflight 出力 JSON の読み書きユーティリティ。

incident.md §0.4 の冗長な jq シェルを置き換える。

利用箇所:
    - /preflight 実行時: write_preflight_state() で /tmp/preflight_state.json を書く
       + (任意) data/incidents/<id>/preflight__<ts>.json にも書き出し
    - /incident §0.4: load_preflight_context() で /tmp の最新状態を取り込む
"""
from __future__ import annotations

import json
import os
import pathlib
from datetime import datetime, timezone
from typing import Any


PREFLIGHT_STATE_PATH = pathlib.Path("/tmp/preflight_state.json")


def load_preflight_context() -> dict[str, Any] | None:
    """/tmp/preflight_state.json があれば読んで dict を返す。
    無い / 壊れていれば None。後方互換のためファイル不在は正常扱い。"""
    if not PREFLIGHT_STATE_PATH.exists():
        return None
    try:
        return json.loads(PREFLIGHT_STATE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def summarize_for_incident(state: dict[str, Any]) -> dict[str, Any]:
    """preflight state を /incident §4 Claude 推論に渡す形式に整形する。
    現状の構造:
        state.outputs[host].anomalies = [{severity, kind, detail}]
        state.outputs[host].etc_changed_recently = [...]
    """
    if not state:
        return {
            "anomalies":           [],
            "etc_changed_recently": [],
            "outputs":             {},
        }

    outputs = state.get("outputs", {})
    anomalies: list[dict[str, Any]] = []
    etc_changed: list[str] = []

    for host, host_data in outputs.items():
        if not isinstance(host_data, dict):
            continue
        for a in (host_data.get("anomalies") or []):
            anomalies.append({
                "host":     host,
                "severity": a.get("severity", "?"),
                "kind":     a.get("kind", "?"),
                "detail":   a.get("detail", "?"),
            })
        for f in (host_data.get("etc_changed_recently") or []):
            etc_changed.append(f"[{host}] {f}")

    return {
        "anomalies":           anomalies,
        "etc_changed_recently": etc_changed,
        "outputs":             outputs,
    }


def emit_preflight_json(
    state: dict[str, Any],
    incident_dir: pathlib.Path | str | None = None,
) -> dict[str, str]:
    """preflight state を 2 箇所に書き出し。
        1. /tmp/preflight_state.json (常時)
        2. incident_dir/preflight__<ts>.json (incident_dir があれば)

    返り値:  {"tmp": <path>, "incident": <path or "">}
    """
    paths: dict[str, str] = {}

    # 1. /tmp 側
    PREFLIGHT_STATE_PATH.write_text(
        json.dumps(state, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    paths["tmp"] = str(PREFLIGHT_STATE_PATH)

    # 2. incident_dir 側 (dashboard 連携用)
    if incident_dir:
        d = pathlib.Path(incident_dir)
        d.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        target = d / f"preflight__{ts}.json"

        # incident JSON 共通スキーマに包む (skill / incident_id / timestamp / actor)
        wrapped = {
            "skill":       "preflight",
            "incident_id": d.name,
            "timestamp":   datetime.now(timezone.utc).isoformat(),
            "actor":       "ai_auto",
            "outputs":     state,
            "verdict":     state.get("verdict", {"status": "info", "summary": "preflight baseline"}),
            "next_skills": state.get("next_skills", []),
        }
        target.write_text(
            json.dumps(wrapped, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        paths["incident"] = str(target)
    else:
        paths["incident"] = ""

    return paths
