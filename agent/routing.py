"""analyzer signals → 次手順ルーティング (単一情報源)

旧版は pattern_tag → /check / /playbook の二段ルーティングを保持していたが、
/check (26 本) と /playbook (5 本) は archive/ に退避し、復旧手順は
docs/recovery_cookbook.md (人間向けリファレンス) と /incident §4
(カテゴリ判定 + attack_pattern 推論) に集約された。

このため routing.py の責務は次の 1 点に縮約:
    どの signals が来ても「次に叩くべき skill」は常に /review 一本。
    attack_pattern (= pattern_tag) は /review がカテゴリ判断に使う
    ヒントとして注釈で渡すだけで、skill 選択の分岐キーには使わない。

利用箇所:
    1. .claude/commands/incident.md §5 が python -c で suggest() を呼んで表示
    2. docs/25_システム仕様書.html (review タブ) が同じデータを fetch して
       「次の推奨」を /review ボタンとしてレンダリング
"""
from __future__ import annotations

from typing import Any


NEXT_SKILL = "/review"


def suggest(signals: list[Any]) -> dict[str, Any]:
    """signals 全体から次手順 (/review) と attack_pattern ヒントを返す。

    返り値:
        {
            "next_skills": [{"skill": "/review", "hint": {"attack_pattern": "<tag>"}}],
            "by_signal":   [{pattern_tag, path, user, ip}, ...],
            "attack_patterns": [...],   # signals に出てきた pattern_tag (重複除外)
        }

        attack_patterns は出現順保持で重複除外。次手順の hint には
        最初に出てきた pattern_tag (None なら "") を入れる。
    """
    by_signal: list[dict[str, Any]] = []
    all_patterns: list[str] = []

    for s in signals:
        if isinstance(s, dict):
            ev = s.get("evidence", s)
            path = s.get("path", "")
        else:
            ev = getattr(s, "evidence", {})
            path = getattr(s, "path", "")
        tag = ev.get("pattern_tag", "")

        by_signal.append({
            "pattern_tag": tag,
            "path":        path[:80] if path else "",
            "user":        ev.get("user", ""),
            "ip":          ev.get("ip", ""),
        })
        if tag:
            all_patterns.append(tag)

    seen = set()
    uniq_patterns = [t for t in all_patterns if not (t in seen or seen.add(t))]
    primary = uniq_patterns[0] if uniq_patterns else ""

    return {
        "next_skills": [{"skill": NEXT_SKILL, "hint": {"attack_pattern": primary}}],
        "by_signal":   by_signal,
        "attack_patterns": uniq_patterns,
    }
