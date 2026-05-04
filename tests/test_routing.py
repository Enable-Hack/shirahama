"""routing.py 動作確認 — 次手順は常に /review 単独。

実行:
    PYTHONPATH=. python3 tests/test_routing.py
"""
from __future__ import annotations
import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.routing import suggest, NEXT_SKILL


class FakeSig:
    def __init__(self, tag, path="", user="", ip=""):
        self.evidence = {"pattern_tag": tag, "user": user, "ip": ip}
        self.path = path


def test_suggest_returns_review_only():
    """signals が何であれ next_skills は /review 一本。"""
    sigs = [
        FakeSig("webapp/auth-bruteforce", ip="161.33.12.212"),
        FakeSig("mail/sasl-failed", ip="161.33.12.212"),
        FakeSig("webapp/dotfile-access", path="/cgi-bin/.my.cnf.6804"),
    ]
    r = suggest(sigs)

    assert len(r["next_skills"]) == 1, f"next_skills は 1 件: {r['next_skills']}"
    assert r["next_skills"][0]["skill"] == NEXT_SKILL == "/review", \
        f"skill 期待 /review got {r['next_skills'][0]}"
    print(f"OK  : next_skills = {r['next_skills']}")


def test_attack_pattern_hint_passes_through():
    """最初の signal の pattern_tag が hint.attack_pattern として渡る。"""
    sigs = [
        FakeSig("dns/amplification-bait", ip="198.51.100.7"),
        FakeSig("dns/axfr-attempt", ip="198.51.100.7"),
    ]
    r = suggest(sigs)

    hint = r["next_skills"][0]["hint"]
    assert hint["attack_pattern"] == "dns/amplification-bait", \
        f"hint 期待 dns/amplification-bait got {hint}"
    assert r["attack_patterns"] == ["dns/amplification-bait", "dns/axfr-attempt"], \
        f"attack_patterns 期待外: {r['attack_patterns']}"
    print(f"OK  : hint = {hint}, attack_patterns = {r['attack_patterns']}")


def test_by_signal_metadata_preserved():
    """by_signal に pattern_tag/path/user/ip が残ること。"""
    sigs = [FakeSig("auth/ssh-bruteforce", user="obuchi", ip="203.0.113.77")]
    r = suggest(sigs)

    assert len(r["by_signal"]) == 1
    bs = r["by_signal"][0]
    assert bs["pattern_tag"] == "auth/ssh-bruteforce"
    assert bs["user"] == "obuchi"
    assert bs["ip"] == "203.0.113.77"
    print(f"OK  : by_signal = {bs}")


def test_empty_signals():
    """signals 0 件でも /review は返る (hint は空文字列)。"""
    r = suggest([])
    assert r["next_skills"] == [{"skill": "/review", "hint": {"attack_pattern": ""}}], \
        f"空 signals 期待外: {r['next_skills']}"
    assert r["attack_patterns"] == []
    assert r["by_signal"] == []
    print("OK  : empty signals → /review with empty hint")


def test_pattern_dedup_preserves_order():
    """同一 pattern_tag が複数 signal に出ても attack_patterns は出現順 1 回。"""
    sigs = [
        FakeSig("webapp/xmlrpc"),
        FakeSig("mail/relay-attempt"),
        FakeSig("webapp/xmlrpc"),
    ]
    r = suggest(sigs)
    assert r["attack_patterns"] == ["webapp/xmlrpc", "mail/relay-attempt"], \
        f"重複除外順 期待外: {r['attack_patterns']}"
    print(f"OK  : dedup attack_patterns = {r['attack_patterns']}")


if __name__ == "__main__":
    test_suggest_returns_review_only()
    test_attack_pattern_hint_passes_through()
    test_by_signal_metadata_preserved()
    test_empty_signals()
    test_pattern_dedup_preserves_order()
    print("\nall routing tests passed")
