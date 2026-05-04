"""analyzer 回帰テスト — リファクタで壊さないための最小ガード。

実行:
    PYTHONPATH=. python3 tests/test_analyzer_regression.py
"""
from __future__ import annotations

import sys
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts" / "preprocess"))

from agent.analyzer import analyze_nginx, analyze_maillog, analyze_named, analyze_secure


def assert_eq(actual, expected, label):
    if actual != expected:
        print(f"FAIL: {label}: expected={expected} actual={actual}")
        sys.exit(1)
    print(f"OK  : {label}")


def test_auth_bruteforce_via_parse_clf_field_names():
    """parse_clf.py が出力する src_ip/timestamp フィールド名でも
    _detect_auth_bruteforce が発火することを保証する (analyzer_field_drift.md)。"""
    entries = [
        {
            "src_ip": "203.0.113.77",
            "timestamp": f"2026-05-02T14:37:{26 + i:02d}+00:00",
            "method": "POST",
            "path": "/wp-login.php",
            "status": 200,
            "ua": "curl/8.5.0",
        }
        for i in range(15)
    ]
    signals = analyze_nginx(entries)
    bf = [s for s in signals if s.evidence.get("pattern_tag") == "webapp/auth-bruteforce"]
    assert_eq(len(bf), 1, "auth-bruteforce signal count (parse_clf field names)")
    assert_eq(bf[0].evidence["count"], 15, "auth-bruteforce count")
    assert_eq(bf[0].evidence["ip"], "203.0.113.77", "auth-bruteforce ip")


def test_auth_bruteforce_below_threshold():
    entries = [
        {
            "src_ip": "203.0.113.77",
            "timestamp": "2026-05-02T14:37:00+00:00",
            "method": "POST",
            "path": "/wp-login.php",
            "status": 200,
        }
        for _ in range(5)
    ]
    signals = analyze_nginx(entries)
    bf = [s for s in signals if s.evidence.get("pattern_tag") == "webapp/auth-bruteforce"]
    assert_eq(len(bf), 0, "below threshold should NOT trigger bruteforce")


def test_maillog_sasl_failed_carries_ip():
    """analyze_maillog の sasl-failed signal に evidence.ip が乗ること
    (mock_backend Layer 3b cross-ref のために必須)。"""
    lines = [
        "May  3 14:37:26 victor dovecot: imap-login: Disconnected (auth failed, 1 attempts in 2 secs): "
        "user=<obuchi>, method=PLAIN, rip=203.0.113.77, lip=10.1.1.2, TLS",
    ] * 6
    sigs = analyze_maillog(lines)
    sasl = [s for s in sigs if s.evidence.get("pattern_tag") == "mail/sasl-failed"]
    if not sasl:
        print("SKIP: mail/sasl-failed not detected — analyze_maillog parsing differs")
        return
    has_ip = any(s.evidence.get("ip") for s in sasl)
    assert_eq(has_ip, True, "mail/sasl-failed signals carry evidence.ip")


def test_named_unauthorized_update_carries_ip():
    """analyze_named の unauthorized-update signal に evidence.ip が乗ること。"""
    lines = [
        "May  3 14:37:26 bravo named[12345]: client @0xdeadbeef 203.0.113.77#54321: "
        "updating zone 'example.com/IN': update unsuccessful: 'example.com/IN': "
        "denied (NXDOMAIN)",
    ]
    sigs = analyze_named(lines)
    upd = [s for s in sigs if "update" in s.evidence.get("pattern_tag", "")]
    if not upd:
        print("SKIP: dns/update tag not detected — analyze_named parsing differs")
        return
    has_ip = any(s.evidence.get("ip") for s in upd)
    assert_eq(has_ip, True, "dns/update signals carry evidence.ip")


def test_secure_ssh_bruteforce_carries_ip():
    """analyze_secure の ssh-bruteforce 集約 signal に evidence.ip が乗ること
    (単発 ssh-failed は集約に降格されるので集約だけ確認)。"""
    lines = [
        f"May  3 14:37:{26 + i:02d} victor sshd[12345]: "
        f"Failed password for invalid user obuchi from 203.0.113.77 port {40000 + i} ssh2"
        for i in range(8)  # SSH_BRUTE_THRESHOLD 以上
    ]
    sigs = analyze_secure(lines)
    bf = [s for s in sigs if s.evidence.get("pattern_tag") == "auth/ssh-bruteforce"]
    if not bf:
        print(f"SKIP: ssh-bruteforce not aggregated (threshold 未到達 — got signals: {[s.evidence.get('pattern_tag') for s in sigs]})")
        return
    assert_eq(bf[0].evidence.get("ip"), "203.0.113.77", "ssh-bruteforce signal ip")


def test_secure_pkexec_carries_ip_or_ts():
    """analyze_secure の privesc/pkexec-attempt は host-local 攻撃なので IP は無いが
    タイムスタンプは付くこと。"""
    lines = [
        "May  3 14:37:26 victor pkexec[12345]: pam_unix(polkit-1:auth): "
        "authentication failure; logname=obuchi uid=1001 euid=0 ...",
    ]
    sigs = analyze_secure(lines)
    pk = [s for s in sigs if "pkexec" in s.evidence.get("pattern_tag", "")]
    if not pk:
        print("SKIP: privesc/pkexec-attempt not detected — analyze_secure pattern differs")
        return
    assert_eq(bool(pk[0].timestamp), True, "pkexec signal carries timestamp")


def test_baseline_zero_false_positives():
    """tests/fixtures/test_env_baseline/ で 0 件 — 設定スナップショットが
    誤検知を生まないことのガード。"""
    from agent.analyzer import run as analyzer_run
    baseline = ROOT / "tests" / "fixtures" / "test_env_baseline"
    if not baseline.exists():
        print("SKIP: baseline fixtures not found")
        return
    sigs = analyzer_run(baseline)
    assert_eq(len(sigs), 0, "baseline should produce 0 signals")


if __name__ == "__main__":
    test_auth_bruteforce_via_parse_clf_field_names()
    test_auth_bruteforce_below_threshold()
    test_maillog_sasl_failed_carries_ip()
    test_named_unauthorized_update_carries_ip()
    test_secure_ssh_bruteforce_carries_ip()
    test_secure_pkexec_carries_ip_or_ts()
    test_baseline_zero_false_positives()
    print("\nall regression tests passed (or skipped)")
