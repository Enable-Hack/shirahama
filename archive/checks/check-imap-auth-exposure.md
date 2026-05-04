---
model: claude-haiku-4-5
description: IMAP 認証経路の露出を一括確認 (旧 courier-imap-plain + dovecot-passdb-pam) — 平文プロトコル + PAM 経由全システム認証 + 試行ユーザ網羅性 を read-only で確認
---

# /check:check-imap-auth-exposure — IMAP 認証経路 一括確認

引数: `<時間窓> <ホスト>`
例: `/check:check-imap-auth-exposure 14:30-14:40 victor`

## 0. 前提

- 対象: **victor (Dovecot)** + **bravo (courier-imap or Dovecot)** 両方
- 関連 weakness:
  - 14_:B4 / 16_:#2 — 143/tcp 平文 IMAP / 110 POP3 + 993/995 IMAPS/POP3S 無し → パスワード平文流出
  - 16_:#22 / 16_:2.4 — Dovecot `passdb=pam` + `userdb=passwd` + `first_valid_uid=1000` → **システム全ユーザ (100 名 + obuchi/manage) が IMAP ログイン可能**
- analyzer.py の対応 pattern_tag: `mail/sasl-failed` (集計)
- ⚠️ **bravo の manage は sudo 不可** (本番 FreeBSD) — そこは ssh root@10.1.1.1 直接が必要
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
SSH_VICTOR="${SSH_VICTOR:-manage@10.1.1.2}"
SSH_BRAVO="${SSH_BRAVO:-manage@10.1.1.1}"
```

## 1. 収集 (read-only)

### 1.1 平文プロトコル経路の露出 (旧 courier-imap-plain)

```bash
echo "═══ /check:check-imap-auth-exposure ═══"
echo "─── §1.1 平文プロトコル経路 ───"

# listen ポート — 143 (IMAP) / 110 (POP3) が listen で 993 (IMAPS) / 995 (POP3S) が無いか
for label_host in "victor:$SSH_VICTOR" "bravo:$SSH_BRAVO"; do
    label="${label_host%%:*}"; host="${label_host#*:}"
    echo "[$label] listen ports (IMAP/POP):"
    ssh -o BatchMode=yes -o ConnectTimeout=5 "$host" \
        'sudo ss -tlnp 2>/dev/null | grep -E ":(110|143|993|995)\b"' 2>/dev/null | sed 's/^/    /'
done

# Dovecot 設定で disable_plaintext_auth / ssl 状態
echo "[victor] Dovecot 設定:"
ssh "$SSH_VICTOR" \
    'sudo grep -iE "^(disable_plaintext_auth|ssl|auth_mechanisms)" /etc/dovecot/conf.d/*.conf /etc/dovecot/dovecot.conf 2>/dev/null | head -20' 2>/dev/null | sed 's/^/    /'

# courier-imap or Dovecot for bravo (FreeBSD では courier 系も可能性あり)
echo "[bravo] IMAP server config:"
ssh "$SSH_BRAVO" \
    'sudo grep -iE "^(imap|pop3|disable_plaintext|ssl|tls)" /usr/local/etc/courier-imap/*.cnf /etc/dovecot/conf.d/*.conf 2>/dev/null | head -15' 2>/dev/null | sed 's/^/    /'
```

### 1.2 全システムユーザ認証経路 (旧 dovecot-passdb-pam)

```bash
echo "─── §1.2 全システムユーザ認証経路 ───"

# Dovecot passdb=pam + userdb=passwd の有無
echo "[victor] Dovecot auth-system.conf.ext:"
ssh "$SSH_VICTOR" \
    'sudo grep -A3 -iE "passdb|userdb" /etc/dovecot/conf.d/auth-system.conf.ext 2>/dev/null;
     sudo grep -iE "first_valid_uid|last_valid_uid|!include.*auth-" /etc/dovecot/conf.d/10-auth.conf 2>/dev/null' \
    2>/dev/null | head -30 | sed 's/^/    /'

# PAM dovecot ファイルの存在 (= PAM 経由認証が活きてる証拠)
ssh "$SSH_VICTOR" \
    'sudo ls -la /etc/pam.d/dovecot 2>/dev/null;
     sudo cat /etc/pam.d/dovecot 2>/dev/null | head -10' \
    2>/dev/null | sed 's/^/    /'

# /etc/passwd で UID >= 1000 (一般ユーザ + obuchi 等) の数 — IMAP ログイン候補
echo "[victor] /etc/passwd UID>=1000 (IMAP ログイン候補数):"
ssh "$SSH_VICTOR" \
    'awk -F: "\$3 >= 1000 && \$3 < 65534 { print \$1 }" /etc/passwd 2>/dev/null | wc -l' \
    2>/dev/null | sed 's/^/    /'
```

### 1.3 攻撃痕跡 (両機 maillog)

```bash
echo "─── §1.3 maillog 認証失敗痕跡 ───"

# rip= で送信元 IP を、user=<X>, method=PLAIN/LOGIN を抽出
# attacker IP / 試行ユーザ / 平文 method の 3 列で出す
for label_host in "victor:$SSH_VICTOR" "bravo:$SSH_BRAVO"; do
    label="${label_host%%:*}"; host="${label_host#*:}"
    echo "[$label] sasl/imap-login 失敗:"
    ssh "$host" 'sudo tail -2000 /var/log/maillog 2>/dev/null | \
        grep -iE "imap-login.*(auth failed|disconnected)|sasl_login" | \
        sed -nE "s/.*method=([A-Z]+).*rip=([0-9.]+).*user=<([^>]*)>.*/  method=\1 ip=\2 user=\3/p" | \
        sort | uniq -c | sort -rn | head -10' \
        2>/dev/null | sed 's/^/    /'
done
```

## 2. 検知パターン

| 観点 | 危険シグナル | 重要度 |
|---|---|---|
| 平文プロトコル | 143/110 listen + 993/995 不在 | ⚠️ 露出確定 (passive sniff 可能) |
| Dovecot disable_plaintext_auth | `no` | 🚨 平文受け入れ |
| Dovecot ssl | `no` or 設定なし | 🚨 暗号化なし |
| passdb=pam | 設定有 | 🚨 全システムユーザ認証可能 |
| first_valid_uid | 1000 (デフォ寄り) | 🚨 一般ユーザ全員ログイン可 |
| 試行ユーザ | obuchi / manage / admin / root を含む | 🚨 配布アカウント以外 = 既侵害情報を持つ攻撃者 |
| method=PLAIN 試行 | あり | 🚨 平文経路を狙ってる |

## 3. 判定基準

- ✅ **正常**: TLS only (143 close / 993 only) + passdb=passwd-file or LDAP + 試行 0
- ⚠️ **疑い (露出のみ)**: 平文 listen はあるが攻撃試行は窓内 0 → 報告書に記載、封じ込めはリーダー承認後
- 🚨 **確定 (露出 + 攻撃試行)**: passdb=pam + 平文 listen + 試行ユーザに obuchi/admin 等を含む — `/playbook:phishing` に直行

## 4. 次のアクション

- 🚨 確定時の封じ手提案 (リーダー承認後):
  - `disable_plaintext_auth = yes`
  - `ssl = required` (証明書発行が必要なら一時的に `ssl = yes`)
  - 攻撃元 IP を nginx / iptables で deny
- 連鎖：
  - 試行ユーザに obuchi → `/check:check-obuchi-777-hijack` (SSH 乗っ取り懸念)
  - root が試行リストに → `/check:check-known-attacker-ip` (既侵害再利用)
  - sasl 失敗が即 sendmail relay 失敗に転じてる → `/check:check-sendmail-open-relay`

## 5. JSON 永続化

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-imap-auth-exposure
{
  "inputs": {"target_host": "both", "window": "$1"},
  "outputs": {
    "plaintext_listen": {"victor_143": true, "victor_993": false, "bravo_143": true, "bravo_993": false},
    "dovecot_disable_plaintext_auth": "no|yes",
    "dovecot_ssl": "no|yes|required",
    "passdb_pam_enabled": true,
    "first_valid_uid": 1000,
    "candidate_users_count": 102,
    "attempted_users":  ["obuchi", "admin", "manage", "root"],
    "attacker_ips":     ["...必要なら..."],
    "method_plain_count": 5
  },
  "verdict": {
    "status": "🚨|⚠️|✅",
    "summary": "(平文露出 + 攻撃試行有無 + 試行ユーザの危険性 を 1 行)"
  },
  "next_skills": ["/check:check-...", "/playbook:phishing"]
}
JSON_EOF
```

保存先: `data/incidents/${INCIDENT_ID}/check-imap-auth-exposure__<ts>.json`
