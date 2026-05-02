---
description: Dovecot passdb=pam によるシステム全員 IMAP ログイン可能状態の悪用痕跡を確認
---

# /check:check-dovecot-passdb-pam — Dovecot 全システム認証悪用確認

引数: `<時間窓> <ホスト>`
例: `/check:check-dovecot-passdb-pam 13:00-13:30 victor`

## 0. 前提

- 対象: **victor (10.1.1.2 / Rocky / Dovecot)**
- 関連 weakness: 16_:#22 / 16_:2.4 — `passdb=pam` + `userdb=passwd` + `first_valid_uid=1000` → **システム全ユーザ (≈100 学生 + obuchi/manage 等) が IMAP ログイン可能**
- 16_ では「単独で危険度トップ級」と評価
- analyzer.py の対応 pattern_tag: `mail/sasl-failed`、`mail/spf-fail` (横展開で詐称メール)
- 影響: 1 アカウント侵害 → 100 ユーザ全員のメール閲覧 / 横展開
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"   # 本番: manage / デモ: rocky
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
```

## 1. 収集 (read-only)

### 1.1 Dovecot 設定の致命箇所確認

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo doveconf -n 2>/dev/null' > /tmp/check_dovecot_conf.log

grep -iE "passdb|userdb|first_valid_uid|auth_mechanisms|disable_plaintext_auth|protocols|ssl" \
  /tmp/check_dovecot_conf.log
```

期待 (危険):
- `passdb { driver = pam }` + `userdb { driver = passwd }` + `first_valid_uid = 1000`
- `disable_plaintext_auth = no`
- `ssl = no` または `auth_mechanisms = plain login`

### 1.2 IMAP ログイン履歴 (maillog)

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -5000 /var/log/maillog' > /tmp/check_dovecot_maillog.log

# Dovecot login の成功/失敗
grep -iE "dovecot.*imap-login.*Login:|dovecot.*imap-login.*auth failed" /tmp/check_dovecot_maillog.log | tail -50

# 配布アカウント以外のユーザでログインがあれば異常
grep -iE "dovecot.*imap-login.*Login:" /tmp/check_dovecot_maillog.log \
  | grep -oE "user=<[^>]+>" | sort | uniq -c | sort -rn | head -20
```

### 1.3 ユーザ別ログイン IP の集計 (横展開検出)

```bash
# 同一ユーザが複数 IP からログイン = 認証情報漏洩の物証
grep -iE "dovecot.*imap-login.*Login:" /tmp/check_dovecot_maillog.log \
  | grep -oE "user=<[^>]+>.*rip=[0-9.]+" | sort | uniq -c | sort -rn | head -30
```

### 1.4 brute force 痕跡 (同 IP から失敗連発)

```bash
grep -iE "dovecot.*imap-login.*auth failed" /tmp/check_dovecot_maillog.log \
  | grep -oE "rip=[0-9.]+" | sort | uniq -c | sort -rn | head -10

# 配布アカウント (manage/root) ではなく、obuchi 等のサービス系ユーザを狙ってないか
grep -iE "auth failed.*user=<(obuchi|admin|test|guest|backup)>" /tmp/check_dovecot_maillog.log | tail -20
```

### 1.5 listening port + TLS 設定

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo ss -tlnp | grep -E ":(143|993)\\b"'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo openssl s_client -connect 10.1.1.2:993 -showcerts < /dev/null 2>&1 | head -20'
```

### 1.6 JSONL 化

```bash
python scripts/preprocess/parse_maillog.py /tmp/check_dovecot_maillog.log > /tmp/check_dovecot_maillog.jsonl
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. passdb=pam + 平文許可 | doveconf に上記設定 | 🚨 設定上の脆弱性 (前提崩壊) |
| B. 同一ユーザ複数 IP ログイン | 1 user が 5+ 異なる IP から imap-login | 🚨 確定 (認証情報漏洩) |
| C. サービス系アカウントでログイン | apache / nobody / mysql 等が IMAP ログイン | 🚨 確定 (異常な使い方) |
| D. brute 痕跡 | 同一 IP から auth failed が 20+ | ⚠️ 疑わしい (試行中) |
| E. analyzer tag | `mail/sasl-failed` 多発 | ⚠️〜🚨 |

## 3. 判定基準

- ✅ **正常**: 平文 IMAP 無効 / passdb 個別、配布アカウントのみ login、複数 IP 単一ユーザなし
- ⚠️ **疑わしい**: D のみ → 監視継続 + 攻撃元 IP を `/check:check-known-attacker-ip` と突合
- 🚨 **確定**: A + B/C → **/playbook:phishing** + 全ユーザのパスワード強制リセットをリーダーに進言

## 4. 次のアクション

### 確定なら
- **`/playbook:phishing`** (アカウント乗っ取り後のなりすまし送信を疑う)
- 並行して **`/check:check-rainloop-cve29360`** (rainloop 経由の認証情報漏洩の可能性)
- 並行して **`/check:check-known-attacker-ip`** (同一 IP が他経路で出てないか)

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: 平文 IMAP 無効化 (運用影響あり、メール業務止まる可能性)
# /etc/dovecot/conf.d/10-auth.conf: disable_plaintext_auth = yes
# 案2: passdb を専用ファイルに分離 (システム全員ログイン可を止める)
# 案3: 攻撃元 IP を fail2ban / iptables drop
```

### メモするだけ
- システム全員ログイン可は **出題前提の可能性** (横展開シナリオの足場として用意されているはず)
- 18_§4.3「触らない」を優先しつつ、被害ユーザのパスワード強制リセットだけはリーダー判断で実施

## 5. 参照

- 関連 playbook: [playbook/phishing.md](../playbook/phishing.md)
- 連鎖先 check: [check-rainloop-cve29360.md](check-rainloop-cve29360.md)、[check-known-attacker-ip.md](check-known-attacker-ip.md)
- analyzer 該当: `agent/analyzer.py` `MAIL_PATTERNS` (`mail/sasl-failed`)
- 既存ドキュメント: 16_:#22 / 16_:2.4 / 14_:6.9 (doveconf -n 全文)
