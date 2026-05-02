---
description: courier-imap / Dovecot 143/tcp 平文 IMAP の認証情報漏洩痕跡を確認
---

# /check:check-courier-imap-plain — IMAP 平文認証確認

引数: `<時間窓> <ホスト>`
例: `/check:check-courier-imap-plain 13:00-13:30 bravo`

## 0. 前提

- 対象: **bravo (10.1.1.1 / courier-imap)** **victor (10.1.1.2 / Dovecot)** 両方
- 関連 weakness: 14_:B4 / 16_:#2 — bravo `courier-imap 143/tcp` + victor `Dovecot 143/tcp` 平文。993 (IMAPS) なし → メールパスワード平文流出
- 注意: **`/check:check-dovecot-passdb-pam` はシステム全員ログイン可の問題に特化、本 check は平文プロトコル経路に特化**。両方並行で叩く
- analyzer.py の対応 pattern_tag: `mail/sasl-failed` (集計)
- ⚠️ **bravo の manage は sudo 不可**
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.1}"
```

## 1. 収集 (read-only)

### 1.1 listen 状態と TLS 設定

```bash
# bravo (FreeBSD courier-imap)
ssh "$TARGET_USER@10.1.1.1" 'sockstat -4l | grep -E ":(143|993)\\b"'
ssh "$TARGET_USER@10.1.1.1" 'cat /usr/local/etc/courier-imap/imapd 2>/dev/null | grep -iE "TLS|SSL|AUTHMODULES|MAILDIR"'

# victor (Dovecot)
ssh "$TARGET_USER@10.1.1.2" 'sudo ss -tlnp | grep -E ":(143|993)\\b"'
ssh "$TARGET_USER@10.1.1.2" 'sudo doveconf -n 2>/dev/null | grep -iE "ssl|disable_plaintext|protocols"'
```

期待 (危険):
- 143 listen + 993 不在
- `disable_plaintext_auth = no` (Dovecot)
- courier-imap で `TLS_REQUIRED=0`

### 1.2 maillog で IMAP login 痕跡

```bash
# bravo
ssh "$TARGET_USER@10.1.1.1" 'tail -5000 /var/log/maillog 2>/dev/null' > /tmp/check_imap_bravo.log
grep -iE "imap|imapd-ssl|courier" /tmp/check_imap_bravo.log | tail -30

# victor
ssh "$TARGET_USER@10.1.1.2" 'sudo tail -5000 /var/log/maillog 2>/dev/null' > /tmp/check_imap_victor.log
grep -iE "imap-login.*Login:|imap-login.*auth failed" /tmp/check_imap_victor.log | tail -30
```

### 1.3 平文 vs TLS の比率 (TLS 移行が進んでないか)

```bash
# Dovecot は login ログに TLS の有無が出る
grep -iE "imap-login" /tmp/check_imap_victor.log \
  | awk '/TLS/ {tls++} !/TLS/ {plain++} END {print "TLS:", tls, "Plain:", plain}'
```

期待:
- ✅ TLS が大半
- 🚨 Plain が大半 → 平文流通

### 1.4 同一ユーザの複数 IP ログイン (認証漏洩物証)

```bash
grep -iE "imap-login.*Login:" /tmp/check_imap_victor.log \
  | grep -oE "user=<[^>]+>.*rip=[0-9.]+" | sort | uniq -c | sort -rn | head -20
```

### 1.5 brute 試行

```bash
grep -iE "imap-login.*auth failed|courier.*FAILED LOGIN" /tmp/check_imap_bravo.log /tmp/check_imap_victor.log \
  | grep -oE "rip=[0-9.]+|from [0-9.]+" | sort | uniq -c | sort -rn | head -10
```

### 1.6 conntrack で 143 への接続元

```bash
ssh "$TARGET_USER@10.1.1.2" 'sudo conntrack -L -p tcp --dport 143 2>/dev/null | head -20'
ssh "$TARGET_USER@10.1.1.1" 'sockstat -4 -P tcp | grep -E ":143\\b" | head -20'
```

### 1.7 JSONL 化

```bash
python scripts/preprocess/parse_maillog.py /tmp/check_imap_victor.log > /tmp/check_imap_victor.jsonl
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. 143 listen + 993 不在 | sockstat / ss で 143 only | 🚨 設定上の脆弱性 |
| B. Plain login が大半 | TLS でない login が時間窓内多数 | 🚨 確定 (平文流通中) |
| C. 同ユーザ複数 IP | 認証情報漏洩の物証 | 🚨 確定 |
| D. brute 試行 | 同 IP からの auth failed 多発 | ⚠️ 疑わしい |
| E. analyzer tag | `mail/sasl-failed` 発火 | ⚠️〜🚨 |

## 3. 判定基準

- ✅ **正常**: 143 不在 / TLS 強制、Plain login 0、複数 IP 単一ユーザなし
- ⚠️ **疑わしい**: A / D のみ → 設定リスク + brute 試行報告
- 🚨 **確定**: B / C → **/playbook:phishing** (アカウント乗っ取り後のなりすまし)

## 4. 次のアクション

### 確定なら
- **`/playbook:phishing`**
- 並行して **`/check:check-dovecot-passdb-pam`** (システム全員ログイン可の影響範囲)
- 並行して **`/check:check-known-attacker-ip`** (login 元 IP の突合)

### 即時封じ手（リーダー承認後のみ）
```bash
# bravo (courier-imap):
# /usr/local/etc/courier-imap/imapd: TLS_REQUIRED=1 / IMAP_TLS_REQUIRED=1
# service courier-imap-imapd restart

# victor (Dovecot):
# /etc/dovecot/conf.d/10-auth.conf: disable_plaintext_auth = yes
# /etc/dovecot/conf.d/10-master.conf: 143 を inet_listener から削除
# systemctl reload dovecot
```

### メモするだけ
- 「触らない」優先、ただし平文流通は被害拡大早い
- 16_:#2 で「短期対応」リスト入り

## 5. 参照

- 関連 playbook: [playbook/phishing.md](../playbook/phishing.md)
- 連鎖先 check: [check-dovecot-passdb-pam.md](check-dovecot-passdb-pam.md)、[check-known-attacker-ip.md](check-known-attacker-ip.md)
- analyzer 該当: `agent/analyzer.py` `MAIL_PATTERNS` (`mail/sasl-failed`)
- 既存ドキュメント: 14_:B4 / 16_:#2 / 14_:6.9 (Dovecot 設定全文)
