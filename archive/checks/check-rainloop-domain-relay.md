---
model: claude-haiku-4-5
description: RainLoop domains/ 配下の gmail/yahoo/outlook/qq 残存設定経由で外部 IMAP に認証情報中継される痕跡を確認
---

# /check:check-rainloop-domain-relay — RainLoop 外部 IMAP 中継確認

引数: `<時間窓> <ホスト>`
例: `/check:check-rainloop-domain-relay 13:00-13:30 victor`

## 0. 前提

- 対象: **victor (10.1.1.2 / RainLoop 1.12.0)**
- 関連 weakness: 14_:V13 / 16_:2.3-#3 — `domains/` 配下に **gmail / outlook / qq / yahoo の IMAP 設定が登録済**。RainLoop ログイン時に `user@gmail.com / pw` を入れると **その認証情報が IMAP サーバに送信される** = 攻撃者が偽 RainLoop を立てて認証情報窃取
- 影響: 外部メールアカウント (gmail/yahoo) の認証情報が攻撃者の手元に流れる
- analyzer.py の対応 pattern_tag: `xss/*` (rainloop パス配下)、`mail/sasl-failed`
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
RAINLOOP_BASE="${RAINLOOP_BASE:-/var/www/rain}"
```

## 1. 収集 (read-only)

### 1.1 domains/ 配下の登録ドメイン確認

```bash
ssh "$TARGET_USER@$TARGET_HOST" \
  "sudo ls -la $RAINLOOP_BASE/rainloop/data/_data_/_default_/domains/ 2>/dev/null"

# 各ドメインの IMAP/SMTP 設定 (外部 IMAP に飛ばされている物証)
ssh "$TARGET_USER@$TARGET_HOST" \
  "sudo cat $RAINLOOP_BASE/rainloop/data/_data_/_default_/domains/gmail.com.ini 2>/dev/null"
ssh "$TARGET_USER@$TARGET_HOST" \
  "sudo cat $RAINLOOP_BASE/rainloop/data/_data_/_default_/domains/outlook.com.ini 2>/dev/null"
ssh "$TARGET_USER@$TARGET_HOST" \
  "sudo cat $RAINLOOP_BASE/rainloop/data/_data_/_default_/domains/yahoo.com.ini 2>/dev/null"
ssh "$TARGET_USER@$TARGET_HOST" \
  "sudo cat $RAINLOOP_BASE/rainloop/data/_data_/_default_/domains/qq.com.ini 2>/dev/null"
```

### 1.2 RainLoop ログイン試行で外部メールアドレスを使った痕跡

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -5000 /var/log/httpd/access_log' > /tmp/check_rldomain_access.log

# /rain/?/Json/&q[]=Login への POST に外部ドメイン (簡易判定: body はログにないので URL パラメータ経由)
grep -iE "POST /rain/.*(gmail|yahoo|outlook|qq)" /tmp/check_rldomain_access.log | tail -20

# RainLoop 経由の外向き接続 (mailclient の egress)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo conntrack -L -p tcp --dport 993 2>/dev/null | head -10'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo conntrack -L -p tcp --dport 465 2>/dev/null | head -10'
```

### 1.3 RainLoop 自身のログ

```bash
# data/logs/ 配下のアクセスログ
ssh "$TARGET_USER@$TARGET_HOST" \
  "sudo find $RAINLOOP_BASE -path '*/data/logs/*' -mmin -120 -ls 2>/dev/null"

ssh "$TARGET_USER@$TARGET_HOST" \
  "sudo tail -200 $RAINLOOP_BASE/rainloop/data/_data_/_default_/logs/log-*.txt 2>/dev/null" | tail -50
```

### 1.4 rainloop プロセスの外向き接続

```bash
# httpd プロセスから 993/465 への ESTABLISHED
ssh "$TARGET_USER@$TARGET_HOST" 'sudo ss -tnp | grep -E ":(993|465)\\b"'

# DNS で外部 imap.gmail.com 等を解決した形跡 (bravo named.log)
ssh "$TARGET_USER@10.1.1.1" \
  'grep -iE "imap\\.(gmail|outlook|yahoo|qq)|smtp\\.(gmail|outlook|yahoo)" /var/log/named.log 2>/dev/null' | tail -20
```

### 1.5 攻撃者が新規ドメイン設定を追加した可能性

```bash
ssh "$TARGET_USER@$TARGET_HOST" \
  "sudo find $RAINLOOP_BASE -path '*/domains/*' -mmin -120 -ls 2>/dev/null"
```

### 1.6 JSONL 化

```bash
python scripts/preprocess/parse_clf.py /tmp/check_rldomain_access.log \
  | jq --arg start "$START" --arg end "$END" \
       'select(.timestamp >= $start and .timestamp <= $end)' \
  > /tmp/check_rldomain_access.jsonl
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. domains/ に外部ドメインの ini | gmail.com.ini / outlook.com.ini 等が存在 | 🚨 設定上の脆弱性 |
| B. /rain への外部メール login | URL parameter / referer に gmail/yahoo を含む | 🚨 確定 (外部認証情報入力) |
| C. httpd → 外部 993/465 接続 | conntrack で imap.gmail.com 等への ESTABLISHED | 🚨 確定 (中継成立) |
| D. 新規 ini 追加 | mtime 直近の domains/*.ini | 🚨 確定 (攻撃者の追加) |

## 3. 判定基準

- ✅ **正常**: domains/ にローカルドメイン (com1.local) のみ、外部接続なし
- ⚠️ **疑わしい**: A のみ + B/C なし → 設定リスクとして報告
- 🚨 **確定**: B / C / D → **/playbook:phishing** + **/check:check-rainloop-cve29360** 並行

## 4. 次のアクション

### 確定なら
- **`/playbook:phishing`** (外部メールアカウント乗っ取り経路)
- 並行 **`/check:check-rainloop-cve29360`**
- 外部メールユーザに「**RainLoop 経由で gmail パスワードを入れていた場合は即変更**」を周知

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: domains/ から外部ドメイン .ini を退避
# sudo mv /var/www/rain/rainloop/data/_data_/_default_/domains/{gmail,yahoo,outlook,qq}.com.ini \\
#   /root/forensic_rainloop_domains/
# 案2: RainLoop 自体を停止 (メール業務影響大)
```

### メモするだけ
- 外部メール中継は出題側の "情報漏洩シナリオ" の典型的仕込み
- 18_§4.3 の「触らない」優先、ただし新規 ini 追加は攻撃の物証

## 5. 参照

- 関連 playbook: [playbook/phishing.md](../playbook/phishing.md)
- 連鎖先 check: [check-rainloop-cve29360.md](check-rainloop-cve29360.md)、[check-sendmail-open-relay.md](check-sendmail-open-relay.md)
- 既存ドキュメント: 14_:V13 / 16_:2.3-#3

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-rainloop-domain-relay__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-rainloop-domain-relay
{
  "inputs": {
    "target_host": "victor | bravo | both",
    "known_ips": ["...必要なら..."]
  },
  "outputs": {
    "patterns_matched": [
      {"id": "A", "label": "...§3 判定基準のパターンA...", "verdict": "🚨 | ⚠️ | ❌"},
      {"id": "B", "label": "...§3 判定基準のパターンB...", "verdict": "🚨 | ⚠️ | ❌"}
    ],
    "evidence": [
      "<§1 で取得した実ログから 2-3 行の重要なものを抜粋>"
    ]
  },
  "verdict": {
    "status": "🚨 | ⚠️ | ✅ | info",
    "summary": "<§4 で出した判定 1-2 行を再掲>"
  },
  "next_skills": ["/playbook:..." または "/check:..."]
}
JSON_EOF
```

- `patterns_matched` の `id` は §3 判定基準のパターン (A/B/C/D/E/F 等) と対応させる
- `evidence` は §1 で取得した実ログから 2-3 行抜粋 (PII / 機密に注意)
- `verdict.status` は §4 で出した判定と一致させる
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-rainloop-domain-relay__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
