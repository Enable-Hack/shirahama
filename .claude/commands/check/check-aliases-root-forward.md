---
description: /etc/aliases で全サービスアカウントが root 宛転送されている悪用痕跡を確認
---

# /check:check-aliases-root-forward — エイリアス root 転送悪用確認

引数: `<時間窓> <ホスト>`
例: `/check:check-aliases-root-forward 13:00-13:30 victor`

## 0. 前提

- 対象: **victor (10.1.1.2)** 主、**bravo (10.1.1.1)** 副
- 関連 weakness: 14_:V6 / 16_:2.3-#6 — `/etc/aliases` で apache, dovecot, mysql 等のサービスアカウントが **全部 root 宛転送**
- 影響: 攻撃者が `apache` `dovecot` の名前で root にメールを直撃させ、運用判断を誤誘導 / 添付付き標的型攻撃
- analyzer.py の対応 pattern_tag: `mail/relay-attempt` (場合によって)、直接対応ルールなし
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
```

## 1. 収集 (read-only)

### 1.1 /etc/aliases の構造確認

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo cat /etc/aliases 2>/dev/null'

# サービスアカウントが root に転送されているか
ssh "$TARGET_USER@$TARGET_HOST" \
  'sudo grep -E "^(apache|httpd|nobody|dovecot|mysql|nginx|www-data|postfix):" /etc/aliases 2>/dev/null'
```

期待 (危険):
- `apache: root` `dovecot: root` `mysql: root` 等が並んでいる

### 1.2 root メールボックスの直近メール

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo ls -la /var/spool/mail/root /var/mail/root 2>/dev/null'

# サービスアカウント名で来た直近メールの抜粋 (件名のみ)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -200 /var/spool/mail/root 2>/dev/null' \
  | grep -iE "^(From|Subject):" | tail -30
```

### 1.3 maillog でサービスアカウント発のメール送信痕跡

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -5000 /var/log/maillog' > /tmp/check_aliases_maillog.log

# from=apache@... / from=dovecot@... = サービス名詐称メール
grep -iE "from=<(apache|dovecot|mysql|nobody|nginx|httpd|postfix)@" /tmp/check_aliases_maillog.log | tail -30

# 同サービスアカウント発の送信先集計 (大量送信なら C2 / phishing 中継)
grep -iE "from=<(apache|dovecot|mysql)@" /tmp/check_aliases_maillog.log \
  | grep -oE "to=<[^>]+>" | sort | uniq -c | sort -rn | head -10
```

### 1.4 webshell 経由の mail 送信痕跡 (Apache 由来)

```bash
# webshell が apache 権限で php mail() を叩くと from=apache@ で出る
grep -E "from=<apache@" /tmp/check_aliases_maillog.log | grep -oE "size=[0-9]+" \
  | awk -F= '{print $2}' | sort -n | tail -5

# 異常に大きい / 連続送信なら確定
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /var/www -name "*.php" -mmin -120 2>/dev/null | head -20'
```

### 1.5 root のメール転送設定 (.forward)

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo cat /root/.forward 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -E "^root:" /etc/aliases'
```

期待:
- 🚨 root が外部メールアドレスに転送されていれば、root メールが攻撃者の手元に流れる

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. apache 由来の送信メール | maillog に `from=<apache@*>` が時間窓内に複数 | 🚨 確定 (webshell 経由の送信) |
| B. サービス名詐称の root 着信 | /var/spool/mail/root に dovecot/mysql 名のメール急増 | ⚠️ 疑わしい (誤誘導) |
| C. /etc/aliases に新規エントリ | aliases 自体が改竄されて外部 from 追加 | 🚨 確定 (改竄) |
| D. root の .forward 外部 | .forward に外部メールアドレス | 🚨 確定 (情報漏洩) |
| E. 連鎖: webshell + apache 送信 | /var/www に直近 PHP + maillog で apache 送信 | 🚨 確定 |

## 3. 判定基準

- ✅ **正常**: aliases は標準構成、apache/dovecot 由来メールなし、.forward なし
- ⚠️ **疑わしい**: B のみ → 内容確認、運用上の正常メール (cron 通知等) でないか判定
- 🚨 **確定**: A / C / D / E → **/playbook:phishing** + **/playbook:wp-tamper** (webshell 経路)

## 4. 次のアクション

### 確定なら
- **`/playbook:phishing`** (apache 詐称メールの追跡)
- **`/playbook:wp-tamper`** (webshell 起点なら WP 配下を深掘り)
- root メールの内容を **forensic 保管** (`cp /var/spool/mail/root /tmp/forensic_root_mbox`)

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: aliases から不審エントリを削除 → newaliases で反映
# 案2: webshell 削除 (/var/www の不審 .php を退避)
# 案3: apache 由来送信を sendmail で reject (access.db 投入)
```

### メモするだけ
- /etc/aliases の標準構成は出題前提に近い → 全削除はリスク
- 「サービス名で root にメール届く」は監査上は本来正しい挙動 (cron 通知等)、判定は内容ベース

## 5. 参照

- 関連 playbook: [playbook/phishing.md](../playbook/phishing.md)、[playbook/wp-tamper.md](../playbook/wp-tamper.md)
- 連鎖先 check: [check-sendmail-open-relay.md](check-sendmail-open-relay.md)
- analyzer 該当: `agent/analyzer.py` `MAIL_PATTERNS` (`mail/burst`)
- 既存ドキュメント: 14_:V6 / 16_:2.3-#6

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-aliases-root-forward__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-aliases-root-forward
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
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-aliases-root-forward__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
