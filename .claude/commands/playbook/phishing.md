---
description: フィッシング・不審メール対応。受電通報 or maillog 異常をトリガー
---

# /phishing — フィッシング・不審メール対応

## 0. 前提（必ず最初に確認）

- 対象: **victor (10.1.1.2)** が postfix/dovecot、**bravo (10.1.1.1)** が sendmail/courier-imap。両方を見ることがある
- /incident の §0 共通定数を必ず参照
- ⚠️ `postsuper -d`（キュー削除）は settings.json で **deny** 設定済 = 実行不可。**証拠保全のため削除前に保存**
- ⚠️ 18_ §31「sendmail Open Relay 化リスク」、§34「SPF/DKIM/DMARC 不在」が前提

## 1. 追加収集コマンド（read-only）

### 1.1 メールキューと履歴

```bash
# キュー状況 (両機)
ssh manage@10.1.1.2 'mailq 2>&1 | head -50'
ssh manage@10.1.1.1 'mailq 2>&1 | head -50'

# maillog 取得 (時間窓は呼び出し側で絞る)
ssh manage@10.1.1.2 'sudo tail -1000 /var/log/maillog' > /tmp/incident_maillog.log
ssh manage@10.1.1.1 'tail -1000 /var/log/maillog' >> /tmp/incident_maillog.log

# 通報された特定 message-id を保存 (削除はしない)
# postcat -q <queue_id> | tee /tmp/evidence_<queue_id>.eml
```

### 1.2 送信元・受信元の集計

```bash
# 送信元 IP の集計 (burst 検出 / 18_ #31 由来)
ssh manage@10.1.1.2 'sudo tail -2000 /var/log/maillog | grep -oE "client=[^,[:space:]]+\\[[0-9.]+\\]" | sort | uniq -c | sort -rn | head -10'

# 拒否された送信先（フィッシング標的の手がかり）
ssh manage@10.1.1.2 'sudo grep -E "NOQUEUE: reject|relay access denied" /var/log/maillog | tail -30'

# 認証失敗 (SMTP AUTH brute / 18_ MAIL_PATTERNS sasl-failed 由来)
ssh manage@10.1.1.2 'sudo grep -iE "SASL.*authentication failed|warning.*authentication" /var/log/maillog | tail -30'
```

### 1.3 SPF / DKIM / DMARC / なりすまし兆候（18_ #34 由来）

```bash
# SPF / DKIM / DMARC 検証結果の抽出
ssh manage@10.1.1.2 'sudo grep -iE "spf=|dkim=|dmarc=" /var/log/maillog 2>/dev/null | tail -30'

# Received-SPF: fail / dkim=fail を直接抽出 (analyzer の MAIL_PATTERNS と一致)
ssh manage@10.1.1.2 'sudo grep -iE "Received-SPF.*fail|dkim=fail" /var/log/maillog 2>/dev/null | tail -20'

# 自ドメインの SPF/DKIM/DMARC レコードがあるか (無いと攻撃者がなりすませる)
dig com1.local TXT +short | grep -iE "spf|dkim|dmarc"
dig _dmarc.com1.local TXT +short
```

### 1.4 Open Relay / 不審 alias 確認（18_ #31, #35 由来）

```bash
# relay-domains / mynetworks (read-only)
ssh manage@10.1.1.2 'sudo cat /etc/postfix/main.cf 2>/dev/null | grep -E "mynetworks|relay_domains|smtpd_relay_restrictions"'
ssh manage@10.1.1.1 'sudo cat /etc/mail/relay-domains 2>/dev/null; sudo cat /etc/mail/access 2>/dev/null'

# /etc/aliases に不審な転送先が追加されていないか
ssh manage@10.1.1.2 'sudo cat /etc/aliases | grep -vE "^#|^$" | tail -30'
```

### 1.5 解析ツール投入

```bash
python scripts/preprocess/parse_maillog.py /tmp/incident_maillog.log > /tmp/incident_maillog.jsonl
# analyzer.run() → MAIL_PATTERNS で spf-fail / sasl-failed / mail-burst が出る
```

## 2. Mock パターン参照

`analyzer.py` の以下:
- `mail/spf-fail`
- `mail/from-mismatch`（From ≠ Return-Path）
- `mail/burst`（短時間に同一送信元から大量）

## 3. Claude 投入用プロンプト（メール本文判定が必要なら）

```
以下のメールが「不審」と通報されました。フィッシングか正規メールか判定してください。

ヘッダ: <貼る>
本文: <貼る>

判定基準:
- 偽装ドメイン（表示名と実 From の不一致）
- 緊急性を煽る文言（24時間以内、停止します等）
- リンク先 URL と表示文字列の不一致
- 添付ファイル種別（exe / scr / iso / マクロ Office）
- 文法・言い回しの不自然さ

出力:
1. is_phishing: true/false
2. confidence: 0.0-1.0
3. indicators: 具体的な根拠 3 つ
4. recommended_action: block / quarantine / warn / pass
5. ユーザー向け説明文（「このメールは...」）
```

## 4. 既存 playbook 参照

- `03_シナリオ別対応プレイブック.md` §1「フィッシング」
- `01_受電ヒアリングシート.md` パターン C/D（外部通報 / ユーザー苦情）

## 5. 報告書テンプレ生成指示

`04_完了報告テンプレート.md` の構造で出力。
特に **全社向け注意喚起メールの文面**を別途生成（ユーザーへの被害防止）。

## 6. 復旧/封じ込めコマンド (人間が手で実行)

⚠️ 以下は **すべて人間がリーダー承認後に手で実行する**コマンドです。
AI は表示・検証・突合のみ。実行には関与しません。
理由:
- タイポ / 不完全な diff / 旧設定上書きで復旧失敗 → サービスダウン継続のリスク
- settings.production.json で物理的に deny されているため AI 実行は不可
- チームが「自分たちで何を直しているか」を理解する必要がある（競技後の説明責任）

```text
# postfix で特定送信元 IP をブロック
echo "1.2.3.4 REJECT" >> /etc/postfix/access
postmap /etc/postfix/access
postfix reload

# 不審メールのキュー削除（証拠保全のため postcat で先に保存してから削除）
postcat -q <queue_id> | tee /tmp/evidence_<queue_id>.eml
postsuper -d <queue_id>

# 全社向け注意喚起メール（Claude 生成文を流し込む）
# echo "<件名>" | mail -s "【重要】フィッシング注意" all_users@com1.local
```

→ 表示後、§7 cmd_validator gate を必ず通すこと。

## 7. コマンド検証ゲート（封じ込めコマンド提示時 必須）

§6 の `postmap` / `postfix reload` / `postsuper -d` 等を 1 行でも提示する場合、**リーダーに見せる前に必ず `agent/cmd_validator.py` を通すこと**。settings.production.json で postfix reload / postsuper -d / postmap / Edit(/etc/**) は deny になっており **AI は実行できない** — 提案文字列の事故防止が validator の役割。

```bash
cat > /tmp/playbook_proposed.sh <<'EOF'
# ※リーダー承認後 + 顧客通知後に人間が手で実行すること
ssh manage@10.1.1.2 'sudo postsuper -d <queue_id>'
EOF

PYTHONPATH=. ${SHIRAHAMA_PY:-python3} -m agent.cmd_validator /tmp/playbook_proposed.sh
echo "exit=$?"
```

判定:
- `exit=0` ✅ — リーダーに提示してよい。承認後に**人間が手で打つ**
- `exit=1` 🚨 — ERROR あり。bravo に `manage` で sudo 等を弾く
- WARN のみ — 提示してよいが補足説明を添える

## 8. JSON 永続化（HTML dashboard 連携）

§6 の対策コマンド + §7 の cmd_validator 結果を JSON 化して helper に渡す。actor は `ai_human` (AI 提案 → 人間実行) を明示。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh playbook-phishing --actor ai_human
{
  "inputs": {
    "scenario": "phishing",
    "incident_id": "$INCIDENT_ID"
  },
  "outputs": {
    "proposed_commands": [
      "<§6 で提案したコマンド全文 (1 行 1 件)>"
    ],
    "cmd_validator_result": {
      "exit_code": 0,
      "errors": [],
      "warnings": ["<§7 cmd_validator が出した WARN/ERROR>"]
    },
    "scope": {
      "in_scope": ["<受電内容と直結する対策>"],
      "out_of_scope_logged": ["<観察したが今回触らないもの (治しすぎない哲学)>"]
    }
  },
  "verdict": {
    "status": "🚨 | ⚠️ | ✅",
    "summary": "<提案 N 件 (validator PASS), 採用は人間判断>"
  },
  "next_skills": ["/report", "/ticket"]
}
JSON_EOF
```

- `actor=ai_human` で「AI が提案、人間が実行」を JSON 上で明示 (dashboard が UI 上で「未実行/実行済」バッジを出せる)
- `proposed_commands[]` は §6 で提案した対策コマンドを 1 行 1 件で羅列。`text` フェンス内のコマンドをそのまま転記
- `cmd_validator_result` は §7 で実行した `agent.cmd_validator` の exit_code + errors + warnings をそのまま入れる
- `scope.out_of_scope_logged` で「観察したが今回触らない」項目を残し、報告書/ticket での記録に使う (治しすぎない哲学)
- 保存先: `data/incidents/${INCIDENT_ID}/playbook-phishing__<ts>.json`
