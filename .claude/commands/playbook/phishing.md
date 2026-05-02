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

## 6. 即時対応コマンド雛形

```bash
# postfix で特定送信元 IP をブロック
echo "1.2.3.4 REJECT" >> /etc/postfix/access
postmap /etc/postfix/access
postfix reload

# 不審メールのキュー削除
postsuper -d <queue_id>

# 全社向け注意喚起メール（Claude 生成文を流し込む）
# echo "<件名>" | mail -s "【重要】フィッシング注意" all_users@com1.local
```
