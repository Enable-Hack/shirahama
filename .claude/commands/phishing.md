---
description: フィッシング・不審メール対応。受電通報 or maillog 異常をトリガー
---

# /phishing — フィッシング・不審メール対応

## 1. 追加収集コマンド

```bash
# postfix/sendmail のキューと履歴
ssh manage@10.1.1.2 'mailq | head -50'
ssh manage@10.1.1.2 'tail -500 /var/log/maillog'

# 特定 message-id のメール本文を retrieve（ユーザー通報されたメール）
# ssh manage@10.1.1.2 'postcat -q <queue_id>'

# 送信元 IP の集計
ssh manage@10.1.1.2 'tail -1000 /var/log/maillog | grep "client=" | awk -F"client=" "{print \$2}" | awk "{print \$1}" | sort | uniq -c | sort -rn | head'

# SPF / DKIM / DMARC 検証結果
ssh manage@10.1.1.2 'grep -i "spf\|dkim\|dmarc" /var/log/maillog | tail -30'
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
