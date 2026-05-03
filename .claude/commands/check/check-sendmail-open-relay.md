---
description: Sendmail オープンリレー悪用 (外部 → 外部メール中継) の痕跡を確認
---

# /check:sendmail-open-relay — オープンリレー確認

引数: `<時間窓> <ホスト>`
例: `/check:sendmail-open-relay 13:00-13:30 victor`

## 0. 前提

- 対象: **victor (10.1.1.2 / Rocky)** および **bravo (10.1.1.1 / FreeBSD)** いずれも sendmail 稼働
- 関連 weakness: `relay-domains` 過広 + SPF/DKIM/DMARC 未設定 → 第三者中継成立の可能性
- analyzer.py の対応 pattern_tag: `mail/relay-attempt`、`mail/relay-denied`、`mail/spf-fail`、`mail/dkim-fail`、`mail/burst`
- ⚠️ **bravo の manage は sudo 不可** — root が必要なら `ssh root@10.1.1.1` 直ログイン
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"     # victor デフォルト / bravo は 10.1.1.1 に上書き
```

## 1. 収集 (read-only)

### 1.1 sendmail 設定の致命箇所確認

```bash
# victor (Rocky)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo cat /etc/mail/access /etc/mail/relay-domains 2>/dev/null | head -50'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -iE "relay|promiscuous|smart_host" /etc/mail/sendmail.cf 2>/dev/null | head -20'

# bravo (FreeBSD) パスは異なる
ssh "$TARGET_USER@10.1.1.1" 'cat /etc/mail/access /etc/mail/relay-domains 2>/dev/null | head -50'
```

### 1.2 maillog からリレー試行/成立の抽出

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -5000 /var/log/maillog' > /tmp/check_relay_maillog.log

# 拒否 (allow-relay が効いている証拠)
grep -iE "NOQUEUE: reject: RCPT from|relay access denied|domain not found" /tmp/check_relay_maillog.log | tail -30

# 中継成立 (外部 from → 外部 to で stat=Sent)
grep -iE "from=<[^@]+@[^>]+>.*to=<[^@]+@[^>]+>.*stat=Sent" /tmp/check_relay_maillog.log | tail -30

# 異常な送信先 (ローカルドメインじゃない)
grep -iE "to=<.*@(?!com1\\.local|localhost)" /tmp/check_relay_maillog.log | tail -30
```

### 1.3 送信元 IP の集計（burst 検出）

```bash
# 短時間に同一 IP から大量送信 = リレー悪用の典型
grep -iE "relay=\\[[0-9.]+\\]" /tmp/check_relay_maillog.log \
  | grep -oE "relay=\\[[0-9.]+\\]" | sort | uniq -c | sort -rn | head -10

# from MAIL アドレスのドメイン別集計（spoofing 検出）
grep -iE "from=<[^>]+>" /tmp/check_relay_maillog.log \
  | grep -oE "from=<[^>]+>" | sort | uniq -c | sort -rn | head -10
```

### 1.4 SPF/DKIM/DMARC 設定の確認

```bash
# 自ドメインの SPF レコード（外部からの dig）
dig com1.local TXT +short | grep -iE "v=spf"
dig _dmarc.com1.local TXT +short
dig default._domainkey.com1.local TXT +short

# 期待: SPF ない / -all がない / DMARC がない → なりすましされやすい
```

### 1.5 SMTP AUTH brute 痕跡（リレーのもう 1 経路）

```bash
grep -iE "SASL\\s+(LOGIN|PLAIN)\\s+authentication failed" /tmp/check_relay_maillog.log \
  | grep -oE "from=\\[[0-9.]+\\]" | sort | uniq -c | sort -rn | head
```

### 1.6 JSONL 化

```bash
python scripts/preprocess/parse_maillog.py /tmp/check_relay_maillog.log > /tmp/check_relay_maillog.jsonl
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. 外部→外部 stat=Sent | from / to 双方が com1.local 以外で `stat=Sent` | 🚨 確定 (オープンリレー悪用成立) |
| B. relay access denied 多発 | 拒否ログが大量 → 試行はあるが防御は効いている | ⚠️ 疑わしい |
| C. 送信 burst | 同一 IP から数百通/分 | 🚨 確定 (スパム送信中) |
| D. SPF -all 不在 | 自ドメインに SPF レコードなし or `?all` | 🚨 設定上の脆弱性 |
| E. SASL brute | 同一 IP から SASL 認証失敗 多発 | ⚠️ 疑わしい (前段 brute) |
| F. analyzer tag | `mail/relay-attempt` または `mail/burst` 発火 | 🚨 確定 |

## 3. 判定基準

- ✅ **正常**: 外部→外部 Sent 0、burst なし、SPF/DKIM/DMARC 設定済
- ⚠️ **疑わしい**: B / E のみ → 監視継続 + 攻撃元 IP を `/check:` 他経路と突合
- 🚨 **確定**: A / C / F → **/playbook:phishing** へ即時遷移

## 4. 次のアクション

### 確定なら
- **`/playbook:phishing`** (フィッシング送信元として悪用されている前提で全工程実施)
- バウンスメール / RBL リスト掲載 / IP reputation 低下を運営に即時報告
- 並行して **`/check:rainloop-cve29360`** (rainloop 経由でアカウント乗っ取られた可能性)

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: relay-domains を local のみに絞る
# 案2: /etc/mail/access に攻撃元 IP を REJECT 登録
# 案3: 一時的に sendmail 停止 — メール業務影響大、最後の手段
```

### メモするだけ
- リレー悪用は出題前提の可能性高（access ファイルが過広に設定されているはず）
- 18_§4.3「触らない」を優先しつつ、被害送信は止める判断をリーダーへ

## 5. 参照

- 関連 playbook: [playbook/phishing.md](../playbook/phishing.md)
- 連鎖先 check: [check-rainloop-cve29360.md](check-rainloop-cve29360.md)
- analyzer 該当: `agent/analyzer.py` `MAIL_PATTERNS`、`_detect_mail_burst`
- 既存ドキュメント: `docs/14_サーバ調査レポート_20260424.md` §「Sendmail open relay」

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-sendmail-open-relay__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-sendmail-open-relay
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
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-sendmail-open-relay__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
