---
model: claude-haiku-4-5
description: BIND ゾーン転送 (AXFR / IXFR) による情報漏洩試行の痕跡を確認
---

# /check:bind-axfr — DNS ゾーン転送試行確認

引数: `<時間窓> <ホスト>`
例: `/check:bind-axfr 13:00-13:30 bravo`

## 0. 前提

- 対象: **bravo** (本番 10.1.1.1 / FreeBSD、BIND9)
- 関連 weakness: `allow-transfer` が広い / 未設定 → 任意の外部から `dig AXFR com1.local @10.1.1.1` で全レコード取得可能
- analyzer.py の対応 pattern_tag: `dns/axfr-attempt`
- ⚠️ **bravo の manage は sudo 不可** — root が必要なら `ssh root@10.1.1.1` 直ログイン
- AXFR 成立 = 全レコード（内部 IP / 隠し host / メールサーバ等）が漏洩する
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.1}"
```

## 1. 収集 (read-only)

### 1.1 allow-transfer の設定値確認

```bash
ssh "$TARGET_USER@$TARGET_HOST" \
  'grep -iE "allow-transfer|also-notify|notify" /usr/local/etc/namedb/named.conf 2>/dev/null'
```

### 1.2 named.log の AXFR/IXFR 試行痕跡

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'tail -5000 /var/log/named.log 2>/dev/null || tail -5000 /var/log/messages | grep named' \
  > /tmp/check_bind_axfr.log

# transfer 試行（成功/拒否いずれもログに残る）
grep -iE "transfer.*'[^']+'.*from.*[0-9.]+#[0-9]+" /tmp/check_bind_axfr.log | tail -30

# 明示拒否
grep -iE "zone transfer.*denied|client.*query.*axfr.*denied" /tmp/check_bind_axfr.log | tail -20

# 成功（最悪）
grep -iE "transfer of '[^']+' to.*[0-9.]+.*: end of transfer" /tmp/check_bind_axfr.log | tail -20
```

### 1.3 外部から実際に AXFR が取れるか試す（攻撃者目線の検証）

```bash
# AXFR が通ってしまえば全レコード露出
dig @"$TARGET_HOST" com1.local AXFR 2>&1 | head -50

# IXFR (差分転送) も同様
dig @"$TARGET_HOST" com1.local IXFR=0 2>&1 | head -20
```

期待値:
- ✅ `; Transfer failed` または `Server response: REFUSED` → allow-transfer が効いている
- 🚨 大量レコードが返る → 漏洩確定

### 1.4 攻撃元 IP の集計（試行が観測されている場合）

```bash
grep -iE "transfer|axfr|ixfr" /tmp/check_bind_axfr.log \
  | grep -oE "[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+" | sort | uniq -c | sort -rn | head -10
```

### 1.5 JSONL 化

```bash
python scripts/preprocess/parse_named.py /tmp/check_bind_axfr.log > /tmp/check_bind_axfr.jsonl
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. allow-transfer 未設定 / any | `named.conf` に `allow-transfer { any; };` または項目なし | 🚨 設定上の脆弱性 |
| B. AXFR 成功痕跡 | `transfer of ... to <IP>: end of transfer` ログ | 🚨 確定 (漏洩) |
| C. 外部からの AXFR 通過 | 1.3 の `dig AXFR` で全レコードが返る | 🚨 確定 |
| D. 試行多発 | 同一 IP から AXFR/IXFR が時間窓内 5+ | ⚠️ 疑わしい |
| E. analyzer tag | `dns/axfr-attempt` 発火 | ⚠️〜🚨 (内容次第) |

## 3. 判定基準

- ✅ **正常**: allow-transfer が secondary IP のみ、外部 dig AXFR が REFUSED
- ⚠️ **疑わしい**: D のみ → 監視継続、攻撃元 IP を **`/check:` 系で他経路（brute / amplification）と突き合わせ**
- 🚨 **確定**: A/B/C → **/playbook:dns-tamper** へ → 漏洩内容の特定と影響評価

## 4. 次のアクション

### 確定なら
- **`/playbook:dns-tamper`** (情報漏洩としての扱い)
- 並行して **`/check:bind-allow-update`** (AXFR と nsupdate は同 IP から同時に来やすい)
- 漏洩したレコードの一覧化 → リーダー報告

### 即時封じ手（リーダー承認後のみ）
```bash
# named.conf の allow-transfer を絞る (CIC DNS = 10.1.130.1 のみ許可、本番想定)
# allow-transfer { 10.1.130.1; };
# 反映: rndc reload
```

### メモするだけ
- AXFR は出題側の調査経路として用意されている可能性 → 即座に塞がない
- ただし「漏洩した内容」は明確に報告書に残す

## 5. 参照

- 関連 playbook: [playbook/dns-tamper.md](../playbook/dns-tamper.md)
- 連鎖先 check: [check-bind-allow-update.md](check-bind-allow-update.md)
- analyzer 該当: `agent/analyzer.py` `DNS_PATTERNS` (`dns/axfr-attempt`)

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-bind-axfr__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-bind-axfr
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
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-bind-axfr__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
