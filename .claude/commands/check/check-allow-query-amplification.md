---
description: BIND allow-query 過広 + recursion 制限なし による DNS amplification 反射攻撃の踏み台化を確認
---

# /check:check-allow-query-amplification — DNS 反射増幅攻撃確認

引数: `<時間窓> <ホスト>`
例: `/check:check-allow-query-amplification 13:00-13:30 bravo`

## 0. 前提

- 対象: **bravo (10.1.1.1 / FreeBSD / BIND9)**
- 関連 weakness: 14_:8.1#6 / 16_:#6 — `allow-query { 10.0.0.0/8; }` + `recursion yes` + `allow-recursion` 制限なし → **DNS amplification 攻撃の踏み台**
- 影響: 攻撃者が `dig ANY isc.org @10.1.1.1` 系を spoofed source IP で送信 → 標的 IP に大量応答 (反射増幅)
- analyzer.py の対応 pattern_tag: `dns/amplification-bait` (ANY クエリ検出)、`dns/amplification-ratio` (応答サイズ比)
- ⚠️ **bravo の manage は sudo 不可**
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.1}"
```

## 1. 収集 (read-only)

### 1.1 named.conf の致命箇所

```bash
ssh "$TARGET_USER@$TARGET_HOST" \
  'grep -iE "allow-query|allow-recursion|recursion|response-rate-limit|rate-limit" /usr/local/etc/namedb/named.conf 2>/dev/null'
```

期待 (危険):
- `allow-query { 10.0.0.0/8; };` (10/8 全部に開放)
- `recursion yes` (デフォルト)
- `allow-recursion` 設定なし
- `rate-limit` / RRL なし

### 1.2 ANY クエリの集計 (amplification の典型)

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'tail -10000 /var/log/named.log 2>/dev/null' > /tmp/check_amp_named.log

# ANY クエリ単独
grep -iE "query:.*IN ANY" /tmp/check_amp_named.log | wc -l

# クエリ元 IP の集計
grep -iE "query:.*IN ANY" /tmp/check_amp_named.log \
  | grep -oE "client [0-9.]+#[0-9]+" | awk '{print $2}' | cut -d'#' -f1 \
  | sort | uniq -c | sort -rn | head -10

# 標的 (ANY で返したサイズが大きいゾーン)
grep -iE "query:.*IN ANY" /tmp/check_amp_named.log \
  | awk '{print $NF}' | sort | uniq -c | sort -rn | head -10
```

### 1.3 応答サイズ (RRL ログがあれば)

```bash
# response-rate-limit 由来の slip / drop ログ
grep -iE "rrl|response-rate-limit|rate-limit|drop" /tmp/check_amp_named.log | tail -20

# クエリ vs 応答パケット数の不均衡 (簡易)
QUERIES=$(grep -c "query:" /tmp/check_amp_named.log)
RESP=$(grep -c "client.*response" /tmp/check_amp_named.log)
echo "queries=$QUERIES responses=$RESP ratio=$(echo "scale=2; $RESP/$QUERIES" | bc 2>/dev/null)"
```

### 1.4 conntrack / sockstat で 53/UDP の異常

```bash
# 同一送信元から大量の 53/UDP (= 反射元として使われている)
ssh "$TARGET_USER@$TARGET_HOST" 'sockstat -4 -P udp | grep -E ":53\\b" | head -20'

# 短時間で大量送信元の集計
ssh "$TARGET_USER@$TARGET_HOST" \
  'tcpdump -nn -c 200 -r /var/log/dnstop.pcap udp port 53 2>/dev/null | head -30 || echo "no pcap"'
```

### 1.5 spoofed source の手がかり (反射攻撃なら標的 IP が "応答先" に出る)

```bash
# 短時間に同じクエリを大量に投げる "クエリ元" は、実は spoofed = 反射先 IP
# 例: 10.1.1.99 が 100 回/秒で ANY isc.org → 10.1.1.99 が標的になっている
grep -iE "query:.*IN ANY" /tmp/check_amp_named.log \
  | awk '{print $4}' | sort | uniq -c | sort -rn \
  | awk '$1 > 10 {print $0, "← 標的候補"}' | head
```

### 1.6 JSONL 化

```bash
python scripts/preprocess/parse_named.py /tmp/check_amp_named.log > /tmp/check_amp_named.jsonl
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. allow-query 過広 + recursion 制限なし | named.conf に上記 | 🚨 設定上の脆弱性 |
| B. ANY クエリ多発 | 時間窓内に 100+ の ANY query | 🚨 確定 (amp 試行) |
| C. 単一 "クエリ元" から多数 | 同 IP 由来 query が 50+/分 | 🚨 確定 (反射先 = 標的) |
| D. RRL が大量 drop | response-rate-limit が反射を絞っている | ⚠️ 疑わしい (試行はあった) |
| E. analyzer tag | `dns/amplification-bait` / `dns/amplification-ratio` 発火 | 🚨 確定 |

## 3. 判定基準

- ✅ **正常**: ANY クエリ少数、recursion 制限あり、RRL 動作中
- ⚠️ **疑わしい**: D のみ → 試行はあるが緩和されている → 監視継続
- 🚨 **確定**: B / C / E → **/playbook:ddos** で「反射元として悪用されている」扱い

## 4. 次のアクション

### 確定なら
- **`/playbook:ddos`** (反射元として悪用されている = 自社サーバが攻撃の片棒担いでいる)
- リーダーへ「うちの DNS が他者攻撃の踏み台になっている」を即報告 (法的責任 / レピュテーションリスク)
- 並行 **`/check:check-bind-allow-update`** + **`/check:check-bind-axfr`** (DNS 系の他経路も同時被弾しがち)

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: allow-query を絞る
# allow-query { 10.1.1.0/24; localhost; };
# 案2: recursion 制限
# allow-recursion { 10.1.1.0/24; localhost; };
# 案3: response-rate-limit を有効化
# rate-limit { responses-per-second 5; window 5; };
# 反映: rndc reload (settings.json で deny されてる可能性あり)
```

### メモするだけ
- 反射攻撃の踏み台化は **自社が加害者になる** 構造 → 即時対応の優先度は通常より高い
- ただし RRL 設定変更は出題シナリオを止める可能性 → リーダー判断必須

## 5. 参照

- 関連 playbook: [playbook/ddos.md](../playbook/ddos.md)、[playbook/dns-tamper.md](../playbook/dns-tamper.md)
- 連鎖先 check: [check-bind-allow-update.md](check-bind-allow-update.md)、[check-bind-axfr.md](check-bind-axfr.md)
- analyzer 該当: `agent/analyzer.py` `DNS_PATTERNS` (`dns/amplification-bait`)、`_detect_dns_amplification_ratio`
- 既存ドキュメント: 14_:8.1#6 / 16_:#6

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-allow-query-amplification__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-allow-query-amplification
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
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-allow-query-amplification__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
