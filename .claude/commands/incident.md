---
description: 電話受電起点でログ取得 → analyzer → Mock → Claude → カテゴリ判定 → 推奨次手順を一気通貫で出す
---

# /incident — 汎用インシデント対応エントリ

引数: `<時間窓> <ホスト>`
例: `/incident 13:00-13:30 victor`

## やること（このファイルは Claude Code 自身に対する指示書）

以下の手順を順番に実行してください。

### 1. ログ取得

引数で指定された時間窓と対象ホスト（victor または bravo）に対し、必要なログを取得する:

```bash
# victor (Rocky Linux, 10.1.1.2) の場合
ssh manage@10.1.1.2 'tail -2000 /var/log/httpd/access_log'  > /tmp/incident_access.log
ssh manage@10.1.1.2 'tail -1000 /var/log/secure'           > /tmp/incident_secure.log
ssh manage@10.1.1.2 'tail -1000 /var/log/maillog'          > /tmp/incident_maillog.log

# bravo (FreeBSD, 10.1.1.1) の場合
ssh manage@10.1.1.1 'tail -2000 /var/log/named.log'         > /tmp/incident_named.log
ssh manage@10.1.1.1 'tail -1000 /var/log/auth.log'          > /tmp/incident_auth.log
ssh manage@10.1.1.1 'tail -1000 /var/log/httpd-error.log'   > /tmp/incident_httpd_err.log
```

### 2. 時間窓フィルタ + JSONL 化

`scripts/preprocess/parse_*.py` を使ってテキストログを JSONL に変換し、指定時間窓だけ抽出:

```bash
python scripts/preprocess/parse_clf.py /tmp/incident_access.log \
  | jq --arg start "$START" --arg end "$END" 'select(.timestamp >= $start and .timestamp <= $end)' \
  > /tmp/incident_access.jsonl
```

他のログも同様。

### 3. analyzer 起動

```bash
python -c "
from agent import analyzer
signals = analyzer.run('/tmp')
print(f'検出シグナル: {len(signals)} 件')
for s in signals:
    print(f'  [{s.severity}] {s.type} @ {s.path[:80]}')
"
```

### 4. Mock 二段ふるい + Claude 集約

```bash
python -c "
from agent import analyzer
from agent.backends.mock_backend import MockBackend
from agent.backends.claude_backend import ClaudeBackend
from agent.validator import validate_patches

signals = analyzer.run('/tmp')

# Mock で whitelist drop + known-bad 即出し
mock = MockBackend()
mock_patches = mock.propose_patches(signals)

# grey シグナルだけ Claude に集約
known_bad_targets = {p.target for p in mock_patches}
grey = [s for s in signals if s.path not in known_bad_targets]
claude_patches = ClaudeBackend().propose_patches(grey) if grey else []

all_patches = mock_patches + claude_patches
validated = validate_patches(all_patches)

for p in validated:
    print(f'[{p.action}] {p.rule_id} conf={p.confidence:.2f}')
    print(f'  target: {p.target}')
    print(f'  match: {p.match_type} {p.match_operator} {p.match_value!r}')
    print(f'  rationale: {p.rationale_ja}')
"
```

### 5. カテゴリ判定 + 次に叩くべき skill 提示

検出された pattern_tag から推測:
- `xss/*`、`sqli/*`、`wp-bruteforce`、`rainloop-known` → **`/wp-tamper` を次に叩いてください**
- `dns/unauthorized-update`、`dns/axfr-attempt` → **`/dns-tamper` を次に叩いてください**
- `xss-flood`、`http-flood`、同一 IP 大量リクエスト → **`/ddos` を次に叩いてください**
- `mail/spf-fail`、`mail/from-mismatch` → **`/phishing` を次に叩いてください**
- `pkexec-attempt`、`sudo/unauthorized`、不審 mtime → **`/ransomware` を次に叩いてください**
- どれにも該当しない → 人間判断

### 6. 状況サマリ生成

```bash
python -c "
from agent.backends.claude_backend import ClaudeBackend
print(ClaudeBackend().explain_to_operator_ja(signals, validated))
"
```

→ この出力を `01_受電ヒアリングシート.md` に追記し、リーダーに報告。

## 参照
- `19_AIパイプライン実装ガイド.md` — 詳細手順
- `18_キャンプ知見の白浜活用方針.md` — 思想
- `03_シナリオ別対応プレイブック.md` — カテゴリ別の対応手順
