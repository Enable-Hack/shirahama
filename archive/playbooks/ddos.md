---
model: claude-sonnet-4-6
description: DDoS 攻撃の判定と対応。HTTP flood / DNS amplification / SYN flood の切り分け
---

# /ddos — DDoS 対応深掘り

## 0. 前提（必ず最初に確認）

- 対象: **victor (10.1.1.2)** が web/mail / **bravo (10.1.1.1)** が DNS。両方を見ることが多い
- /incident の §0 共通定数を必ず参照
- ⚠️ 対策コマンド（iptables -j DROP / nginx limit_req）は settings.json で **ask** = リーダー承認必須
- ⚠️ 18_§4.2「サービス影響あるので、リーダー承認 + 顧客通知後に実施」

## 1. 追加収集コマンド（スナップショット系が重要 / read-only）

### 1.1 接続状況スナップショット

```bash
# 現在の TCP 接続状況 (victor)
ssh manage@10.1.1.2 'ss -s; echo ---; ss -tan state syn-recv | wc -l; echo ---; ss -tan state established | wc -l'

# bravo (FreeBSD) は sockstat
ssh manage@10.1.1.1 'sockstat -4 -c 2>&1 | head -50; echo ---; sockstat -4 -c | wc -l'

# パケットドロップ・キュー溢れ
ssh manage@10.1.1.2 'sudo netstat -s | grep -iE "drop|overflow|reset|listen.*queue"'
```

### 1.2 同一 IP 集計（HTTP flood の典型 / 18_ #18 由来）

```bash
# 直近 1000 リクエストの上位 IP
ssh manage@10.1.1.2 'sudo tail -1000 /var/log/httpd/access_log | awk "{print \$1}" | sort | uniq -c | sort -rn | head -10'

# 同一 URL への集中（特定エンドポイント狙い）
ssh manage@10.1.1.2 'sudo tail -2000 /var/log/httpd/access_log | awk "{print \$7}" | sort | uniq -c | sort -rn | head -10'

# User-Agent 偏り（攻撃ツール痕跡）
ssh manage@10.1.1.2 'sudo tail -2000 /var/log/httpd/access_log | grep -oE "\"[^\"]*\" \"[^\"]*\"$" | awk -F\\" "{print \$4}" | sort | uniq -c | sort -rn | head -10'
```

### 1.3 DNS amplification 兆候（18_ #37 由来）

```bash
# ANY クエリ比率（30% 超なら amplification 疑い）
ssh manage@10.1.1.1 'TOTAL=$(grep -c "query:" /var/log/named.log 2>/dev/null); ANY=$(grep "query:" /var/log/named.log | grep -c " ANY "); echo "ANY ratio: $ANY / $TOTAL"'

# 偽装ソース IP 候補（外部からの直撃）
ssh manage@10.1.1.1 'grep -i "query:" /var/log/named.log | awk "{print \$NF}" | sort | uniq -c | sort -rn | head -10'
```

### 1.4 SYN flood / DHCP / SNMP 異常

```bash
# SYN flood: SYN_RECV が多発しているか
ssh manage@10.1.1.2 'ss -tan state syn-recv | wc -l'

# DHCP 配布が異常 (rogue DHCP の可能性 / 18_ #40)
ssh manage@10.1.1.2 'sudo tail -100 /var/log/dhcp.log 2>/dev/null; sudo tail -50 /var/lib/dhcpd/dhcpd.leases 2>/dev/null'

# SNMP への異常問い合わせ (18_ #43-44)
ssh manage@10.1.1.2 'sudo journalctl -u snmpd --since "30 min ago" 2>/dev/null | tail -30'

# RTX1200/1210 syslog の確認
ssh manage@10.1.1.2 'sudo grep -E "rtx|yamaha|syn-flood|exceeded" /var/log/messages 2>/dev/null | tail -20'
```

### 1.5 解析ツール投入

```bash
python scripts/preprocess/parse_clf.py /tmp/incident_access.log > /tmp/incident_access.jsonl
# analyzer.run() → 集約検出（path_scan, auth-bruteforce, dns/amplification-ratio）が出る
```

## 2. Mock パターン参照

`analyzer.py` の以下:
- 同一 IP 集計閾値超過（要実装: time window 集計）
- `dns/amplification-bait`（ANY クエリ大量）
- HTTP flood パターン

## 3. Claude 投入用プロンプト

```
以下は victor のアクセスログとスナップショットです。

スナップショット:
- ss -s 出力: <貼る>
- 上位 IP 集計: <貼る>
- iptables カウンタ: <貼る>

シグナル: <analyzer 出力を貼る>

判定してください:
1. これは DDoS か正規バーストか
2. 攻撃種別（HTTP flood / SYN flood / DNS amp / その他）
3. 即時対応コマンド（iptables / nginx limit_req / RTX ACL）
4. 顧客向け説明（「アクセスしづらい状況」の説明と復旧見込み）
```

## 4. 既存 playbook 参照

- `06_DDoS対応詳細.md` — 1000 行の詳細マニュアル（最重要）
- `13_DDoSアキネーター.html` — 攻撃種別の絞り込み
- `03_シナリオ別対応プレイブック.md` §4「DDoS」

## 5. 報告書テンプレ生成指示

`04_完了報告テンプレート.md` の構造で出力。
特に **「ピーク時のリクエスト数 / 帯域」を時系列で書く**こと。

## 6. 復旧/封じ込めコマンド (人間が手で実行)

⚠️ 以下は **すべて人間がリーダー承認後に手で実行する**コマンドです。
AI は表示・検証・突合のみ。実行には関与しません。
理由:
- タイポ / 不完全な diff / 旧設定上書きで復旧失敗 → サービスダウン継続のリスク
- settings.production.json で物理的に deny されているため AI 実行は不可
- チームが「自分たちで何を直しているか」を理解する必要がある（競技後の説明責任）

```text
# HTTP flood 緊急: 同一 IP からの接続数制限
iptables -I INPUT -p tcp --dport 80 -m connlimit --connlimit-above 20 -j DROP

# SYN flood 緊急
iptables -A INPUT -p tcp --syn -m limit --limit 10/s -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP
sysctl -w net.ipv4.tcp_syncookies=1

# DNS amp 緊急（bravo）
# /etc/named.conf に rate-limit を追加 → rndc reload
```

→ 表示後、§7 cmd_validator gate を必ず通すこと。
→ サービス影響あるので、リーダー承認 + 顧客通知後に人間が手で実施。

## 7. コマンド検証ゲート（封じ込めコマンド提示時 必須）

§6 のような封じ込め / 復旧コマンドを 1 行でも提示する場合、**リーダーに見せる前に必ず `agent/cmd_validator.py` を通すこと**。settings.production.json で iptables / kill / userdel / systemctl 等は deny になっており **AI は実行できない** — 提案文字列の事故防止が validator の役割。

```bash
# 提示候補を一時ファイルに書き出す（先頭に「※リーダー承認後」コメント必須）
cat > /tmp/playbook_proposed.sh <<'EOF'
# ※リーダー承認後 + 顧客通知後に人間が手で実行すること
ssh manage@10.1.1.2 'sudo iptables -I INPUT -s <ATTACKER_IP> -j DROP'
EOF

PYTHONPATH=. ${SHIRAHAMA_PY:-python3} -m agent.cmd_validator /tmp/playbook_proposed.sh
echo "exit=$?"
```

判定:
- `exit=0` ✅ — リーダーに提示してよい。承認後に**人間が手で打つ**
- `exit=1` 🚨 — ERROR あり。リーダーに見せず AI が再生成（自爆 IP / 触禁ホスト / sudo 不可ホスト等）
- WARN のみ — 提示してよいが補足説明を添える

## 8. JSON 永続化（HTML dashboard 連携）

§6 の対策コマンド + §7 の cmd_validator 結果を JSON 化して helper に渡す。actor は `ai_human` (AI 提案 → 人間実行) を明示。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh playbook-ddos --actor ai_human
{
  "inputs": {
    "scenario": "ddos",
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
- 保存先: `data/incidents/${INCIDENT_ID}/playbook-ddos__<ts>.json`
