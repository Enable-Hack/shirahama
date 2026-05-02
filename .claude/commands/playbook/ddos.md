---
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

## 6. 事前準備しておく緊急対応コマンド

```bash
# HTTP flood 緊急: 同一 IP からの接続数制限
iptables -I INPUT -p tcp --dport 80 -m connlimit --connlimit-above 20 -j DROP

# SYN flood 緊急
iptables -A INPUT -p tcp --syn -m limit --limit 10/s -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP
sysctl -w net.ipv4.tcp_syncookies=1

# DNS amp 緊急（bravo）
# /etc/named.conf に rate-limit を追加 → rndc reload
```

⚠️ **これらは全てサービス影響あるので、リーダー承認 + 顧客通知後に実施**
