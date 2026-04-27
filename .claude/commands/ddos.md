---
description: DDoS 攻撃の判定と対応。HTTP flood / DNS amplification / SYN flood の切り分け
---

# /ddos — DDoS 対応深掘り

## 1. 追加収集コマンド（スナップショット系が重要）

```bash
# TCP 接続状況スナップショット
ssh manage@10.1.1.2 'ss -s; echo ---; ss -tan state syn-recv | wc -l'

# 同一 IP からのアクセス集計（直近 1000 リクエスト）
ssh manage@10.1.1.2 'tail -1000 /var/log/httpd/access_log | awk "{print \$1}" | sort | uniq -c | sort -rn | head -10'

# iptables カウンタ
ssh manage@10.1.1.2 'iptables -L -n -v 2>&1 | head -30'

# DNS amplification 兆候（ANY クエリ集中）
ssh manage@10.1.1.1 'tail -1000 /var/log/named.log | grep -i "ANY" | wc -l'

# ヤマハ RTX1200/1210 の syslog（事前に転送設定済みなら）
# tail -100 /var/log/yamaha-syslog.log
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
