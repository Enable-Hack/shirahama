# 06. DDoS 対応詳細

> [03_シナリオ別対応プレイブック](./03_シナリオ別対応プレイブック.md) の「シナリオ4：DDoS／大量アクセス」を詳細化したもの。
> **受電 → 判定 → 対応 → 完了報告** の流れに沿って、OS別・環境別（オンプレ／AWS）に分けて記載。

---

## ⚠ 事前必読

**この文書は「DDoS と確定してから」の詳細対応書。**
判定に入る前の切り分けは必ず **[02.1_先にやること](./02.1_先にやること.md)** を通すこと。
いきなり DDoS 判定から入ると、DB 詰まり・外部API遅延・DNS障害などを誤診して **遮断事故** を起こす。

---

## ⓪ 速見カード（戦闘中に見る）

### ⓪-1. 最重要原則（3つだけ覚える）

```
★ 観測点 ≠ 攻撃対象 ≠ 被害箇所
　症状が見えた場所 ≠ パケットが来ている場所 ≠ 枯渇している場所

★ 止まった ≠ 防げた
　攻撃者が諦めただけかもしれない

★ 構成図は信じすぎない
　実機から取った情報で自作する
```

### ⓪-2. 数値しきい値（この数字で判定する）

| 観測項目 | 正常 | 注意 | 異常（疑い） |
|---|---|---|---|
| `ss -s` の synrecv | 0〜10 | 10〜100 | **100+ → SYN Flood 疑い** |
| `ss -s` の estab | 0〜50 | 50〜200 | **200+ → HTTP / Slow 疑い** |
| `ss -nua` の UDP | 0〜20 | 20〜100 | **100+ → UDP 系疑い** |
| `uptime` のロードアベレージ | コア数 以下 | コア数〜2倍 | **2倍超 → 過負荷** |
| access_log req/min | 平常時 | 平常時 ×3 | **平常時 ×10+ → Flood 疑い** |
| `/proc/sys/fs/file-nr` 第1列 | 余裕あり | 上限の50% | **上限の90%超 → FD 枯渇** |

※ 「平常時」は大会開始直後に自分たちで測っておく。

### ⓪-3. 一発分類コマンド（コピペ用）

```bash
echo "=== STATE ==="    && ss -s
echo "=== SYN_RECV ===" && ss -ntu state syn-recv 2>/dev/null | wc -l
echo "=== ESTAB ==="    && ss -ntu state established 2>/dev/null | wc -l
echo "=== UDP ==="      && ss -nua 2>/dev/null | wc -l
echo "=== LOAD ==="     && uptime
echo "=== FD ==="       && cat /proc/sys/fs/file-nr
echo "=== TOP SRC ==="  && ss -ntu 2>/dev/null | awk 'NR>1{print $6}' | cut -d: -f1 | sort | uniq -c | sort -rn | head
echo "=== KERN ==="     && dmesg | tail -10 | grep -iE 'syn|flood|drop|overflow' || echo "(no flood warn)"
echo "=== ACCESS ==="   && tail -5 /var/log/httpd/access_log 2>/dev/null || tail -5 /var/log/apache2/access.log 2>/dev/null
```

### ⓪-4. 判定フローチャート（確定用）

```
上記ワンライナーの出力から：

接続数が異常？
 ├─ NO ─→ DDoS ではない可能性大（[02.1] の DDoS じゃないランキングへ）
 └─ YES
     ├─ synrecv 100+       → SYN Flood
     │    ├─ 送信元IP 少数集中 → 固定IP型、iptables 遮断効く
     │    └─ 送信元IP バラバラ → 偽装型、SYN cookies が本命
     ├─ estab 200+
     │    ├─ access_log 多い  → HTTP GET/POST Flood
     │    └─ access_log 少ない → Slow HTTP（Slowloris等）
     ├─ UDP 100+
     │    ├─ 53番集中        → DNS Flood / Amp
     │    └─ ランダム        → UDP Flood
     ├─ 帯域飽和+混合        → Stream / Volumetric
     └─ FD 枯渇 + estab 多   → Connection Exhaustion
```

### ⓪-5. 30秒即対応テンプレ（分類確定直後に打つ）

**SYN Flood**
```bash
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.tcp_max_syn_backlog=4096
sysctl -w net.core.somaxconn=4096
# 固定IP型なら追加で：
iptables -I INPUT 1 -s <攻撃元IP> -j DROP
```

**HTTP GET/POST Flood**
```bash
iptables -I INPUT 1 -s <攻撃元IP> -j DROP
iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 30 -j DROP
iptables -A INPUT -p tcp --dport 443 -m connlimit --connlimit-above 30 -j DROP
```

**Slow HTTP**
```bash
# /etc/httpd/conf.d/slow.conf か /etc/apache2/conf-available/slow.conf に追記
cat << 'EOF'
RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500
Timeout 30
KeepAliveTimeout 5
EOF
# RHEL: systemctl reload httpd / Debian: systemctl reload apache2
```

**UDP Flood**
```bash
iptables -A INPUT -p udp -m limit --limit 10/s --limit-burst 20 -j ACCEPT
iptables -A INPUT -p udp -j DROP
```

**DNS Amp（踏み台化）**
```bash
# named.conf options に追記
# allow-recursion { 127.0.0.1; 内部NW/24; };
# minimal-responses yes;
# rate-limit { responses-per-second 10; window 5; };
systemctl reload named
```

### ⓪-6. やってはいけない10箇条（対応中）

| # | NG 行動 | 代わりにどうする |
|---|---|---|
| 1 | IP 単位遮断で満足（偽装なら無意味） | `hashlimit` / SYN cookies に切替 |
| 2 | DB / バックエンド側で制限 | **攻撃対象の直前（前段 Web）で絞る** |
| 3 | サーバ再起動 | プロセス状態を保全、設定リロードで対応 |
| 4 | 審査員 IP レンジを含む遮断 | 複数ログソースでクロスチェック |
| 5 | ロールバック手順なしでルーター変更 | 実行前に `show config` → 既存番号メモ |
| 6 | `sysctl -w` だけで永続化せず | `/etc/sysctl.d/99-antiddos.conf` 併記 |
| 7 | `ss -s` だけで「効いた」判定 | **被害箇所も回復したか** を両方で確認 |
| 8 | 陽動の可能性を忘れる | 指揮係が別ログ（認証・改ざん）を並行監視 |
| 9 | 単一サーバだけ見て判断 | 11章の「観測点・攻撃対象・被害箇所」で横断確認 |
| 10 | 「止まった」＝「防げた」と誤認 | 完了報告では「現時点で沈静化」と表現 |

### ⓪-7. ディストリ差分（Linux の RHEL 系 vs Debian 系）

| 項目 | RHEL系（CentOS/Rocky） | Debian系（Ubuntu/Debian） |
|---|---|---|
| Apache サービス | `httpd` | `apache2` |
| Apache ログ | `/var/log/httpd/access_log` | `/var/log/apache2/access.log` |
| Apache 設定 | `/etc/httpd/conf/httpd.conf` | `/etc/apache2/apache2.conf` |
| モジュール有効化 | 設定内 `LoadModule` | `a2enmod reqtimeout` |
| FW 標準 | `firewalld` | `ufw` |
| iptables 永続化 | `service iptables save` / `iptables-save > /etc/sysconfig/iptables` | `iptables-persistent` |
| MAC | SELinux（`setenforce 0` で一時無効化） | AppArmor（`aa-complain`） |

`ss` `sysctl` `iptables` `tcpdump` 本体は共通。**違うのはサービス名・ログパス・永続化の仕方**。

### ⓪-8. FreeBSD について

- コンテストの機材リストに含まれるので、DNS/Mail 役で出る可能性は残る
- ただし Web 攻撃対象としては Linux が主体
- 準備配分：**Linux 80% / FreeBSD 20%**
- 詳細コマンド差分は各節の「FreeBSD」パラグラフ参照

---

## 0. まず1分でやる「DDoSかどうか」の判定

> いきなり攻撃対応に入らず、**DDoSで本当にいいのか** を1分で切り分ける。早合点は大減点ポイント。

### 0-1. 1分判定シーケンス（サーバにSSH済みの前提）

```bash
# ① サービス自体は生きているか（プロセス・ポート）
systemctl status httpd named postfix 2>/dev/null || service apache24 status

# ② TCP接続の全体像（Linuxならss、FreeBSDならnetstat）
ss -s 2>/dev/null || netstat -an | awk '{print $6}' | sort | uniq -c

# ③ 負荷
uptime
```

### 0-2. 判定表

| 観測 | 判断 |
|---|---|
| プロセス停止・ポート Listen なし | **DDoS ではない**（サービス障害・設定ミス） |
| プロセス生存・接続が数百〜数千以上に急増 | **DDoS 疑い**（次フェーズへ） |
| プロセス生存・接続数は平常通り・個別ユーザのみ不通 | **DDoS ではない**（経路・DNS・クライアント側） |
| アクセスログに改ざん痕跡・不審POST | **DDoSではなく侵害** → [03] シナリオ2/7 へ |

### 0-3. ここを間違えやすい

- **「遅い＝DDoS」ではない**。ISP側障害、DNS障害、バックエンドDB詰まり、証明書期限切れでも「遅い」
- **「遅いし接続数も多い」** でも、キャンペーン直後の正規アクセス集中かもしれない
- **複数インシデント同時発生の陽動**：DDoS に気を取られて侵害を見逃す。Phase 0 後半で「同時刻の別ログ異常」を必ず確認

---

## 1. 受電〜引き継ぎ（[01]・[02] との接続）

### 1-1. 受電時に電話応対係が聞くべきこと（[01] A-1 の DDoS 向け拡張）

| # | 質問 | 意図 |
|---|---|---|
| 1 | いつから発生しているか（時刻） | 攻撃開始時刻の特定 |
| 2 | どのサービスか（Web／メール／DNS／全部） | 攻撃対象レイヤの特定 |
| 3 | 完全にダメか、遅いだけか | 帯域飽和型 vs L7 攻撃 |
| 4 | 特定のページだけか、サイト全体か | L7 攻撃なら対象URL推定 |
| 5 | 現在も続いているか、波があるか | リアルタイム vs パルス型 |
| 6 | 他のサービス（社内ファイル共有等）は正常か | 帯域全体 vs 特定サービス |

### 1-2. 技術担当への引き継ぎに追加するDDoS固有項目

[02_技術担当引き継ぎテンプレート](./02_技術担当引き継ぎテンプレート.md) の「NW管理者向け」に以下を追記：

```
【DDoS 固有】
- 推定攻撃対象：□Web □メール □DNS □帯域全体 □不明
- 推定攻撃レイヤ：□L3/L4（帯域型） □L7（アプリ型） □不明
- 同時刻の他インシデント有無：□なし □あり（陽動の可能性）
- サービス継続方針：□全停止 □維持（対応優先） □一部停止
```

> **判断事項**：サービスを止めるか・維持するかは指揮係決定。技術担当の独断で止めない。

---

## 2. 環境判定（オンプレ or AWS）

> 大会開始直後、**自分たちの環境がどちらか** を30秒で把握する。混在の場合もある。

### 2-1. サーバがオンプレかAWSか（30秒）

```bash
# AWS EC2 なら 200 を返す（IMDSv1）
curl -s -m 2 http://169.254.169.254/latest/meta-data/ && echo "=> AWS EC2"

# AWS EC2 なら以下も取れる
curl -s -m 2 http://169.254.169.254/latest/meta-data/instance-id
curl -s -m 2 http://169.254.169.254/latest/meta-data/placement/region

# dmidecode でも判別可（root必要）
dmidecode -s system-manufacturer 2>/dev/null
# "Amazon EC2" → AWS
# "QEMU" / "VMware, Inc." → 仮想環境（多くはオンプレ）
```

### 2-2. ネットワーク機器の確認

```bash
# デフォルトゲートウェイ
ip route | grep default
route -n | grep '^0\.0\.0\.0'

# ARP テーブルでゲートウェイのMACから機器特定
arp -an | grep $(ip route | awk '/default/ {print $3}')
# YAMAHA ルーター: 00:a0:de:... (OUI)
# Cisco:         00:1a:6c:... など
```

### 2-3. 環境別の武器

| 層 | オンプレ環境 | AWS 環境 |
|---|---|---|
| 上流遮断 | YAMAHA RTX, Cisco Catalyst | AWS Shield（自動）, WAF, Network Firewall |
| サブネット境界 | VLAN + ACL | NACL（ステートレス） |
| インスタンス境界 | iptables / pf / ipfw | Security Group + iptables |
| アプリ層 | Apache/nginx の tuning | ALB/CloudFront + WAF + アプリtuning |
| 監視 | snmp, syslog, top | CloudWatch Metrics, VPC Flow Logs |

---

## 3. 攻撃分類（3分以内）

### 3-1. 分類判定フロー（簡略版）

```
① ss -s（もしくは netstat -an | grep -c）で分類
│
├─ synrecv/SYN_RECEIVED が異常数 → SYN Flood
│   └ 送信元IPが分散なら反射/偽装型
│
├─ estab/ESTABLISHED が異常数
│   ├ アクセスログに大量リクエスト → HTTP Flood（GET/POST）
│   └ ログ静かだが接続維持 → Slow HTTP系（Slowloris等）
│
├─ UDP 接続が異常数
│   ├ ポート53 集中 → DNS Flood / Amplification
│   └ ランダムポート → UDP Flood
│
└─ TCP/UDP/ICMP 混合で帯域飽和 → Stream / Volumetric
```

### 3-2. 高速ワンライナー（判定用）

```bash
# Linux 用（CentOS/Rocky/Ubuntu 共通）
echo "=== STATE ===" && ss -s
echo "=== SYN_RECV ===" && ss -ntu state syn-recv 2>/dev/null | wc -l
echo "=== ESTAB ===" && ss -ntu state established 2>/dev/null | wc -l
echo "=== TOP SRC ===" && ss -ntu 2>/dev/null | awk 'NR>1{print $6}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10
echo "=== UDP ===" && ss -nua 2>/dev/null | wc -l
echo "=== KERN ===" && dmesg | tail -10 | grep -iE 'syn|flood|drop|overflow' || echo "(no flood warn)"
```

```bash
# FreeBSD 用
echo "=== STATE ===" && netstat -an | awk '{print $6}' | sort | uniq -c | sort -rn
echo "=== TOP SRC ===" && netstat -an -f inet | awk 'NR>2{print $5}' | sed 's/\.[0-9]*$//' | sort | uniq -c | sort -rn | head -10
echo "=== SYN ===" && netstat -an | grep -c SYN_RECEIVED
echo "=== ESTAB ===" && netstat -an | grep -c ESTABLISHED
```

### 3-3. 10秒パケットキャプチャでの確定

```bash
# Linux（インターフェースは適宜変更：eth0, ens5 等）
timeout 10 tcpdump -i eth0 -nn -c 5000 2>/dev/null | awk '
  /Flags \[S\]/ && !/\[S\.\]/ {syn++}
  /Flags \[F/ {fin++}
  /Flags \[\.\]/ {ack++}
  /UDP/ {udp++}
  /ICMP/ {icmp++}
  END {printf "SYN:%d FIN:%d ACK:%d UDP:%d ICMP:%d\n", syn, fin, ack, udp, icmp}'
```

> **評価メモ**：既存 `ddos_skill.md` の判定ロジックはおおむね正しい。ただし `Flags \[S\]` は ACK+SYN の `[S.]` も拾うので、除外条件を加えると精度向上。

---

## 4. 攻撃タイプ別対応

### 4-1. SYN Flood

**症状**：`SYN_RECEIVED` が数百〜数千、正規接続がタイムアウト。
**原理**：3WHS の途中で放置、バックログ枯渇。

#### オンプレ Linux

```bash
# ① SYN cookies（最優先・副作用ほぼなし）
sysctl -w net.ipv4.tcp_syncookies=1

# ② バックログ拡大
sysctl -w net.ipv4.tcp_max_syn_backlog=4096
sysctl -w net.core.somaxconn=4096

# ③ SYN+ACK リトライ減らす
sysctl -w net.ipv4.tcp_synack_retries=2

# ④ 攻撃元IP が特定できるなら遮断（偽装だと無意味）
iptables -I INPUT 1 -s <攻撃元IP> -j DROP

# ⑤ SYN レート制限（送信元偽装型に効く最後の砦）
iptables -A INPUT -p tcp --syn -m hashlimit \
  --hashlimit-name syn --hashlimit-above 20/sec --hashlimit-mode srcip -j DROP
```

> **評価メモ**：`net.ipv4.tcp_synack_retries=1` はやや攻撃的（正規クライアントも再送1回で諦める）。`2` のほうが安全。`net.core.somaxconn` が小さいと `tcp_max_syn_backlog` だけ広げても意味がないので併記が必要。

#### FreeBSD

```bash
sysctl net.inet.tcp.syncookies=1
sysctl net.inet.tcp.syncache.hashsize=1024
sysctl net.inet.tcp.syncache.bucketlimit=100
# pf の場合
# /etc/pf.conf:
# pass in on $ext_if proto tcp to any port {80, 443} \
#   flags S/SA keep state (max-src-conn-rate 50/5, overload <bad> flush)
pfctl -f /etc/pf.conf
```

#### AWS

```
ALB / NLB を使っている場合：
　・AWS Shield Standard が L3/L4 SYN Flood を自動吸収（基本は放置で OK）
　・CloudWatch で `NewConnectionCount`, `ActiveConnectionCount` を監視

直接 EC2 に来ている場合：
　・上記 Linux コマンドで即応
　・並行して Security Group で送信元IPを拒否 or ALB を前段に挿入
　・NACL は「VPC全体に効くが誤爆で全断」するので慎重に
```

> **評価メモ**：AWS Shield Standard は無料・自動・常時オン。多くの L3/L4 Flood はここで止まる。Shield Advanced は有償でオプション。

---

### 4-2. HTTP GET/POST Flood（L7 型）

**症状**：TCP は正常確立、アクセスログに特定IPから大量リクエスト、または URL 集中。

#### オンプレ Linux（Apache）

```bash
# ① 攻撃元IP 即時遮断
iptables -I INPUT 1 -s <攻撃元IP> -j DROP

# ② 複数IP を ipset で一括管理
ipset create ddos_bl hash:ip timeout 3600 2>/dev/null
ipset add ddos_bl <攻撃元IP1>
ipset add ddos_bl <攻撃元IP2>
iptables -I INPUT 1 -m set --match-set ddos_bl src -j DROP

# ③ 同一IP同時接続数制限
iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 30 -j DROP
iptables -A INPUT -p tcp --dport 443 -m connlimit --connlimit-above 30 -j DROP

# ④ レート制限（分散攻撃向け）
iptables -A INPUT -p tcp --dport 80 -m hashlimit \
  --hashlimit-name http --hashlimit-above 50/sec --hashlimit-mode srcip \
  --hashlimit-burst 80 -j DROP

# ⑤ Apache 側の保険（高負荷時の暴走防止）
# /etc/httpd/conf/httpd.conf
#   Timeout 30
#   KeepAliveTimeout 5
#   MaxRequestWorkers 200
systemctl reload httpd
```

> **評価メモ**：既存 `ddos_skill.md` の `MaxRequestWorkers 100` は小さめ。攻撃時に正規ユーザも弾くので、実機を確認してから決める。

#### AWS（ALB + WAF）

```
推奨順：
① AWS WAF の Rate-Based Rule を即有効化
   - Limit: 1000 req / 5min / source IP（実機に応じて調整）
   - Action: Block
② AWS Managed Rules の "AWSManagedRulesCommonRuleSet" を Count→Block へ
③ 特定 User-Agent / URI パスでのカスタムルール追加
④ ALB のアクセスログから攻撃元IP抽出 → WAF IP set に追加

CLI 例：
aws wafv2 update-ip-set --name ddos_bl --scope REGIONAL \
  --id <ID> --addresses 1.2.3.4/32 5.6.7.8/32 --lock-token <TOKEN>

Security Group での遮断：
- SG は allow ルールのみ。拒否は NACL を使う
- NACL は stateless。return traffic のための ephemeral ポート開放忘れに注意
```

> **重要**：AWS 環境では **「L7 対策は WAF が主役、iptables は補助」**。iptables で個別IPを弾いても、ALB の上流には効かない（ALB→EC2 間は通る）。

---

### 4-3. Slow HTTP（Slowloris / Slow POST / Slow Read）

**症状**：少量帯域、ESTABLISHED は多いが access_log にリクエスト完了が出ない。

#### Apache 側（共通）

```apache
# /etc/httpd/conf/httpd.conf または conf.d/slow_http.conf
# ヘッダ：初期20秒、500B/sec 未満なら切断、最大40秒
RequestReadTimeout header=20-40,MinRate=500
# ボディ：最大20秒、500B/sec
RequestReadTimeout body=20,MinRate=500
Timeout 30
KeepAliveTimeout 5
```

```bash
# 反映（reload で十分、restart は接続切れる）
apachectl -t && systemctl reload httpd
```

#### 既存接続の強制切断

```bash
# 攻撃元IPからの既存接続を切る（Linux）
ss -K dst :80 src <攻撃元IP> 2>/dev/null
# 上が使えない環境
conntrack -D -s <攻撃元IP> 2>/dev/null

# connlimit 追加
iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 20 -j DROP
```

#### AWS

```
ALB には同等の機能がビルトイン（idle timeout がデフォルト 60秒）
→ Slowloris はほぼ通らない。まずは ALB 経由か確認

直接 EC2 に来ているなら Apache 設定（上記）
WAF では Slowloris 検出系の Rate-Based ルール＋接続時間閾値
```

> **評価メモ**：`mod_reqtimeout` は CentOS の httpd で標準同梱。`LoadModule` 行の確認を忘れない。

---

### 4-4. UDP Flood / DNS Amplification

**症状**：UDP 接続数異常、帯域飽和、53番ポートへのクエリ急増。

#### オンプレ（自分が DNS サーバを持っている場合）

```bash
# BIND を開放リゾルバにしない（最重要）
# /etc/named.conf
options {
    allow-query { any; };                          # 権威応答は誰にでも
    allow-recursion { 127.0.0.1; 192.168.0.0/16; }; # 再帰は内部のみ
    allow-query-cache { 127.0.0.1; 192.168.0.0/16; };
    minimal-responses yes;
    rate-limit {
        responses-per-second 10;
        window 5;
        slip 2;
    };
};
```

```bash
# iptables: 権威DNS宛は通し、自分が発する外向き DNS も通す
iptables -A INPUT -p udp --dport 53 -m hashlimit \
  --hashlimit-name dns --hashlimit-above 50/sec --hashlimit-mode srcip -j DROP

systemctl reload named
```

#### 非DNSホストで UDP 53 が来ている場合（本来いらない）

```bash
# 完全に塞ぐ
iptables -A INPUT -p udp --dport 53 -j DROP
```

#### AWS

```
Route 53 を使っているなら DNS 自体は AWS が守る（基本放置）
自前で DNS を EC2 に建てているなら BIND 設定＋Security Group で 53/udp の送信元制限
```

> **評価メモ**：既存 `ddos_skill.md` の `minimal-any yes` は BIND 9.11+ で使えるが、`minimal-responses yes` のほうが互換性が広い。両方併記が安全。

---

### 4-5. 混合型（Stream / Volumetric Flood）

**症状**：TCP/UDP/ICMP 混合、帯域飽和。

- **オンプレ**：サーバ側ではもう止められない。**ルーター／上流ISPで止める** しかない
- **AWS**：Shield Standard で基本的に吸収される。吸収しきれなければ AWS Shield Advanced or CloudFront 前段挿入
- **共通の心得**：サーバ側 iptables で粘っても帯域は救えない。**「上に持っていく」判断を早く**

---

## 5. ルーター／スイッチ（オンプレのみ）

### 5-1. YAMAHA RTX

```
# ★まず現状確認（絶対に先にやる）
show config | grep "ip pp secure filter"
show status pp 1

# 既存のフィルタ番号をメモ
# 例: ip pp secure filter in 1000 1001 1002 2000 2001

# 攻撃元IP用フィルタ追加
ip filter 3000 reject <攻撃元IP> * * * *
ip filter 3001 reject <攻撃元NW>/24 * * * *

# 既存フィルタにアペンドする形で適用（★既存番号を必ず含める）
ip pp secure filter in 3000 3001 1000 1001 1002 2000 2001

# 効果確認
show status ip filter
show log 10
```

> **評価メモ**：`ip pp secure filter in` は上書きなので、書き換え前に `show config` → 既存番号を **メモ** → 新番号を先頭に足すのが鉄則。これを怠ると全通信が落ちる。落とした場合は telnet/console から復旧。

#### ロールバック用：元に戻すコマンドを先に用意

```
# 適用前にメモ
# 元：ip pp secure filter in 1000 1001 1002 2000 2001
# 戻す時
ip pp secure filter in 1000 1001 1002 2000 2001
```

### 5-2. Cisco Catalyst

```
! 現状確認
show access-lists
show running-config interface vlan 10

! ACL 追加（名前付きにする）
ip access-list extended ANTI-DDOS
 10 deny ip host <攻撃元IP> any
 20 deny ip <攻撃元NW> 0.0.0.255 any
 30 permit ip any any
exit

! 対象 VLAN に適用
interface vlan 10
 ip access-group ANTI-DDOS in
exit

! 確認
show access-lists ANTI-DDOS
show ip interface vlan 10
```

---

## 6. AWS 対応（クラウド環境のみ）

### 6-1. 事前確認（大会開始直後）

```bash
# EC2 内から
curl -s http://169.254.169.254/latest/meta-data/security-groups      # 付与されているSG
curl -s http://169.254.169.254/latest/meta-data/iam/info             # IAMロール有無

# AWS CLI が入っていれば（権限があれば）
aws ec2 describe-instances --instance-ids $(curl -s http://169.254.169.254/latest/meta-data/instance-id)
aws elbv2 describe-load-balancers
aws wafv2 list-web-acls --scope REGIONAL
```

### 6-2. AWS での優先遮断レイヤ

```
[インターネット]
      ↓
[AWS Shield Standard] ← 自動・無料・L3/L4 Flood を吸収
      ↓
[CloudFront / Route 53] ← 前段にある場合、Edge で吸収
      ↓
[AWS WAF] ← L7 攻撃・Rate-Based Rule は最強
      ↓
[ALB / NLB] ← idle timeout・接続制限
      ↓
[NACL] ← サブネット境界、stateless、誤爆リスク大
      ↓
[Security Group] ← インスタンス境界、stateful、推奨
      ↓
[EC2 iptables] ← 最後の防衛線、OS レベル
```

### 6-3. Security Group で素早く遮断

```bash
# SG ルール追加（allow のみなので、元の許可ルールから該当IPを削除する形）
# または VPC 全体に効く NACL で deny を追加

# NACL の例（優先度番号の低いルールが先に評価される）
aws ec2 create-network-acl-entry \
  --network-acl-id <NACL-ID> \
  --rule-number 50 \
  --protocol tcp \
  --port-range From=80,To=80 \
  --cidr-block 1.2.3.4/32 \
  --rule-action deny \
  --ingress
```

### 6-4. WAF Rate-Based Rule（L7 の主役）

```bash
# IP set 作成
aws wafv2 create-ip-set --name ddos-blacklist --scope REGIONAL \
  --ip-address-version IPV4 --addresses 1.2.3.4/32

# Rate-Based Rule を Web ACL に追加（5分で1000リクエスト/IPを超えたらBlock）
# マネコンでの追加のほうが早い：WAF → Web ACL → Add Rule → Rate-based rule
```

### 6-5. CloudWatch で確認

```
主要メトリクス：
- ALB: RequestCount, TargetResponseTime, HTTPCode_Target_5XX_Count
- EC2: CPUUtilization, NetworkIn, NetworkPacketsIn
- WAF: BlockedRequests, AllowedRequests
- VPC Flow Logs: 拒否パケットの集計
```

### 6-6. AWS 環境で特に注意

- **Auto Scaling が有効だと攻撃でコストが伸びる**。上限（Max Size）を確認、なければ設定
- **NACL は stateless**：443/tcp の return 通信用に ephemeral ポート（1024-65535）を別途許可
- **IMDSv1 のままだと SSRF から credential が抜かれる**：IMDSv2 強制に
- **CloudFront 経由の場合、CloudFront→ALB の IP レンジ許可が必要**
- **コンテストで AWS アカウントが本番でない可能性**：過剰な破壊的変更は避ける

---

## 7. 事前堅牢化（ゲーム開始直後に投入）

### 7-1. Linux（最小セット）

```bash
# /etc/sysctl.d/99-antiddos.conf
cat > /etc/sysctl.d/99-antiddos.conf << 'EOF'
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.core.somaxconn = 4096
net.ipv4.tcp_synack_retries = 2
net.ipv4.conf.all.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.icmp_ratelimit = 100
fs.file-max = 100000
EOF
sysctl --system
```

```bash
# iptables 最小セット（既存ルールを壊さないよう -A で末尾追加）
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 5/s -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -j DROP
iptables -A INPUT -p tcp --dport 80 -m connlimit --connlimit-above 50 -j DROP
iptables -A INPUT -p tcp --dport 443 -m connlimit --connlimit-above 50 -j DROP
# 保存（CentOS 7）
service iptables save
# CentOS 8+/Rocky は firewalld もしくは iptables-save > /etc/sysconfig/iptables
```

> **評価メモ**：既存 `ddos.md` の `iptables -f -j DROP`（全フラグメントDROP）は、正規トラフィックにも影響する可能性。**フラグメント攻撃が来てから入れる** のが安全。

### 7-2. Apache 最小セット

```apache
# /etc/httpd/conf.d/hardening.conf
Timeout 30
KeepAliveTimeout 5
RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500
ServerTokens Prod
ServerSignature Off
TraceEnable Off
# mod_reqtimeout を使う
LoadModule reqtimeout_module modules/mod_reqtimeout.so
```

### 7-3. AWS 最小セット

```
[ ] WAF Web ACL を ALB/CloudFront にアタッチ
[ ] Rate-Based Rule（5min/1000req/IP）を有効化（最初は Count モード）
[ ] ALB の Idle timeout を 30〜60 秒に
[ ] Auto Scaling 上限を現実的な値に（無制限にしない）
[ ] IMDSv2 を require に
[ ] CloudWatch Alarm：NewConnectionCount, RequestCount
[ ] VPC Flow Logs を有効化
```

---

## 8. 完了・報告（[04] への接続）

### 8-1. DDoS 対応完了と言ってよい条件

```
[ ] 攻撃トラフィックが減衰もしくは遮断された（数値で確認）
[ ] 正規ユーザの接続が復旧した（別回線で curl 等で確認）
[ ] 投入した遮断ルールがドキュメント化されている
[ ] 同時刻の他インシデント（陽動）を調査済み
[ ] 今後の閾値調整・除外ルールのプランがある
```

### 8-2. 顧客向け完了報告テンプレ（DDoS 版）

```
【事実】
　外部からの大量アクセス（分類：〇〇）を mm/dd HH:MM に検知、
　mm/dd HH:MM までに攻撃元IP群を遮断しサービス復旧を確認しました。

【影響】
　〇〇（サービス名）の応答が約〇〇分、遅延・不通となりました。
　現時点で、情報漏えいや設定改ざんは観測されていません（根拠：〇〇ログ確認済み）。

【対応】
　・サーバ側：SYN cookies 有効化、同一IP接続数制限（30→10）
　・ルーター：攻撃元IP群 15件を遮断フィルタに追加
　・サービス維持・停止の判断：〇〇

【継続観察】
　攻撃の再発に備え、監視強化・閾値調整を実施中です。
　〇日までに詳細報告書をお届けします。
```

### 8-3. 言ってはいけないこと

- 「**今後 DDoS は来ません**」（ルーチンで再発する）
- 「**完全に防げます**」（帯域飽和型は上流次第）
- 「**攻撃者が分かりました**」（IPは偽装されうる。断定は危険）

---

## 9. 落とし穴・大会頻出ミス

| # | ミス | 対策 |
|---|---|---|
| 1 | YAMAHA RTX の `ip pp secure filter in` 上書きで全断 | 実行前に `show config` → 既存番号メモ → 末尾に追加 |
| 2 | 審査員・大学側のIPを誤ブロック | 攻撃元IP は複数ログソース（ss, access_log, iptables カウンタ）でクロスチェック |
| 3 | `sysctl -w` の設定が再起動で消えた | `/etc/sysctl.d/99-antiddos.conf` にも書いて `sysctl --system` |
| 4 | DDoSに気を取られ陽動（侵害）を見逃す | 対応中も指揮係が別ログ（認証・アクセス）を監視 |
| 5 | spoofed source IP を `-s IP -j DROP` で追いかけ続ける | ソースIP固定型でないと諦め、connlimit/hashlimit で形を変える |
| 6 | L7 攻撃に iptables だけで対抗 | Apache 設定・WAF・アプリ層の保護を併用 |
| 7 | 顧客への折り返し連絡を忘れる | 電話応対係がタイマー運用（15分毎） |
| 8 | ルール投入後の効果確認をせず「完了」宣言 | 必ず `watch -n 2 'ss -s'`・`show ip filter`・CloudWatch で確認 |
| 9 | AWS 環境で iptables だけで止めようとする | SG/NACL/WAF に必ず登る |
| 10 | ログを保全せず対応、後で報告書が書けない | `script` で端末ログ、`cp /var/log/...` で即バックアップ |

---

## 10. クイックリファレンス（印刷用）

### 10-1. 最初に打つ5コマンド（Linux）

```bash
ss -s                                                  # 全体像
ss -ntu | awk 'NR>1{print $6}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -10
dmesg | tail -5 | grep -iE "syn|flood"
ss -ntu state syn-recv 2>/dev/null | wc -l             # SYN Flood 判定
ss -ntu state established 2>/dev/null | wc -l          # HTTP/Slow 判定
```

### 10-2. 分類早見表

```
SYN_RECV 大量    → SYN Flood       → sysctl syncookies=1
ESTAB大量+ログ大 → HTTP Flood      → IP遮断 + connlimit
ESTAB大量+ログ少 → Slow HTTP       → Apache RequestReadTimeout
UDP(53)大量      → DNS Flood/Amp   → BIND allow-recursion 制限
UDP(ランダム)    → UDP Flood       → 不要UDP全DROP
混合+帯域飽和    → Stream/Volumetric → ルーター or AWS Shield
```

### 10-3. タイムライン目安（現実値）

```
0:00  受電
1:00  SSH + 3コマンドで判定
3:00  分類確定
5:00  サーバ側即時対応（iptables/sysctl/Apache）
7:00  中間報告「封じ込め開始」
10:00 ルーター/WAF 側で根本遮断
12:00 効果確認（ss -s, CloudWatch）
15:00 顧客に第一報続報
20:00 完了条件確認
25:00 完了報告 or 一次対応完了報告
```

> 既存マニュアルの「5分以内に完了」は非現実的。**15〜30分を想定** し、そのあいだ中間報告を挟むのが実戦。

---

## 11. 複数サーバ構成での攻撃識別（★重要補遺）

> 10章までは「1台のサーバで症状が見える」前提。実際は **観測点 ≠ 攻撃対象 ≠ 実被害箇所** のことがある。

### 11-1. 3つを分けて考える

| 用語 | 意味 | 例 |
|---|---|---|
| **観測点** | 症状（遅い・落ちる・ログ急増）が最初に見えたサーバ | 「ユーザが繋がらない」と言われた Web サーバ |
| **攻撃対象** | 実際に攻撃パケットが到着しているサーバ | 前段の Web サーバ |
| **実被害箇所** | リソース枯渇している本当のボトルネック | 後段の DB サーバ |

この3つが一致するとは限らない。**遮断は「攻撃対象」の直前で、緩和は「実被害箇所」で** 考えるのが基本。

### 11-2. 典型構成と攻撃の通り道

**パターンA: 3層 Web**
```
[外] → [nginx/ALB] → [Apache+PHP] → [MySQL]
         Srv A          Srv B          Srv C
```

**パターンB: 権威DNS + Web**
```
[外] → [BIND]  Srv A
     → [Web]   Srv B
```

**パターンC: Mail + Web + DNS の共存**
```
[外] → [FW/RT] → [DMZ: Web, Mail, DNS （別ホスト or 同一）]
```

### 11-3. ケーススタディ（大会で特に引っかかりやすいやつ）

#### ケース1：Slowloris を Srv A (nginx) に送られた

- Srv A：ESTABLISHED 急増だが非同期処理なので比較的耐える
- Srv B：**基本的に影響なし**（nginx がヘッダ完成まで proxy しない設定の場合）
- ただし `proxy_request_buffering off` が入っていると B も巻き込まれる
- 判断：**観測点=A、攻撃対象=A、被害=A**。A のタイムアウト設定で対処。

#### ケース2：HTTP POST Flood を Srv A の /search に送られた

- Srv A：リクエスト数は多いが、1本1本は「受け取って B に投げる」だけで軽い
- Srv B (PHP-FPM)：プロセス全部 DB 応答待ちで詰まる
- Srv C (DB)：active session が上限到達、他の正規クエリも落ちる
- 観測： **最初に落ちるのは B か C**、でも A の CPU は通常。
- 判断：**観測点=C、攻撃対象=A、被害=C**。
- **B や C で connlimit かけても正規クエリを止めるだけ**。A の `/search` を WAF や mod_security で絞る or Apache の `LimitRequestBody`・`mod_qos` で抑えるのが正解。

#### ケース3：BIND (Srv A) が DNS Amp の踏み台にされている

- Srv A：UDP 53 への外向き送信が急増（通常の数十倍）
- 顧客：社内DNSが遅い（正規クエリが弾かれる）
- 被害者：見知らぬ第三者（反射先）
- 判断：**自社は「加害者」側**。対応姿勢が全く違う。
- → `allow-recursion` を即座に内部レンジのみに制限、`minimal-responses yes`、RRL 追加。

#### ケース4：SMTP サーバ (Srv D) への接続 Flood

- Srv D：SMTP 25/587 への大量接続、正規メールが詰まる
- Srv A (Web)：無影響
- 判断：対応は SMTP 専用（postfix の `smtpd_client_connection_count_limit` など）。
- Web 対応のノリで動くと違う場所を見ることになる。

#### ケース5：Srv A と Srv B が **ロードバランサの背後に両方いる**

- 攻撃が一方に偏る or 両方に振られる（LB のアルゴリズム次第）
- Srv A で connlimit かけると LB が healthy判定で外し、全トラフィックが B へ集中 → B が落ちる
- 判断：LB より下で個別対応すると **障害が玉突き** する。LB 前段で対処するのが原則。

### 11-4. 構成を知るためのコマンド（大会開始直後に必ず実行）

```bash
# 自ホストの役割
hostname; cat /etc/hosts; uname -a

# Listen しているポート = このサーバが提供するサービス
ss -tlnp 2>/dev/null || sockstat -4 -l

# 外向きに張っている接続 = このサーバが依存している他サーバ
ss -ntp 2>/dev/null | grep -vE '127\.|::1' | head -20

# リバースプロキシ・バックエンド設定
grep -RhE "proxy_pass|upstream|ProxyPass" /etc/nginx/ /etc/httpd/ 2>/dev/null | head
grep -RhE "DB_HOST|DATABASE_URL|mysql\.host" /var/www/ 2>/dev/null | head

# 同セグメントの他サーバ（ARP で見える範囲）
ip neigh show; arp -an
```

> **大会開始時の約束ごと**：これらを実行して **構成図を自作しホワイトボードに書く**。配られた資料の構成図は参考にとどめ、実機から取った情報を信じる。

### 11-5. クロスサーバのログ相関

複数サーバにまたがる攻撃は、**同じ時刻帯のログを並べて見る** のが基本。

```bash
# A のアクセスログで /search への急増時刻を特定
awk -v t='20/Apr/2026:10:3' '$4 ~ t && $7 ~ /\/search/' /var/log/httpd/access_log | wc -l

# B (PHP-FPM) の slow log で同時刻帯の遅延
grep '2026-04-20 10:3' /var/log/php-fpm/slow.log

# C (MySQL) の process list と slow query
mysql -e 'SHOW FULL PROCESSLIST' | wc -l
tail /var/log/mysql/slow.log
```

ホワイトボードに時系列で並べる：

```
10:30  A: access_log /search 急増（100→5000/min）
10:31  B: php-fpm active 20→90
10:31  C: mysql processlist 30→400、slow query 急増
10:32  A の /search を WAF/Apache で絞る
10:35  B, C 回復 ← 攻撃対象（A）の絞り込みが正解だった
```

---

## 12. DDoS 受信時の完全対応フロー（構成考慮版）

> 既存マニュアルの「5分完結フロー」は単一サーバ前提。**複数サーバ構成では2フェーズ追加** が必要。

### 12-1. 拡張フェーズ定義

```
[Phase 0]  受電・一次観察          0〜3分
　└ 症状の「観測点」の把握だけ。対処はまだしない
[Phase 1]  構成の再確認            3〜6分
　└ 11-4 のコマンドで依存関係を確認
[Phase 2]  攻撃対象の推定          6〜10分
　└ パケットが直接届いているのはどのサーバか
[Phase 3]  実被害箇所の特定        10〜15分
　└ リソースが一番先にしぬのはどこか
[Phase 4]  遮断ポイント決定        15〜18分
　└ 「攻撃対象の直前」が基本、でも制約次第で変わる
[Phase 5]  遮断実行                18〜22分
　└ ロールバック手順を先に用意してから実施
[Phase 6]  効果検証（観測点・被害箇所両方）22〜28分
[Phase 7]  中間／完了報告          28〜35分
```

### 12-2. 遮断ポイント決定マトリクス

| 攻撃タイプ | 推奨遮断ポイント | なぜ |
|---|---|---|
| SYN Flood（固定IP） | ルーター／WAF | 上流ほど負荷軽減 |
| SYN Flood（偽装IP） | サーバ SYN cookies | IP 単位遮断は無意味 |
| HTTP GET Flood | WAF / フロント Web | パスで絞れる |
| Slow HTTP | フロント Web の timeout | OS・上流では識別困難 |
| HTTP Flood が DB を詰まらせる | **フロント Web の該当URL** | DB 側では正規も止まる |
| UDP Flood | ルーター | サーバ側では帯域既に詰まっている |
| DNS Amp（踏み台） | DNS の `allow-recursion` | 根元を塞ぐ |
| 混合・帯域飽和 | 上流ISP／CDN | サーバ側では無理 |
| 複数サーバ同時 | LB 前段 or ルーター | 個別対応は玉突き |

### 12-3. 対応中のダッシュボード（ホワイトボード推奨）

対応中は次の表をリアルタイム更新。**観測点・被害箇所の両方** が回復していることを確認する。

```
         観測点(A)     攻撃対象(A)   被害箇所(C)    判定
10:30    ESTAB 342     ESTAB 342     queries 450    攻撃進行中
10:35    ESTAB 180 ↓   ESTAB 180 ↓   queries 80 ↓   A で絞り効いた
10:40    ESTAB  45 ↓   ESTAB  45 ↓   queries 20 ↓   正常化
```

どれかが回復しないなら、**遮断ポイントが間違っている** 可能性が高い。

---

## 13. 本対応方法の限界（正直な評価）

> 「この対応で本当に大丈夫か？」への答え：**完全には大丈夫ではない**。限界を認識したうえで使う。

### 13-1. 送信元IP偽装には IP 単位遮断が効かない
SYN Flood / UDP Flood ではソースIP偽装が常套。`iptables -s IP -j DROP` は何度打っても毎回違うIP。対策はシグネチャ・レート制限、最終的には上流での吸収。**偽装か固定か** の見極めが最初に必要。

### 13-2. 分散攻撃には IP リスト運用が追いつかない
数千IPからの分散は手動で追えない。`ipset` / `hashlimit` / WAF Rate-Based Rule に切り替える判断を早く。

### 13-3. 帯域飽和型は自サーバでは止められない
回線帯域（例100Mbps）を超える攻撃が来たら、サーバで何をしてもパケットは捌けない。上流（ルーター、ISP、CDN）の仕事。**「ここから先はサーバ側では無理」の判断** も対応能力のひとつ。

### 13-4. 陽動の可能性を常に持つ
DDoS で注意を引きつけ、裏で不正アクセスが進む。対応中も指揮係は **別ログ（認証・アクセス・ファイル変更）** の監視を継続。チーム全員が DDoS に集中したら負け。

### 13-5. 正常アクセスとの区別は本質的に難しい
「キャンペーン直後」「ニュース掲載直後」と HTTP Flood は数値上区別しづらい。過剰な遮断で正規ユーザを弾く。**段階的な閾値（最初は Count、効果見て Block）** が安全。

### 13-6. L7 攻撃は最終的にアプリロジック次第
OS 層でどれだけ守っても、アプリが `/search` で全件検索していたら DoS は成立する。アプリ層の `rate_limit`・CAPTCHA・キャッシュまで踏み込まないと根本解決しない。

### 13-7. AWS では自分の IAM 権限が絶対的制約
SG / NACL / WAF の変更権限がなければ打つ手が減る。対応前に `aws sts get-caller-identity` と `aws iam list-attached-user-policies` で自分の権限を確認。

### 13-8. 「止まった」と「防げた」は違う
攻撃側が諦めただけかもしれない。遮断ルールを外すと再発するかは確認できない（大会中にルール外す余裕はない）。完了報告では「**現時点で沈静化を確認**」と言い、「**今後も防げます**」は絶対に言わない。

### 13-9. 構成図は信じすぎない
資料の構成図と実機が違うことは珍しくない（隠しサーバ、設定変更済み、inject での変更）。**実機から取った情報を優先**。

---

## 14. 大会で起きる可能性ランキング

> 情報危機管理コンテストの過去傾向と問題設計の常識からの推定。断定ではなく **準備の重点配分** の指針。

### 14-1. DDoS サブタイプ別

| ランク | サブタイプ | 根拠 |
|---|---|---|
| **S**（ほぼ確実） | HTTP GET Flood（L7） | 仕掛けが簡単・診断の定番・改ざん系と絡められる |
| **S**（ほぼ確実） | Slow HTTP（Slowloris） | 検知が難しく教育効果が高い古典 |
| **A**（頻出） | SYN Flood（固定／少数IP） | 切り分け問題の定番 |
| **A**（頻出） | Connection Exhaustion | Slowloris と並ぶ古典 |
| **A**（頻出） | HTTP POST Flood | フォーム送信・重API と絡められる |
| **B**（十分あり） | DNS Amplification（踏み台化） | BIND 設定の基礎を問える |
| **B**（十分あり） | UDP Flood（ランダムポート） | iptables 基礎問題 |
| **B**（十分あり） | SYN Flood（大規模偽装） | OS 対策の理解を問う |
| **C**（レア） | FIN/ACK Flood / Fragment | 単独では出にくい |
| **C**（レア） | 純粋な Volumetric Flood | 実機では帯域生成が難しい |

### 14-2. シナリオ構造（DDoSとの組み合わせ）

| ランク | シナリオ | 根拠 |
|---|---|---|
| **S** | **DDoS を陽動にした別侵害** | 教育目的に合致、チームの集中力分散を試す定番 |
| **S** | **顧客経営層からの強いクレーム電話** | 大会で必ず来る |
| **S** | **複数サーバ構成で観測点と攻撃対象が違う** | Web→DB の詰まりは頻出 |
| **A** | 複数サーバに同時攻撃（Web + DNS + Mail） | 優先度判断を試す |
| **A** | 構成把握が不完全な状態で攻撃開始 | 事前準備の価値を試す |
| **A** | 踏み台化（自社が加害者側） | DNS Amp でよく出る |
| **B** | 途中で inject（新症状追加） | 運用能力を見る |
| **B** | 攻撃元に審査員レンジが紛れ込む | 誤遮断リスクのテスト |
| **C** | 偽物攻撃・誤検知（「対応しない」判断） | 出ることもある |

### 14-3. 問われる運用能力

| ランク | 能力 | 典型的な試され方 |
|---|---|---|
| **S** | **観測点・攻撃対象・被害箇所の分離** | ほぼ確実 |
| **S** | **顧客への中間報告タイミング** | 減点定番 |
| **S** | **攻撃元IPのクロスチェック（誤遮断回避）** | 罠として出やすい |
| **A** | 複数サーバの優先度判断 | 複合構成で出る |
| **A** | ロールバック手順の事前準備 | 構成変更ミス対策 |
| **A** | ログ保全（対応前のコピー） | 報告書作成に必要 |
| **B** | 踏み台化されている自覚 | DNS Amp 系 |
| **B** | 陽動検知 | 上位で差がつく |
| **C** | ISP連携（本大会スコープ外の可能性大） | 実施形式次第 |

### 14-4. 準備時間の推奨配分

- **70%**：S ランク（HTTP GET Flood / Slow HTTP / 陽動 / 顧客対応 / 観測点・攻撃対象分離）
- **20%**：A ランク（SYN Flood / 複数サーバ / AWS 対応 / ロールバック）
- **10%**：B ランク（DNS Amp 踏み台 / 途中 inject / 誤遮断回避）
- **0%**：C ランク（当日出たら現場判断で）

### 14-5. 準備ドリル（推奨）

時間があれば以下を手を動かして練習：

- [ ] Slow HTTP を自分たちのサーバに打って `server-status` で Reading が増えるのを見る
- [ ] HTTP Flood を /重いページ に打って、観測点（Web）と被害箇所（DB）を両方モニタする
- [ ] `ip pp secure filter in` を実環境で1度やり、既存番号消し事故→復旧の練習
- [ ] AWS なら WAF Rate-Based Rule を Count→Block 切替える練習
- [ ] 4人で受電（電話応対）→ 構成把握→ 遮断→ 報告のロールプレイを通しで1本

---

## 付録：既存 `ddos.md` / `ddos_skill.md` 評価サマリ

| 項目 | 評価 | 備考 |
|---|---|---|
| 全体構成（検知→分類→対応） | ◎ | そのまま使える |
| 攻撃タイプ網羅性 | ◎ | 10種は十分 |
| Linux コマンド正確性 | ○ | おおむね正しいが `net.core.somaxconn` 抜け等あり |
| FreeBSD コマンド正確性 | ○ | `pf`/`ipfw` の混在に注意、環境確認必須 |
| YAMAHA RTX 記述 | △ | `ip pp secure filter in` 上書きの運用が弱い。ロールバック手順必須 |
| Cisco 記述 | ○ | ACL は正しい。名前付きACL推奨を追記 |
| AWS 対応 | ✗ | 記述なし → 本資料で補完 |
| 受電・電話対応との接続 | △ | 電話文面はあるが [01][02][04] との連動なし |
| タイムライン現実性 | △ | 「5分で完了」は過剰。15〜30分が現実 |
| 陽動・複合シナリオ | △ | 言及少。本資料 0-3 と 9-4 で補完 |
| ログ保全 | △ | 触れているが弱い。対応前の `cp` と `script` を強調すべき |
| ロールバック手順 | ✗ | 投入失敗時の復旧手順が欠如 → 本資料 5-1 で追加 |

### 既存ファイルで「そのまま使える部分」

- 攻撃タイプ別の**概要説明**（4.1〜4.10 の冒頭）
- Linux の**検知コマンド**（`ss`, `dmesg`, `tcpdump`）
- Apache の **`RequestReadTimeout`, `Timeout`, `KeepAliveTimeout`** 設定
- BIND の **`allow-recursion`, `rate-limit`** 設定
- iptables の **`connlimit`, `hashlimit`** の考え方

### 既存ファイルで「書き換え推奨の部分」

- 「2分で判定」「5分で完了」→ **現実的なタイムライン**に
- 「電話応対テンプレート」→ [01_受電ヒアリングシート] に吸収済みなので削除
- 「JPCERT/CC 報告・警察連絡」→ **本大会スコープ外** なので削除
- YAMAHA RTX の運用→ **ロールバックコマンドの併記** 必須
- 「全フラグメントDROP」の事前投入→ **発生後投入** に変更

---

> このファイルは [03_シナリオ別対応プレイブック.md](./03_シナリオ別対応プレイブック.md) の DDoS セクションと併用してください。
> オンプレ／AWS の判別が終わり次第、**該当環境の章だけ** を参照すれば大会時間内に回せるように設計しています。
