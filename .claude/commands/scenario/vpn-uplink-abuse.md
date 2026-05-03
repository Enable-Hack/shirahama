---
description: シナリオ③ VPN 経路 → 上流信頼を悪用した横断攻撃のキルチェーン全体を確認
---

# /scenario:vpn-uplink-abuse — キルチェーン③: VPN 経路 → 上流信頼悪用横断

引数: `<時間窓> <ホスト>`
例: `/scenario:vpn-uplink-abuse 13:00-13:30 victor`

## 0. 想定キルチェーン (16_:1.3-③ 由来)

```
ステージ1: VPN 接続 (10.1.11.50-99 配布) または上流 (10.1.129.0/24 既侵害)
  └ 既知侵害 IP (10.1.129.10) からの再アクセス
       ↓
ステージ2: 配布アカウントでの侵入
  └ telnet 23 / ssh 22 / IMAP 143 で manage / obuchi / admin 試行
       ↓
ステージ3: 弱い前提条件の悪用
  └ /home/obuchi 777 で authorized_keys 改竄、または
    Dovecot passdb=pam でシステム全員 IMAP login
       ↓
ステージ4: 権限昇格
  └ pkexec PwnKit / toor:0 / sudo 不正利用
       ↓
ステージ5: 横展開と永続化
  └ at ジョブ仕込み / cron 改竄 / 別マシンへ pivot
```

## 1. 起動条件

- analyzer 出力に **`auth/ssh-bruteforce`** または **`auth/ssh-failed`** が多発
- analyzer 出力に **`protocol/telnet-access`** 発火
- 受電内容に「manage / obuchi が変な時間にログインしている」「VPN 接続元から不審な動き」
- 10.1.129.0/24 由来のトラフィック観測

## 2. 各ステージで叩く /check 一覧

### ステージ1: VPN / 上流経路
- **必ず並行起動 (これが本シナリオの核)**:
  - `/check:check-known-attacker-ip` (10.1.129.10 既侵害)
  - `/check:check-syslog-udp-injection` (誤誘導工作の有無)

### ステージ2: 配布アカウント侵入
- **並行起動**:
  - `/check:check-telnet-plain-auth`
  - `/check:check-courier-imap-plain`
  - `/check:check-dovecot-passdb-pam`

### ステージ3: 弱い前提条件の悪用
- **並行起動**:
  - `/check:check-obuchi-777-hijack`
  - `/check:check-aliases-root-forward` (apache 詐称メール経由の連鎖)
  - `/check:check-userdir-listing` (public_html 経由の足場)

### ステージ4: 権限昇格
- **並行起動**:
  - `/check:check-pkexec-pwnkit`
  - `/check:check-toor-uid0`

### ステージ5: 横展開と永続化
- **並行起動**:
  - `/check:check-at-job-persist`
  - `/check:check-nkf-rpm-residue` (RPM 経由 injection)

## 3. ステージ間の連鎖判定

| 連鎖判定 | 解釈 |
|---|---|
| ステージ1 確定 + ステージ2 ⚠️ | 既侵害 IP は活動中だが新規侵入はまだ |
| ステージ1 確定 + ステージ2 確定 | 配布アカウント乗っ取り成立 |
| ステージ3 確定 + ステージ4 確定 | root 取られた前提 |
| ステージ4 確定 + ステージ5 確定 | 永続化成立、攻撃者が居座っている |

## 4. 確定後のアクション

### 並行起動する playbook
- **`/playbook:ransomware`** (root 化後の永続化全工程)
- **`/playbook:phishing`** (アカウント詐称メールが組み合わさる場合)

### リーダー報告のシナリオストーリー
> "**10.1.129.10 (既侵害)** から **manage / obuchi で SSH 再ログイン** → **/home/obuchi 777 で authorized_keys 改竄済** → **pkexec PwnKit で root 化** → **at ジョブ仕込み + 別マシンへ pivot**。
> 即時対応: 1) 10.1.129.10 を iptables drop 2) 全配布アカウントのパスワード即時リセット 3) authorized_keys 全棚卸し 4) at ジョブ全削除 5) bravo / victor 両方の forensic 保管 → 必要なら停止判断"

### 即時封じ手は個別 check の §4 を参照

## 5. 参照

- 関連 playbook: [playbook/ransomware.md](../playbook/ransomware.md)、[playbook/phishing.md](../playbook/phishing.md)
- 既存ドキュメント: 16_:1.3-③ / 16_:#40 / `incident.md` §0.5
- 関連シナリオ:
  - [scenario/killchain-recon-rce-dbexfil.md](killchain-recon-rce-dbexfil.md) (Web 系の足場が併存する場合)
  - [scenario/dns-spoof-phish.md](dns-spoof-phish.md) (フィッシング窃取クレデンシャルでの再侵入)
