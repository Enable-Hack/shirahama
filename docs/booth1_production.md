# Booth1 (com1.local / whiskey) 本番環境 — 全 skill が常時参照する正典

このファイルは大会本番 (Whiskey 配布資料) の全情報をまとめた正典です。
`/preflight` `/incident` `/review` `/report` `/call_close` `/ticket` の各 skill は
判断・コマンド生成・文書化の前に必ず本ファイルを Read して、本番環境の前提を踏まえてください。

**最終更新**: 2026-05-05 — 配布 PDF (`docs/参加者配布資料_whiskey.pdf`) からの抽出

---

## 0. KILL SWITCH — 本番接続条件

- **大会開始の合図前は本番に絶対接続しない**。受電前の ssh / VPN 接続痕跡は審査減点
- 接続合図 = 受電開始 (電話が鳴った瞬間) 以降のみ
- 事前は OCI デモ環境 (`ssh victor` / `ssh bravo` のエイリアス) で動作確認

---

## 1. ネットワーク構成 (Booth1 / com1.local)

### セグメント
| VLAN | セグメント | 用途 |
|---|---|---|
| `v601` | `10.1.31.0/24` | 上流 (ISP 側、ASA Bridge mode 上の transit) |
| `v701` | `10.1.21.0/24` + `10.1.1.0/24` | サーバ群 (RTX1200 経由) |
| `v801` | `10.1.11.0/24` | 本社 + 支社 + 参加者 VPN (DHCP 配布 .50-99) |

### 主要機器
- ASA (Bridge Mode): 10.1.31.254/.251 — Cat3560 から telnet で接続
- RTX1210 (Router): 10.1.31.253 / 10.1.21.254 / 10.1.11.254
- RTX1200 (Router): 10.1.21.253 / 10.1.1.254
- Cat3560 (L2): 10.1.11.253
- NP2000-24T4X-1 (L2): 10.1.11.252
- 参加者 VPN 入口: 10.1.11.100 (RTX1210、**運営機器・触禁**)

---

## 2. サーバ (Booth Rack、VMware ESXi 6.7 / 10.1.1.201)

### bravo (DNS / Mail / WP user hosting)
- **IP**: 10.1.1.1 (GW: 10.1.1.254)
- **OS**: **FreeBSD** (本番は FreeBSD、デモは Rocky)
- **サービス**: apache, php, perl, mysql, sendmail, procmail, courier-imap, **bind**
- **特殊**: ユーザ別ホスティング 100 人 (`http://<user>.com1.local/`)

### victor (Web / Mail / DHCP)
- **IP**: 10.1.1.2 (GW: 10.1.1.254)
- **OS**: **Rocky Linux**
- **サービス**: apache, php, perl, mysql, sendmail, procmail, courier-imap, pop, **dhcpd**, mrtg, **syslog**
- **特殊**: WordPress (`http://www.com1.local/wp-admin/`) + RainLoop (`/rain`) + Members chat board + Company Page

### ESXi (hypervisor)
- 10.1.1.201/24 — bravo / victor をホスト

---

## 3. 認証情報 (PDF p.5、変更不可、攻撃側は使えない)

| 対象 | アカウント | パスワード |
|---|---|---|
| VPN (133.42.49.151) | booth1[1-5] | `sccs2026-DmJYjc` (事前共有キーも同) |
| Cat3560 / ASA vty | — | `sh1Ra8mA` |
| Cat3560 / ASA enable | — | `KCom10sT` |
| RTX1210 / RTX1200 manage | manage | `sh1Ra8mA` |
| RTX1210 / RTX1200 admin | admin | `KCom10sT` |
| NP2000-24T4X-1 manage | manage | `sh1Ra8mA` |
| NP2000-24T4X-1 enable | — | `KCom10sT` |
| **★ victor / bravo manage** | **manage** | **`sh1Ra8mA`** |
| victor / bravo root | root | `KCom10sT` |
| Mysql | mysql | `yoursql` |

**重要 (PDF 明記)**: ① これら認証情報は **変更しない** / ② これらアカウントを使用した **攻撃は無い** (= 攻撃の認証ログにこれらが出たら誤認 or 内部不正)

---

## 4. サービス URL

| サービス | URL | 認証 | 用途 |
|---|---|---|---|
| Company Page | `http://www.com1.local/` | — | victor 公開 |
| WordPress | `http://www.com1.local/wp-admin/` | admin / `Cm0re` | 改ざん攻撃の標的候補 |
| RainLoop メール | `http://www.com1.local/rain` | manage@com1.local / `sh1Ra8mA` | フィッシング攻撃の標的候補 |
| User Page | `http://<user>.com1.local/` | login at `http://com1.local/` | bravo 上、100 ユーザ |
| **PukiWiki** | `http://133.42.49.140/trouble_ticket_137/index.php` | whiskey / `E5mA9cF3` | **/ticket 投稿先** |

---

## 5. CIC DNS 関係 (DNS 改ざん攻撃の前提)

```
CIC DNS (10.1.130.1, cic.local, 触禁、Recursion off)
  ↕ forward + slave 双方向
com1 DNS (bravo 10.1.1.1) — Domain: com1.local
com2-6 DNS — 他 booth (com2.local〜com6.local)
```

- CIC DNS は recursion off + reverse 設定無し
- bravo の named (10.1.1.1) を触ることは可、CIC DNS (10.1.130.1) は **絶対触らない**
- DNS 改ざん攻撃は bravo の named.conf / zone ファイルが標的

---

## 6. ログ収集ポイント

| ログ種 | victor (Rocky) | bravo (FreeBSD) |
|---|---|---|
| httpd access | `/var/log/httpd/access_log` | `/var/log/httpd-access.log` |
| httpd error | `/var/log/httpd/error_log` | `/var/log/httpd-error.log` |
| 認証 | `/var/log/secure` | `/var/log/auth.log` |
| メール | `/var/log/maillog` | `/var/log/maillog` |
| named | (該当なし、bravo のみ) | `/var/log/named.log` or `/var/log/named/named.log` |
| DHCP | `/var/log/messages` | (該当なし、victor のみ) |
| syslog 集約 | `/var/log/rsyslog/` | `/var/log/messages` |

→ `/incident` §1 の `tail_first_existing` が複数候補パスを試すので OS 違いを自動吸収。

---

## 7. 触禁機器 (絶対に ssh / コマンド送らない)

- **133.42.49.151** (VPN 入口、運営機器)
- **10.1.130.1** (CIC DNS、運営機器)
- **上流 ISP Router** (管理対象外、ASA より外)
- **他 booth** (`com2.local`〜`com6.local`、`10.1.2.0/24`〜`10.1.6.0/24`)

---

## 8. OS 差分の重要ポイント

bravo は **FreeBSD**:
- `service apache24 onestatus` (systemctl ではない)
- `sockstat -l4` (ss ではない)
- `/usr/local/etc/apache24/` (httpd の設定パス)
- `/usr/local/etc/namedb/named.conf` (BIND 設定)
- `pf` (firewall、iptables/nft ではない)

victor は **Rocky Linux**:
- `systemctl status httpd`
- `ss -tlnp`
- `/etc/httpd/conf.d/`
- `/etc/named.conf`
- `iptables` or `nft` or `firewalld` (確認要)

→ `/review §2.5` は **コマンド提案前に `which` で在庫確認必須**。OCI Rocky は firewall 系全部未インストールだったが、本番 Rocky は不明。

---

## 9. DHCP 配布範囲の意味

- victor の `dhcpd` が `10.1.11.0/24` セグメントを管理
- 配布 IP: `10.1.11.50〜99`
- 参加者 VPN 経由のクライアントもここに入る = **攻撃側の IP がこのレンジに入りうる**
- 攻撃元 IP が `10.1.11.50〜99` なら参加者 VPN 経由 (= 他チーム or 攻撃 VM)

---

## 10. 既侵害前提 / 4/24 痕跡 (確認要)

- 過去テスト環境では `10.1.129.0/24` 由来の 4/24 既ログイン痕跡があった
- 本番でこれが再現されているかは **未確認**
- preflight の `last -i` で確認、incident.md §0.5 の前提ロジックを適用するかどうかは現場判断

---

## 11. Skill 利用時の注意点

各 skill が本ファイルを Read するときに踏まえること:

- **/preflight**: 両機並行で baseline 取得。bravo は FreeBSD コマンド (sockstat / service onestatus) も試す。victor の dhcpd / syslog 集約も確認
- **/incident**: ログ取得は両機並行、OS 差分は `tail_first_existing` で吸収
- **/review §2.5 補強調査**: コマンド提案前に必ず `which iptables nft firewall-cmd pf` で在庫確認
- **/review [B] 確認質問**: VPN booth1[1-5] のうちどのアカウントから来てるか / 受電ユーザの所属が本社か支社か (10.1.11.0/24 内の位置)
- **/review [C] コマンド**: 認証情報変更系 (passwd, usermod) は基本不要 (PDF 明記の認証は変更不可)。設定ファイル操作 + サービス reload が基本パス
- **/report**: 顧客向けに「com1.local」「booth1」の用語を使う。社内向け (PukiWiki) では機器名 (bravo/victor/RTX1210 等) を使う
- **/call_close**: 顧客名が「manage@com1.local」のような形式の場合あり、敬称 (様/さん) は文脈判断
- **/ticket**: PukiWiki (133.42.49.140/trouble_ticket_137/) に投稿、認証 whiskey/E5mA9cF3 (人間が手で投稿)

---

## 12. 参考: PDF 配布資料

`docs/参加者配布資料_whiskey.pdf` (10 ページ、3.9MB) — 本ファイルの一次ソース。
不明点があればここに戻って確認。
