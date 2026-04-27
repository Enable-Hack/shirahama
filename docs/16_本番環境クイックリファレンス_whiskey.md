# 16. 本番環境クイックリファレンス (Booth 1 / whiskey)

> **SCCS2026 予選 / Booth-1 / Team whiskey / Domain: com1.local**
> **このドキュメントは A4 印刷して机に置く想定**
> **最終更新**: 2026-04-24（運営配布資料 `参加者配布資料_whiskey.pdf` 反映）

---

## 🚨 0. 最優先確認事項（机に貼る）

```
❌ 配布パスワードは絶対に変更しない（ルール）
❌ 管理対象外の機器は触らない（CIC DNS 10.1.130.1 / インターネット側ルーター / 参加者用VPN）
❌ ログは消さない・改竄しない
✅ 配布アカウント (manage / root / admin / vty / enable) を使った攻撃は来ない
✅ 攻撃は別アカウントで来る → 不審なユーザー作成・SSH ログを最重要監視
✅ 迷ったら何もしない
```

---

## 🔑 1. 全パスワード一覧（紛失厳禁）

### 1.1 ネットワーク機器

| 機器 | 用途 | ユーザ/レベル | パスワード |
|---|---|---|---|
| Cat3560 | スイッチ | vty | `sh1Ra8mA` |
| Cat3560 | スイッチ | enable | `KCom10sT` |
| ASA | FW (Bridge Mode) | vty | `sh1Ra8mA` |
| ASA | FW (Bridge Mode) | enable | `KCom10sT` |
| RTX1210 | ルーター | manage | `sh1Ra8mA` |
| RTX1210 | ルーター | admin | `KCom10sT` |
| RTX1200 | ルーター | manage | `sh1Ra8mA` |
| RTX1200 | ルーター | admin | `KCom10sT` |
| NP2000-24T4X-1 | L2SW | manage | `sh1Ra8mA` |
| NP2000-24T4X-1 | L2SW | enable | `KCom10sT` |

⚠️ **ASA は Cat3560 から telnet 経由で接続する**（直接 SSH 不可）

### 1.2 サーバー

| サーバー | OS | ユーザ | パスワード |
|---|---|---|---|
| Bravo | FreeBSD | manage | `sh1Ra8mA` |
| Bravo | FreeBSD | root | `KCom10sT` |
| Victor | Rocky Linux | manage | `sh1Ra8mA` |
| Victor | Rocky Linux | root | `KCom10sT` |

### 1.3 アプリケーション

| アプリ | URL | ユーザー | パスワード |
|---|---|---|---|
| WordPress | `http://www.com1.local/wp-admin/` | `admin` | `Cm0re` |
| RainLoop | `http://www.com1.local/rain` | `manage@com1.local` | `sh1Ra8mA` |
| MySQL | (Bravo/Victor 上) | `mysql` | `yoursql` |
| PukiWiki (報告) | `http://133.42.49.140/trouble_ticket_137/index.php` | `whiskey` | `E5mA9cF3` |

### 1.4 VPN（参加用）

```
アドレス      : 133.42.49.151
事前共有キー  : sccs2026-DmJYjc
ユーザ名      : booth11 / booth12 / booth13 / booth14 / booth15
パスワード    : sccs2026-DmJYjc
プロトコル    : L2TP/IPsec (推定 — デモ環境と同じ構成)
```

→ チーム 5 人で `booth11`〜`booth15` を 1 人 1 ID 使う想定

---

## 🌐 2. ネットワーク構成

### 2.1 論理構成図（運営配布資料より）

```
                     Internet
                         │
                  [管理対象外ルーター]
                         │
                  10.1.31.0/24 (v601)
                         │
                  ┌──────┴──────┐
                  │ ASA (.251)  │ ← Bridge Mode
                  │ Cat3560経由 │
                  │ telnet で管理 │
                  └──────┬──────┘
                  10.1.31.0/24 (v601)
                         │ .253
                  ┌──────┴──────┐
                  │   RTX1210   │
                  │  .254/.254  │
                  └──┬───────┬──┘
                     │       │
       10.1.21.0/24  │       │  10.1.11.0/24 (v801)
        (v701) .253  │       │ ← ユーザ/DHCP/AP帯
                     │       │
              ┌──────┴──┐    │
              │ RTX1200 │    │
              │  .254   │    │
              └────┬────┘    │
                   │ 10.1.1.0/24 ← サーバー帯
                   │
           ┌───────┴────────┐
           │                │
       Bravo .1         Victor .2
       (FreeBSD)        (Rocky Linux)
       DNS/Mail/        Web/Mail/
       sb_blog 等       DHCP/MRTG 等

       仮想化基盤: VMware ESXi 6.7 (10.1.1.201/24)
```

### 2.2 IP / セグメント早見表

| 名前 | サブネット | VLAN | 主な機器 |
|---|---|---|---|
| 上流帯 | 10.1.31.0/24 | v601 | ASA, RTX1210 |
| 中継帯 | 10.1.21.0/24 | v701 | RTX1210 ↔ RTX1200 |
| **サーバー帯** | **10.1.1.0/24** | (v701内?) | **bravo (.1) / victor (.2)** / ESXi (.201) / GW (.254) |
| ユーザ帯 | 10.1.11.0/24 | v801 | Cat3560 (.253), 参加者VPN(.100), NP2000(.252), DHCP配布50-99 |
| CIC DNS | 10.1.130.0/24 | (外部) | **10.1.130.1 = CIC DNS（管理対象外）** |
| 外部 | 133.42.49.0/24 | (外部) | 参加者VPN入口(.151), Pukiwiki(.140) |

### 2.3 VLAN

- v601 = 10.1.31.0/24（上流）
- v701 = 10.1.21.0/24 + 10.1.1.0/24（中継 + サーバー）
- v801 = 10.1.11.0/24（ユーザー/DHCP/AP）

### 2.4 SPAN（ポートミラー）

- Cat3560: `src Gi0/10 => dst Gi0/8`
- → 運営が監視している可能性 / こちらでも tcpdump 可能な配置

---

## 🖥️ 3. サーバー稼働サービス

### 3.1 Bravo (10.1.1.1, FreeBSD)

| サービス | 用途 |
|---|---|
| **BIND** | DNS 権威（com1.local） |
| sendmail / procmail | メール SMTP |
| courier-imap | IMAP |
| Apache / PHP / CGI / DB | ユーザーホスティング (100 ユーザー) |
| MySQL | sb_blog 等の DB |
| ssh | 管理用 |

**Web 構成（重要）**
- `http://com1.local/` → ログイン入口
- `http://(user).com1.local/` → ユーザー個別ページ（ワイルドカード）
- `(user)@service.com1.local` → ユーザーメールアドレス

### 3.2 Victor (10.1.1.2, Rocky Linux)

| サービス | 用途 |
|---|---|
| Apache / PHP / Perl | 会社 Web (`http://www.com1.local/`) |
| **WordPress** (`/wp-admin/`) | 会社サイト管理 |
| **RainLoop** (`/rain`) | Web メーラー |
| sendmail / procmail | メール SMTP |
| courier-imap / pop | メール受信 |
| MySQL | DB |
| **ISC DHCP** | 10.1.11.50-99 配布 |
| **MRTG / SNMP** | 監視 |
| **rsyslog** (`/var/log/rsyslog/`) | 全 syslog 集約 |
| ssh / **telnet** | 管理用（telnet 注意！） |
| Members chat board | 社員用掲示板 |

### 3.3 ESXi 6.7 (10.1.1.201)

- VMware ESXi 6.7（**EOL 済**、本番では仕込みの可能性あり）
- Web 管理画面：`https://10.1.1.201/`（要確認）
- 注意：管理対象内か外かは要確認

---

## 📁 4. ログの場所（最重要）

### 4.1 Victor (Rocky Linux)

| ログ | パス | 用途 |
|---|---|---|
| 認証 | `/var/log/secure` | SSH ログイン履歴 |
| システム | `/var/log/messages` | DHCP, syslog 等 |
| **rsyslog 集約** | `/var/log/rsyslog/` | **他機器からの集約ログ** |
| Apache | `/var/log/httpd/access_log`, `error_log` | Web アクセス |
| メール | `/var/log/maillog` | sendmail / dovecot |
| Audit | `/var/log/audit/audit.log` | auditd（有効なら） |
| ログイン履歴 | `/var/log/wtmp`, `/var/log/btmp` | `last`, `lastb` で表示 |

### 4.2 Bravo (FreeBSD)

| ログ | パス | 用途 |
|---|---|---|
| 認証 | `/var/log/auth.log` | SSH ログイン / sudo 履歴 |
| システム | `/var/log/messages` | 一般 syslog |
| BIND | `/var/log/named.log` (要確認) | DNS クエリ・更新 |
| Apache | `/var/log/httpd-access.log`, `httpd-error.log` | (要確認パス) |
| メール | `/var/log/maillog` | sendmail |
| ログイン | `/var/log/wtmp`, `/var/log/utx.log` | `last` で表示 |

### 4.3 ネットワーク機器

| 機器 | ログ取得方法 |
|---|---|
| Cat3560 | `show log` (telnet/ssh ログイン後) |
| ASA | `show logging` (Cat3560 から telnet) |
| RTX1210/1200 | `show log` (manage ログイン後) |
| NP2000 | `show log` (要確認) |

---

## 🚨 5. デモで判明した脆弱性チェックリスト

> **本番でも同構成の可能性が高い → これらが想定インシデント候補**
> 🔴=ほぼ確実 / 🟡=可能性高 / 🟢=構成依存

### 5.1 Victor (Web/Mail) 側

- 🔴 **Rainloop 1.12.0** (2018 年版)
  - CVE-2022-29360 (任意ファイル読取 / directory traversal)
  - CVE-2020-12641 (phpinfo 経由情報漏洩)
  - CVE-2019-10025 (XSS)
- 🔴 **WordPress 4.9.4** (2018 年版) + admin/Cm0re で入れる
  - REST API 系 CVE / プラグイン経由 RCE
- 🔴 **PHP 7.2.24** (EOL 2019) 危険設定多数
  - CVE-2019-11043 (PHP-FPM RCE)
- 🟡 **pkexec SUID** (CVE-2021-4034 PwnKit) → root 取得
- 🔴 **telnet :23** 平文 → 認証情報漏洩
- 🔴 **HTTPS 無し / iptables 空 / SELinux Disabled**
- 🟡 **obuchi /home 777** → 踏み台候補
- 🟡 **過去コンテストの残存設定**（rainloop の `_data_/` 配下）

### 5.2 Bravo (DNS/User Hosting) 側

- 🔴 **BIND `allow-update { 10.0.0.0/8; }`** ← DNS 改ざんシナリオの仕込み？
  - `nsupdate` で 10.x 全域から DNS レコード書き換え可能
- 🟡 **MySQL X Protocol :33060** 外部公開
- 🟡 **syslog :514/UDP** 外部受信可 → 偽ログ注入
- 🟡 **courier-imap :143** 平文 / IMAPS :993 無し
- 🟡 **pf/ipfw 無効** = L3 防御ゼロ
- 🟡 **HTTPS 無し**
- 🟢 **inetd 有効** → 古典的 inetd サービスの仕込みあり得る

### 5.3 ネットワーク機器

- 🟡 RTX1210/1200 のファーム古い可能性
- 🟡 Cat3560 / NP2000 のデフォルト設定の弱点
- 🟡 ASA Bridge Mode = L2 透過 → ACL での遮断のみ
- 🟢 **SPAN がある = パケットキャプチャできる**（こちらの武器）

---

## 📝 6. PukiWiki 報告書の書き方

### 6.1 提出先

```
URL    : http://133.42.49.140/trouble_ticket_137/index.php
ユーザ : whiskey
パス   : E5mA9cF3
```

### 6.2 PukiWiki 記法チートシート

```
* 見出し1
** 見出し2
*** 見出し3

- リスト
-- ネスト
--- さらにネスト

+ 番号付きリスト
++ ネスト

|セル|セル|h    ← h を末尾につけるとヘッダー行
|セル|セル|

''強調''
'''太字'''
%%打ち消し%%

[[リンク>http://example.com]]

> 引用

#code(言語){{
ソースコード
}}
```

### 6.3 報告書の構成テンプレ（既存 `04_完了報告テンプレート.md` ベース）

```
* インシデント概要
- 発生時刻 :
- 検知契機 :
- 影響範囲 :

* 原因
（ログ・調査結果から判明した原因）

* 対応内容
+ 一次対応（被害拡大防止）
+ 復旧作業
+ 再発防止

* 残課題・推奨事項

* 添付情報
- 関連ログ抜粋
- 確認コマンド出力
```

---

## 🔄 7. デモ ↔ 本番 IP マッピング

| 項目 | デモ (com6) | 本番 (com1, whiskey) | 法則 |
|---|---|---|---|
| サーバー帯 | 10.1.6.0/24 | **10.1.1.0/24** | -5 |
| RTX1200 中継 | 10.1.26.0/24 | **10.1.21.0/24** | -5 |
| ユーザー帯 | 10.1.16.0/24 | **10.1.11.0/24** | -5 |
| ASA 配下 | 10.1.36.0/24 | **10.1.31.0/24** | -5 |
| bravo | 10.1.6.1 | **10.1.1.1** | -5 |
| victor | 10.1.6.2 | **10.1.1.2** | -5 |
| GW | 10.1.6.254 | **10.1.1.254** | -5 |
| DHCP 配布 | 10.1.16.50-99 | **10.1.11.50-99** | -5 |
| ESXi/Hypervisor | (Proxmox) | **10.1.1.201 (ESXi 6.7)** | 別 |
| CIC DNS | 10.1.130.1 | **10.1.130.1** | 同 |
| VPN 入口 | 133.42.49.151 | **133.42.49.151** | 同 |
| Pukiwiki | (デモ無し) | **133.42.49.140** | 新 |
| ドメイン | com6.local | **com1.local** | 別 |

**覚え方**: 「デモの第3オクテットから 5 を引く」「ドメインを com6 → com1 に」

---

## ⚠️ 8. 管理対象 / 管理対象外

### 8.1 管理対象（こちらが守る）

- Bravo / Victor（サーバー）
- RTX1210（メイン）/ RTX1200
- Cat3560 / NP2000-24T4X-1（スイッチ）
- ASA (Bridge Mode)
- 上記サーバーで稼働するサービス（Apache/BIND/MySQL/sendmail/dovecot/dhcpd/SNMP 等）

### 8.2 管理対象外（触らない）

- ⛔ **インターネット側上流ルーター**（10.1.31.0/24 の上）
- ⛔ **CIC DNS (10.1.130.1)**
- ⛔ **参加者用 VPN ルーター (RTX1210 .100)** — 接続はするが設定は触らない
- ⛔ **Pukiwiki サーバー (133.42.49.140)** — 提出するだけ

---

## 🎯 9. 想定シナリオ初動フロー（既存 `03_プレイブック` 参考）

| 通報内容 | 一次調査先 |
|---|---|
| 「Web が見えない」 | Victor: Apache, DNS (Bravo), DHCP (Victor), GW |
| 「メールが届かない」 | Victor sendmail, dovecot / Bravo sendmail, courier |
| 「DNS が変な応答」 | **Bravo BIND**（allow-update の悪用？） |
| 「サイト改ざん」 | Victor `/var/www/`, WordPress, Rainloop |
| 「ログイン異常」 | Victor `/var/log/secure`, Bravo `/var/log/auth.log` |
| 「DHCP もらえない」 | Victor dhcpd, `/var/log/messages` |
| 「ログ大量・容量逼迫」 | Victor `/var/log/rsyslog/`（外部からの偽ログ注入？） |
| 「ネットワーク遅い」 | Cat3560 `show int`, RTX1210 `show status`, MRTG |

---

## 📌 10. 連絡・提出先

| 用途 | URL / 連絡先 |
|---|---|
| トラブル報告 | http://133.42.49.140/trouble_ticket_137/index.php |
| WordPress 管理 | http://www.com1.local/wp-admin/ |
| RainLoop メール | http://www.com1.local/rain |
| 会社サイト | http://www.com1.local/ |
| ユーザーページ | http://(user).com1.local/ |

---

## 11. 当日の自分メモ欄（手書き用）

```
[ ] チーム連絡手段:                          
[ ] 自分の booth ID (例: booth11):           
[ ] 自分の役割:                              
[ ] 指揮役:                                  
[ ] 受電役:                                  
[ ] 記録役:                                  
[ ] 報告書作成役:                            
[ ] 開始時刻:        終了時刻:               
[ ] 第1インシデント発生時刻:                 
[ ] 提出した報告書数:                        

メモ:




```

---

**作成日**: 2026-04-24
**作成者**: Guzen (whiskey チーム)
**用途**: SCCS2026 予選 Booth-1 当日机上配置用
**関連**:
- `14_サーバ調査レポート_20260424.md` — デモ環境の詳細調査（com6.local）
- `15_本日の作業記録と対応方針_20260424.md` — デモ調査の管理者対応メモ
- `17_本番前タスクリスト.md` — 本番までにやることリスト
- `03_シナリオ別対応プレイブック.md` — シナリオ別フロー
- `04_完了報告テンプレート.md` — 報告書フォーマット
- `05_受電ヒアリングシート.md` — 電話対応用
