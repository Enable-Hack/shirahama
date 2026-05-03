---
description: シナリオ① 偵察 → Web 経由 RCE → 横展開 → DB 全件持ち出し のキルチェーン全体を確認 (複数 /check 並行起動)
---

# /scenario:killchain-recon-rce-dbexfil — キルチェーン①: Web RCE → DB 全件持ち出し

引数: `<時間窓> <ホスト>`
例: `/scenario:killchain-recon-rce-dbexfil 13:00-13:30 victor`

## 0. 想定キルチェーン (16_:1.3-① 由来)

```
ステージ1: 偵察 (recon)
  └ SNMP MIB walk / ?author= 列挙 / scanner UA で攻撃面の地図取得
       ↓
ステージ2: 初期侵入 (initial access)
  └ WP xmlrpc-brute / RainLoop CVE-2022-29360 / .htaccess RCE / LFI(php-allow-url)
       ↓
ステージ3: 認証情報奪取 (credential theft)
  └ .my.cnf 読み取り / wp-config.php 漏洩 / SALT.php 復号
       ↓
ステージ4: 横展開 (lateral move)
  └ MariaDB 3306 直接接続 / MySQL X 33060 / Dovecot passdb-pam で全システムユーザ
       ↓
ステージ5: 持ち出し (exfiltration)
  └ INTO OUTFILE で webshell + curl で外送、または mysqldump 経由
```

## 1. 起動条件 (どんな兆候で叩くべきか)

`/incident` で以下のいずれかが観測されたら **本シナリオを起動**:

- analyzer 出力に **`webapp/scanner-ua` + `webapp/dotfile-access`** が同時発火
- analyzer 出力に **`path_traversal` または `cmdi`** が WP / rainloop パス配下
- analyzer 出力に **`webapp/upload-php`** (uploads 配下に PHP)
- 受電内容に「DB が空になった」「学生情報が漏れた」を含む

## 2. 各ステージで叩く /check 一覧

### ステージ1: 偵察
- **並行起動**:
  - `/check:check-snmp-public-walk`
  - `/check:check-wp-rest-author-scan`
  - `/check:check-backup-html-exposure`
  - `/check:check-userdir-listing`

### ステージ2: 初期侵入
- **並行起動**:
  - `/check:check-wp-xmlrpc-brute`
  - `/check:check-rainloop-cve29360`
  - `/check:check-htaccess-rce`
  - `/check:check-php-allow-url-fopen`

### ステージ3: 認証情報奪取
- **並行起動**:
  - `/check:check-mycnf-leak`
  - `/check:check-wp-config-leak`

### ステージ4: 横展開
- **並行起動**:
  - `/check:check-mariadb-3306-direct`
  - `/check:check-mysql-x-direct`
  - `/check:check-dovecot-passdb-pam`

### ステージ5: 持ち出し
- 既存 check では完全カバーできない → 以下を手動確認:
  - `/var/www` 配下の直近 .php (webshell)
  - mysqld general_log の `INTO OUTFILE` / `SELECT.*FROM.*users`
  - 大きい outbound transfer (conntrack / tcpdump)

## 3. ステージ間の連鎖判定

各ステージの結果を見て、**1 つでも 🚨 確定 が出たら次ステージへ進む**。

| 連鎖判定 | 解釈 |
|---|---|
| ステージ1 確定 + ステージ2 ⚠️ | 偵察止まり、初期侵入は防御で止まっている |
| ステージ2 確定 + ステージ3 確定 | RCE → 認証情報奪取は成立、横展開を最警戒 |
| ステージ3 確定 + ステージ4 確定 | DB 直接アクセス成立、データ全件取られた前提 |
| ステージ4 確定 + ステージ5 確定 | 持ち出し成立、被害公表 / 通報判断必要 |

## 4. 確定後のアクション

### 並行起動する playbook
- **`/playbook:wp-tamper`** (Web 改竄経路全工程)
- **`/playbook:ransomware`** (横展開・永続化)

### リーダー報告のシナリオストーリー
> "**WP 4.9.4 の xmlrpc-brute** または **RainLoop CVE-2022-29360** で初期侵入 → **`.my.cnf.6804` / wp-config.php** で DB 認証情報奪取 → **MariaDB 3306 / MySQL X 33060** に外部から直接接続 → **学生情報 100 件 + 過去 BBS 投稿が外部に流出**。
> 即時対応: 1) 該当 IP の遮断 2) DB 全アカウント認証情報変更 3) webshell 退避 4) 影響学生への通知判断"

### 即時封じ手 (リーダー承認後 / 個別 check の §4 を参照)

## 5. 参照

- 関連 playbook: [playbook/wp-tamper.md](../playbook/wp-tamper.md)、[playbook/ransomware.md](../playbook/ransomware.md)
- 既存ドキュメント: 16_:1.3-① / 14_:8.1
- 関連シナリオ:
  - [scenario/dns-spoof-phish.md](dns-spoof-phish.md) (DNS 偽装と組み合わさる場合)
  - [scenario/vpn-uplink-abuse.md](vpn-uplink-abuse.md) (VPN 経由侵入の場合)

## 6. JSON 永続化（HTML dashboard 連携）

§2 で並行起動した /check の結果を集約し、キルチェーン全体の総括を JSON で出力する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh scenario-killchain-recon-rce-dbexfil
{
  "inputs": {
    "checks_dispatched": ["check-backup-html-exposure", "check-userdir-listing", "check-wp-xmlrpc-brute", "check-htaccess-rce", "check-php-allow-url-fopen", "check-mycnf-leak", "check-wp-config-leak", "check-mariadb-3306-direct", "check-mysql-x-direct"]
  },
  "outputs": {
    "killchain_phase_results": [
      {"phase": "recon", "checks": ["check-backup-html-exposure", "check-userdir-listing"], "verdict": "🚨 | ⚠️ | ✅"},
      {"phase": "initial-access-rce", "checks": ["check-wp-xmlrpc-brute", "check-htaccess-rce", "check-php-allow-url-fopen"], "verdict": "🚨 | ⚠️ | ✅"},
      {"phase": "credential-leak", "checks": ["check-mycnf-leak", "check-wp-config-leak"], "verdict": "🚨 | ⚠️ | ✅"},
      {"phase": "db-exfil", "checks": ["check-mariadb-3306-direct", "check-mysql-x-direct"], "verdict": "🚨 | ⚠️ | ✅"}
    ],
    "chain_completeness": "<どのフェーズまで観測できたか / 抜けているフェーズ>"
  },
  "verdict": {
    "status": "🚨 | ⚠️ | ✅",
    "summary": "<キルチェーン全体の 1-2 行総括>"
  },
  "next_skills": ["/playbook:wp-tamper", "/playbook:ransomware", "/review"]
}
JSON_EOF
```

- 保存先: `data/incidents/${INCIDENT_ID}/scenario-killchain-recon-rce-dbexfil__<ts>.json`
