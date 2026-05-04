---
model: claude-haiku-4-5
description: DB 認証情報・直接接続・X Protocol 経路を一括確認 (旧 mycnf-leak + mariadb-3306-direct + mysql-x-direct) — 認証情報漏洩 + 外部直接接続 + X Protocol 33060 を read-only で確認
---

# /check:check-db-exposure — DB 露出 一括確認

引数: `<時間窓> <ホスト>`
例: `/check:check-db-exposure 14:30-14:40 victor`

## 0. 前提

- 対象: **victor (10.1.1.2 / MariaDB)**
- 関連 weakness:
  - 16_:#7  — `/var/www/cgi-bin/.my.cnf.6804` が web 経由読取可 (DB 認証情報漏洩)
  - 16_:#8  — MariaDB 3306/tcp が外部直接接続可 (Skip-name-resolve / bind-address=0.0.0.0)
  - 16_:#9  — MySQL X Protocol 33060/tcp が listen 中 (3306 とは別経路の認証突破)
- 関連: MariaDB 10.3 EOL は `/check:check-static-recon` で確認済前提
- analyzer.py の対応 pattern_tag: `webapp/dotfile-access` (path=.my.cnf), `webapp/scanner-ua` (3306 探査)
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
SSH_VICTOR="${SSH_VICTOR:-manage@10.1.1.2}"
```

## 1. 収集 (read-only)

### 1.1 .my.cnf 等の認証情報ファイル漏洩 (旧 mycnf-leak)

```bash
echo "═══ /check:check-db-exposure ═══"
echo "─── §1.1 認証情報ファイル漏洩 ───"

# Web ツリーから直接読める .my.cnf 系ファイル
ssh "$SSH_VICTOR" \
    'sudo find /var/www -type f \( -name ".my.cnf*" -o -name ".pgpass" -o -name "wp-config.php.bak" \) -ls 2>/dev/null' \
    | sed 's/^/    /'

# .my.cnf.6804 の Web 経由アクセス痕跡
ssh "$SSH_VICTOR" \
    'sudo grep -E "\.my\.cnf|\.pgpass" /var/log/httpd/access_log 2>/dev/null | tail -20' \
    | sed 's/^/    /'

# .htaccess で .my.cnf がブロックされてるかどうか
ssh "$SSH_VICTOR" \
    'sudo grep -A2 -iE "FilesMatch.*my\.cnf|Files.*my\.cnf" /var/www/html/.htaccess /etc/httpd/conf/httpd.conf 2>/dev/null' \
    | sed 's/^/    /'
```

### 1.2 MariaDB 3306/tcp 外部直接接続 (旧 mariadb-3306-direct)

```bash
echo "─── §1.2 MariaDB 3306 外部接続 ───"

# bind-address / skip-networking
ssh "$SSH_VICTOR" \
    'sudo grep -iE "^(bind-address|skip-networking|skip-name-resolve)" /etc/my.cnf /etc/my.cnf.d/*.cnf 2>/dev/null' \
    | sed 's/^/    /'

# 3306 listen 状態
ssh "$SSH_VICTOR" \
    'sudo ss -tlnp 2>/dev/null | grep -E ":3306\b"' \
    | sed 's/^/    /'

# MariaDB 認証ログ (general_log / error.log) — 外部からの接続成功痕跡
ssh "$SSH_VICTOR" \
    'sudo tail -500 /var/log/mariadb/mariadb.log /var/log/mysqld.log 2>/dev/null | \
       grep -iE "Access denied|Connect|Aborted_connects" | tail -20' \
    | sed 's/^/    /'

# MySQL ユーザ Host=% の有無 (= 任意 IP からログイン可)
ssh "$SSH_VICTOR" \
    'sudo mysql -e "SELECT User, Host FROM mysql.user WHERE Host = '\''%'\'' OR Host = '\''0.0.0.0'\''" 2>/dev/null' \
    | sed 's/^/    /'
```

### 1.3 MySQL X Protocol 33060/tcp (旧 mysql-x-direct)

```bash
echo "─── §1.3 MySQL X Protocol 33060 ───"

# 33060 listen 状態
ssh "$SSH_VICTOR" \
    'sudo ss -tlnp 2>/dev/null | grep -E ":33060\b"' \
    | sed 's/^/    /'

# X Protocol 設定 — mysqlx_port / mysqlx_bind_address
ssh "$SSH_VICTOR" \
    'sudo grep -iE "^(mysqlx|loose_mysqlx)_(port|bind_address|socket)" /etc/my.cnf /etc/my.cnf.d/*.cnf 2>/dev/null' \
    | sed 's/^/    /'

# X Protocol プラグインの状態
ssh "$SSH_VICTOR" \
    'sudo mysql -e "SHOW PLUGINS" 2>/dev/null | grep -iE "mysqlx"' \
    | sed 's/^/    /'

# X Protocol 認証エラー痕跡
ssh "$SSH_VICTOR" \
    'sudo tail -500 /var/log/mariadb/mariadb.log /var/log/mysqld.log 2>/dev/null | \
       grep -iE "X Protocol|mysqlx" | tail -10' \
    | sed 's/^/    /'
```

## 2. 検知パターン

| 観点 | 危険シグナル | 重要度 |
|---|---|---|
| .my.cnf web 露出 | `/var/www` 配下に `.my.cnf*` 存在 | 🚨 認証情報漏洩 |
| .my.cnf アクセス痕跡 | access_log に 200 OK | 🚨 攻撃者が読み取った物証 |
| 3306 listen 0.0.0.0 | `bind-address=0.0.0.0` or 未設定 | 🚨 外部接続可能 |
| Aborted_connects 急増 | error.log に多数 | ⚠️ 認証総当たり中 |
| User Host=% | mysql.user に存在 | 🚨 任意 IP から認証可 |
| 33060 listen | 0.0.0.0:33060 | 🚨 X Protocol 別経路 |
| skip-name-resolve | `ON` | ⚠️ DNS bypass で監査困難 |

## 3. 判定基準

- ✅ **正常**: .my.cnf web 不在 + 3306 bind=127.0.0.1 + 33060 close + Host=% 不在
- ⚠️ **露出のみ**: 設定が緩いが攻撃試行なし → 報告書に記載
- 🚨 **確定**: .my.cnf アクセス痕跡 or 3306/33060 への成功 connect → `/playbook:wp-tamper` + `/playbook:ransomware`

## 4. 次のアクション

- 🚨 確定時の封じ手提案 (リーダー承認後):
  - `bind-address = 127.0.0.1` + `skip-networking`
  - `disable_x_plugin` (mysqlx を停止)
  - `mysql.user WHERE Host='%'` を `Host='localhost'` に変更
  - .htaccess に `<FilesMatch "\.my\.cnf">Require all denied</FilesMatch>`
  - 攻撃元 IP を iptables で deny
- 連鎖：
  - WordPress 経由の dotfile アクセスが起点 → `/check:check-wp-config-leak`
  - mariadb 操作の権限昇格痕跡 → `/check:check-known-attacker-ip` で IP 突合

## 5. JSON 永続化

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-db-exposure
{
  "inputs": {"target_host": "victor", "window": "$1"},
  "outputs": {
    "mycnf_web_files":      ["...必要なら..."],
    "mycnf_access_count":   0,
    "mariadb_bind_address": "127.0.0.1|0.0.0.0",
    "mariadb_3306_listen":  true,
    "mysql_user_wildcard_host": [],
    "mysqlx_33060_listen":  false,
    "aborted_connects":     0
  },
  "verdict": {
    "status": "🚨|⚠️|✅",
    "summary": "(認証情報漏洩 + 直接接続経路 + X Protocol の 3 観点を 1 行)"
  },
  "next_skills": ["/check:check-...", "/playbook:wp-tamper", "/playbook:ransomware"]
}
JSON_EOF
```

保存先: `data/incidents/${INCIDENT_ID}/check-db-exposure__<ts>.json`
