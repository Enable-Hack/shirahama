---
description: MariaDB 3306/tcp の外部直接接続 / 認証突破の痕跡を確認 (X Protocol 33060 とは別経路)
---

# /check:check-mariadb-3306-direct — MariaDB 3306 直叩き確認

引数: `<時間窓> <ホスト>`
例: `/check:check-mariadb-3306-direct 13:00-13:30 victor`

## 0. 前提

- 対象: **victor (10.1.1.2 / MariaDB 10.3 EOL)**
- 関連 weakness: 14_:V3 / 16_:#26 — MariaDB の `bind-address = *` で 3306/tcp 全公開
- 注意: **`/check:check-mysql-x-direct` は X Protocol (33060) を見るのに対し、本 check は純粋な 3306/tcp 経路に特化**。両方並行で叩くべき
- 関連 file: `wp-config.php` / `.my.cnf.6804` 漏洩と組み合わさると認証突破成立
- analyzer.py の対応 pattern_tag: `webapp/dotfile-access` (連鎖)、直接対応なし
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
```

## 1. 収集 (read-only)

### 1.1 3306 listen 状態 + bind-address

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo ss -tlnp | grep -E ":3306\\b"'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -iE "^(bind-address|skip-networking|port)" /etc/my.cnf /etc/my.cnf.d/*.cnf 2>/dev/null'

# 外部到達可能性
nc -zv "$TARGET_HOST" 3306 2>&1 | head -3
```

### 1.2 接続ログ (general_log / error.log)

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -3000 /var/log/mariadb/mariadb.log /var/log/mysqld.log 2>/dev/null' \
  > /tmp/check_mdb3306_log.log

# Connect / Access denied
grep -iE "Connect.*@.*on|Access denied for user.*@" /tmp/check_mdb3306_log.log | tail -50

# 接続元 IP の集計
grep -iE "Connect.*@" /tmp/check_mdb3306_log.log \
  | grep -oE "@'?[0-9.]+'?" | sort | uniq -c | sort -rn | head -10
```

### 1.3 conntrack で確立済セッション

```bash
ssh "$TARGET_USER@$TARGET_HOST" \
  'sudo conntrack -L -p tcp --dport 3306 -o extended 2>/dev/null | head -20 || \
   ss -tn state established sport = :3306 2>/dev/null'

# 不審な外部 IP からの接続
ssh "$TARGET_USER@$TARGET_HOST" \
  'sudo ss -tn state established sport = :3306 | awk "{print \$5}" | sort -u | head -10'
```

### 1.4 認証突破痕跡 (Access denied burst → 後続 Connect 成功)

```bash
# 同一 IP からの Access denied が時間窓で多発、その後 Connect 成功 = brute 突破
grep -iE "Access denied.*@'?([0-9.]+)" /tmp/check_mdb3306_log.log \
  | grep -oE "@'?[0-9.]+'?" | sort | uniq -c | sort -rn | head -5
```

### 1.5 SQL クエリ痕跡 (general_log が ON なら)

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -iE "general_log" /etc/my.cnf /etc/my.cnf.d/*.cnf 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -200 /var/log/mariadb/general.log 2>/dev/null' \
  | grep -iE "SELECT.*FROM.*(user|password|wp_users|mysql\\.user)" | tail -10

# DROP / TRUNCATE / GRANT 等の破壊的 SQL
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -500 /var/log/mariadb/general.log 2>/dev/null' \
  | grep -iE "DROP|TRUNCATE|GRANT|CREATE USER|UPDATE.*password" | tail -10
```

### 1.6 mysql.user テーブル改竄物証 (read-only)

```bash
# 直近で touched された mysql システムテーブル
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /var/lib/mysql/mysql -mmin -120 -ls 2>/dev/null'
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. bind-address = * | my.cnf に上記 | 🚨 設定上の脆弱性 |
| B. 外部 IP からの Connect 成功 | error.log で 10.1.11.x 等から Connect | 🚨 確定 |
| C. Access denied burst | 同 IP から多発 | ⚠️ 疑わしい (brute 中) |
| D. burst の後に Connect 成功 | C の IP が突破 | 🚨 確定 (brute 突破) |
| E. SELECT で user/password 抽出 | general_log で password テーブルアクセス | 🚨 確定 (情報漏洩) |
| F. mysql.user mtime 直近 | システムテーブル改竄 | 🚨 確定 |

## 3. 判定基準

- ✅ **正常**: 3306 が localhost only、外部 Connect なし
- ⚠️ **疑わしい**: A / C のみ → 設定リスク + brute 試行報告
- 🚨 **確定**: B / D / E / F → **/playbook:wp-tamper** + **/playbook:ransomware**

## 4. 次のアクション

### 確定なら
- **`/playbook:wp-tamper`** + **`/playbook:ransomware`**
- 並行 **`/check:check-mycnf-leak`** + **`/check:check-wp-config-leak`** (認証情報漏洩元の特定)
- DB の **全アカウント認証情報変更** をリーダーに即進言

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: bind-address = 127.0.0.1 → systemctl restart mariadb (運用影響あり)
# 案2: 3306 を firewalld で deny
# 案3: GRANT 不正があれば取り消し
```

### メモするだけ
- 16_:#26 で「短期対応」リスト入り
- WP / 掲示板アプリは 3306 を localhost で叩く設計のはず → bind 縛りで運用影響なし

## 5. 参照

- 関連 playbook: [playbook/wp-tamper.md](../playbook/wp-tamper.md)、[playbook/ransomware.md](../playbook/ransomware.md)
- 連鎖先 check: [check-mysql-x-direct.md](check-mysql-x-direct.md)、[check-mycnf-leak.md](check-mycnf-leak.md)、[check-wp-config-leak.md](check-wp-config-leak.md)
- analyzer 該当: 直接対応ルールなし (要追加メモ)
- 既存ドキュメント: 14_:V3 / 16_:#26
