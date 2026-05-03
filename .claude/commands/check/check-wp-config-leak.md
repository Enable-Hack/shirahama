---
description: wp-config.php (DB 認証情報を含む) の Web 経由読み取り痕跡を確認
---

# /check:check-wp-config-leak — wp-config.php 露出確認

引数: `<時間窓> <ホスト>`
例: `/check:check-wp-config-leak 13:00-13:30 victor`

## 0. 前提

- 対象: **victor (10.1.1.2)**
- 関連 weakness: 16_:2.3-#1 — `wp-config.php` が **`apache:apache 644`** で配置 → Apache の PHP ハンドラが落ちた瞬間に **DB 認証情報が平文で読まれる**
- 影響: WP 用 DB の認証情報漏洩 → 直接 SQL 実行 → 全テーブル取得・改竄
- analyzer.py の対応 pattern_tag: `webapp/dotfile-access` (関連)、`path_traversal` (LFI 経路)
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
WP_BASE="${WP_BASE:-/var/www/wordpress}"   # 候補: /var/www/html, /var/www/wordpress
```

## 1. 収集 (read-only)

### 1.1 wp-config.php の場所と権限

```bash
# 候補パス総当たり
ssh "$TARGET_USER@$TARGET_HOST" \
  'for d in /var/www/html /var/www/wordpress /var/www; do
     test -f "$d/wp-config.php" && echo "FOUND: $d/wp-config.php" && sudo ls -la "$d/wp-config.php"
   done'

# 権限が 644 なら apache が落ちた瞬間に読まれる
# 600 なら Apache が読めず WP も動かない (= 通常は 640 root:apache が安全)
```

### 1.2 wp-config 系のバックアップ / コピーの存在

```bash
ssh "$TARGET_USER@$TARGET_HOST" \
  'sudo find /var/www -name "wp-config*" -ls 2>/dev/null'

# wp-config.php.bak / wp-config.old / .wp-config.php.swp
ssh "$TARGET_USER@$TARGET_HOST" \
  'sudo find /var/www \( -name "wp-config.*" \! -name "wp-config.php" \) -ls 2>/dev/null'
```

### 1.3 アクセスログでの wp-config 直叩き

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -5000 /var/log/httpd/access_log' > /tmp/check_wpconfig_access.log

# 直接アクセス試行
grep -iE "wp-config\\.(php|bak|old|txt)" /tmp/check_wpconfig_access.log | tail -30

# 200 応答 (= 漏洩確定)
grep -iE "wp-config\\.(php|bak|old|txt).* 200" /tmp/check_wpconfig_access.log | tail -10

# .swp / バックアップ拡張子
grep -iE "wp-config.*\\.(swp|swo|bak|orig|save|~)" /tmp/check_wpconfig_access.log | tail -10
```

### 1.4 LFI 経由の wp-config 読み取り

```bash
# php://filter/convert.base64-encode/resource=wp-config (典型 LFI payload)
grep -iE "php://filter|convert\\.base64.*wp-config" /tmp/check_wpconfig_access.log | tail -20

# パストラバーサルで wp-config に到達
grep -iE "(\\.\\./)+wp-config" /tmp/check_wpconfig_access.log | tail -10
```

### 1.5 外部からの到達試験 (read-only)

```bash
# 直接 GET (期待: 200 でも空 body / または 403)
curl -sI "http://10.1.1.2/wp-config.php" 2>&1 | head -3
curl -sI "http://10.1.1.2/wp-config.php.bak" 2>&1 | head -3
curl -sI "http://10.1.1.2/wp-config.php.swp" 2>&1 | head -3

# .swp が読めれば確定
curl -s "http://10.1.1.2/.wp-config.php.swp" 2>&1 | head -5
```

### 1.6 漏洩後の DB 直接アクセス (連鎖)

```bash
# 同 IP からの MySQL/MariaDB 接続
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -2000 /var/log/mariadb/mariadb.log /var/log/mysqld.log 2>/dev/null' \
  > /tmp/check_wpconfig_mysql.log

grep -iE "Connect|Access denied" /tmp/check_wpconfig_mysql.log | tail -30
```

### 1.7 JSONL 化

```bash
python scripts/preprocess/parse_clf.py /tmp/check_wpconfig_access.log \
  | jq --arg start "$START" --arg end "$END" \
       'select(.timestamp >= $start and .timestamp <= $end)' \
  > /tmp/check_wpconfig_access.jsonl
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. wp-config.php へ 200 + 内容あり | curl 試験で内容露出 | 🚨 確定 (PHP ハンドラ脱落 / 漏洩) |
| B. wp-config.bak / .swp 取得成功 | バックアップ拡張子で 200 | 🚨 確定 |
| C. LFI 経由 base64 抽出 | php://filter リクエストが 200 | 🚨 確定 |
| D. wp-config 644 + apache 所有 | 設定上の脆弱性 | ⚠️ 疑わしい (前提条件) |
| E. 同 IP の MySQL Connect | 漏洩後の DB 直接アクセス | 🚨 確定 (連鎖) |

## 3. 判定基準

- ✅ **正常**: wp-config.php 直叩きが 403/404、バックアップなし
- ⚠️ **疑わしい**: D のみ + 攻撃痕跡なし → 権限を 640 root:apache に直すよう報告
- 🚨 **確定**: A / B / C / E → **/playbook:wp-tamper** + **/playbook:ransomware**

## 4. 次のアクション

### 確定なら
- **`/playbook:wp-tamper`** (WP 改竄)
- **`/playbook:ransomware`** (DB 経由の横展開)
- 並行して **`/check:check-mycnf-leak`** (.my.cnf も同時漏洩しがち)
- DB の **WP 用アカウントを即変更**、wp-config.php に新認証情報を反映

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: 権限変更
# sudo chmod 640 /var/www/wordpress/wp-config.php
# sudo chown root:apache /var/www/wordpress/wp-config.php
# 案2: バックアップを退避
# sudo mv /var/www/wordpress/wp-config.bak /root/forensic_wp-config.bak
# 案3: Apache で <Files "wp-config.php"> Require all denied </Files>
```

### メモするだけ
- 16_:2.3-#1 が「14/15 番でも軽くしか触れていない」と指摘 → 重要度過小評価されがち
- WP 用 DB アカウントは WP テーブルへの書込のみ持っているはず → 横展開先は限定的だが、SELECT 権限で個人情報が抜ける

## 5. 参照

- 関連 playbook: [playbook/wp-tamper.md](../playbook/wp-tamper.md)、[playbook/ransomware.md](../playbook/ransomware.md)
- 連鎖先 check: [check-mycnf-leak.md](check-mycnf-leak.md)、[check-php-allow-url-fopen.md](check-php-allow-url-fopen.md)
- analyzer 該当: `agent/analyzer.py` `WEBAPP_DOTFILE_PATTERNS`、`PATH_TRAVERSAL_PATTERNS`
- 既存ドキュメント: 16_:2.3-#1 / 14_:6.7 (WP DocumentRoot 構成)

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-wp-config-leak__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-wp-config-leak
{
  "inputs": {
    "target_host": "victor | bravo | both",
    "known_ips": ["...必要なら..."]
  },
  "outputs": {
    "patterns_matched": [
      {"id": "A", "label": "...§3 判定基準のパターンA...", "verdict": "🚨 | ⚠️ | ❌"},
      {"id": "B", "label": "...§3 判定基準のパターンB...", "verdict": "🚨 | ⚠️ | ❌"}
    ],
    "evidence": [
      "<§1 で取得した実ログから 2-3 行の重要なものを抜粋>"
    ]
  },
  "verdict": {
    "status": "🚨 | ⚠️ | ✅ | info",
    "summary": "<§4 で出した判定 1-2 行を再掲>"
  },
  "next_skills": ["/playbook:..." または "/check:..."]
}
JSON_EOF
```

- `patterns_matched` の `id` は §3 判定基準のパターン (A/B/C/D/E/F 等) と対応させる
- `evidence` は §1 で取得した実ログから 2-3 行抜粋 (PII / 機密に注意)
- `verdict.status` は §4 で出した判定と一致させる
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-wp-config-leak__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
