---
model: claude-haiku-4-5
description: PHP の allow_url_fopen=On + disable_functions 空 + open_basedir 空 を悪用した LFI/RFI/RCE 痕跡を確認
---

# /check:check-php-allow-url-fopen — PHP 設定無制限の悪用確認

引数: `<時間窓> <ホスト>`
例: `/check:check-php-allow-url-fopen 13:00-13:30 victor`

## 0. 前提

- 対象: **victor (10.1.1.2 / PHP 7.2.24 EOL)**
- 関連 weakness: 14_:8.1#3 / 16_:#19 — `allow_url_fopen=On` `disable_functions=空` `open_basedir=空` `short_open_tag=On` `expose_php=On`
- 影響: WP 等の脆弱性で LFI/RFI 発火 → `system()` 等で **サーバ全体が取られる**
- analyzer.py の対応 pattern_tag: `path_traversal`、`cmdi`、`webapp/upload-php`
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
```

## 1. 収集 (read-only)

### 1.1 PHP 設定の確認

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'php -i 2>/dev/null' \
  | grep -iE "allow_url_fopen|allow_url_include|disable_functions|open_basedir|short_open_tag|expose_php|file_uploads|upload_tmp_dir"

ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -iE "^(allow_url|disable_functions|open_basedir|short_open|expose_php)" /etc/php.ini /etc/php.d/*.ini 2>/dev/null'
```

期待 (危険):
- `allow_url_fopen = On` + `disable_functions = ` (空) + `open_basedir = ` (空)

### 1.2 LFI/RFI 試行痕跡 (アクセスログ)

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -5000 /var/log/httpd/access_log' > /tmp/check_php_access.log

# RFI: ?file=http:// / ?include=ftp://
grep -iE "[?&](file|page|include|path|url|src|target)=(https?|ftp|php):" /tmp/check_php_access.log | tail -20

# LFI: ../../etc/passwd / php://filter
grep -iE "(\\.\\./){2,}|/etc/passwd|php://(filter|input|expect)" /tmp/check_php_access.log | tail -20

# data:// wrapper (RFI without external server)
grep -iE "data://|data:text/plain" /tmp/check_php_access.log | tail -10
```

### 1.3 PHP error_log で include 失敗 / wrapper 警告

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -2000 /var/log/httpd/error_log' > /tmp/check_php_error.log

grep -iE "failed to open stream|file_get_contents|allow_url_include|wrapper" /tmp/check_php_error.log | tail -30
grep -iE "system|exec|shell_exec|passthru|popen|proc_open" /tmp/check_php_error.log | tail -20
```

### 1.4 webshell 配置痕跡

```bash
# 直近で書かれた .php / .phtml / .phar
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /var/www -type f \( -name "*.php" -o -name "*.phtml" -o -name "*.phar" \) -mmin -120 2>/dev/null | head -20'

# uploads / tmp / cache 配下に PHP (典型的な webshell 置き場)
ssh "$TARGET_USER@$TARGET_HOST" \
  'sudo find /var/www -path "*uploads*" -name "*.php" -ls 2>/dev/null | head -10'

# /tmp 配下に PHP (LFI で書かれる典型)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /tmp -name "*.php" -ls 2>/dev/null'
```

### 1.5 PHP プロセスの異常子プロセス

```bash
# httpd の子で sh / bash / nc が走っていれば webshell 経由 RCE 確定
ssh "$TARGET_USER@$TARGET_HOST" 'sudo ps -ef --forest | grep -E "httpd|apache" | head -30'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo ps -ef | grep -vE "grep" | grep -E "(sh|bash|nc|python|perl) " | head -20'
```

### 1.6 JSONL 化

```bash
python scripts/preprocess/parse_clf.py /tmp/check_php_access.log \
  | jq --arg start "$START" --arg end "$END" \
       'select(.timestamp >= $start and .timestamp <= $end)' \
  > /tmp/check_php_access.jsonl
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. RFI 試行 | URL に `http://` `ftp://` `data://` を含む | 🚨 確定 (試行) |
| B. LFI 試行 | `../` 連発 / `php://filter` / `/etc/passwd` | 🚨 確定 (試行) |
| C. webshell 配置 | uploads/ や /tmp に直近 .php、httpd 子に sh | 🚨 確定 (RCE 成立) |
| D. PHP error: failed to open stream | error_log に外部 URL 込みの fopen 警告 | 🚨 確定 (試行成功 / 失敗どちらも) |
| E. analyzer tag | `path_traversal`、`cmdi`、`webapp/upload-php` 発火 | 🚨 確定 |

## 3. 判定基準

- ✅ **正常**: A〜D 痕跡 0、PHP 設定が安全側
- ⚠️ **疑わしい**: A/B のみで C/D なし → 試行されたが防御 (404/403) で止まっている
- 🚨 **確定**: C / D / E → **/playbook:wp-tamper** + **/playbook:ransomware** (webshell 経由 RCE)

## 4. 次のアクション

### 確定なら
- **`/playbook:wp-tamper`** (LFI/RFI の入口は WP の脆弱性が大半)
- **`/playbook:ransomware`** (RCE 後の永続化チェック)
- 並行して **`/check:check-htaccess-rce`** + **/check:check-mycnf-leak**

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: php.ini で disable_functions に exec/system/passthru/shell_exec/proc_open/popen を追記 → httpd reload
# 案2: allow_url_fopen=Off + open_basedir=/var/www に絞る (運用影響大)
# 案3: webshell の .php を /tmp 等から退避
```

### メモするだけ
- PHP EOL = dnf でも更新不可、設定での緩和のみ
- 「触らない」優先、ただし RCE 成立確認後は即退避

## 5. 参照

- 関連 playbook: [playbook/wp-tamper.md](../playbook/wp-tamper.md)、[playbook/ransomware.md](../playbook/ransomware.md)
- 連鎖先 check: check-htaccess-rce、check-mycnf-leak、check-wp-config-leak
- analyzer 該当: `agent/analyzer.py` `PATH_TRAVERSAL_PATTERNS`、`CMDI_PATTERNS`、`WEBAPP_UPLOAD_PHP_PATTERNS`
- 既存ドキュメント: 14_:8.1#3 / 16_:#19 / 14_:6.14 (PHP 設定全文)

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-php-allow-url-fopen__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-php-allow-url-fopen
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
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-php-allow-url-fopen__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
