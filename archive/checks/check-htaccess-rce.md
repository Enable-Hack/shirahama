---
model: claude-haiku-4-5
description: Apache <Directory /> AllowOverride All + ExecCGI を悪用した .htaccess 経由 RCE の痕跡を確認
---

# /check:check-htaccess-rce — .htaccess 経由 RCE 確認

引数: `<時間窓> <ホスト>`
例: `/check:check-htaccess-rce 13:00-13:30 victor`

## 0. 前提

- 対象: **victor (10.1.1.2)**
- 関連 weakness: 14_:V9 / 16_:#11 — `<Directory />` で `AllowOverride All` + `Options FollowSymLinks ExecCGI` + `AddHandler cgi-script .cgi .pi` → **任意ディレクトリに `.htaccess` を置けば挙動改変 / CGI 実行**
- 影響: WP uploads や rainloop data 配下に `.htaccess` + `AddType application/x-httpd-php .jpg` で画像偽装 webshell、または `AddHandler cgi-script` で .pl/.cgi 偽装 RCE
- analyzer.py の対応 pattern_tag: `webapp/upload-php`、`webapp/dotfile-access`
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
```

## 1. 収集 (read-only)

### 1.1 Apache 設定の確認

```bash
ssh "$TARGET_USER@$TARGET_HOST" \
  'sudo grep -rEn "AllowOverride|Options.*(ExecCGI|FollowSymLinks|Includes)|AddHandler|AddType" /etc/httpd/conf/ /etc/httpd/conf.d/ 2>/dev/null | grep -vE "^\\s*#"'
```

期待 (危険):
- `AllowOverride All` が `<Directory />` か `<Directory "/var/www/html">` にある
- `AddHandler cgi-script .cgi .pi` が広いスコープで適用

### 1.2 既存 .htaccess の総点検

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /var/www -name ".htaccess" -ls 2>/dev/null'

# 直近で更新された .htaccess (攻撃者の改竄痕跡)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /var/www -name ".htaccess" -mmin -120 -ls 2>/dev/null'

# .htaccess の中身 (危険ディレクティブを抽出)
ssh "$TARGET_USER@$TARGET_HOST" \
  'for f in $(sudo find /var/www -name ".htaccess" 2>/dev/null); do
     echo "=== $f ===";
     sudo grep -iE "AddHandler|AddType|SetHandler|Options.*ExecCGI|RewriteRule|php_value|php_admin" "$f" 2>/dev/null;
   done'
```

### 1.3 偽装 webshell の探索

```bash
# 画像拡張子なのに PHP ハンドラ扱いされている箇所
ssh "$TARGET_USER@$TARGET_HOST" \
  'sudo find /var/www \( -name "*.jpg" -o -name "*.png" -o -name "*.gif" \) -mmin -120 -size +1k 2>/dev/null | head -10'

# .pl / .cgi 拡張子で直近に書かれたファイル
ssh "$TARGET_USER@$TARGET_HOST" \
  'sudo find /var/www \( -name "*.pl" -o -name "*.cgi" \) -mmin -120 -ls 2>/dev/null'
```

### 1.4 アクセスログでの呼び出し試行

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -5000 /var/log/httpd/access_log' > /tmp/check_htaccess_access.log

# 画像拡張子なのに 200 + body size が大きい (偽装 webshell の応答)
grep -iE "GET /[^ ]+\\.(jpg|png|gif) HTTP/[^ ]+ 200" /tmp/check_htaccess_access.log \
  | awk '$NF > 5000' | tail -10

# .htaccess 直叩き (情報漏洩試行)
grep -iE "GET /[^ ]+/\\.htaccess" /tmp/check_htaccess_access.log | tail -10

# .pl / .cgi の不審な呼び出し
grep -iE "GET /[^ ]+\\.(pl|cgi)" /tmp/check_htaccess_access.log | tail -20
```

### 1.5 SymLink 経路 (FollowSymLinks 悪用)

```bash
# /var/www 配下の symlink 探索
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /var/www -type l -ls 2>/dev/null'

# 危険な symlink (/etc/passwd や /root へのリンク)
ssh "$TARGET_USER@$TARGET_HOST" \
  'sudo find /var/www -type l -lname "/etc/*" -o -lname "/root/*" -o -lname "/home/*" 2>/dev/null'
```

### 1.6 JSONL 化

```bash
python scripts/preprocess/parse_clf.py /tmp/check_htaccess_access.log \
  | jq --arg start "$START" --arg end "$END" \
       'select(.timestamp >= $start and .timestamp <= $end)' \
  > /tmp/check_htaccess_access.jsonl
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. .htaccess 新規配置 | mtime 時間窓内の .htaccess | 🚨 確定 |
| B. 危険ディレクティブ含有 | AddHandler / AddType / SetHandler が .htaccess に記述 | 🚨 確定 |
| C. 画像偽装 webshell | .jpg/.png で 200 + 異常 body size | 🚨 確定 (RCE 成立) |
| D. symlink 経路 | /var/www 配下から /etc/ /root/ への symlink | 🚨 確定 |
| E. analyzer tag | `webapp/upload-php` / `webapp/dotfile-access` | 🚨 確定 |

## 3. 判定基準

- ✅ **正常**: .htaccess 既存のみで mtime 古い、危険ディレクティブなし
- ⚠️ **疑わしい**: AllowOverride All はあるが .htaccess 自体は変更なし → 設定リスクとして報告
- 🚨 **確定**: A〜D / E → **/playbook:wp-tamper** + **/playbook:ransomware**

## 4. 次のアクション

### 確定なら
- **`/playbook:wp-tamper`** (uploads や rainloop data 経路の深掘り)
- **`/playbook:ransomware`** (RCE 経由の永続化)
- 並行して **`/check:check-php-allow-url-fopen`**

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: <Directory "/"> AllowOverride None </Directory> を追加 (運用影響大)
# 案2: 不審な .htaccess を退避 (mv して中身を /tmp/forensic_ に保管)
# 案3: AddHandler cgi-script のスコープを <Directory "/var/www/cgi-bin"> に限定
```

### メモするだけ
- AllowOverride All は「触らない」候補だが、新規 .htaccess は出題前提を超えた攻撃の物証 → 退避してよい
- symlink 経由の /etc/passwd 読み取りは forensic 価値あり、即削除しない

## 5. 参照

- 関連 playbook: [playbook/wp-tamper.md](../playbook/wp-tamper.md)、[playbook/ransomware.md](../playbook/ransomware.md)
- 連鎖先 check: [check-php-allow-url-fopen.md](check-php-allow-url-fopen.md)、check-mycnf-leak、check-backup-html-exposure
- analyzer 該当: `agent/analyzer.py` `WEBAPP_UPLOAD_PHP_PATTERNS`、`WEBAPP_DOTFILE_PATTERNS`
- 既存ドキュメント: 14_:V9 / 16_:#11 / 14_:6.5 (Apache 設定全文)

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-htaccess-rce__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-htaccess-rce
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
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-htaccess-rce__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
