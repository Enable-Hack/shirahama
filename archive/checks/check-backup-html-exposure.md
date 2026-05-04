---
model: claude-haiku-4-5
description: /var/www/backup_html/ の旧 BBS / .swp / .bak が公開ツリーから読み取られた痕跡を確認
---

# /check:check-backup-html-exposure — backup_html 旧資産露出確認

引数: `<時間窓> <ホスト>`
例: `/check:check-backup-html-exposure 13:00-13:30 victor`

## 0. 前提

- 対象: **victor (10.1.1.2 / Rocky)**
- 関連 weakness: 14_:V7 / V8 / 16_:#13 — `/var/www/backup_html/` 配下に旧 BBS、`conf.cgi`、`log.dat`、`_careers.html.swp`、`*.bak` が残存。今は Alias 無しだが、`.htaccess` 1 行 / `Alias` 1 行で公開化される
- 影響: 過去 BBS の SQLi/RCE、設定情報漏洩、過去アカウント認証情報の流出
- analyzer.py の対応 pattern_tag: `webapp/dotfile-access`、`webapp/scanner-ua`、`webapp/upload-php`
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
```

## 1. 収集 (read-only)

### 1.1 backup_html の存在 + 内容スナップショット

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /var/www/backup_html -maxdepth 3 -type f 2>/dev/null | head -30'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo ls -la /var/www/backup_html 2>/dev/null'

# 危険拡張子の総点検
ssh "$TARGET_USER@$TARGET_HOST" \
  'sudo find /var/www/backup_html \( -name "*.swp" -o -name "*.bak" -o -name "*.cgi" -o -name "*.pl" -o -name "*.dat" -o -name ".git" \) -ls 2>/dev/null'
```

### 1.2 Apache 設定で backup_html が公開されていないかの確認

```bash
# Alias / Directory ディレクティブで backup_html が参照されていないか
ssh "$TARGET_USER@$TARGET_HOST" \
  'sudo grep -rE "backup_html|backup\\b" /etc/httpd/conf/ /etc/httpd/conf.d/ 2>/dev/null'

# 配下に .htaccess が新規で配置されていないか
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /var/www/backup_html -name ".htaccess" -ls 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /var/www -name ".htaccess" -mmin -120 -ls 2>/dev/null'
```

### 1.3 アクセス痕跡 (httpd access_log)

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -5000 /var/log/httpd/access_log' > /tmp/check_backup_access.log

# /backup_html/ への到達試行
grep -iE "GET /backup_html/" /tmp/check_backup_access.log | tail -30

# 200 応答 (= 公開された)
grep -iE "GET /backup_html/.* 200" /tmp/check_backup_access.log | tail -10

# .swp / .bak / .cgi 直叩き
grep -iE "GET /[^ ]+\\.(swp|bak|cgi|pl|dat)" /tmp/check_backup_access.log | tail -20

# vim swap (.html.swp) は典型的な過去ソース漏洩経路
grep -E "\\.swp" /tmp/check_backup_access.log | tail -10
```

### 1.4 外部から実際に到達するかの試験 (read-only)

```bash
# Web 経由で到達試験 (200 が返れば公開されている)
curl -sI "http://10.1.1.2/backup_html/" 2>&1 | head -3
curl -sI "http://10.1.1.2/backup_html/_careers.html.swp" 2>&1 | head -3
curl -sI "http://www.com1.local/backup_html/" 2>&1 | head -3
```

### 1.5 旧 BBS 配下の固有ファイル (権限 + mtime)

```bash
ssh "$TARGET_USER@$TARGET_HOST" \
  'sudo find /var/www/backup_html -type f \( -name "conf.cgi" -o -name "log.dat" -o -name "*.cnf" -o -name "config.php" -o -name "settings.php" \) -ls 2>/dev/null'

# 直近で touched されてないか
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /var/www/backup_html -type f -mmin -120 -ls 2>/dev/null'
```

### 1.6 JSONL 化

```bash
python scripts/preprocess/parse_clf.py /tmp/check_backup_access.log \
  | jq --arg start "$START" --arg end "$END" \
       'select(.timestamp >= $start and .timestamp <= $end)' \
  > /tmp/check_backup_access.jsonl
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. /backup_html/ への 200 応答 | access_log で 200、curl 試験で到達可 | 🚨 確定 (公開された) |
| B. .swp / .bak への 200 応答 | vim swap や設定 backup の取得成功 | 🚨 確定 (過去ソース漏洩) |
| C. .htaccess / Alias 新規配置 | conf.d/ に backup_html 参照、または backup_html/.htaccess 新規 | 🚨 確定 (公開化攻撃) |
| D. backup_html 配下 mtime 直近 | 攻撃者が書込済 (アップロード) | 🚨 確定 |
| E. 旧 BBS への scanner UA | wpscan/nikto が backup_html を探っている | ⚠️ 疑わしい (偵察中) |

## 3. 判定基準

- ✅ **正常**: backup_html へのアクセス 0 件、Alias なし、.htaccess なし
- ⚠️ **疑わしい**: E のみ → まだ公開されてないので 403/404 が返ってる → 設定維持で OK
- 🚨 **確定**: A / B / C / D → **/playbook:wp-tamper** + 漏洩内容のリーダー報告

## 4. 次のアクション

### 確定なら
- **`/playbook:wp-tamper`** (公開化された旧 BBS の RCE / SQLi 連鎖を疑う)
- 漏洩した過去アカウント認証情報を **棚卸し**、現用と一致するものは即パスワード変更
- 並行して **`/check:check-htaccess-rce`** (Apache `.htaccess` 経路の悪用)

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: backup_html を DocumentRoot 外に退避
# sudo mv /var/www/backup_html /root/forensic_backup_html
# 案2: Apache で Require all denied
# <Directory "/var/www/backup_html"> Require all denied </Directory>
# 案3: 不審な .htaccess を削除 (mv で退避)
```

### メモするだけ
- backup_html は出題側が用意した "おとり" の可能性も → 即削除はせず退避
- vim swap / .bak は forensic 価値があるので削除前に必ず保管

## 5. 参照

- 関連 playbook: [playbook/wp-tamper.md](../playbook/wp-tamper.md)
- 連鎖先 check: check-htaccess-rce、check-wp-config-leak
- analyzer 該当: `agent/analyzer.py` `WEBAPP_DOTFILE_PATTERNS`、`WEBAPP_SCANNER_PATTERNS`
- 既存ドキュメント: 14_:V7 / V8 / 16_:#13

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-backup-html-exposure__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-backup-html-exposure
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
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-backup-html-exposure__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
