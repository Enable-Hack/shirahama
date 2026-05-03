---
description: /var/www/cgi-bin/.my.cnf.6804 を Web 経由で読み取られた痕跡を確認 (DB 認証情報漏洩)
---

# /check:check-mycnf-leak — .my.cnf 公開ファイル読み取り確認

引数: `<時間窓> <ホスト>`
例: `/check:check-mycnf-leak 13:00-13:30 victor`

## 0. 前提

- 対象: **victor (10.1.1.2)**
- 関連 weakness: 14_:V5 / 16_:#12 — `/var/www/cgi-bin/.my.cnf.6804` (mode 644) と `.mysql.6804` が **Web 公開ディレクトリに認証なしで存在**。`AddHandler cgi-script .cgi .pi` でも .cnf は CGI 扱いされず、**生ファイルとして 200 で返る**
- 16_:1.5 で「最も危険な単一発見」と評価されている
- analyzer.py の対応 pattern_tag: `webapp/dotfile-access`
- /incident §0〜§0.6 を読み返してから実行すること

注意: **`/check:check-mysql-x-direct` は「33060 直接接続」を見るのに対し、本 check は「.my.cnf を読み取られた痕跡」に特化**。両方並行で叩くべき。

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
```

## 1. 収集 (read-only)

### 1.1 ファイル存在 + 権限確認

```bash
ssh "$TARGET_USER@$TARGET_HOST" \
  'sudo ls -la /var/www/cgi-bin/.my.cnf* /var/www/cgi-bin/.mysql* /var/www/html/.my.cnf* 2>/dev/null'

# 中身を直接読めるか (運営の仕込み物の確認)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo head -20 /var/www/cgi-bin/.my.cnf.6804 2>/dev/null | head -5'

# その他の .my.cnf 系
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /var/www -name ".my.cnf*" -ls 2>/dev/null'
```

### 1.2 アクセスログで直叩きの痕跡

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -5000 /var/log/httpd/access_log' > /tmp/check_mycnf_access.log

# /cgi-bin/.my.cnf.6804 への GET (200 が返れば漏洩確定)
grep -iE "/cgi-bin/\\.my\\.cnf|/cgi-bin/\\.mysql|\\.my\\.cnf\\.6804" /tmp/check_mycnf_access.log | tail -30

# 200 応答 (成立)
grep -iE "/cgi-bin/\\.my\\.cnf.* 200" /tmp/check_mycnf_access.log | tail -10
grep -iE "/cgi-bin/\\.mysql.* 200" /tmp/check_mycnf_access.log | tail -10

# 攻撃元 IP の集計
grep -iE "/cgi-bin/\\.my\\.cnf|/cgi-bin/\\.mysql" /tmp/check_mycnf_access.log \
  | awk '{print $1}' | sort | uniq -c | sort -rn | head
```

### 1.3 外部からの到達試験 (read-only)

```bash
# 200 が返るか実試験
curl -sI "http://10.1.1.2/cgi-bin/.my.cnf.6804" 2>&1 | head -3
curl -sI "http://10.1.1.2/cgi-bin/.mysql.6804" 2>&1 | head -3
curl -sI "http://www.com1.local/cgi-bin/.my.cnf.6804" 2>&1 | head -3
```

期待:
- 🚨 `200 OK` → 漏洩確定
- ✅ `403 Forbidden` / `404 Not Found` → 防御 OK

### 1.4 漏洩後の連鎖痕跡 (DB 直接アクセス)

```bash
# .my.cnf 漏洩 → MySQL 直接接続の痕跡
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -2000 /var/log/mariadb/mariadb.log /var/log/mysql/error.log /var/log/mysqld.log 2>/dev/null' \
  > /tmp/check_mycnf_mysql.log

# 同 IP からの DB 接続 (1.2 で抽出した IP と突合)
grep -iE "Connect|Access denied" /tmp/check_mycnf_mysql.log | tail -30
```

### 1.5 webshell 経路の確認

```bash
# Apache の cgi-bin に webshell が置かれてないか
ssh "$TARGET_USER@$TARGET_HOST" \
  'sudo find /var/www/cgi-bin -type f \( -name "*.cgi" -o -name "*.pl" -o -name "*.php" \) -ls 2>/dev/null'
```

### 1.6 JSONL 化

```bash
python scripts/preprocess/parse_clf.py /tmp/check_mycnf_access.log \
  | jq --arg start "$START" --arg end "$END" \
       'select(.timestamp >= $start and .timestamp <= $end)' \
  > /tmp/check_mycnf_access.jsonl
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. .my.cnf へ 200 応答 | access_log で 200、curl 試験で 200 | 🚨 確定 (DB 認証情報漏洩) |
| B. 同 IP の DB 直接アクセス | .my.cnf 取得後、同 IP が MySQL/MariaDB に Connect | 🚨 確定 (連鎖成立) |
| C. .my.cnf mtime 直近 | ファイル自体が直近更新 → 攻撃者が書き換えた可能性 | ⚠️ 疑わしい |
| D. analyzer tag | `webapp/dotfile-access` 発火 | 🚨 確定 |

## 3. 判定基準

- ✅ **正常**: .my.cnf へのアクセス 0、curl 試験で 403/404
- ⚠️ **疑わしい**: アクセス試行はあるが 403/404 のみ、200 なし
- 🚨 **確定**: A / B / D → **/playbook:wp-tamper** + **/playbook:ransomware** + **`/check:check-mysql-x-direct`** 並行

## 4. 次のアクション

### 確定なら
- **`/playbook:wp-tamper`** (Apache 設定経路の深掘り)
- **`/playbook:ransomware`** (DB 認証情報漏洩 → 横展開)
- 並行 **`/check:check-mysql-x-direct`** (33060 経由の直接接続)
- DB の **全アカウント認証情報変更** をリーダーへ進言

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: ファイルを退避 + 権限変更
# sudo cp /var/www/cgi-bin/.my.cnf.6804 /root/forensic_mycnf
# sudo chmod 600 /var/www/cgi-bin/.my.cnf.6804 && sudo chown apache:apache ...
# 案2: Apache で <FilesMatch "^\\."> Require all denied </FilesMatch>
# 案3: ファイル即削除 (forensic 観点から退避を先に)
```

### メモするだけ
- 16_:1.5 で「最も危険な単一発見」と評価されている → 確定したら最優先で対応
- DocumentRoot 配下の dotfile 公開は出題前提と完全一致

## 5. 参照

- 関連 playbook: [playbook/wp-tamper.md](../playbook/wp-tamper.md)、[playbook/ransomware.md](../playbook/ransomware.md)
- 連鎖先 check: [check-mysql-x-direct.md](check-mysql-x-direct.md)、[check-htaccess-rce.md](check-htaccess-rce.md)
- analyzer 該当: `agent/analyzer.py` `WEBAPP_DOTFILE_PATTERNS` (`webapp/dotfile-access`)
- 既存ドキュメント: 14_:V5 / 16_:#12 / 16_:1.5

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-mycnf-leak__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-mycnf-leak
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
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-mycnf-leak__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
