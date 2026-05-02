---
description: WordPress / rainloop / PHP 脆弱性攻撃の深掘り。/incident で WP 系検出された後に叩く
---

# /wp-tamper — WordPress 改ざん深掘り

## 0. 前提（必ず最初に確認）

- 対象: **victor (10.1.1.2 / Rocky Linux)** — manage で sudo 可、root パス `KCom10sT`
- ドメイン: `com1.local`、DocumentRoot は `/var/www/wordpress`（推定、§1.1 で要確認）
- /incident の §0 共通定数を必ず参照
- ⚠️ 「触らない」が正解の可能性 — 18_§4.3、対策は運営合意後に限る

## 1. 追加収集コマンド（read-only）

### 1.1 環境確認（パス推定の検証 — 必ず最初に）

```bash
# WP のインストール先と version (com1.local 環境では /var/www/html か /var/www/wordpress)
ssh manage@10.1.1.2 'sudo grep -E "DocumentRoot|Alias" /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf 2>/dev/null | grep -v "^#"'
ssh manage@10.1.1.2 'for d in /var/www/html /var/www/wordpress /var/www; do test -f $d/wp-includes/version.php && echo "WP at $d:" && grep wp_version $d/wp-includes/version.php; done'

# rainloop のパス (com1.local では /var/www/rain と推定)
ssh manage@10.1.1.2 'for d in /var/www/rain /var/www/html/rain; do test -d $d && echo "Rainloop at $d:" && cat $d/rainloop/data/VERSION 2>/dev/null && cat $d/data/VERSION 2>/dev/null; done'

# PHP 版数 (7.2.24 EOL 想定)
ssh manage@10.1.1.2 'php -v 2>&1 | head -3'
```

### 1.2 攻撃痕跡の収集（18_ #16-30 由来）

```bash
# httpd-access.log: 攻撃トラフィック (時間窓は呼び出し側で絞る)
ssh manage@10.1.1.2 'sudo tail -2000 /var/log/httpd/access_log' > /tmp/incident_access.log

# httpd-error.log: PHP エラー / 不審 include
ssh manage@10.1.1.2 'sudo tail -500 /var/log/httpd/error_log' > /tmp/incident_httpd_err.log

# 18_ #17 .my.cnf 系の dotfile 直叩き
ssh manage@10.1.1.2 'sudo grep -E "/cgi-bin/\\.|/\\.env|/\\.git|/\\.htaccess|/\\.ssh" /var/log/httpd/access_log | tail -30'

# 18_ #19 wp-login / xmlrpc への brute (POST 連発)
ssh manage@10.1.1.2 'sudo grep -E "POST .*(wp-login|xmlrpc|wp-admin)" /var/log/httpd/access_log | awk "{print \$1}" | sort | uniq -c | sort -rn | head -10'

# 18_ #20 backup_html 配下が公開されてないか (Alias 追加されてないか)
ssh manage@10.1.1.2 'curl -sI http://www.com1.local/backup_html/ 2>&1 | head -3'

# 18_ #29 PHP の disable_functions が緩いか
ssh manage@10.1.1.2 'php -i 2>/dev/null | grep -iE "expose_php|disable_functions|open_basedir|allow_url_fopen|short_open_tag"'

# uploads 配下に PHP / PHTML / PHAR が居ないか (webshell 痕跡)
ssh manage@10.1.1.2 'sudo find /var/www -path "*/uploads/*" \( -name "*.php" -o -name "*.phtml" -o -name "*.phar" -o -name "*.pl" \) -mtime -1 2>/dev/null'

# 不審な mtime (直近 1 時間の変更)
ssh manage@10.1.1.2 'sudo find /var/www -type f -mmin -60 2>/dev/null | head -30'

# 18_ #25-26 rainloop cfg / SALT (前年認証情報残存リスク)
ssh manage@10.1.1.2 'sudo ls /var/www/rain/data/_data_/_default_/storage/cfg/*/ 2>/dev/null | head'

# Apache 設定の AllowOverride / Options ExecCGI (18_ #16 #18)
ssh manage@10.1.1.2 'sudo grep -E "AllowOverride|Options.*ExecCGI|AddHandler" /etc/httpd/conf/httpd.conf /etc/httpd/conf.d/*.conf 2>/dev/null'
```

### 1.3 JSONL 化（analyzer に流す前段）

```bash
START="..." END="..."  # 時間窓 (HH:MM 形式 → ISO に変換)
python scripts/preprocess/parse_clf.py /tmp/incident_access.log \
  | jq --arg start "$START" --arg end "$END" \
       'select(.timestamp >= $start and .timestamp <= $end)' \
  > /tmp/incident_access.jsonl
```

## 2. Mock パターン参照

`analyzer.py` の以下の pattern_tag を見る:
- `xss/script-tag`, `xss/onerror-handler`
- `sqli/union-select`, `sqli/or-tautology`
- `wp-bruteforce`（POST /wp-login.php 連発）
- `rainloop-known`（CVE-2022-29360 等）
- `path-traversal`

## 3. Claude 投入用プロンプト

```
以下は victor (10.1.1.2) で観測された WordPress / rainloop 関連のシグナルです。
14_サーバ調査レポート で WP 4.9.4 + rainloop 1.12.0 + PHP 7.2.24 EOL が確認されています。

シグナル: <ここに analyzer 出力を貼る>

以下を出力してください:
1. 攻撃の手口推定（具体的 CVE 番号があれば明記）
2. 即時対応すべきコマンド 3 つ（コピペで実行可能な形式）
3. 顧客向け説明（200 字以内、技術用語なし）
4. 経営層報告のドラフト（300 字以内）
```

## 4. 既存 playbook 参照

- `03_シナリオ別対応プレイブック.md` §2 「WordPress改ざん」
- `06_DDoS対応詳細.md`（WP brute force が DDoS 化した場合）
- `14_サーバ調査レポート_20260424.md` §「victor 脆弱性 TOP3」

## 5. 報告書テンプレ生成指示

`04_完了報告テンプレート.md` の構造で出力:
- 事象概要 / 検知経緯 / 影響範囲 / 原因 / 対応内容 / 再発防止
