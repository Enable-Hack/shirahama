---
model: claude-sonnet-4-6
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

## 6. 復旧/封じ込めコマンド (人間が手で実行)

⚠️ 以下は **すべて人間がリーダー承認後に手で実行する**コマンドです。
AI は表示・検証・突合のみ。実行には関与しません。
理由:
- タイポ / 不完全な diff / 旧設定上書きで復旧失敗 → サービスダウン継続のリスク
- settings.production.json で物理的に deny されているため AI 実行は不可
- チームが「自分たちで何を直しているか」を理解する必要がある（競技後の説明責任）

```text
# 攻撃元 IP の即時遮断 (HTTP / WP-login brute 緊急対応)
iptables -I INPUT -s <ATTACKER_IP> -j DROP

# WordPress xmlrpc.php / wp-cron.php の一時退避 (brute / amplification 遮断)
mv /var/www/wordpress/xmlrpc.php /var/www/wordpress/xmlrpc.php.disabled
mv /var/www/wordpress/wp-cron.php /var/www/wordpress/wp-cron.php.disabled

# wp-config.php の権限戻し (640 / owner=apache:apache)
chown apache:apache /var/www/wordpress/wp-config.php
chmod 640 /var/www/wordpress/wp-config.php

# uploads 配下の不審 PHP/PHTML/PHAR を退避 (webshell 即時隔離)
find /var/www/wordpress/wp-content/uploads -type f \( -name "*.php" -o -name "*.phtml" -o -name "*.phar" \) -exec mv {} /tmp/evidence_webshell/ \;

# .htaccess に PHP 実行禁止を追加 (uploads 配下からの RCE 遮断)
cat >> /var/www/wordpress/wp-content/uploads/.htaccess <<'HTACCESS'
<FilesMatch "\.(php|phtml|phar|pl)$">
    Require all denied
</FilesMatch>
HTACCESS

# obuchi/.ssh/authorized_keys 退避 (横展開ルート遮断 / 18_ #8)
mv /home/obuchi/.ssh/authorized_keys /tmp/evidence_obuchi_authkeys.bak
chmod 700 /home/obuchi

# Apache 再読込 (上記 .htaccess / 退避を反映)
apachectl -t   # 構文チェック先
apachectl graceful
```

→ 表示後、§7 cmd_validator gate を必ず通すこと。
→ サービス影響あるので、リーダー承認 + 顧客通知後に人間が手で実施。

## 7. コマンド検証ゲート（封じ込めコマンド提示時 必須）

**この playbook が封じ込め / 復旧コマンドを 1 行でも提示する場合**、リーダーに見せる前に必ず `agent/cmd_validator.py` を通すこと。settings.production.json で封じ込め系 + 復旧系 (cp /etc/, mv /etc/, sysctl -w 等) は deny になっており **AI は実行できない** — 提案文字列の事故防止が validator の役割。

```bash
# 提示候補を一時ファイルに書き出す（コメント行に「※リーダー承認後」を含めること）
cat > /tmp/playbook_proposed.sh <<'EOF'
# ※リーダー承認後 + 顧客通知後に人間が手で実行すること
# (以下、AI が生成した封じ込め / 復旧コマンドを並べる)
ssh manage@10.1.1.2 'sudo iptables -I INPUT -s <ATTACKER_IP> -j DROP'
EOF

# 検証
PYTHONPATH=. ${SHIRAHAMA_PY:-python3} -m agent.cmd_validator /tmp/playbook_proposed.sh
echo "exit=$?"
```

判定:
- `exit=0` ✅ — リーダーに提示してよい。承認後に**人間が手で打つ**
- `exit=1` 🚨 — ERROR あり。リーダーに見せず AI が再生成（自爆 IP / 触禁ホスト / sudo 不可ホスト等）
- WARN のみ — 提示してよいが補足説明を添える

## 8. JSON 永続化（HTML dashboard 連携）

§6 の対策コマンド + §7 の cmd_validator 結果を JSON 化して helper に渡す。actor は `ai_human` (AI 提案 → 人間実行) を明示。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh playbook-wp-tamper --actor ai_human
{
  "inputs": {
    "scenario": "wp-tamper",
    "incident_id": "$INCIDENT_ID"
  },
  "outputs": {
    "proposed_commands": [
      "<§6 で提案したコマンド全文 (1 行 1 件)>"
    ],
    "cmd_validator_result": {
      "exit_code": 0,
      "errors": [],
      "warnings": ["<§7 cmd_validator が出した WARN/ERROR>"]
    },
    "scope": {
      "in_scope": ["<受電内容と直結する対策>"],
      "out_of_scope_logged": ["<観察したが今回触らないもの (治しすぎない哲学)>"]
    }
  },
  "verdict": {
    "status": "🚨 | ⚠️ | ✅",
    "summary": "<提案 N 件 (validator PASS), 採用は人間判断>"
  },
  "next_skills": ["/report", "/ticket"]
}
JSON_EOF
```

- `actor=ai_human` で「AI が提案、人間が実行」を JSON 上で明示 (dashboard が UI 上で「未実行/実行済」バッジを出せる)
- `proposed_commands[]` は §6 で提案した対策コマンドを 1 行 1 件で羅列。`text` フェンス内のコマンドをそのまま転記
- `cmd_validator_result` は §7 で実行した `agent.cmd_validator` の exit_code + errors + warnings をそのまま入れる
- `scope.out_of_scope_logged` で「観察したが今回触らない」項目を残し、報告書/ticket での記録に使う (治しすぎない哲学)
- 保存先: `data/incidents/${INCIDENT_ID}/playbook-wp-tamper__<ts>.json`
