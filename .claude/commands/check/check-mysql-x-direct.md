---
description: MySQL X Protocol (33060/tcp) への外部直接接続の痕跡を確認
---

# /check:mysql-x-direct — MySQL X Protocol 直叩き確認

引数: `<時間窓> <ホスト>`
例: `/check:mysql-x-direct 13:00-13:30 victor`

## 0. 前提

- 対象: **victor (10.1.1.2)** および **bravo (10.1.1.1)** いずれも MySQL X Protocol 33060/tcp 開放
- 関連 weakness: `bind-address = *` + 33060/tcp が外部到達可 → `mysqlsh --uri user@host:33060` で直接認証可能
- 関連 file: `/var/www/cgi-bin/.my.cnf.6804` (mode 644 推定 / 18_ #17) に DB 認証情報が公開可読 → 認証情報も漏れている前提
- analyzer.py の対応 pattern_tag: **直接対応ルールなし** (TODO: `db/x-direct-connect` ルール追加検討。現状は webapp/dotfile-access で .my.cnf 漏洩を検出するのみ)
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"   # 本番: manage / デモ: rocky
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
```

## 1. 収集 (read-only)

### 1.1 33060 が外部到達可かの確認

```bash
ssh "$TARGET_USER@$TARGET_HOST" "ss -tlnp 2>/dev/null | grep -E ':3306|:33060'"
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -iE "bind-address|mysqlx_bind_address|mysqlx_port" /etc/my.cnf /etc/my.cnf.d/*.cnf 2>/dev/null'

# 外部から 33060 に届くか (攻撃者目線)
nc -zv "$TARGET_HOST" 33060 2>&1 | head -3
nc -zv "$TARGET_HOST" 3306  2>&1 | head -3
```

### 1.2 .my.cnf 漏洩経路（X Protocol 認証情報の入手元）

```bash
# 18_ #17 .my.cnf.6804 が cgi-bin 配下で公開可読か
ssh "$TARGET_USER@$TARGET_HOST" 'sudo ls -la /var/www/cgi-bin/.my.cnf* /var/www/html/.my.cnf* 2>/dev/null'

# httpd access_log で .my.cnf に対する 200 応答があれば漏洩確定
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -E "/cgi-bin/\\.my\\.cnf" /var/log/httpd/access_log' | tail -20
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -E "/cgi-bin/\\.my\\.cnf.* 200" /var/log/httpd/access_log' | tail -10
```

### 1.3 mysqld の接続ログ（X Protocol 接続痕跡）

```bash
# general_log が ON なら接続が記録される（多くは OFF）
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -iE "general_log|log_error" /etc/my.cnf /etc/my.cnf.d/*.cnf 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -3000 /var/log/mysql/error.log /var/log/mysqld.log 2>/dev/null' \
  > /tmp/check_mysqlx_error.log

# X Protocol 由来の接続/切断（"X Plugin" "Plugin mysqlx" などのキーワード）
grep -iE "X Plugin|mysqlx|Plugin\\s+mysqlx|address.*33060" /tmp/check_mysqlx_error.log | tail -30

# 認証失敗
grep -iE "Access denied for user.*@" /tmp/check_mysqlx_error.log | tail -30
```

### 1.4 OS 側の接続痕跡（conntrack / firewalld 不在の確認）

```bash
# conntrack で 33060 の established/recent
ssh "$TARGET_USER@$TARGET_HOST" 'sudo conntrack -L -p tcp --dport 33060 2>/dev/null | head -20 || ss -tn state established sport = :33060 2>/dev/null'

# firewalld / iptables 状態（"全 ACCEPT" だと外部直叩き許容）
ssh "$TARGET_USER@$TARGET_HOST" 'sudo systemctl is-active firewalld 2>/dev/null; sudo iptables -nvL INPUT 2>/dev/null | head -20'
```

### 1.5 横展開の物証（DB 経由で取られた疑い）

```bash
# attacker が DB 経由で SELECT INTO OUTFILE で webshell 設置していないか
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /var/www -mmin -120 -name "*.php" 2>/dev/null | head -20'

# user テーブル乗っ取り (新規 root 風アカウント追加) は CLI で要確認
# (実行は read-only に留めるため select のみ、リーダー判断後)
# echo "SELECT user, host, password_last_changed FROM mysql.user;" | mysql -h $TARGET_HOST -P 3306 -u <ro-user> -p
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. 33060 外部到達可 | `nc -zv` で接続成功、bind-address が `*` | 🚨 設定上の脆弱性 |
| B. .my.cnf 200 応答 | httpd access_log で .my.cnf への GET が 200 | 🚨 確定 (認証情報漏洩) |
| C. X Plugin 接続ログ | mysqld error.log に X Plugin 由来の接続記録、外部 IP | 🚨 確定 (悪用) |
| D. Access denied burst | `Access denied for user` が同一 IP から多発 | ⚠️ 疑わしい (brute 試行) |
| E. INTO OUTFILE 痕跡 | /var/www 配下に直近作成された PHP ファイル | 🚨 確定 (webshell 設置) |

## 3. 判定基準

- ✅ **正常**: 33060 がローカルバインドのみ、.my.cnf 公開なし、X Plugin 接続記録なし
- ⚠️ **疑わしい**: A のみ + 接続痕跡なし → 設定不備として報告 + 監視
- 🚨 **確定**: B / C / E → **/playbook:wp-tamper** + **/playbook:ransomware** 並行起動

## 4. 次のアクション

### 確定なら
- **`/playbook:wp-tamper`** (.my.cnf 漏洩経路としての WP / Apache を深掘り)
- **`/playbook:ransomware`** (DB 経由で webshell 設置 → 横展開を疑う)
- 並行して **`/check:wp-xmlrpc-brute`** (DB 認証情報があれば WP も同時に取られている前提)

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: bind-address を 127.0.0.1 / 10.1.1.2 のみに制限 → mysqld 再起動
# 案2: 33060 を一時 firewall block (firewalld 起動 + rich rule)
# 案3: .my.cnf.6804 のパーミッションを 600 に
# chmod 600 /var/www/cgi-bin/.my.cnf.6804 && chown apache:apache ...
```

### メモするだけ
- analyzer に **`db/x-direct-connect`** 相当のルールがない → 新規追加検討（ただし「不足が見つかったらメモするだけ」方針）
- mysqld の general_log は通常 OFF なので接続痕跡が取れない可能性 → conntrack / netflow 側で補完
- .my.cnf は出題前提の典型的な公開ファイル

## 5. 参照

- 関連 playbook: [playbook/wp-tamper.md](../playbook/wp-tamper.md)、[playbook/ransomware.md](../playbook/ransomware.md)
- 連鎖先 check: [check-wp-xmlrpc-brute.md](check-wp-xmlrpc-brute.md)
- analyzer 該当: `agent/analyzer.py` `WEBAPP_DOTFILE_PATTERNS` (.my.cnf 漏洩経路のみ。X Protocol 直叩き本体のルールは未実装)
- 既存ドキュメント: `docs/14_サーバ調査レポート_20260424.md` §「.my.cnf.6804 公開」、`docs/16_本番環境クイックリファレンス_whiskey.md`

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-mysql-x-direct__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-mysql-x-direct
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
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-mysql-x-direct__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
