---
model: claude-haiku-4-5
description: WordPress REST API 経由のユーザー列挙 (?author=N / wp-json/wp/v2/users) の痕跡を確認
---

# /check:wp-rest-author-scan — WP ユーザー列挙確認

引数: `<時間窓> <ホスト>`
例: `/check:wp-rest-author-scan 13:00-13:30 victor`

## 0. 前提

- 対象: **victor** (本番 10.1.1.2 / Rocky Linux、WordPress 4.9.4 EOL)
- 関連 weakness: WP 4.9.4 では `?author=N` リダイレクトと `wp-json/wp/v2/users` がデフォルト有効 → ログイン名露出
- analyzer.py の対応 pattern_tag: `webapp/author-scan`、`webapp/scanner-ua` (wpscan 等)
- 列挙単独はクリティカルではないが、**xmlrpc/login brute の前段** として頻出
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"   # 本番: manage / デモ: rocky
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
```

## 1. 収集 (read-only)

### 1.1 ?author=N の列挙痕跡

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -E "GET /\\?author=[0-9]+" /var/log/httpd/access_log' \
  | awk '{print $1, $7}' | sort | uniq -c | sort -rn | head -20

ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -5000 /var/log/httpd/access_log' > /tmp/check_authorscan_access.log
```

### 1.2 REST API ユーザー列挙

```bash
# wp-json/wp/v2/users（直接列挙エンドポイント）
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -E "GET /wp-json/wp/v2/users" /var/log/httpd/access_log' | tail -30

# 200 応答が返っていれば情報露出確定
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -E "GET /wp-json/wp/v2/users.* 200" /var/log/httpd/access_log' | tail -10
```

### 1.3 スキャナ UA の併用確認

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -iE "wpscan|nuclei|nikto|gobuster" /var/log/httpd/access_log' \
  | awk '{print $1}' | sort -u | head -10
```

### 1.4 列挙 → brute への遷移確認

```bash
# 同一 IP が author scan の後に POST /wp-login.php / xmlrpc.php を打っているか
SUSPECT_IP="<ここに 1.1 で出た上位 IP>"
ssh "$TARGET_USER@$TARGET_HOST" "sudo grep \"^$SUSPECT_IP \" /var/log/httpd/access_log | tail -50"
```

### 1.5 JSONL 化

```bash
python scripts/preprocess/parse_clf.py /tmp/check_authorscan_access.log \
  | jq --arg start "$START" --arg end "$END" \
       'select(.timestamp >= $start and .timestamp <= $end)' \
  > /tmp/check_authorscan_access.jsonl
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. ?author=N 連番列挙 | 同一 IP から `?author=1`...`?author=20` を順次 GET | ⚠️ 疑わしい |
| B. wp-json/wp/v2/users 200 | REST API でユーザー一覧露出 | ⚠️ 疑わしい (情報漏洩) |
| C. 列挙 → brute 連鎖 | author スキャン直後に同一 IP が `/wp-login.php` 多数 POST | 🚨 確定 |
| D. analyzer tag | `webapp/author-scan` 単発でも `webapp/scanner-ua` と同 IP で同時発火 | 🚨 確定 |

## 3. 判定基準

- ✅ **正常**: `?author=N` ヒット 0 / wp-json/users が 401-403 返却
- ⚠️ **疑わしい**: 列挙痕跡あり、brute 連鎖なし → 監視継続 + 報告書ドラフト
- 🚨 **確定**: パターン C / D → ただちに **/check:wp-xmlrpc-brute** で brute 痕跡確認 → **/playbook:wp-tamper**

## 4. 次のアクション

### 確定なら
- 連鎖確認 → **`/check:wp-xmlrpc-brute`**
- カテゴリ確定なら **`/playbook:wp-tamper`**

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: REST API users エンドポイントを 401 化（functions.php への hook）
# add_filter('rest_authentication_errors', ...) — 競技中に functions.php 改修はリスク高、案2 推奨
# 案2: Apache rewrite で /?author=N を 403
# RewriteRule ^/?author=([0-9]+) - [F,L]
```

### メモするだけ
- author 列挙は WP 4.9.4 のデフォルト挙動 = 出題前提の可能性高
- 18_§4.3「触らない」を優先

## 5. 参照

- 関連 playbook: [playbook/wp-tamper.md](../playbook/wp-tamper.md)
- 連鎖先 check: [check-wp-xmlrpc-brute.md](check-wp-xmlrpc-brute.md)
- analyzer 該当: `agent/analyzer.py` `WEBAPP_AUTH_PATTERNS` (`webapp/author-scan`)、`WEBAPP_SCANNER_PATTERNS`

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-wp-rest-author-scan__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-wp-rest-author-scan
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
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-wp-rest-author-scan__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
