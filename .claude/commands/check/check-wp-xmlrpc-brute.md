---
description: WordPress XML-RPC ブルートフォースの痕跡を確認する (system.multicall 増幅 / wp.getUsersBlogs)
---

# /check:wp-xmlrpc-brute — XML-RPC ブルート確認

引数: `<時間窓> <ホスト>`
例: `/check:wp-xmlrpc-brute 13:00-13:30 victor`

## 0. 前提

- 対象: **victor** (本番 10.1.1.2 / Rocky Linux、WordPress 4.9.4 EOL)
- 関連 weakness: WP 4.9.4 で `xmlrpc.php` が有効、`system.multicall` で 1 リクエスト数百試行が可能
- analyzer.py の対応 pattern_tag: `webapp/xmlrpc`、`webapp/auth-bruteforce`（POST /xmlrpc.php が閾値超え）
- 「触らない」哲学: xmlrpc 無効化は **リーダー承認後**。観察のみ
- /incident §0〜§0.6 を読み返してから実行すること

```bash
# 本番: TARGET_USER=manage (sudo 可) / デモ OCI: TARGET_USER=rocky (sudo 可)
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
```

## 1. 収集 (read-only)

### 1.1 アクセスログから XML-RPC 叩きの抽出

```bash
# POST /xmlrpc.php を送信元 IP 集計 (高頻度なら brute 確定)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -E "POST /xmlrpc\\.php" /var/log/httpd/access_log' \
  | awk '{print $1}' | sort | uniq -c | sort -rn | head -10

# 時間窓フィルタ込みで生ログを保存
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -5000 /var/log/httpd/access_log' > /tmp/check_xmlrpc_access.log
grep -E "POST /xmlrpc\\.php" /tmp/check_xmlrpc_access.log | head -50
```

### 1.2 system.multicall の痕跡（増幅 brute の決定打）

```bash
# multicall 本体は POST body にあるため access_log には現れない。error_log と body ロギングを併用
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -i "system.multicall\\|wp.getUsersBlogs" /var/log/httpd/error_log' | tail -30

# mod_security 等で body ログがあれば
ssh "$TARGET_USER@$TARGET_HOST" 'sudo ls /var/log/httpd/ 2>/dev/null | grep -iE "modsec|audit"'
```

### 1.3 wp-login.php への brute 並行（xmlrpc が止められた場合の代替経路）

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -E "POST /wp-login\\.php" /var/log/httpd/access_log' \
  | awk '{print $1}' | sort | uniq -c | sort -rn | head -10
```

### 1.4 認証成功有無の確認（最重要）

```bash
# 200 応答 + 直後の wp-admin/ アクセスがあれば突破された可能性
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -E "POST /xmlrpc\\.php HTTP/[0-9.]+\" 200" /var/log/httpd/access_log' | tail -20

# WP 管理画面に新規セッションがないか
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -E "wp-admin/(profile|users|plugins)" /var/log/httpd/access_log' | tail -20
```

### 1.5 JSONL 化（analyzer 連携）

```bash
python scripts/preprocess/parse_clf.py /tmp/check_xmlrpc_access.log \
  | jq --arg start "$START" --arg end "$END" \
       'select(.timestamp >= $start and .timestamp <= $end)' \
  > /tmp/check_xmlrpc_access.jsonl
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. 単純 brute | 同一 IP から `POST /xmlrpc.php` が短時間に 50+ | ⚠️ 疑わしい |
| B. multicall 増幅 | `error_log` に `system.multicall` / 1 IP 単発でも内側で数百試行 | 🚨 確定 |
| C. 認証成功痕跡 | `xmlrpc.php` 200 応答 + 直後の `wp-admin/` 200 | 🚨 突破済 |
| D. UA スキャナ | `wpscan`, `xmlrpc-bruteforcer` 等の User-Agent | 🚨 確定 |
| E. analyzer tag | `webapp/xmlrpc` + `webapp/auth-bruteforce` 同時発火 | 🚨 確定 |

## 3. 判定基準

- ✅ **正常**: POST /xmlrpc.php が時間窓内 5 件未満、すべて pingback 由来 IP
- ⚠️ **疑わしい**: 同一 IP 10〜50 回 POST、403/401 返却が大半（ブロック効いている）
- 🚨 **確定**: パターン B / C / D いずれか観測 → ただちに **/playbook:wp-tamper** へ

## 4. 次のアクション

### 確定なら
- カテゴリ判定 → **`/playbook:wp-tamper`** で深掘り（rainloop / .my.cnf 漏洩との連鎖を確認）
- 突破済みなら **`/playbook:ransomware`** を並行起動（横展開・永続化チェック）

### 即時封じ手（リーダー承認後のみ提示 / 実行は別フロー）
```bash
# 案1: xmlrpc.php への外部アクセスを遮断 (Apache 側)
# /etc/httpd/conf.d/wp-block-xmlrpc.conf
# <Files "xmlrpc.php"> Require all denied </Files>

# 案2: 攻撃元 IP を一時 drop (settings.json で deny の可能性あり / 要確認)
# sudo iptables -I INPUT -s <IP> -j DROP
```

### メモするだけ（観察用）
- `xmlrpc.php` を完全無効化すると正規 pingback / Jetpack も切れる → 競技進行に影響
- 18_§4.3「触らない」を優先し、報告書ドラフトに残すのみ

## 5. 参照

- 関連 playbook: [playbook/wp-tamper.md](../playbook/wp-tamper.md)
- 既存ドキュメント: `docs/14_サーバ調査レポート_20260424.md` §「victor 脆弱性 TOP3」
- analyzer 該当: `agent/analyzer.py` `WEBAPP_AUTH_PATTERNS`、`_detect_auth_bruteforce`

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-wp-xmlrpc-brute__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-wp-xmlrpc-brute
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
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-wp-xmlrpc-brute__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
