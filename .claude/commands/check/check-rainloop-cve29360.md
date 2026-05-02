---
description: RainLoop 1.12.0 の CVE-2022-29360 認証バイパス / SALT.php クレデンシャル復元の痕跡を確認
---

# /check:rainloop-cve29360 — RainLoop 認証バイパス確認

引数: `<時間窓> <ホスト>`
例: `/check:rainloop-cve29360 13:00-13:30 victor`

## 0. 前提

- 対象: **victor** (本番 10.1.1.2 / Rocky Linux、RainLoop 1.12.0)
- 関連 CVE: **CVE-2022-29360** (Stored XSS → 認証バイパス)、**SALT.php 露出** (data 配下、過去環境流用で残存可能性)
- analyzer.py の対応 pattern_tag: `xss/script-tag`, `xss/onerror-handler` (XSS 段)、`webapp/dotfile-access` (cfg 漏洩)
- RainLoop 設置パス推定: `/var/www/rain` (本番) / `/usr/share/rainloop` (デモ可能性あり)
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"   # 本番: manage / デモ: rocky
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
RAINLOOP_BASE="${RAINLOOP_BASE:-/var/www/rain}"
```

## 1. 収集 (read-only)

### 1.1 設置パスとバージョン確定（最初に必ず）

```bash
# 候補パスを総当たり
ssh "$TARGET_USER@$TARGET_HOST" 'for d in /var/www/rain /var/www/html/rain /usr/share/rainloop /var/www/rainloop; do
  test -d "$d" && echo "FOUND: $d" && cat "$d/rainloop/data/VERSION" 2>/dev/null && cat "$d/data/VERSION" 2>/dev/null
done'
```

### 1.2 /rain/ への攻撃トラフィック

```bash
# CVE-2022-29360 は管理画面経由のため /rain/?admin や /rain/?/Json/ への異常 POST を見る
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -E "(POST|GET) /rain/" /var/log/httpd/access_log' \
  | awk '{print $1, $6, $7}' | sort | uniq -c | sort -rn | head -20

ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -5000 /var/log/httpd/access_log' > /tmp/check_rainloop_access.log
```

### 1.3 SALT.php / cfg / storage への直接アクセス（情報漏洩）

```bash
# data/_data_/_default_/storage/cfg/<domain>/.account / .ini / SALT.php
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -iE "/rain/.*(SALT\\.php|/cfg/|/storage/|\\.account|/data/_data_)" /var/log/httpd/access_log' | tail -30

# 200 応答 = 漏洩確定
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -iE "/rain/.*(SALT\\.php|/storage/).* 200" /var/log/httpd/access_log' | tail -10
```

### 1.4 XSS payload の痕跡 (CVE-2022-29360 入り口)

```bash
# script タグ / onerror= / javascript: が URL や POST に混入していないか
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -iE "/rain/.*(<script|onerror=|javascript:|%3Cscript)" /var/log/httpd/access_log' | tail -20

# error_log に PHP warning が出ていれば XSS 注入が試行されている
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -i rainloop /var/log/httpd/error_log' | tail -30
```

### 1.5 ファイルシステム側の痕跡（権限と mtime）

```bash
# SALT.php / cfg ディレクトリの権限 (公開可読なら致命的)
ssh "$TARGET_USER@$TARGET_HOST" "sudo ls -la $RAINLOOP_BASE/rainloop/data/_data_/_default_/storage/cfg/ 2>/dev/null | head -20"
ssh "$TARGET_USER@$TARGET_HOST" "sudo find $RAINLOOP_BASE -name 'SALT.php' -ls 2>/dev/null"

# 直近 1 時間で更新された rainloop ファイル (改ざん痕跡)
ssh "$TARGET_USER@$TARGET_HOST" "sudo find $RAINLOOP_BASE -type f -mmin -60 2>/dev/null | head -30"
```

### 1.6 JSONL 化

```bash
python scripts/preprocess/parse_clf.py /tmp/check_rainloop_access.log \
  | jq --arg start "$START" --arg end "$END" \
       'select(.timestamp >= $start and .timestamp <= $end)' \
  > /tmp/check_rainloop_access.jsonl
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. SALT.php 直叩き 200 | `/rain/...SALT.php` GET で 200 応答 | 🚨 確定 (クレデンシャル漏洩) |
| B. /storage/cfg/ 列挙 | `cfg/` 配下を curl で読み取り | 🚨 確定 |
| C. XSS payload 注入 | `/rain/?Json/` に `<script>` / `onerror=` 含む POST | 🚨 確定 |
| D. /?admin への brute | `/rain/?admin` POST 連発 | ⚠️ 疑わしい |
| E. analyzer tag | `xss/*` または `webapp/dotfile-access` が rainloop 配下で発火 | 🚨 確定 |

## 3. 判定基準

- ✅ **正常**: /rain/ への通常メールアクセスのみ、SALT.php / storage への外部リクエストなし
- ⚠️ **疑わしい**: D のみ、A〜C 痕跡なし → 監視継続
- 🚨 **確定**: A〜C / E いずれか → **/playbook:wp-tamper** + **/playbook:phishing** (rainloop はメールサーバー乗っ取り経路)

## 4. 次のアクション

### 確定なら
- **`/playbook:wp-tamper`** (RainLoop 改ざん深掘り)
- **`/playbook:phishing`** (メール送信元として悪用される可能性 — open relay と連鎖)
- 漏洩疑いなら → ストアされたメールアカウントの **強制パスワード変更** をリーダーに進言

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: /rain/ 配下の data/ への直接アクセスを Apache で遮断
# <Directory "/var/www/rain/rainloop/data"> Require all denied </Directory>
# 案2: rainloop 自体を一時停止 (メール業務影響 — 慎重に)
```

### メモするだけ
- SALT.php は前年テスト環境からの流用残存物の可能性 → 残存チェックは事前に済ませる
- メール業務影響があるため、停止判断はリーダー必須

## 5. 参照

- 関連 playbook: [playbook/wp-tamper.md](../playbook/wp-tamper.md)、[playbook/phishing.md](../playbook/phishing.md)
- CVE: CVE-2022-29360 (RainLoop ≤ 1.16.0)
- analyzer 該当: `agent/analyzer.py` `XSS_PATTERNS`、`WEBAPP_DOTFILE_PATTERNS`
- 既存ドキュメント: `docs/16_攻撃分析と既存ファイルレビュー_20260427.md` §rainloop
