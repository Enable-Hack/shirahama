---
description: Apache UserDir + Options Indexes による /home/<user>/public_html 列挙の痕跡を確認
---

# /check:check-userdir-listing — UserDir 列挙確認

引数: `<時間窓> <ホスト>`
例: `/check:check-userdir-listing 13:00-13:30 victor`

## 0. 前提

- 対象: **victor (10.1.1.2)**
- 関連 weakness: 14_:V14 (近) / 16_:#14 — `userdir.conf` で `<Directory /home/*/public_html> Options Indexes` → ユーザディレクトリのファイル列挙可能
- 影響: 100 学生のホームディレクトリ構造、過去ファイル、SSH キー漏洩の入口
- analyzer.py の対応 pattern_tag: `webapp/scanner-ua` (UA 由来)、直接対応なし
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
```

## 1. 収集 (read-only)

### 1.1 UserDir 設定確認

```bash
ssh "$TARGET_USER@$TARGET_HOST" \
  'sudo grep -E "^(UserDir|<Directory /home)" /etc/httpd/conf.d/userdir.conf /etc/httpd/conf/httpd.conf 2>/dev/null'

ssh "$TARGET_USER@$TARGET_HOST" \
  'sudo cat /etc/httpd/conf.d/userdir.conf 2>/dev/null | grep -iE "Options|AllowOverride|Require"'
```

期待 (危険):
- `UserDir public_html` 有効 + `Options Indexes` 含む

### 1.2 /~user/ 形式アクセス痕跡

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -5000 /var/log/httpd/access_log' > /tmp/check_userdir_access.log

# /~obuchi/ 等の試行
grep -iE "GET /~[a-zA-Z0-9_-]+/" /tmp/check_userdir_access.log | tail -30

# 200 応答 (= 公開された)
grep -iE "GET /~[a-zA-Z0-9_-]+/.* 200" /tmp/check_userdir_access.log | tail -10

# 試行されたユーザ名の集計 (ユーザ列挙の物証)
grep -oE "GET /~[a-zA-Z0-9_-]+/" /tmp/check_userdir_access.log \
  | sort | uniq -c | sort -rn | head -20
```

### 1.3 列挙された機密ファイル (.ssh / .bash_history 等)

```bash
grep -iE "GET /~[a-zA-Z0-9_-]+/(\\.ssh|\\.bash_history|\\.profile|id_rsa)" /tmp/check_userdir_access.log | tail -20
```

### 1.4 /home/*/public_html の存在確認

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo ls -la /home/*/public_html 2>/dev/null | head -30'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /home -name "public_html" -type d -ls 2>/dev/null'

# public_html 配下に PHP / 直近書き込みファイル
ssh "$TARGET_USER@$TARGET_HOST" \
  'sudo find /home/*/public_html -type f -mmin -120 -ls 2>/dev/null | head -10'
```

### 1.5 外部からの試験 (read-only)

```bash
curl -sI "http://10.1.1.2/~obuchi/" 2>&1 | head -3
curl -sI "http://10.1.1.2/~manage/" 2>&1 | head -3
curl -s "http://10.1.1.2/~obuchi/" 2>&1 | head -10  # body に Index of が含まれていれば確定
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. UserDir + Options Indexes | userdir.conf に上記 | 🚨 設定上の脆弱性 |
| B. /~user/ 200 応答 | access_log で 200 | 🚨 確定 (列挙可) |
| C. 機密 dotfile アクセス | .ssh / .bash_history への 200 | 🚨 確定 (漏洩) |
| D. ユーザ列挙ブルート | 多数の username で /~$user/ 試行 | ⚠️ 疑わしい (列挙中) |

## 3. 判定基準

- ✅ **正常**: UserDir 無効 / Options Indexes なし、/~user/ 試行 0
- ⚠️ **疑わしい**: A + D のみ → 設定リスク + 列挙試行として報告
- 🚨 **確定**: B / C → **/playbook:wp-tamper** + 該当ユーザの SSH 鍵棚卸

## 4. 次のアクション

### 確定なら
- **`/playbook:wp-tamper`** (Web 経由情報漏洩の流れ)
- 漏洩した authorized_keys / id_rsa 系の **即時無効化** をリーダーに進言
- 並行 **`/check:check-obuchi-777-hijack`** (777 だと public_html 経由でも書込可)

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: userdir.conf で Options から Indexes 削除
# 案2: <Directory /home/*/public_html> Require all denied で全停止
# 案3: UserDir disabled で UserDir 機能ごと停止
```

### メモするだけ
- 100 学生分の public_html が公開対象 → 影響範囲広い
- 出題側のシナリオで「ユーザ列挙が必要」が含まれるなら触らない判断もあり

## 5. 参照

- 関連 playbook: [playbook/wp-tamper.md](../playbook/wp-tamper.md)
- 連鎖先 check: [check-obuchi-777-hijack.md](check-obuchi-777-hijack.md)、[check-backup-html-exposure.md](check-backup-html-exposure.md)
- analyzer 該当: `agent/analyzer.py` `WEBAPP_SCANNER_PATTERNS`
- 既存ドキュメント: 16_:#14
