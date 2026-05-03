---
description: atd 経由の at ジョブによる永続化痕跡を確認
---

# /check:check-at-job-persist — at ジョブ永続化確認

引数: `<時間窓> <ホスト>`
例: `/check:check-at-job-persist 13:00-13:30 victor`

## 0. 前提

- 対象: **bravo (10.1.1.1)** **victor (10.1.1.2)** 両方
- 関連 weakness: 16_:#36 — atd 稼働中 + `at` SUID あり → 一般ユーザが root として遅延実行ジョブを仕込める = **永続化バックドア**
- analyzer.py の対応 pattern_tag: `persist/at-job` (atd[PID] executing ログ)
- 連鎖: pkexec / obuchi 777 で root 取得 → `at` でジョブ仕込み → 検出を遅らせる
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
```

## 1. 収集 (read-only)

### 1.1 atd 稼働状態 + at SUID

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo systemctl is-active atd 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'ls -la /usr/bin/at /usr/bin/atq /usr/bin/atrm 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo cat /etc/at.allow /etc/at.deny 2>/dev/null'
```

期待 (危険):
- `atd active` + `/usr/bin/at` が `-rwsr-xr-x` (SUID)
- `/etc/at.allow` 不在 = 全ユーザ at 使用可

### 1.2 既存 at ジョブ一覧

```bash
# 全ユーザの atq (root 権限で見ないと全部見えない)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo atq 2>/dev/null'

# at spool 配下の実体
ssh "$TARGET_USER@$TARGET_HOST" 'sudo ls -la /var/spool/at/ /var/spool/cron/atjobs/ 2>/dev/null'

# 直近で追加されたジョブファイル
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /var/spool/at /var/spool/cron/atjobs -type f -mmin -120 -ls 2>/dev/null'
```

### 1.3 ジョブの中身 (実行されるコマンド)

```bash
# 各ジョブファイルをダンプ (シェルスクリプトとして読める)
ssh "$TARGET_USER@$TARGET_HOST" \
  'for f in $(sudo find /var/spool/at /var/spool/cron/atjobs -type f 2>/dev/null); do
     echo "=== $f ===";
     sudo cat "$f" | head -20;
   done'
```

### 1.4 atd 実行ログ (analyzer pattern_tag `persist/at-job`)

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -3000 /var/log/messages /var/log/secure 2>/dev/null' \
  > /tmp/check_at_log.log

# atd[PID]: executing
grep -iE "atd\\[[0-9]+\\]:.*executing" /tmp/check_at_log.log | tail -30

# 異常な実行ユーザ (root 以外で executing)
grep -iE "atd.*executing.*as.*[a-zA-Z0-9]+" /tmp/check_at_log.log | tail -10
```

### 1.5 cron との連鎖確認 (at + cron で多重永続化されてないか)

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo ls -la /etc/cron.d /etc/cron.hourly /etc/cron.daily 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /etc/cron* -type f -mmin -120 -ls 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /var/spool/cron -type f -ls 2>/dev/null'
```

### 1.6 JSONL 化

```bash
python scripts/preprocess/parse_secure.py /tmp/check_at_log.log > /tmp/check_at_secure.jsonl
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. /etc/at.allow 不在 + atd active | 全員 at 使用可 | 🚨 設定上の脆弱性 |
| B. 直近の at job 追加 | spool に mtime 直近のファイル | 🚨 確定 (永続化試行) |
| C. ジョブ中身が不審 | curl/wget で外部接続、reverse shell 等 | 🚨 確定 |
| D. analyzer tag | `persist/at-job` 発火 | 🚨 確定 |
| E. cron 直近変更 | at と並行で cron も触られている | 🚨 確定 (多重永続化) |

## 3. 判定基準

- ✅ **正常**: at job 0 件、at.allow で root のみ許可、atd 停止
- ⚠️ **疑わしい**: A のみ → 設定リスクとして報告
- 🚨 **確定**: B / C / D / E → **/playbook:ransomware** で永続化全工程

## 4. 次のアクション

### 確定なら
- **`/playbook:ransomware`** (永続化チェック全工程)
- 並行 **`/check:check-pkexec-pwnkit`** + **`/check:check-toor-uid0`** (root 取得経路)
- 不審ジョブを **`atrm` する前に内容を保管** (forensic)

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: 不審ジョブを atrm
# sudo atq | grep <suspect>; sudo atrm <jobid>
# 案2: at.allow に root のみ追加 + at.deny を空に
# echo "root" | sudo tee /etc/at.allow
# 案3: atd 停止 (他の at 利用がなければ)
# sudo systemctl disable --now atd
```

### メモするだけ
- atd は標準有効なので「触らない」候補だが、不審ジョブは攻撃の物証 → 退避してよい
- at SUID 剥奪は再起動後の cron job 等にも影響する可能性

## 5. 参照

- 関連 playbook: [playbook/ransomware.md](../playbook/ransomware.md)
- 連鎖先 check: [check-pkexec-pwnkit.md](check-pkexec-pwnkit.md)、[check-toor-uid0.md](check-toor-uid0.md)
- analyzer 該当: `agent/analyzer.py` `SECURE_PATTERNS` (`persist/at-job`)
- 既存ドキュメント: 16_:#36
