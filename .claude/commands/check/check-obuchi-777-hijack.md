---
description: /home/obuchi が 777 で authorized_keys 改竄 → SSH 乗っ取りされた痕跡を確認
---

# /check:check-obuchi-777-hijack — obuchi 777 SSH 乗っ取り確認

引数: `<時間窓> <ホスト>`
例: `/check:check-obuchi-777-hijack 13:00-13:30 victor`

## 0. 前提

- 対象: **victor (10.1.1.2)**
- 関連 weakness: 14_:V4 / 16_:#31 — `/home/obuchi` が **`drwxrwxrwx` (777)** → 任意ユーザが `~/.ssh/authorized_keys` を書込可能 → obuchi として SSH 乗っ取り
- 既知背景: 14_:5.9 / 8.1 — obuchi が **4/24 深夜に 10.1.129.10 から長時間ログイン** している = 既に乗っ取られた疑い濃厚
- 16_:1.5 で「最も危険な単一発見」の片割れ
- analyzer.py の対応 pattern_tag: `auth/ssh-failed`、`auth/ssh-invalid-user` (集計)、直接的な authorized_keys 改竄ルールなし
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
```

## 1. 収集 (read-only)

### 1.1 /home/obuchi の権限と中身

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo ls -la /home/obuchi 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo ls -la /home/obuchi/.ssh 2>/dev/null'

# authorized_keys の存在 + 権限 + mtime
ssh "$TARGET_USER@$TARGET_HOST" 'sudo ls -la /home/obuchi/.ssh/authorized_keys 2>/dev/null'

# 中身 (公開鍵のコメント部分は身元の手掛かり)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo cat /home/obuchi/.ssh/authorized_keys 2>/dev/null' \
  | awk '{print $1, substr($2,1,30)"...", $3}'
```

### 1.2 authorized_keys の直近変更検知

```bash
# 直近 7 日で更新された authorized_keys (全ユーザ)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /home /root -name "authorized_keys" -mtime -7 -ls 2>/dev/null'

# 既知ベースラインとの差分 (もしハッシュを保存してあれば)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo sha256sum /home/obuchi/.ssh/authorized_keys 2>/dev/null'
```

### 1.3 obuchi のログイン履歴 (last + secure)

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo last -F obuchi | head -30'

# secure ログから obuchi の Accepted を抽出
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -E "Accepted (password|publickey) for obuchi" /var/log/secure | tail -30'

# 公開鍵での認証なら fingerprint がログに出る (修正版 sshd の場合)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -E "Accepted publickey for obuchi.*ED25519|RSA SHA" /var/log/secure | tail -10'
```

### 1.4 obuchi のシェル履歴 (forensic)

```bash
# bash_history (777 なので攻撃者は消す可能性が高い)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo ls -la /home/obuchi/.bash_history 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -50 /home/obuchi/.bash_history 2>/dev/null'

# 直近の cmd
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /home/obuchi -type f -mmin -120 -ls 2>/dev/null | head -20'

# /tmp や /dev/shm に obuchi 所有のファイル
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /tmp /dev/shm -user obuchi -ls 2>/dev/null'
```

### 1.5 /home/obuchi 配下から特権昇格への連鎖

```bash
# obuchi の crontab / systemd user unit (永続化)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo crontab -u obuchi -l 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /home/obuchi -name "*.timer" -o -name "*.service" 2>/dev/null'

# obuchi 所有の SUID バイナリ (LPE 経路)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /home/obuchi -perm -4000 -ls 2>/dev/null'
```

### 1.6 JSONL 化

```bash
python scripts/preprocess/parse_secure.py /var/log/secure 2>/dev/null > /tmp/check_obuchi_secure.jsonl
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. authorized_keys mtime 直近 | 時間窓内に obuchi の authorized_keys 更新 | 🚨 確定 (改竄) |
| B. 想定外の公開鍵が含まれる | comment が運営/チームの形式と異なる | 🚨 確定 |
| C. publickey login 成功 | secure に Accepted publickey for obuchi | 🚨 確定 (乗っ取り成立) |
| D. obuchi 配下に直近書き込み | /home/obuchi 配下に新規ファイル / bash_history 削除痕跡 | 🚨 確定 |
| E. /tmp /dev/shm に obuchi 所有 | LPE / 永続化試行 | 🚨 確定 |
| F. 10.1.129.10 から obuchi login | 既知侵害 IP 由来 | 🚨 確定 |

## 3. 判定基準

- ✅ **正常**: authorized_keys mtime 古い、publickey login なし、配下に直近変更なし
- ⚠️ **疑わしい**: 777 のままだが authorized_keys 未配置 → 設定リスクとして報告
- 🚨 **確定**: A〜F のいずれか → **/playbook:ransomware** で全工程

## 4. 次のアクション

### 確定なら
- **`/playbook:ransomware`** (root 化 / 横展開を疑う)
- 並行して **`/check:check-known-attacker-ip`** (10.1.129.10 由来か確認)
- 並行して **`/check:check-pkexec-pwnkit`** (LPE 連鎖)
- obuchi のパスワード強制リセット + authorized_keys 棚卸 をリーダーに進言

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: chmod 700 /home/obuchi && chmod 600 /home/obuchi/.ssh/authorized_keys
# 案2: 不審な公開鍵をコメントアウト (ファイルを保管した上で)
# sudo cp /home/obuchi/.ssh/authorized_keys /root/forensic_obuchi_authkeys
# 案3: obuchi のログイン一時無効化 (passwd -l obuchi、SSH 鍵は残るので別途対応必要)
```

### メモするだけ
- 16_:1.5 で「最も危険な単一発見」の片割れ → 即対応案件
- 既に侵害済の前提なので、authorized_keys を削除する前に **必ず forensic 保管**
- /home/obuchi 配下の bash_history 消去は攻撃の痕跡 → 復元不可、別ログから推定

## 5. 参照

- 関連 playbook: [playbook/ransomware.md](../playbook/ransomware.md)
- 連鎖先 check: [check-known-attacker-ip.md](check-known-attacker-ip.md)、[check-pkexec-pwnkit.md](check-pkexec-pwnkit.md)
- analyzer 該当: `agent/analyzer.py` `SECURE_PATTERNS` (`auth/ssh-*`)
- 既存ドキュメント: 14_:V4 / 16_:#31 / 16_:1.5 / 14_:5.9 (obuchi の last 履歴)

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-obuchi-777-hijack__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-obuchi-777-hijack
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
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-obuchi-777-hijack__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
