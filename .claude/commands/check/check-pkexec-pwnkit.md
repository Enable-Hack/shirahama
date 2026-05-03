---
description: PwnKit (CVE-2021-4034) による pkexec ローカル権限昇格の痕跡を確認
---

# /check:pkexec-pwnkit — PwnKit (CVE-2021-4034) 確認

引数: `<時間窓> <ホスト>`
例: `/check:pkexec-pwnkit 13:00-13:30 victor`

## 0. 前提

- 対象: **victor** (本番 10.1.1.2 / Rocky Linux、polkit 0.115 系で PwnKit 影響範囲)
- 関連 CVE: **CVE-2021-4034** (`pkexec` SUID + 引数 0 件で `GCONV_PATH` 経由任意コード実行 → root)
- analyzer.py の対応 pattern_tag: `privesc/pkexec-attempt`
- これが成立 = **既に低権限の足場（webshell / SSH 一般ユーザ）を取られている** 前提
- 連鎖先: 必ず **/playbook:ransomware** (横展開・永続化を疑う)
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"   # 本番: manage / デモ: rocky
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
```

## 1. 収集 (read-only)

### 1.1 SUID 状態確認（脆弱性の存在）

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'ls -la /usr/bin/pkexec /usr/lib/polkit-1/polkit-agent-helper-1 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'rpm -q polkit polkit-libs 2>/dev/null'
```

期待:
- `-rwsr-xr-x ... /usr/bin/pkexec` → SUID あり = 脆弱
- polkit < 0.120 → CVE 該当版

### 1.2 secure / messages の pkexec 異常ログ（攻撃成立の物証）

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -3000 /var/log/secure'   > /tmp/check_pkexec_secure.log
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -3000 /var/log/messages' > /tmp/check_pkexec_msg.log

# PwnKit の典型シグナル: GCONV_PATH 環境変数 / "The value for the SHELL variable was not found"
grep -iE "pkexec.*(GCONV_PATH|CHARSET=|gconv|The value for the SHELL variable was not found)" \
  /tmp/check_pkexec_secure.log /tmp/check_pkexec_msg.log | tail -30

# pkexec 実行記録自体（正規でも出るが、低権限ユーザが叩いていれば異常）
grep -iE "pkexec.*\\[.*\\]" /tmp/check_pkexec_secure.log | tail -20
```

### 1.3 pkexec 実行ユーザの素性チェック

```bash
# Apache (httpd) や mysql 等のサービスユーザが pkexec を叩いていれば確定
grep -iE "pkexec" /tmp/check_pkexec_secure.log | grep -iE "httpd|apache|nobody|nginx|mysql" | tail -10

# 直近の uid 0 化 (su - / sudo -i) との時系列付き合わせ
grep -iE "session opened for user root|COMMAND=" /tmp/check_pkexec_secure.log | tail -30
```

### 1.4 補助的物証: bash_history と auth.log の異常 SSH

```bash
# 直近に編集された bash_history (特権ユーザ含む)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /home /root -name ".bash_history" -mmin -120 -ls 2>/dev/null'

# /tmp や /dev/shm に suid 化された実行ファイル (PwnKit exploit 残骸の典型置き場)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /tmp /dev/shm -perm -4000 -mmin -120 2>/dev/null'

# 攻撃元の SSH 流入 (低権限の足場が SSH 経由ならここに痕跡)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -E "Accepted password|Accepted publickey" /var/log/secure' | tail -30
```

### 1.5 JSONL 化

```bash
python scripts/preprocess/parse_secure.py /tmp/check_pkexec_secure.log > /tmp/check_pkexec_secure.jsonl
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. GCONV_PATH 痕跡 | secure に `GCONV_PATH=` または `CHARSET=` を含む pkexec ログ | 🚨 確定 (PwnKit 試行) |
| B. pkexec by service user | `apache`, `httpd`, `nobody`, `mysql` 等が pkexec 実行 | 🚨 確定 |
| C. /tmp に SUID バイナリ | `/tmp` `/dev/shm` 配下に直近 SUID 付きファイル | 🚨 確定 |
| D. SHELL variable error | secure に `The value for the SHELL variable was not found` | 🚨 確定 (CVE-2021-4034 シグネチャ) |
| E. analyzer tag | `privesc/pkexec-attempt` 発火 | 🚨 確定 |

## 3. 判定基準

- ✅ **正常**: pkexec 実行ログ 0 件、SUID なし or polkit ≥ 0.120
- ⚠️ **疑わしい**: pkexec 実行ログはあるが正規ユーザ（admin 等）のみ → 実行内容を確認
- 🚨 **確定**: A〜E いずれか → **既に root 取られた前提で /playbook:ransomware 並行起動**

## 4. 次のアクション

### 確定なら
- **`/playbook:ransomware`** (root 化後の横展開・永続化チェックは ransomware playbook が担当)
- 並行して **`/check:obuchi-777-hijack`** (足場が SSH 経由なら authorized_keys 改竄も疑う / 第二優先で予定)
- リーダーへ「権限昇格成立、影響範囲調査開始」を即報告

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: pkexec の SUID を一時剥奪 (ただし polkit 経由の正規 GUI sudo が止まる)
# chmod 0755 /usr/bin/pkexec
# 案2: polkit を更新（dnf update polkit — settings.json で deny の可能性あり）
```

### メモするだけ
- root 取られた以降のあらゆる「正常そうなログ」も信用できない → forensic 観点で全ログを別保管
- attacker が `/etc/passwd` に toor:0 を追加している可能性 → `/check:toor-uid0` (第二優先) を後で叩く

## 5. 参照

- 関連 playbook: [playbook/ransomware.md](../playbook/ransomware.md)
- 連鎖先 check: check-obuchi-777-hijack (Second priority、未作成)、check-toor-uid0 (Second priority、未作成)
- CVE: CVE-2021-4034 (Qualys disclosure 2022-01)
- analyzer 該当: `agent/analyzer.py` `SECURE_PATTERNS` (`privesc/pkexec-attempt`)

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-pkexec-pwnkit__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-pkexec-pwnkit
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
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-pkexec-pwnkit__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
