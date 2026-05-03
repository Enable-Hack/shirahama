---
description: Telnet 23/tcp 平文認証の使用痕跡を確認 (認証情報スニッフ / 総当たり)
---

# /check:check-telnet-plain-auth — Telnet 平文認証確認

引数: `<時間窓> <ホスト>`
例: `/check:check-telnet-plain-auth 13:00-13:30 victor`

## 0. 前提

- 対象: **victor (10.1.1.2)**
- 関連 weakness: 14_:V1 / 16_:#1 — `telnet.socket` が **Active**、23/tcp listen → 認証情報が **平文で流れる** + 総当たり可能
- 影響: スニッフでの認証情報漏洩、平文 brute 攻撃の標的
- analyzer.py の対応 pattern_tag: `protocol/telnet-access`
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
```

## 1. 収集 (read-only)

### 1.1 listen 状態と service 状態

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo ss -tlnp | grep -E ":23\\b"'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo systemctl status telnet.socket telnet@.service 2>/dev/null | head -10'

# rpm 確認
ssh "$TARGET_USER@$TARGET_HOST" 'rpm -q telnet-server 2>/dev/null'
```

### 1.2 secure log での telnet ログイン痕跡

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -3000 /var/log/secure' > /tmp/check_telnet_secure.log

# telnet/in.telnetd プロセスのログイン記録
grep -iE "telnet|in\\.telnetd" /tmp/check_telnet_secure.log | tail -30

# login プロセス経由の対話ログイン
grep -iE "login\\[\\d+\\]:.*ROOT LOGIN|login\\[\\d+\\]:.*FAILED LOGIN" /tmp/check_telnet_secure.log | tail -20
```

### 1.3 23/tcp への接続元集計

```bash
# conntrack で 23 への確立済セッション
ssh "$TARGET_USER@$TARGET_HOST" 'sudo conntrack -L -p tcp --dport 23 2>/dev/null | head -20 || ss -tn state established sport = :23'

# pacct (プロセス会計) で in.telnetd の起動履歴
ssh "$TARGET_USER@$TARGET_HOST" 'sudo lastcomm in.telnetd 2>/dev/null | head -20'
```

### 1.4 brute force 痕跡

```bash
# FAILED LOGIN がまとまって出てれば brute
grep -iE "FAILED LOGIN" /tmp/check_telnet_secure.log | tail -30

# tcpdump 履歴があれば 23 ポートのトラフィック増を確認
ssh "$TARGET_USER@$TARGET_HOST" 'sudo ls /var/log/tcpdump_telnet* 2>/dev/null'
```

### 1.5 認証成功後のシェル活動

```bash
# telnet 経由のログインなら tty が pts/N で来る、who で確認
ssh "$TARGET_USER@$TARGET_HOST" 'who -a | grep -E "pts/"'

# /var/run/utmp の記録
ssh "$TARGET_USER@$TARGET_HOST" 'last -F | head -20'
```

### 1.6 JSONL 化

```bash
python scripts/preprocess/parse_secure.py /tmp/check_telnet_secure.log > /tmp/check_telnet_secure.jsonl
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. 23/tcp listen | telnet.socket Active | 🚨 設定上の脆弱性 |
| B. ROOT LOGIN | login プロセスで root が telnet ログイン | 🚨 確定 (平文 root 認証) |
| C. FAILED LOGIN burst | 同一 IP から複数失敗 | ⚠️ 疑わしい (brute 中) |
| D. 想定外ユーザの login 成功 | 配布アカウント以外 | 🚨 確定 |
| E. analyzer tag | `protocol/telnet-access` 発火 | ⚠️〜🚨 |

## 3. 判定基準

- ✅ **正常**: 23/tcp listen していない、または運用上の正規 telnet 接続のみ
- ⚠️ **疑わしい**: A / C / E のみ → 設定リスク + brute 試行として報告
- 🚨 **確定**: B / D → **/playbook:ransomware** + **`/check:check-known-attacker-ip`**

## 4. 次のアクション

### 確定なら
- **`/playbook:ransomware`** (平文 root 取得後の永続化を疑う)
- 並行して **`/check:check-known-attacker-ip`** (telnet ログイン元 IP)
- 並行して **`/check:check-courier-imap-plain`** (同じ平文プロトコル系)

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: telnet.socket 停止
# sudo systemctl disable --now telnet.socket
# 案2: 23/tcp を firewalld で deny
# 案3: rpm 削除 (運用影響あり)
# sudo dnf remove telnet-server
```

### メモするだけ
- 16_:#1 で「短期 (本日中)」対応リスト入り → 即対応候補
- ただし運営が telnet を業務利用している可能性 (設備管理) → 18_§4.3 で要確認

## 5. 参照

- 関連 playbook: [playbook/ransomware.md](../playbook/ransomware.md)
- 連鎖先 check: [check-known-attacker-ip.md](check-known-attacker-ip.md)、check-courier-imap-plain
- analyzer 該当: `agent/analyzer.py` `SECURE_PATTERNS` (`protocol/telnet-access`)
- 既存ドキュメント: 14_:V1 / 16_:#1

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-telnet-plain-auth__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-telnet-plain-auth
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
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-telnet-plain-auth__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
