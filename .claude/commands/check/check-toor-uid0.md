---
description: bravo /etc/passwd の toor:0 UID0 重複アカウント悪用痕跡を確認
---

# /check:check-toor-uid0 — toor UID0 重複アカウント確認

引数: `<時間窓> <ホスト>`
例: `/check:check-toor-uid0 13:00-13:30 bravo`

## 0. 前提

- 対象: **bravo (10.1.1.1 / FreeBSD)**
- 関連 weakness: 16_:#28 / 16_:2.4 — `/etc/passwd` に **`toor:*:0:0:...:/root:/bin/sh`** (UID 0 重複アカウント)。FreeBSD 慣習だが、攻撃者が toor で SSH 入れば root 同等で監査ログが分離不能
- 影響: root 監査ログを汚さずに root 同等操作可能 / 既知のデフォルトアカウント名なので brute 標的になりやすい
- analyzer.py の対応 pattern_tag: `auth/ssh-failed`、`auth/ssh-invalid-user` (集計)、`privesc/sudo-unauthorized`
- ⚠️ **bravo の manage は sudo 不可** — root が必要なら `ssh root@10.1.1.1` 直ログイン
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.1}"
```

## 1. 収集 (read-only)

### 1.1 /etc/passwd の UID 0 重複確認

```bash
# UID 0 のエントリを全列挙
ssh "$TARGET_USER@$TARGET_HOST" 'awk -F: "\\$3==0 {print}" /etc/passwd'

# toor が存在し、shell が /usr/sbin/nologin でない場合は危険
ssh "$TARGET_USER@$TARGET_HOST" 'grep -E "^toor:" /etc/passwd /etc/master.passwd 2>/dev/null'
```

期待:
- ✅ root のみが UID 0、または toor の shell が `/usr/sbin/nologin`
- 🚨 toor が UID 0 で `/bin/sh` 起動可能

### 1.2 toor のパスワード状態 (ロックされてるか)

```bash
# FreeBSD では /etc/master.passwd の 2 列目で hash 確認 (`*` ならロック)
ssh root@10.1.1.1 'grep -E "^toor:" /etc/master.passwd 2>/dev/null' | awk -F: '{print $1, length($2), substr($2,1,1)}'

# 期待:
# `toor 1 *` (length=1, char=*) → ロック済 ✅
# `toor 80+ $` (length=80前後, char=$) → 有効パスワードあり 🚨
```

### 1.3 toor のログイン履歴

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'last -F toor 2>/dev/null | head -20'

# secure / auth.log (FreeBSD は /var/log/auth.log)
ssh "$TARGET_USER@$TARGET_HOST" 'grep -E "(Accepted|Failed).*for toor" /var/log/auth.log 2>/dev/null' | tail -30

# bravo は manage で auth.log 読めない場合は root 切替
ssh root@10.1.1.1 'grep -E "(Accepted|Failed).*for toor" /var/log/auth.log 2>/dev/null' | tail -30
```

### 1.4 toor の brute 試行集計

```bash
ssh root@10.1.1.1 'grep -E "(Failed password|Invalid user) .* for toor" /var/log/auth.log 2>/dev/null' \
  | grep -oE "from [0-9.]+" | sort | uniq -c | sort -rn | head -10
```

### 1.5 toor のシェル履歴 (forensic)

```bash
# /root を共有しているので root の bash_history と同じ
ssh root@10.1.1.1 'ls -la /root/.bash_history /root/.sh_history 2>/dev/null'
ssh root@10.1.1.1 'tail -50 /root/.sh_history 2>/dev/null'
```

### 1.6 横展開で victor にも UID 0 重複が無いか

```bash
ssh "$TARGET_USER@10.1.1.2" 'sudo awk -F: "\\$3==0 {print}" /etc/passwd'
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. toor が UID 0 + 有効パスワード | master.passwd で hash 列が `*` でない | 🚨 設定上の脆弱性 |
| B. toor へのログイン成功 | auth.log に Accepted for toor | 🚨 確定 (root 同等乗っ取り) |
| C. toor への brute 試行 | Failed for toor が同 IP から多発 | ⚠️ 疑わしい (試行中) |
| D. 第三者の UID 0 アカウント | toor 以外の UID 0 が /etc/passwd に存在 | 🚨 確定 (改竄) |

## 3. 判定基準

- ✅ **正常**: UID 0 が root のみ、または toor が nologin / lock
- ⚠️ **疑わしい**: A のみ + B/C なし → 設定リスクとして報告
- 🚨 **確定**: B / D → **/playbook:ransomware** で全工程

## 4. 次のアクション

### 確定なら
- **`/playbook:ransomware`** (root 同等乗っ取り前提)
- 並行して **`/check:check-known-attacker-ip`** (toor login 元と既侵害 IP 突合)
- リーダーへ「root 監査ログが分離不能、信頼できるログが他に必要」を伝達

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: toor をロック (FreeBSD)
# pw lock toor   # または vipw で hash を * に
# 案2: toor のシェルを nologin に
# pw usermod toor -s /usr/sbin/nologin
# 案3: sshd_config で AllowUsers から toor 除外 → service sshd reload
```

### メモするだけ
- toor は FreeBSD 標準なので「触らない」候補だが、有効パスワードがついてれば即対応案件
- victor (Rocky) には toor 慣習なし → そこに UID 0 重複あれば即攻撃の物証

## 5. 参照

- 関連 playbook: [playbook/ransomware.md](../playbook/ransomware.md)
- 連鎖先 check: [check-known-attacker-ip.md](check-known-attacker-ip.md)、[check-pkexec-pwnkit.md](check-pkexec-pwnkit.md)
- analyzer 該当: `agent/analyzer.py` `SECURE_PATTERNS` (`auth/ssh-*`)、`privesc/sudo-unauthorized`
- 既存ドキュメント: 16_:#28 / 16_:2.4

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-toor-uid0__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-toor-uid0
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
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-toor-uid0__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
