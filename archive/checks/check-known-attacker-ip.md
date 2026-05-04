---
model: claude-haiku-4-5
description: 既知侵害 IP (10.1.129.10 等) からの再ログイン痕跡を確認。/incident §0.5 既侵害前提の根拠
---

# /check:check-known-attacker-ip — 既侵害 IP 再アクセス確認

引数: `<時間窓> <ホスト>`
例: `/check:check-known-attacker-ip 13:00-13:30 victor`

## 0. 前提

- 対象: **bravo (10.1.1.1)** **victor (10.1.1.2)** 両方
- 関連 weakness: 14_調査:8.1 / 16_:#40 — `obuchi` `manage` が **4/24 深夜に 10.1.129.10 から長時間ログイン**。10.1.129.0/24 は運営管理 VLAN だが、攻撃者の C2 として悪用されている可能性
- analyzer.py の対応 pattern_tag: `auth/ssh-failed`、`auth/ssh-invalid-user`、`auth/ssh-bruteforce` (集計)。**IP 単位での既知侵害判定は mock_backend.py の whitelist で実装済**
- /incident §0.5「既侵害前提」の根拠となる check — これが無いと「攻撃が今初めて起きた」誤判定をする
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"   # 本番: manage / デモ: rocky / bravo は manage 不可なら ssh root@
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
KNOWN_IP="${KNOWN_IP:-10.1.129.10}"    # 必要なら別 IP に上書き
```

## 1. 収集 (read-only)

### 1.1 last / lastb / who での再接続確認

```bash
# 直近の対話ログイン (10.1.129.0/24 由来を強調)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo last -F -i | head -50' \
  | grep -E "10\\.1\\.129\\." || echo "no 10.1.129.x login this window"

# 認証失敗 (lastb)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo lastb -F -i 2>/dev/null | head -30' \
  | grep -E "10\\.1\\.129\\."

# 現在ログイン中
ssh "$TARGET_USER@$TARGET_HOST" 'who -a; w'
```

### 1.2 secure / auth.log での詳細

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -3000 /var/log/secure' > /tmp/check_kai_secure.log

# 既知 IP からの Accepted/Failed
grep -E "from $KNOWN_IP" /tmp/check_kai_secure.log | tail -30
grep -iE "Accepted (password|publickey).*from $KNOWN_IP" /tmp/check_kai_secure.log | tail -10

# 配布アカウント以外のユーザーがログインしてないか
grep -iE "Accepted (password|publickey)" /tmp/check_kai_secure.log \
  | grep -vE " for (manage|root|admin|vty|enable) " | tail -20
```

### 1.3 httpd access_log で同 IP の Web 経由活動

```bash
ssh "$TARGET_USER@$TARGET_HOST" "sudo grep -E \"^$KNOWN_IP \" /var/log/httpd/access_log | tail -50"

# 10.1.129.0/24 全域
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -E "^10\\.1\\.129\\." /var/log/httpd/access_log' | tail -30
```

### 1.4 authorized_keys 改竄チェック (永続化痕跡)

```bash
# 配布アカウント全員の authorized_keys をハッシュ化して比較する基準にする
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /home /root -name "authorized_keys" -ls 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /home /root -name "authorized_keys" -exec sha256sum {} \\; 2>/dev/null'

# 直近 7 日で更新された authorized_keys
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /home /root -name "authorized_keys" -mtime -7 2>/dev/null'
```

### 1.5 同 IP の DNS / メール痕跡 (横断)

```bash
# bravo の named.log で 10.1.129.10 由来のクエリ / 更新試行
ssh "$TARGET_USER@10.1.1.1" "grep $KNOWN_IP /var/log/named.log 2>/dev/null" | tail -20

# maillog で同 IP からの SMTP / IMAP 接続
ssh "$TARGET_USER@$TARGET_HOST" "sudo grep $KNOWN_IP /var/log/maillog 2>/dev/null" | tail -20
```

### 1.6 JSONL 化

```bash
python scripts/preprocess/parse_secure.py /tmp/check_kai_secure.log > /tmp/check_kai_secure.jsonl
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. KNOWN_IP からの新規 Accepted | secure に時間窓内の Accepted | 🚨 確定 (再侵入) |
| B. 配布アカウント以外のログイン成功 | manage/root/admin 以外のユーザーで Accepted | 🚨 確定 (新規アカウント乗っ取り) |
| C. authorized_keys 直近更新 | mtime が時間窓内 | 🚨 確定 (永続化) |
| D. 10.1.129.0/24 由来の Web 異常活動 | httpd access_log で攻撃 URI | 🚨 確定 |
| E. Failed 多発のみ | KNOWN_IP から Failed 多数、Accepted なし | ⚠️ 疑わしい (試行中) |

## 3. 判定基準

- ✅ **正常**: KNOWN_IP からの活動なし、authorized_keys 直近更新なし
- ⚠️ **疑わしい**: パターン E のみ → 監視継続 + 並行 brute (`/check:check-telnet-plain-auth` 等) と突合
- 🚨 **確定**: A〜D いずれか → **/playbook:ransomware** 並行起動 (横展開・永続化チェック)

## 4. 次のアクション

### 確定なら
- **`/playbook:ransomware`** (全権限取られた前提で全工程)
- 並行して **`/check:check-pkexec-pwnkit`** (LPE と同 IP 経路の組み合わせ確認)
- リーダーへ「**既侵害アカウントが再活動した**」と即報告。「初めて起きた」と断定しない (18_§9 由来)

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: KNOWN_IP からのアクセスを iptables drop
# sudo iptables -I INPUT -s 10.1.129.10 -j DROP
# 案2: 配布アカウントの強制パスワードリセット (運用影響あり)
# 案3: 改竄された authorized_keys を退避
```

### メモするだけ
- 10.1.129.0/24 は運営管理 VLAN なので、「全部 drop」は運営との通信も切る
- mock_backend.py の whitelist 機構で「known-bad targets」として既に登録済 (確認: `grep -i 10.1.129 agent/backends/mock_backend.py`)

## 5. 参照

- 関連 playbook: [playbook/ransomware.md](../playbook/ransomware.md)
- 連鎖先 check: [check-pkexec-pwnkit.md](check-pkexec-pwnkit.md)、check-obuchi-777-hijack
- analyzer 該当: `agent/analyzer.py` `SECURE_PATTERNS` (`auth/ssh-*`)、`agent/backends/mock_backend.py` whitelist
- 既存ドキュメント: 14_調査:8.1 / 16_:#40 / `incident.md` §0.5

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-known-attacker-ip__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-known-attacker-ip
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
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-known-attacker-ip__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
