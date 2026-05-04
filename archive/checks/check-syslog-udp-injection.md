---
model: claude-haiku-4-5
description: 514/UDP への偽ログ注入痕跡を確認。ログ自体が汚染されている前提の検査
---

# /check:check-syslog-udp-injection — syslog 偽ログ注入確認

引数: `<時間窓> <ホスト>`
例: `/check:check-syslog-udp-injection 13:00-13:30 bravo`

## 0. 前提

- 対象: **bravo (10.1.1.1 / FreeBSD syslogd)** 主、**victor (10.1.1.2 / rsyslog 集約点)** 副
- 関連 weakness: 14_調査:8.1 #6 / 14_:8.3 B3 — `syslogd` `*:514/UDP` で外部受信 + ACL 無し → `logger -n 10.1.1.1 -P 514` で偽ログ注入可能
- 影響: インシデント調査時の **誤誘導**、SIEM 汚染、analyzer の判定撹乱
- analyzer.py の対応 pattern_tag: **直接対応ルールなし** (TODO: `syslog/spoofed-source` ルール追加検討。現状は時系列の不連続でしか検出できない)
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.1}"
```

## 1. 収集 (read-only)

### 1.1 514/UDP の listen 状態

```bash
# bravo (FreeBSD)
ssh "$TARGET_USER@10.1.1.1" 'sockstat -4l | grep -E ":514\\b"'
ssh "$TARGET_USER@10.1.1.1" 'cat /etc/rc.conf | grep -iE "syslogd_flags|rsyslog"'

# victor (Rocky)
ssh "$TARGET_USER@10.1.1.2" 'sudo ss -ulnp | grep -E ":514\\b"'
ssh "$TARGET_USER@10.1.1.2" 'sudo cat /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -iE "imudp|imtcp|allowedSender"'
```

期待:
- 🚨 `*:514` で listen + `-ss` (FreeBSD) や `$AllowedSender` (rsyslog) なし → 注入可能
- ✅ ACL あり / 外部到達不可

### 1.2 時系列の不連続 (注入痕跡の典型)

```bash
# rsyslog 集約点 (victor) で、ホスト名と送信元 IP が一致しないログ
ssh "$TARGET_USER@10.1.1.2" 'sudo tail -5000 /var/log/rsyslog/*.log 2>/dev/null' \
  > /tmp/check_syslog_collected.log

# タイムスタンプが時系列で逆行 / 飛んでいる箇所
awk '{print $1, $2, $3}' /tmp/check_syslog_collected.log | head -200 | uniq -c | sort -rn | head

# 既知 hostname と送信元 IP のマッピング表 (本番想定)
# bravo:  10.1.1.1
# victor: 10.1.1.2
# RTX1200: 10.1.1.254
# それ以外のホスト名が来てたら不審
grep -oE "^[A-Za-z]+ +[0-9]+ [0-9:]+ [a-zA-Z0-9.-]+" /tmp/check_syslog_collected.log \
  | awk '{print $4}' | sort -u
```

### 1.3 偽装されやすい facility / severity の偏り

```bash
# 攻撃者は「authpriv.notice」「kern.crit」等の "重大そうな" facility を偽装する傾向
grep -iE "authpriv|kern\\.(crit|alert|emerg)" /tmp/check_syslog_collected.log | tail -30

# ログ自体に矛盾がないか (例: sshd[PID] で同 PID が同時刻に複数ホストから)
grep -E "sshd\\[[0-9]+\\]" /tmp/check_syslog_collected.log \
  | awk '{print $4, $5}' | sort | uniq -c | sort -rn | head -10
```

### 1.4 注入元 IP の特定 (conntrack / pf / firewalld)

```bash
# bravo に直近で 514/UDP に届いた送信元 (FreeBSD pflog なし → tcpdump 痕跡限定)
ssh "$TARGET_USER@10.1.1.1" 'sockstat -4 -P udp | grep -E ":514\\b"'

# victor (Rocky) で同様
ssh "$TARGET_USER@10.1.1.2" 'sudo conntrack -L -p udp --dport 514 2>/dev/null | head -20'
```

### 1.5 JSONL 化 (parse_*.py 系統が無い場合は生のまま analyzer に渡せない)

```bash
# 既存パーサーは想定 facility 形式のみ。注入された不整合行は parse 失敗で落ちる可能性あり
# → 落ちた行 = 注入候補として別ファイルに保存
python scripts/preprocess/parse_secure.py /tmp/check_syslog_collected.log \
  > /tmp/check_syslog.jsonl 2> /tmp/check_syslog_parse_errors.log
wc -l /tmp/check_syslog_parse_errors.log
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. 514/UDP 開放 + ACL なし | sockstat `*:514`、`-ss` 不在、`$AllowedSender` なし | 🚨 設定上の脆弱性 |
| B. ホスト名と送信元 IP 不一致 | rsyslog で `bravo` と名乗るログが 10.1.1.1 以外から | 🚨 確定 (注入) |
| C. タイムスタンプ逆行 | 連続行で時刻が過去に戻る | 🚨 確定 (注入 / 改竄) |
| D. parse error 多発 | parse_*.py が落とす行が時間窓で急増 | ⚠️ 疑わしい |
| E. 不審 facility 偏り | authpriv / kern.crit が突如増加、関連ログなし | ⚠️ 疑わしい |

## 3. 判定基準

- ✅ **正常**: 514/UDP に ACL あり、ホスト名と送信元 IP 一致、時系列線形
- ⚠️ **疑わしい**: D / E のみ → 監視継続、analyzer 結果の信頼度を下げて判断
- 🚨 **確定**: A + B/C → **ログそのものが汚染されている前提で全 check の判定を再評価**

## 4. 次のアクション

### 確定なら
- **重要**: 他の `/check:*` 結果の信頼度を下げる。analyzer の pattern_tag に「注入された行が紛れ込んでいる」前提を導入
- 注入元 IP を特定 → **`/check:check-known-attacker-ip`** で同 IP の他経路活動も突合
- 集約点 (victor /var/log/rsyslog/) のログを **forensic 用に別保管** する

### 即時封じ手（リーダー承認後のみ）
```bash
# bravo: /etc/rc.conf に syslogd_flags="-ss" 追記 → service syslogd restart
# victor: rsyslog.conf に $AllowedSender UDP, 10.1.1.0/24 追記
```

### メモするだけ
- analyzer に **`syslog/spoofed-source`** 相当ルールが無い → 追加検討 (memory に追記)
- 注入されたログを「そのまま削除」するのは forensic 観点で NG → 必ずコピー保管後に判断

## 5. 参照

- 関連 playbook: [playbook/ransomware.md](../playbook/ransomware.md) (注入が攻撃連鎖の偽装に使われている前提)
- 連鎖先 check: [check-known-attacker-ip.md](check-known-attacker-ip.md)
- analyzer 該当: 直接対応ルールなし (要追加)
- 既存ドキュメント: 14_調査:8.1 #6 / 14_:8.3 B3 / 16_:#3

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-syslog-udp-injection__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-syslog-udp-injection
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
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-syslog-udp-injection__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
