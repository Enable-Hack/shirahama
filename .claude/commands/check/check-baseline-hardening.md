---
description: SELinux / pf / firewalld / iptables の baseline hardening 状態を一括確認
---

# /check:check-baseline-hardening — ベースライン強化状態確認

引数: `<時間窓> <ホスト>`
例: `/check:check-baseline-hardening 13:00-13:30 victor`

## 0. 前提

- 対象: **bravo (10.1.1.1)** **victor (10.1.1.2)** 両方
- 関連 weakness: 16_:#8 / #9 / #10 — victor は SELinux Disabled + firewalld inactive + iptables 全 ACCEPT、bravo は pf/ipfw 未稼働 (rc.conf に enable 行なし)
- 影響: 「侵害が即ラテラルムーブ」「全ポート素通し」 = 単一脆弱性で全機制圧
- 14_:5.2#382 / 6.3 でも明示
- analyzer.py の対応 pattern_tag: 直接対応なし (静的設定の検査)
- これは「他の check の前提条件」確認の意味合いが強い → 受電直後の状況把握用
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
```

## 1. 収集 (read-only)

### 1.1 SELinux 状態 (Rocky)

```bash
ssh "$TARGET_USER@10.1.1.2" 'getenforce 2>/dev/null'
ssh "$TARGET_USER@10.1.1.2" 'sudo grep -iE "^SELINUX=" /etc/selinux/config 2>/dev/null'

# audit log で AVC denial があれば SELinux が動いている (= enforcing)
ssh "$TARGET_USER@10.1.1.2" 'sudo grep AVC /var/log/audit/audit.log 2>/dev/null | tail -10'
```

期待 (危険):
- `Disabled` または `Permissive`

### 1.2 firewalld / iptables (Rocky)

```bash
ssh "$TARGET_USER@10.1.1.2" 'sudo systemctl is-active firewalld 2>/dev/null'
ssh "$TARGET_USER@10.1.1.2" 'sudo firewall-cmd --state 2>/dev/null'

# iptables の実ルール (空 + ACCEPT デフォルトなら無防備)
ssh "$TARGET_USER@10.1.1.2" 'sudo iptables -nvL --line-numbers | head -30'
ssh "$TARGET_USER@10.1.1.2" 'sudo iptables -P 2>&1 | head'  # デフォルトポリシー (出ないコマンド)
ssh "$TARGET_USER@10.1.1.2" 'sudo iptables -S | head -10'

# nftables も併用されてるか
ssh "$TARGET_USER@10.1.1.2" 'sudo nft list ruleset 2>/dev/null | head -20'
```

期待 (危険):
- firewalld inactive + iptables INPUT 空 + Policy ACCEPT

### 1.3 pf / ipfw 状態 (FreeBSD)

```bash
ssh "$TARGET_USER@10.1.1.1" 'grep -iE "^(pf_enable|ipfw_enable|firewall_enable)" /etc/rc.conf 2>/dev/null'
ssh "$TARGET_USER@10.1.1.1" 'service pf status 2>/dev/null; service ipfw status 2>/dev/null'

# pfctl で ruleset 確認
ssh "$TARGET_USER@10.1.1.1" 'sudo pfctl -s rules 2>/dev/null | head -10'
ssh "$TARGET_USER@10.1.1.1" 'ls /etc/pf.conf 2>/dev/null'
```

期待 (危険):
- pf_enable=YES の行がない、`/etc/pf.conf` 不在

### 1.4 listening ポートの俯瞰 (現状の攻撃面)

```bash
# Rocky
ssh "$TARGET_USER@10.1.1.2" 'sudo ss -tlnp | head -30'
ssh "$TARGET_USER@10.1.1.2" 'sudo ss -ulnp | head -20'

# FreeBSD
ssh "$TARGET_USER@10.1.1.1" 'sockstat -4l | head -30'
```

### 1.5 audit / rsyslog の動作確認 (ログ自体が信頼できるか)

```bash
ssh "$TARGET_USER@10.1.1.2" 'sudo systemctl is-active auditd rsyslog 2>/dev/null'
ssh "$TARGET_USER@10.1.1.1" 'service syslogd status 2>/dev/null'

# auditd 不在のサーバでは forensic 価値が下がる
```

### 1.6 結果のまとめ表 (Claude が出力時に作成)

| サーバ | SELinux | firewalld | iptables Policy | pf | auditd |
|---|---|---|---|---|---|
| victor | <値> | <active/inactive> | <ACCEPT/DROP> | n/a | <active> |
| bravo  | n/a | n/a | n/a | <enabled/disabled> | <none> |

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. SELinux Disabled (victor) | getenforce=Disabled | 🚨 設定 |
| B. firewalld inactive + iptables 空 (victor) | 全 ACCEPT | 🚨 設定 |
| C. pf 無効 (bravo) | rc.conf に pf_enable なし | 🚨 設定 |
| D. auditd 不在 (bravo) | service なし | ⚠️ ログ価値低下 |

## 3. 判定基準

- ✅ **正常**: SELinux enforcing + firewalld active + pf enabled + auditd 動作
- ⚠️ **疑わしい**: D のみ → ログ信頼度低下のメモ
- 🚨 **確定 (= ベースライン崩壊)**: A / B / C → これが他の check の判定信頼度を **常に下げる前提** として機能する

## 4. 次のアクション

### 確定なら
- **どの playbook に進むかは attacker tag と合わせて判断**。本 check 単独では playbook 直行しない
- 「ベースライン崩壊している」事実を **`/incident` の §0.5 既侵害前提と同じレベルで** リーダー報告
- 他の check 結果に「ホスト側防御がない」を付記

### 即時封じ手（リーダー承認後のみ）
```bash
# victor:
# sudo setenforce 1   # SELinux 一時 enforcing (再起動で戻る)
# sudo systemctl start firewalld   # 必要ポート許可後
#
# bravo:
# echo 'pf_enable="YES"' | sudo tee -a /etc/rc.conf
# sudo service pf start (要 pf.conf)
```

### メモするだけ
- ベースライン崩壊は **出題前提の典型** (16_:#8/#9/#10 で「短期 (本日中)」推奨だが本番環境では触らない)
- 競技中の SELinux enforcing 切替は既存サービスを止める可能性大 → リーダー判断必須

## 5. 参照

- 関連 playbook: なし (前提確認用)
- 連鎖先 check: 全 check (本 check の結果は他の check の判定信頼度を補正する)
- analyzer 該当: 直接対応ルールなし (静的設定確認のため)
- 既存ドキュメント: 14_:5.2 / 14_:6.3 / 16_:#8 / #9 / #10

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-baseline-hardening__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-baseline-hardening
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
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-baseline-hardening__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
