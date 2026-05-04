---
model: claude-haiku-4-5
description: ISC dhcpd not authoritative; を悪用した rogue DHCP / MITM 痕跡を確認
---

# /check:check-rogue-dhcp — Rogue DHCP / MITM 確認

引数: `<時間窓> <ホスト>`
例: `/check:check-rogue-dhcp 13:00-13:30 victor`

## 0. 前提

- 対象: **victor (10.1.1.2 / ISC dhcpd)**
- 関連 weakness: 14_:V11 / 16_:#7 — dhcpd.conf に `not authoritative;` + 空 subnet 残存 → **rogue DHCP サーバが共存可能** → クライアントを偽 GW / 偽 DNS に誘導 (MITM)
- 影響: VPN 帯 (10.1.11.50-99) のクライアントが偽 DNS を引かされ、フィッシング誘導される
- analyzer.py の対応 pattern_tag: **直接対応ルールなし**
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
```

## 1. 収集 (read-only)

### 1.1 dhcpd 設定

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo cat /etc/dhcp/dhcpd.conf 2>/dev/null' > /tmp/check_dhcpd_conf.txt

grep -iE "^(authoritative|not authoritative|subnet|range|option (routers|domain-name-servers))" \
  /tmp/check_dhcpd_conf.txt
```

期待 (危険):
- `not authoritative;` がトップレベル
- 複数 subnet が残存 (使われてない subnet 含む)

### 1.2 dhcpd リース履歴

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo cat /var/lib/dhcpd/dhcpd.leases 2>/dev/null | head -100'

# 直近のリース発行 (時間窓内に異常な MAC があるか)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -A5 "^lease " /var/lib/dhcpd/dhcpd.leases 2>/dev/null' | tail -50
```

### 1.3 messages ログから DHCP 異常

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -3000 /var/log/messages' > /tmp/check_dhcpd_msg.log

# DISCOVER / OFFER / REQUEST / ACK の流れ確認
grep -iE "dhcpd:.*(DISCOVER|OFFER|REQUEST|ACK|NAK|DECLINE)" /tmp/check_dhcpd_msg.log | tail -50

# 想定外の MAC ベンダから DHCP 要求
grep -iE "dhcpd:.*from [0-9a-f:]{17}" /tmp/check_dhcpd_msg.log \
  | grep -oE "[0-9a-f:]{17}" | sort -u | head -20

# 同 IP に複数 MAC のリース要求 = MITM の典型
grep -iE "dhcpd:.*ACK" /tmp/check_dhcpd_msg.log | tail -30
```

### 1.4 rogue DHCP の存在検知 (受動的)

```bash
# 同セグメント上に複数 DHCP サーバが居ると "DHCPNAK" や "wrong network" がログに出る
grep -iE "dhcpd:.*(NAK|wrong network|abandoned|conflict)" /tmp/check_dhcpd_msg.log | tail -20

# クライアント側から DHCP DISCOVER して応答数を見る (要 attack-vm 経由 / read-only に近いが LAN noise を出す)
# nmap --script broadcast-dhcp-discover  # → リーダー承認後に検討
```

### 1.5 偽 DNS 誘導の確認 (rogue が通った前提での被害)

```bash
# 配布された option domain-name-servers が想定通りか
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -iE "domain-name-servers" /etc/dhcp/dhcpd.conf'

# クライアントが解決している DNS を bravo の named.log で確認 (10.1.11.x からのクエリ)
ssh "$TARGET_USER@10.1.1.1" 'grep -E "client 10\\.1\\.11\\." /var/log/named.log 2>/dev/null' | tail -20
```

### 1.6 ARP テーブルでの MAC 重複検出 (MITM 物証)

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'arp -an 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'arp -an | awk "{print \$4}" | sort | uniq -c | sort -rn | head -5'
# 同一 MAC が複数 IP に紐づいてれば異常 (MITM の物証)
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. not authoritative; | dhcpd.conf にトップレベルで設定 | 🚨 設定上の脆弱性 |
| B. 想定外 MAC からの REQUEST | OUI が運営機材と異なる MAC | ⚠️ 疑わしい |
| C. DHCPNAK / wrong network | rogue サーバが応答した痕跡 | 🚨 確定 |
| D. ARP MAC 重複 | 1 つの MAC が複数 IP を持つ | 🚨 確定 (MITM) |
| E. 偽 DNS 配布 | dhcpd.conf の DNS と named.log のクエリ元が乖離 | 🚨 確定 (MITM 成立) |

## 3. 判定基準

- ✅ **正常**: authoritative; 設定、想定 MAC のみ、ARP 重複なし
- ⚠️ **疑わしい**: A / B のみ → 監視継続 + tcpdump で DHCP パケット確認
- 🚨 **確定**: C / D / E → **/playbook:dns-tamper** + **/playbook:phishing**

## 4. 次のアクション

### 確定なら
- **`/playbook:dns-tamper`** (誘導された偽 DNS の中身が改竄に近い)
- **`/playbook:phishing`** (誘導先がフィッシングサイトの想定)
- 並行して **`/check:check-bind-allow-update`** (named.conf 改竄も併発しがち)

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: dhcpd.conf に authoritative; を追加 → service dhcpd restart
# 案2: スイッチ側で DHCP スヌーピングを有効化
# 案3: rogue サーバの MAC を特定 → スイッチポート shutdown
```

### メモするだけ
- analyzer に `dhcp/rogue-server` 相当ルールなし → 追加検討メモ
- 「触らない」優先。ただし MITM 確定なら被害拡大するので即時対応案件

## 5. 参照

- 関連 playbook: [playbook/dns-tamper.md](../playbook/dns-tamper.md)、[playbook/phishing.md](../playbook/phishing.md)
- 連鎖先 check: [check-bind-allow-update.md](check-bind-allow-update.md)
- analyzer 該当: 直接対応ルールなし (要追加メモ)
- 既存ドキュメント: 14_:V11 / 16_:#7 / 14_:6.11 (DHCP 設定全文)

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-rogue-dhcp__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-rogue-dhcp
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
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-rogue-dhcp__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
