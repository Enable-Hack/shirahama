---
description: SNMPv1/v2c community=public による MIB 列挙 / 情報漏洩の痕跡を確認
---

# /check:check-snmp-public-walk — SNMP public コミュニティ列挙確認

引数: `<時間窓> <ホスト>`
例: `/check:check-snmp-public-walk 13:00-13:30 victor`

## 0. 前提

- 対象: **bravo (10.1.1.1)** **victor (10.1.1.2)** 両方
- 関連 weakness: 14_:6.12 / 16_:#4 — SNMPv1/v2c で community=`public` 設定。`snmpwalk -v2c -c public 10.1.1.2` で MIB 全列挙 (ホスト名、インストール済 RPM、ネットワークインタフェース、ARP テーブル、稼働プロセス)
- 影響: 偵察 (recon) フェーズで攻撃者が攻撃面の地図を取得する
- analyzer.py の対応 pattern_tag: **直接対応ルールなし**
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
```

## 1. 収集 (read-only)

### 1.1 SNMP listen 状態と設定

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo ss -ulnp | grep -E ":161\\b"'

# Rocky 系
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -iE "^(rocommunity|rwcommunity|com2sec|view|access)" /etc/snmp/snmpd.conf 2>/dev/null'

# FreeBSD 系 (bravo)
ssh "$TARGET_USER@10.1.1.1" 'cat /usr/local/etc/snmpd.conf 2>/dev/null | grep -iE "^(rocommunity|rwcommunity)"'
```

期待 (危険):
- `rocommunity public` (read-only でも MIB 全公開)
- ACL なし (`default` `localhost` 限定でない)

### 1.2 アクセスログ (snmpd 自身は通常ログを残さない → /var/log/messages か audit)

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -i snmpd /var/log/messages 2>/dev/null' > /tmp/check_snmp_msg.log
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -i snmp /var/log/secure 2>/dev/null' >> /tmp/check_snmp_msg.log

tail -30 /tmp/check_snmp_msg.log

# auditd (victor のみ) で snmpd への access
ssh "$TARGET_USER@$TARGET_HOST" 'sudo ausearch -p $(pgrep snmpd | head -1) 2>/dev/null | head -30' || true
```

### 1.3 受信側からの確認: conntrack で 161/UDP

```bash
ssh "$TARGET_USER@$TARGET_HOST" \
  'sudo conntrack -L -p udp --dport 161 2>/dev/null | head -20 || ss -un state unconnected sport = :161 2>/dev/null'

# 直近で 161 に届いた送信元の集計 (tcpdump 履歴があれば)
ssh "$TARGET_USER@$TARGET_HOST" 'ls /var/log/tcpdump_snmp* 2>/dev/null'
```

### 1.4 外部からの実際の試行 (read-only)

```bash
# snmpwalk が通るか確認 (実 walk はしない、sysName だけ)
snmpget -v2c -c public -t 2 "$TARGET_HOST" 1.3.6.1.2.1.1.5.0 2>&1 | head -3
snmpget -v2c -c public -t 2 "$TARGET_HOST" 1.3.6.1.2.1.1.1.0 2>&1 | head -3

# 期待:
# ✅ "Timeout" / "No Response" → ACL OK
# 🚨 "SNMPv2-MIB::sysName.0 = STRING: bravo" 等が返る → 列挙可
```

### 1.5 view 範囲の確認 (14_:V14 / 16_:2.3-#5 — view が `.1.3.6.1.2.1.1` だけだと MRTG が動かない疑い)

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -E "^view " /etc/snmp/snmpd.conf 2>/dev/null'

# MRTG 設定の確認 (動作してるか)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo systemctl is-active mrtg 2>/dev/null; sudo ls -la /var/www/mrtg 2>/dev/null | head'

# MRTG が動いていない疑い = 「監視が壊れている」を出題側が仕込んでいる可能性
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /var/www/mrtg -name "*.png" -mmin -60 2>/dev/null | wc -l'
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. rocommunity public + ACL なし | snmpd.conf に上記 | 🚨 設定上の脆弱性 |
| B. 外部からの sysName 取得成功 | snmpget で値が返る | 🚨 確定 (列挙可) |
| C. 161 への外部接続急増 | conntrack で 1 つの送信元から多数の OID クエリ | 🚨 確定 (walk 中) |
| D. MRTG 不動作 + view 限定 | view が sysName のみ、PNG 更新なし | ⚠️ 疑わしい (出題仕込み or 偶発バグ) |

## 3. 判定基準

- ✅ **正常**: rocommunity の ACL が localhost / 監視サーバ限定、外部 snmpget Timeout
- ⚠️ **疑わしい**: A のみ + 列挙痕跡なし → 設定リスクとして報告
- 🚨 **確定**: B / C → **/playbook:ddos** で「攻撃前段としての偵察」扱い、または **/playbook:wp-tamper** (列挙結果が次の攻撃の入口)

## 4. 次のアクション

### 確定なら
- **`/playbook:ddos`** (DDoS の前段 recon としての扱い) または **シナリオに応じて適切な playbook**
- 並行して **`/check:check-known-attacker-ip`** (列挙元と既侵害 IP の突合)
- リーダーへ「攻撃面の地図が漏れた」と報告 (列挙された情報の範囲を伝える)

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: snmpd.conf で community を変更 + ACL 追加
# rocommunity ${strong_random} 10.1.130.1
# 案2: SNMPv3 authPriv に切替 (運用影響あり、MRTG が止まる)
# 案3: 161/UDP を firewalld で限定
```

### メモするだけ
- analyzer に `recon/snmp-walk` 相当のルールがない → 追加検討メモ
- 14_:V14 の MRTG 不動作仮説は出題側の "罠" の可能性 → 触る前にスクリーンショット保管

## 5. 参照

- 関連 playbook: [playbook/ddos.md](../playbook/ddos.md) (recon → DDoS 連鎖)
- 連鎖先 check: [check-known-attacker-ip.md](check-known-attacker-ip.md)
- analyzer 該当: 直接対応ルールなし (要追加メモ)
- 既存ドキュメント: 14_:6.12 / 16_:#4 / 14_:V14 / 16_:2.3-#5

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-snmp-public-walk__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-snmp-public-walk
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
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-snmp-public-walk__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
