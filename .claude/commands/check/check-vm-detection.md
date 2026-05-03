---
description: VM 環境 (Proxmox VE bc:24:11 prefix) の検出と escape 系痕跡の確認
---

# /check:check-vm-detection — VM 環境検出と escape 痕跡

引数: `<時間窓> <ホスト>`
例: `/check:check-vm-detection 13:00-13:30 bravo`

## 0. 前提

- 対象: **bravo (10.1.1.1)** **victor (10.1.1.2)** 両方
- 関連 weakness: 16_:2.3-#11 — MAC `bc:24:11` prefix から **Proxmox VE 上の VM** と判定可能。実環境は KVM + NEC Express5800 想定 → **デモは VM、本番は物理** の差異がある
- 影響: VM escape 系 CVE (CVE-2024-3094 xz、QEMU 系) の標的になりうる。基本は脅威評価の前提情報
- analyzer.py の対応 pattern_tag: 直接対応なし
- **slim 版 (記録のみ)** — 攻撃検知ではなく environmental fingerprinting
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.1}"
```

## 1. 収集 (read-only)

```bash
# MAC アドレスの OUI 確認
ssh "$TARGET_USER@$TARGET_HOST" 'ip link show 2>/dev/null || ifconfig 2>/dev/null' | grep -iE "ether|HWaddr"

# DMI / virt-what
ssh "$TARGET_USER@$TARGET_HOST" 'sudo dmidecode -s system-manufacturer 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo dmidecode -s system-product-name 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo virt-what 2>/dev/null'

# /proc/cpuinfo の hypervisor フラグ (Linux のみ)
ssh "$TARGET_USER@$TARGET_HOST" 'grep -i hypervisor /proc/cpuinfo 2>/dev/null | head -1'

# FreeBSD 側の VM 検出
ssh "$TARGET_USER@10.1.1.1" 'sysctl kern.vm_guest 2>/dev/null'
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. MAC bc:24:11 (Proxmox) | OUI prefix | ⚠️ 既知 (デモ環境想定) |
| B. virt-what が kvm/qemu 返答 | hypervisor 確定 | ⚠️ |
| C. dmidecode が QEMU/Proxmox | 物理ではない | ⚠️ |
| D. ホスト manufacturer が NEC Express | 本番想定通り | ✅ |

## 3. 判定基準

- ✅ **正常 (本番想定)**: NEC Express5800 manufacturer + KVM hypervisor
- ⚠️ **デモ環境確認**: A / B / C → 既知のデモ前提として記録
- 🚨 該当なし (本 check では新規攻撃の判定はしない)

## 4. 次のアクション

### メモするだけ
- VM 環境であることを報告書に記載
- 本番展開時は物理機材の前提に戻る旨をリーダーへ確認
- VM escape 系 CVE のリストを参考用にメモ (CVE-2024-3094 等)

### 連鎖
- なし (本 check は静的環境確認のため)

## 5. 参照

- 関連 playbook: なし
- 既存ドキュメント: 16_:2.3-#11

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-vm-detection__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-vm-detection
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
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-vm-detection__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
