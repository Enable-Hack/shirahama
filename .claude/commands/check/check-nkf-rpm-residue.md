---
description: /root/nkf-2.1.4-8.el8.x86_64.rpm 等の運営手動 localinstall 残骸の存在と類似物の有無を確認
---

# /check:check-nkf-rpm-residue — 手動 localinstall 痕跡確認

引数: `<時間窓> <ホスト>`
例: `/check:check-nkf-rpm-residue 13:00-13:30 victor`

## 0. 前提

- 対象: **victor (10.1.1.2)**
- 関連 weakness: 16_:2.3-#12 — `/root/nkf-2.1.4-8.el8.x86_64.rpm` が残置 = **運営が手動 localinstall した痕跡**。攻撃者も同手順で **任意 RPM (悪意ある) を localinstall する余地**
- 影響: 直接の脆弱性ではないが、RPM 経由の永続化 / 改竄パッケージ injection の足場になり得る
- analyzer.py の対応 pattern_tag: 直接対応なし
- **slim 版 (記録のみ)**
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
```

## 1. 収集 (read-only)

```bash
# /root 配下の RPM
ssh "$TARGET_USER@$TARGET_HOST" 'sudo ls -la /root/*.rpm /root/*.tar.gz /root/*.tgz 2>/dev/null'

# /home 配下の RPM (持ち込まれた可能性)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /home /tmp /var/tmp -name "*.rpm" -ls 2>/dev/null'

# 直近で localinstall されたパッケージ
ssh "$TARGET_USER@$TARGET_HOST" 'sudo dnf history list 2>/dev/null | head -20'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo dnf history info last 2>/dev/null | head -30'

# 直近 7 日で touched された /usr/bin /usr/sbin (localinstall の影響)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo find /usr/bin /usr/sbin /usr/local/bin -mtime -7 -ls 2>/dev/null | head -20'

# nkf 自体の挙動
ssh "$TARGET_USER@$TARGET_HOST" 'rpm -q nkf 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'which nkf; nkf --version 2>/dev/null | head -3'
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. /root に既知の RPM | nkf-2.1.4-8.el8 等 | ⚠️ 既知 |
| B. /root or /tmp に新規 RPM | 直近で持ち込まれた RPM | 🚨 攻撃の物証 |
| C. dnf history 直近 install | 時間窓内の手動 install | 🚨 確定 |
| D. /usr/bin に直近変更 | localinstall の影響 | 🚨 確定 |

## 3. 判定基準

- ✅ **正常**: /root に RPM なし、dnf history 直近 install なし
- ⚠️ **疑わしい**: A のみ → 既知の運営仕込みとして記録
- 🚨 **確定**: B / C / D → **/playbook:ransomware** (任意 RPM injection 経由の永続化)

## 4. 次のアクション

### メモするだけ (A)
- 既知の運営仕込み痕跡として記録
- nkf rpm が最終形で良いかリーダー確認

### 確定なら (B/C/D)
- **`/playbook:ransomware`**
- 並行 **`/check:check-pkexec-pwnkit`** (RPM install には root 権限が必要 = root 取られた可能性)

```bash
# リーダー承認後
# sudo dnf history undo last
# RPM ファイルを退避
# sudo mv /root/<suspect>.rpm /root/forensic_/
```

## 5. 参照

- 関連 playbook: [playbook/ransomware.md](../playbook/ransomware.md)
- 連鎖先 check: [check-pkexec-pwnkit.md](check-pkexec-pwnkit.md)
- 既存ドキュメント: 16_:2.3-#12

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-nkf-rpm-residue__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-nkf-rpm-residue
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
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-nkf-rpm-residue__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
