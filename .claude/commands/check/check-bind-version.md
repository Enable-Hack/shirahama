---
description: BIND バージョン (9.11.36 既知 CVE) の確認 (静的検査)
---

# /check:check-bind-version — BIND バージョン確認

引数: `<時間窓> <ホスト>`
例: `/check:check-bind-version 13:00-13:30 bravo`

## 0. 前提

- 対象: **bravo (10.1.1.1 / FreeBSD ports BIND9)**
- 関連 weakness: 14_:6.4 / 16_:#34 — BIND 9.11.36 既知 CVE 多数
- 影響: 既知 CVE で named プロセスクラッシュ / DoS / 場合により情報漏洩
- analyzer.py の対応 pattern_tag: 直接対応なし
- **slim 版 (記録のみ)**
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.1}"
```

## 1. 収集 (read-only)

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'pkg info bind* 2>/dev/null | head -10'
ssh "$TARGET_USER@$TARGET_HOST" 'named -v 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'rndc status 2>/dev/null | head -5'

# version.bind chaos 経由で外部からも確認可能 (= 攻撃者にも version 見えてる物証)
dig version.bind chaos txt @"$TARGET_HOST" +short

# named プロセスのクラッシュ痕跡 (CVE 発火の物証)
ssh "$TARGET_USER@$TARGET_HOST" 'tail -1000 /var/log/named.log 2>/dev/null | grep -iE "fatal|crash|assertion|core dump"' | tail -10
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. BIND 9.11.x | 旧版 LTS, EOL | ⚠️ メモ |
| B. version.bind が公開 | 外部 dig で取得可 | ⚠️ 指紋採取容易 |
| C. crash 痕跡 | named.log に fatal/assertion | 🚨 確定 (CVE 発火) |

## 3. 判定基準

- ✅ **正常**: BIND 9.18+、version.bind が "REFUSED"
- ⚠️ **疑わしい**: A / B → メモ
- 🚨 **確定**: C → **/playbook:dns-tamper** + 並行 **/check:check-bind-allow-update** **/check:check-bind-axfr**

## 4. 次のアクション

### メモするだけ
- バージョン情報を報告書に記載
- version.bind の応答を絞ることをリーダーに進言 (`version "hidden";` を named.conf に)

### 連鎖
- C 検出時のみ DNS 系 check を全部叩く

## 5. 参照

- 関連 playbook: [playbook/dns-tamper.md](../playbook/dns-tamper.md)
- 連鎖先 check: [check-bind-allow-update.md](check-bind-allow-update.md)、[check-bind-axfr.md](check-bind-axfr.md)
- 既存ドキュメント: 14_:6.4 / 16_:#34

## 6. JSON 永続化（HTML dashboard 連携）

調査が完了したら、判定結果を JSON で出力し helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/<INCIDENT_ID>/check-bind-version__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-bind-version
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
- helper が `scripts/emit_skill_json.sh` 経由で `INCIDENT_ID` env (= /incident から伝播) を拾い、`data/incidents/${INCIDENT_ID}/check-bind-version__<ts>.json` に永続化
- `/incident` を経由せず単独実行した場合は `<auto-id>_unscoped` 配下に出る (それでも dashboard には載る)
