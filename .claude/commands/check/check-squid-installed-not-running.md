---
description: Squid インストール済み未起動 (いつでも起動できる状態) の確認 (静的検査)
---

# /check:check-squid-installed-not-running — Squid 起動待機状態確認

引数: `<時間窓> <ホスト>`
例: `/check:check-squid-installed-not-running 13:00-13:30 victor`

## 0. 前提

- 対象: **victor (10.1.1.2)**
- 関連 weakness: 14_:V15 — Squid (Forward Proxy) インストール済みだが未起動 → 攻撃者が `systemctl start squid` で **すぐに踏み台 Proxy として起動可能**
- 影響: 起動された場合 → 内部からの C2 中継、外部 SOCKS / HTTP CONNECT 経由の MITM
- analyzer.py の対応 pattern_tag: 直接対応なし
- **slim 版 (記録のみ)** — 起動されたら別 check で対応
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
```

## 1. 収集 (read-only)

```bash
ssh "$TARGET_USER@$TARGET_HOST" 'rpm -q squid 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo systemctl is-active squid 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo systemctl is-enabled squid 2>/dev/null'

# squid.conf の存在 (ACL なし / open relay 状態)
ssh "$TARGET_USER@$TARGET_HOST" \
  'sudo grep -iE "^(http_port|http_access|acl)" /etc/squid/squid.conf 2>/dev/null | head -20'

# 3128 / 8080 が listen し始めていないか
ssh "$TARGET_USER@$TARGET_HOST" 'sudo ss -tlnp | grep -E ":(3128|8080)\\b"'

# /var/log/squid/access.log / cache.log の存在確認
ssh "$TARGET_USER@$TARGET_HOST" 'sudo ls -la /var/log/squid/ 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo tail -50 /var/log/squid/access.log 2>/dev/null'
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. squid rpm install 済 + service inactive | 起動待機 | ⚠️ メモ |
| B. squid service active | 起動された | 🚨 確定 (攻撃の物証) |
| C. squid access.log 直近 | access.log に時間窓内エントリ | 🚨 確定 |
| D. http_access allow all | ACL なし | 🚨 設定 (起動されたら open proxy) |

## 3. 判定基準

- ✅ **正常**: rpm 未インストール、または disabled + masked
- ⚠️ **疑わしい**: A → メモ + D の確認
- 🚨 **確定**: B / C → **/playbook:ddos** (踏み台化前提) + 即停止候補

## 4. 次のアクション

### メモするだけ (A の場合)
- 「いつでも踏み台化される状態」をリーダーへ報告
- masked 化を進言

### 確定なら (B/C)
- **`/playbook:ddos`** (Proxy 経由 C2 / 増幅元の可能性)
- 即停止候補

```bash
# リーダー承認後
# sudo systemctl stop squid && sudo systemctl mask squid
# sudo dnf remove squid (運用判断による)
```

## 5. 参照

- 関連 playbook: [playbook/ddos.md](../playbook/ddos.md)
- 既存ドキュメント: 14_:V15
