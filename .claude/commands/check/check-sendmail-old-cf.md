---
description: sendmail.cf が旧サイト (com1.local の古いビルド) からの流用で ACL/設定の不整合がないかを確認
---

# /check:check-sendmail-old-cf — sendmail.cf 旧サイト流用確認

引数: `<時間窓> <ホスト>`
例: `/check:check-sendmail-old-cf 13:00-13:30 bravo`

## 0. 前提

- 対象: **bravo (10.1.1.1)** **victor (10.1.1.2)** 両方
- 関連 weakness: 14_:B8 / 16_:#21 — sendmail.cf のヘッダコメントに `built by root@bravo.com1.local` 等の **過去サイトの hostname が残存**。設定流用時の ACL ミスマッチで Open Relay / 不要なドメイン許可が混入する可能性
- 影響: relay-domains / mynetworks / Cw が古いまま → 想定外ドメインの中継許可
- analyzer.py の対応 pattern_tag: `mail/relay-attempt` (連鎖)
- **slim 版** — 設定の指紋確認に特化、実害は `/check:check-sendmail-open-relay` で見る
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.1}"
```

## 1. 収集 (read-only)

```bash
# sendmail.cf のビルド情報 (流用元の物証)
ssh "$TARGET_USER@$TARGET_HOST" 'grep -iE "built by|##### built|DZ" /etc/mail/sendmail.cf 2>/dev/null | head -5'

# Cw (受信許容ドメイン) と relay-domains
ssh "$TARGET_USER@$TARGET_HOST" 'sudo cat /etc/mail/local-host-names 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo cat /etc/mail/relay-domains 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'sudo cat /etc/mail/access 2>/dev/null | head -30'

# mynetworks / mailertable
ssh "$TARGET_USER@$TARGET_HOST" 'sudo grep -iE "Cw|DZ|D[Mm]|mailertable" /etc/mail/sendmail.cf 2>/dev/null | head -10'

# .mc ファイルの内容 (本来のソース)
ssh "$TARGET_USER@$TARGET_HOST" 'sudo cat /etc/mail/sendmail.mc 2>/dev/null' | head -30
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. built by コメントが過去 hostname | sendmail.cf に旧 hostname 残存 | ⚠️ 流用痕跡 |
| B. relay-domains に過去ドメイン | com6.local / com1.local 等が並存 | ⚠️ 設定流用 |
| C. access に古い ACL | 想定外の RELAY エントリ | 🚨 設定 |
| D. .mc が再生成されていない | sendmail.mc と .cf の整合不一致 | ⚠️ |

## 3. 判定基準

- ✅ **正常**: 現サイト hostname のみ、relay-domains 最小限
- ⚠️ **疑わしい**: A / B / D → メモ
- 🚨 **確定**: C 観測 → **/check:check-sendmail-open-relay** で実害確認

## 4. 次のアクション

### メモするだけ (A/B/D)
- 流用痕跡を報告書に残す
- 完全な再生成が必要な旨をリーダーへ進言

### 連鎖 (C 検出時)
- **`/check:check-sendmail-open-relay`** + **`/check:check-aliases-root-forward`**

## 5. 参照

- 関連 playbook: [playbook/phishing.md](../playbook/phishing.md)
- 連鎖先 check: [check-sendmail-open-relay.md](check-sendmail-open-relay.md)、[check-aliases-root-forward.md](check-aliases-root-forward.md)
- 既存ドキュメント: 14_:B8 / 16_:#21
