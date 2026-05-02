---
description: BIND の allow-update 経由 DNS 改ざん (nsupdate) の痕跡を確認
---

# /check:bind-allow-update — DNS 動的更新攻撃確認

引数: `<時間窓> <ホスト>`
例: `/check:bind-allow-update 13:00-13:30 bravo`

## 0. 前提

- 対象: **bravo** (本番 10.1.1.1 / FreeBSD、BIND9)
- 関連 weakness: `named.conf` の `allow-update { 10.0.0.0/8; };` + `dnssec-validation no` → 任意の 10.x から `nsupdate` で A/MX/NS 書き換え可能
- analyzer.py の対応 pattern_tag: `dns/unauthorized-update` (approved 検知)、`dns/update-denied` (失敗試行)
- ⚠️ **bravo の manage は sudo 不可** — root が必要なら `ssh root@10.1.1.1` で直ログイン (root パス `KCom10sT`)
- ⚠️ `nsupdate` 自体は settings.json で **deny** → 実行不可（観察のみ）
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"   # 本番: manage (sudo 不可) / デモ: rocky (sudo 可)
TARGET_HOST="${TARGET_HOST:-10.1.1.1}"
# manage で読めない場合は ROOT_FALLBACK=1 にして root 直で読む
```

## 1. 収集 (read-only)

### 1.1 named.conf の致命的設定確認

```bash
# FreeBSD ports インストールパス
ssh "$TARGET_USER@$TARGET_HOST" 'cat /usr/local/etc/namedb/named.conf 2>/dev/null | head -100'

# 致命的キーワード
ssh "$TARGET_USER@$TARGET_HOST" \
  'grep -iE "allow-update|allow-transfer|dnssec-validation|recursion|forwarders" /usr/local/etc/namedb/named.conf'
```

### 1.2 動的更新の approved/denied 痕跡（最重要）

```bash
# manage で読めなければ ssh root@... に切り替え
ssh "$TARGET_USER@$TARGET_HOST" 'tail -5000 /var/log/named.log 2>/dev/null || tail -5000 /var/log/messages | grep named' \
  > /tmp/check_bind_update.log

# approved = 攻撃成立の物証 🚨
grep -iE "update.*'.*'.*approved" /tmp/check_bind_update.log | tail -30

# denied = 試行されたが失敗（allow-update が効いている証拠）
grep -iE "update.*'.*'.*denied" /tmp/check_bind_update.log | tail -30

# signer "..." approved (TSIG なしで通った場合の別表記)
grep -iE 'signer\\s+".*"\\s+approved' /tmp/check_bind_update.log | tail -10
```

### 1.3 ゾーンファイルの mtime + serial（成立物証）

```bash
# dynamic ゾーン (動的更新可能なら BIND がここに journal を作る)
ssh "$TARGET_USER@$TARGET_HOST" 'ls -la /usr/local/etc/namedb/dynamic/ /usr/local/etc/namedb/master/ 2>/dev/null'

# .jnl ファイルが直近で更新されていれば確定的
ssh "$TARGET_USER@$TARGET_HOST" 'find /usr/local/etc/namedb -name "*.jnl" -mmin -60 2>/dev/null'

# SOA serial を外から確認（攻撃者が更新するたびに +1 される）
dig @"$TARGET_HOST" com1.local SOA +short
```

### 1.4 ゾーン整合性確認 (read-only / nsupdate しない)

```bash
# 主要レコードが改ざんされてないか
for r in www mail ns api admin; do
  echo "$r.com1.local: $(dig @$TARGET_HOST $r.com1.local A +short)"
done
dig @"$TARGET_HOST" com1.local MX +short
dig @"$TARGET_HOST" com1.local NS +short

# 既知ベースライン (PDF 配布資料に記載) と照合
# www.com1.local A → 想定値は docs/参加者配布資料 参照
```

### 1.5 JSONL 化

```bash
python scripts/preprocess/parse_named.py /tmp/check_bind_update.log > /tmp/check_bind_update.jsonl
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. update approved | `client X#Y: update '...' approved` ログあり | 🚨 確定 (改ざん成立) |
| B. .jnl 更新 | `dynamic/*.jnl` の mtime が時間窓内 | 🚨 確定 |
| C. SOA serial 急増 | 外部 dig で serial が直前+10 以上に飛んだ | 🚨 確定 |
| D. update denied 多発 | 同一 IP から denied 連発（試行はあったが allow-update が締まっている） | ⚠️ 疑わしい |
| E. レコード改変 | A レコードが既知ベースラインと乖離 | 🚨 確定 |
| F. analyzer tag | `dns/unauthorized-update` 発火 | 🚨 確定 |

## 3. 判定基準

- ✅ **正常**: approved 0 件、.jnl 無更新、SOA serial 静止、A レコード一致
- ⚠️ **疑わしい**: D のみ → 攻撃試行は確認、被害なし → 監視継続
- 🚨 **確定**: A/B/C/E/F いずれか → ただちに **/playbook:dns-tamper** へ

## 4. 次のアクション

### 確定なら
- **`/playbook:dns-tamper`** で深掘り（攻撃元 IP 特定 + 改ざんレコード一覧化）
- 並行して **`/check:bind-axfr`** (情報漏洩経路としての AXFR 試行も同時に来やすい)

### 即時封じ手（リーダー承認後のみ）
```bash
# 案1: named.conf の allow-update を絞る（要 BIND reload）
# allow-update { none; };
# 案2: ゾーンを backup から復元（journal を無効化してから）
# rndc freeze com1.local && cp <backup>.zone /usr/local/etc/namedb/master/com1.local.zone && rndc thaw com1.local
```

### メモするだけ
- `nsupdate` は settings.json deny で実行不可 → 「対策コマンド提示はできるが Claude が実行することはない」
- ゾーン書き換えは出題前提の可能性 → 18_§4.3「触らない」を優先

## 5. 参照

- 関連 playbook: [playbook/dns-tamper.md](../playbook/dns-tamper.md)
- 連鎖先 check: [check-bind-axfr.md](check-bind-axfr.md)
- analyzer 該当: `agent/analyzer.py` `DNS_PATTERNS` (`dns/unauthorized-update`, `dns/update-denied`)
- 既存ドキュメント: `docs/14_サーバ調査レポート_20260424.md` §「BIND allow-update 致命的設定」
