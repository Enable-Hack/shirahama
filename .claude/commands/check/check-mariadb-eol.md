---
description: MariaDB 10.3 (EOL 2023-05) の既知 CVE 該当バージョン確認 (静的検査)
---

# /check:check-mariadb-eol — MariaDB EOL 確認

引数: `<時間窓> <ホスト>`
例: `/check:check-mariadb-eol 13:00-13:30 victor`

## 0. 前提

- 対象: **victor (10.1.1.2)**
- 関連 weakness: 16_:2.4 — MariaDB 10.3 系は **2023-05 EOL** で以後セキュリティパッチなし
- 影響: 既知 CVE が修正されず累積。RCE/権限昇格系の CVE があれば致命的
- analyzer.py の対応 pattern_tag: 直接対応なし (静的バージョン確認)
- **このカテゴリは「記録のみで十分」(slim 版)** — 攻撃検知ではなく前提条件のメモ
- /incident §0〜§0.6 を読み返してから実行すること

```bash
TARGET_USER="${TARGET_USER:-manage}"
TARGET_HOST="${TARGET_HOST:-10.1.1.2}"
```

## 1. 収集 (read-only)

```bash
# パッケージバージョン
ssh "$TARGET_USER@$TARGET_HOST" 'rpm -q mariadb-server mariadb 2>/dev/null'

# 起動中の version
ssh "$TARGET_USER@$TARGET_HOST" 'mysql --version 2>/dev/null'
ssh "$TARGET_USER@$TARGET_HOST" 'mysqld --version 2>/dev/null'

# CVE database を引く (オフラインなら既知リスト参照)
# 10.3.x の主要 CVE: CVE-2022-32083, CVE-2022-32084, CVE-2022-31624 等
```

## 2. 検知パターン

| パターン | 痕跡 | 重要度 |
|---|---|---|
| A. MariaDB 10.3.x | rpm で 10.3 系 | ⚠️ EOL 該当 |
| B. 10.5.x 未満 | 未更新 | ⚠️ EOL 該当 |
| C. CVE 関連症状 | 別 check (mariadb-3306-direct) で異常 SQL | 🚨 |

## 3. 判定基準

- ✅ **正常**: MariaDB 10.11 LTS 以上 / 10.6 LTS
- ⚠️ **疑わしい**: 10.3.x → メモ + 他 check との連鎖を監視
- 🚨 **確定**: 攻撃痕跡は本 check では検出しない → `check-mariadb-3306-direct` 等で見る

## 4. 次のアクション

### メモするだけ
- バージョン情報を報告書に記載
- CVE 引用は事後対応として保管

### 連鎖
- **`/check:check-mariadb-3306-direct`** で実害確認

## 5. 参照

- 関連 playbook: [playbook/wp-tamper.md](../playbook/wp-tamper.md)
- 連鎖先 check: [check-mariadb-3306-direct.md](check-mariadb-3306-direct.md)、[check-mysql-x-direct.md](check-mysql-x-direct.md)
- 既存ドキュメント: 16_:2.4 / 14_:6.4
