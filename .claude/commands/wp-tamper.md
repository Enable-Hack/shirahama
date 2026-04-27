---
description: WordPress / rainloop / PHP 脆弱性攻撃の深掘り。/incident で WP 系検出された後に叩く
---

# /wp-tamper — WordPress 改ざん深掘り

## 1. 追加収集コマンド

```bash
# WP コアファイル整合性
ssh manage@10.1.1.2 'wp --allow-root --path=/var/www/html core verify-checksums 2>&1'

# 不審な PHP ファイル（uploads 配下に PHP は通常無い）
ssh manage@10.1.1.2 'find /var/www/html/wp-content/uploads -name "*.php" -mtime -1'

# rainloop の admin 操作痕跡
ssh manage@10.1.1.2 'grep -i "admin" /var/log/httpd/access_log | tail -50'

# WP プラグイン一覧
ssh manage@10.1.1.2 'wp --allow-root --path=/var/www/html plugin list 2>&1'
```

## 2. Mock パターン参照

`analyzer.py` の以下の pattern_tag を見る:
- `xss/script-tag`, `xss/onerror-handler`
- `sqli/union-select`, `sqli/or-tautology`
- `wp-bruteforce`（POST /wp-login.php 連発）
- `rainloop-known`（CVE-2022-29360 等）
- `path-traversal`

## 3. Claude 投入用プロンプト

```
以下は victor (10.1.1.2) で観測された WordPress / rainloop 関連のシグナルです。
14_サーバ調査レポート で WP 4.9.4 + rainloop 1.12.0 + PHP 7.2.24 EOL が確認されています。

シグナル: <ここに analyzer 出力を貼る>

以下を出力してください:
1. 攻撃の手口推定（具体的 CVE 番号があれば明記）
2. 即時対応すべきコマンド 3 つ（コピペで実行可能な形式）
3. 顧客向け説明（200 字以内、技術用語なし）
4. 経営層報告のドラフト（300 字以内）
```

## 4. 既存 playbook 参照

- `03_シナリオ別対応プレイブック.md` §2 「WordPress改ざん」
- `06_DDoS対応詳細.md`（WP brute force が DDoS 化した場合）
- `14_サーバ調査レポート_20260424.md` §「victor 脆弱性 TOP3」

## 5. 報告書テンプレ生成指示

`04_完了報告テンプレート.md` の構造で出力:
- 事象概要 / 検知経緯 / 影響範囲 / 原因 / 対応内容 / 再発防止
