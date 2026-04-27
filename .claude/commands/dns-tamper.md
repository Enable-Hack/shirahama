---
description: BIND の DNS 改ざん（nsupdate / AXFR）攻撃の深掘り
---

# /dns-tamper — DNS 改ざん深掘り

## 1. 追加収集コマンド

```bash
# 現在のゾーン状態確認
ssh manage@10.1.1.1 'dig @localhost com1.local AXFR 2>&1 | head -30'

# allow-update / allow-transfer 設定確認
ssh manage@10.1.1.1 'cat /etc/named.conf | grep -A2 "allow-update\|allow-transfer"'

# nsupdate 試行ログ抽出
ssh manage@10.1.1.1 'grep -i "update\|transfer" /var/log/named.log | tail -50'

# ゾーンファイル mtime
ssh manage@10.1.1.1 'ls -la /etc/namedb/dynamic/ /var/named/dynamic/ 2>&1'
```

## 2. Mock パターン参照

`analyzer.py` の以下:
- `dns/unauthorized-update`
- `dns/axfr-attempt`
- `dns/amplification-bait`（ANY クエリ大量）

## 3. Claude 投入用プロンプト

```
以下は bravo (10.1.1.1) の DNS サーバー（BIND）で観測されたシグナルです。
14_ レポートで `allow-update { 10.0.0.0/8; };` という致命的設定が確認されています。

シグナル: <貼る>

以下を出力してください:
1. DNS 改ざんが成立したか（NOERROR の update があるか）
2. 影響を受けたレコード推定
3. 即時対応コマンド（named.conf 修正案 + reload 手順）
4. 顧客向け説明（DNS が引けない理由を非エンジニアに説明）
```

## 4. 既存 playbook 参照

- `03_シナリオ別対応プレイブック.md` §6「情報漏えい」（DNS 改ざんによるリダイレクト）
- `14_サーバ調査レポート_20260424.md` §「BIND allow-update 致命的設定」

## 5. 報告書テンプレ生成指示

`04_完了報告テンプレート.md` の構造で出力。
特に **「再発防止」セクションで `allow-update { none; };` または特定 IP のみ許可を明記**。

## 6. 事前準備しておく修正版 named.conf 雛形

```
# /etc/named.conf に適用する差分
options {
    ...
    allow-update { none; };
    allow-transfer { 10.1.130.1; };  # secondary のみ
    rate-limit {
        responses-per-second 10;
        window 5;
    };
};
```

→ 競技中はこの差分を `cp` で当てるだけにする。本番中に named.conf を全書き換えはリスク高。
