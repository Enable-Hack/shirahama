---
description: BIND の DNS 改ざん（nsupdate / AXFR）攻撃の深掘り
---

# /dns-tamper — DNS 改ざん深掘り

## 0. 前提（必ず最初に確認）

- 対象: **bravo (10.1.1.1 / FreeBSD)** — manage は **sudo 不可** なので、root が必要なファイルは `ssh root@10.1.1.1` で直ログイン（root パス `KCom10sT`）
- BIND 設定パス: `/usr/local/etc/namedb/named.conf`（FreeBSD ports）
- ⚠️ `nsupdate` は settings.json で **deny** 設定済 = 実行不可。観察のみ
- ❌ 触禁: CIC DNS `10.1.130.1`（forwarder 先 / 管理対象外）

## 1. 追加収集コマンド（read-only）

### 1.1 BIND 設定確認（18_ #36-39 由来）

```bash
# named.conf の構造把握 (パス確認込み、manage で読める想定)
ssh manage@10.1.1.1 'cat /usr/local/etc/namedb/named.conf 2>/dev/null | head -80'

# 18_ #36 致命的設定: allow-update が広いか / dnssec-validation
ssh manage@10.1.1.1 'grep -iE "allow-update|allow-transfer|allow-query|allow-recursion|dnssec-validation" /usr/local/etc/namedb/named.conf'

# 18_ #38 SOA serial (古い場合は過去環境流用の物証)
dig @10.1.1.1 com1.local SOA +short

# 18_ #39 forwarders の確認 (管理対象外 10.1.130.1 が居るはず)
ssh manage@10.1.1.1 'grep -A2 forwarders /usr/local/etc/namedb/named.conf'
```

### 1.2 動的更新・ゾーン転送試行の痕跡

```bash
# named.log 取得 (時間窓は呼び出し側で絞る)
ssh manage@10.1.1.1 'tail -2000 /var/log/named.log 2>/dev/null || tail -2000 /var/log/messages | grep named' > /tmp/incident_named.log

# 動的更新の denied / approved 痕跡 (18_ #36 が成立した物証)
ssh manage@10.1.1.1 'grep -iE "update.*(approved|denied|forwarded)" /var/log/named.log 2>/dev/null | tail -50'

# AXFR / IXFR 試行 (18_ #37 の amplification 検査と兼用)
ssh manage@10.1.1.1 'grep -iE "transfer|axfr|ixfr" /var/log/named.log 2>/dev/null | tail -30'

# ANY クエリ集計 (DNS amplification の典型)
ssh manage@10.1.1.1 'grep -i "query:" /var/log/named.log 2>/dev/null | grep -i " ANY " | wc -l'
```

### 1.3 ゾーン整合性の確認（read-only / nsupdate しない）

```bash
# 主要レコードを外部からも確認 (改ざんされてないか)
dig @10.1.1.1 www.com1.local A +short
dig @10.1.1.1 mail.com1.local A +short
dig @10.1.1.1 ns.com1.local A +short
dig @10.1.1.1 com1.local MX +short

# ゾーンファイルの mtime (改ざんされたなら更新時刻が動く)
ssh manage@10.1.1.1 'ls -la /usr/local/etc/namedb/dynamic/ /usr/local/etc/namedb/master/ 2>/dev/null'

# AXFR が外から取れるか (取れたら情報漏えい)
dig @10.1.1.1 com1.local AXFR 2>&1 | head -30
```

### 1.4 解析ツール投入

```bash
python scripts/preprocess/parse_named.py /tmp/incident_named.log > /tmp/incident_named.jsonl
# analyzer.run('/tmp/') が DNS_PATTERNS で pattern_tag を出す
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
