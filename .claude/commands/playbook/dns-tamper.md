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

## 6. 復旧/封じ込めコマンド (人間が手で実行)

⚠️ 以下は **すべて人間がリーダー承認後に手で実行する**コマンドです。
AI は表示・検証・突合のみ。実行には関与しません。
理由:
- タイポ / 不完全な diff / 旧設定上書きで復旧失敗 → サービスダウン継続のリスク
- settings.production.json で物理的に deny されているため AI 実行は不可
- チームが「自分たちで何を直しているか」を理解する必要がある（競技後の説明責任）

```text
# /usr/local/etc/namedb/named.conf に適用する差分
options {
    ...
    allow-update { none; };
    allow-transfer { 10.1.130.1; };  # secondary のみ
    rate-limit {
        responses-per-second 10;
        window 5;
    };
};

# 適用手順 (人間がリーダー承認後に実施):
#   1. named.conf.new を作成 (上記差分を反映)
#   2. ssh root@10.1.1.1 で直ログイン (manage は sudo 不可)
#   3. cp /usr/local/etc/namedb/named.conf /usr/local/etc/namedb/named.conf.bak
#   4. cp /usr/local/etc/namedb/named.conf.new /usr/local/etc/namedb/named.conf
#   5. named-checkconf /usr/local/etc/namedb/named.conf  → 構文 OK 確認
#   6. rndc reload
#   7. dig @10.1.1.1 com1.local SOA で疎通確認
```

→ 表示後、§7 cmd_validator gate を必ず通すこと。
→ 競技中はこの差分を `cp` で当てるだけにする。本番中に named.conf を全書き換えはリスク高。

## 7. コマンド検証ゲート（封じ込めコマンド提示時 必須）

§6 の named.conf 適用 / `rndc reload` / `cp` 等を 1 行でも提示する場合、**リーダーに見せる前に必ず `agent/cmd_validator.py` を通すこと**。settings.production.json で nsupdate / rndc / Edit(/etc/**) は deny になっており **AI は実行できない** — 提案文字列の事故防止が validator の役割。

```bash
cat > /tmp/playbook_proposed.sh <<'EOF'
# ※リーダー承認後 + 顧客通知後に人間が手で実行すること
ssh root@10.1.1.1 'cp /usr/local/etc/namedb/named.conf.new /usr/local/etc/namedb/named.conf && rndc reload'
EOF

PYTHONPATH=. ${SHIRAHAMA_PY:-python3} -m agent.cmd_validator /tmp/playbook_proposed.sh
echo "exit=$?"
```

判定:
- `exit=0` ✅ — リーダーに提示してよい。承認後に**人間が手で打つ**
- `exit=1` 🚨 — ERROR あり。bravo に `manage` で sudo を打とうとしている等を弾く
- WARN のみ — 提示してよいが補足説明を添える

## 8. JSON 永続化（HTML dashboard 連携）

§6 の対策コマンド + §7 の cmd_validator 結果を JSON 化して helper に渡す。actor は `ai_human` (AI 提案 → 人間実行) を明示。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh playbook-dns-tamper --actor ai_human
{
  "inputs": {
    "scenario": "dns-tamper",
    "incident_id": "$INCIDENT_ID"
  },
  "outputs": {
    "proposed_commands": [
      "<§6 で提案したコマンド全文 (1 行 1 件)>"
    ],
    "cmd_validator_result": {
      "exit_code": 0,
      "errors": [],
      "warnings": ["<§7 cmd_validator が出した WARN/ERROR>"]
    },
    "scope": {
      "in_scope": ["<受電内容と直結する対策>"],
      "out_of_scope_logged": ["<観察したが今回触らないもの (治しすぎない哲学)>"]
    }
  },
  "verdict": {
    "status": "🚨 | ⚠️ | ✅",
    "summary": "<提案 N 件 (validator PASS), 採用は人間判断>"
  },
  "next_skills": ["/report", "/ticket"]
}
JSON_EOF
```

- `actor=ai_human` で「AI が提案、人間が実行」を JSON 上で明示 (dashboard が UI 上で「未実行/実行済」バッジを出せる)
- `proposed_commands[]` は §6 で提案した対策コマンドを 1 行 1 件で羅列。`text` フェンス内のコマンドをそのまま転記
- `cmd_validator_result` は §7 で実行した `agent.cmd_validator` の exit_code + errors + warnings をそのまま入れる
- `scope.out_of_scope_logged` で「観察したが今回触らない」項目を残し、報告書/ticket での記録に使う (治しすぎない哲学)
- 保存先: `data/incidents/${INCIDENT_ID}/playbook-dns-tamper__<ts>.json`
