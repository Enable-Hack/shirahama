---
description: シナリオ② 内部 MITM → DNS 書換 → フィッシングのキルチェーン全体を確認
---

# /scenario:dns-spoof-phish — キルチェーン②: DNS 書換 → フィッシング

引数: `<時間窓> <ホスト>`
例: `/scenario:dns-spoof-phish 13:00-13:30 bravo`

## 0. 想定キルチェーン (16_:1.3-② 由来)

```
ステージ1: 内部 MITM 立て (rogue DHCP / ARP spoofing)
  └ ISC dhcpd not authoritative; を悪用
       ↓
ステージ2: DNS レコード書換
  └ BIND allow-update {10.0.0.0/8;} で nsupdate
       (または DNS forwarder の途中書換)
       ↓
ステージ3: 偽 Web サイトへの誘導
  └ www.com1.local / mail.com1.local / wp-login が偽サイトに飛ぶ
       ↓
ステージ4: 認証情報窃取
  └ 偽 WP / 偽 RainLoop ログイン画面で credential 入手
       (RainLoop の external domain relay と組み合わせ)
       ↓
ステージ5: 連鎖攻撃
  └ 入手した credential で本物の WP / メール / SSH に侵入
```

## 1. 起動条件

- analyzer 出力に **`dns/unauthorized-update`** が発火
- 受電内容に「サイトが別の見た目になった」「ログインしたらおかしい」を含む
- BIND のゾーンファイル mtime が時間窓内に変化
- 内部 ARP テーブルに同 MAC で複数 IP の重複

## 2. 各ステージで叩く /check 一覧

### ステージ1: 内部 MITM
- **並行起動**:
  - `/check:check-rogue-dhcp`
  - `/check:check-baseline-hardening` (firewalld inactive で MITM が容易になる)

### ステージ2: DNS レコード書換
- **並行起動**:
  - `/check:check-bind-allow-update`
  - `/check:check-bind-axfr`
  - `/check:check-bind-version`

### ステージ3: 誘導確認
- analyzer tag では捕まらないため、手動で:
  - 主要レコード (www / mail / api / ns / wp-admin) を **複数のリゾルバから dig** して比較
  - bravo の named.log で `update '...' approved` を時系列で並べる
  - VPN クライアント帯 (10.1.11.50-99) のクライアントが何を解決しているか

### ステージ4: フィッシング (偽サイト ⇄ 認証情報窃取)
- **並行起動**:
  - `/check:check-rainloop-cve29360`
  - `/check:check-rainloop-domain-relay` (gmail/yahoo IMAP 中継経路)
  - `/check:check-sendmail-open-relay` (なりすまし送信)

### ステージ5: 連鎖攻撃
- 窃取された credential で本物にログインしてくる経路:
  - `/check:check-known-attacker-ip` (10.1.129.10 含む既侵害 IP の再活動)
  - `/check:check-courier-imap-plain` / `/check:check-dovecot-passdb-pam`
  - `/check:check-telnet-plain-auth`

## 3. ステージ間の連鎖判定

| 連鎖判定 | 解釈 |
|---|---|
| ステージ2 確定 + ステージ3 ✅ | DNS は触られたが影響範囲は限定的 (誘導には至っていない or 防御効いてる) |
| ステージ2 確定 + ステージ3 確定 | フィッシング誘導成立 |
| ステージ4 確定 | 認証情報すでに窃取された前提 → 全アカウントパスワード強制リセット |
| ステージ5 確定 | 窃取クレデンシャルでの再侵入が始まっている |

## 4. 確定後のアクション

### 並行起動する playbook
- **`/playbook:dns-tamper`** (DNS 改竄全工程)
- **`/playbook:phishing`** (フィッシング対応)

### リーダー報告のシナリオストーリー
> "**ISC dhcpd の not authoritative;** で rogue DHCP が共存 → **BIND allow-update で nsupdate** が成立 → **www.com1.local が攻撃者サイトへ誘導** → 偽 WP / RainLoop で認証情報窃取 → **窃取された credential で本物の IMAP / SSH へ侵入**。
> 即時対応: 1) bravo named のゾーン復元 2) 全ユーザの強制パスワード変更 3) クライアント帯の DHCP 配布停止 4) スイッチでの DHCP スヌーピング有効化"

### 即時封じ手は個別 check の §4 を参照

## 5. 参照

- 関連 playbook: [playbook/dns-tamper.md](../playbook/dns-tamper.md)、[playbook/phishing.md](../playbook/phishing.md)
- 既存ドキュメント: 16_:1.3-② / 14_:8.1#4
- 関連シナリオ:
  - [scenario/killchain-recon-rce-dbexfil.md](killchain-recon-rce-dbexfil.md) (Web 系キルチェーンと組み合わさる場合)
  - [scenario/vpn-uplink-abuse.md](vpn-uplink-abuse.md)

## 6. JSON 永続化（HTML dashboard 連携）

§2 で並行起動した /check の結果を集約し、キルチェーン全体の総括を JSON で出力する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh scenario-dns-spoof-phish
{
  "inputs": {
    "checks_dispatched": ["check-rogue-dhcp", "check-bind-allow-update", "check-bind-axfr", "check-rainloop-cve29360", "check-sendmail-open-relay"]
  },
  "outputs": {
    "killchain_phase_results": [
      {"phase": "internal-mitm", "checks": ["check-rogue-dhcp"], "verdict": "🚨 | ⚠️ | ✅"},
      {"phase": "dns-rewrite", "checks": ["check-bind-allow-update", "check-bind-axfr"], "verdict": "🚨 | ⚠️ | ✅"},
      {"phase": "phishing-landing", "checks": ["check-rainloop-cve29360", "check-sendmail-open-relay"], "verdict": "🚨 | ⚠️ | ✅"}
    ],
    "chain_completeness": "<どのフェーズまで観測できたか / 抜けているフェーズ>"
  },
  "verdict": {
    "status": "🚨 | ⚠️ | ✅",
    "summary": "<キルチェーン全体の 1-2 行総括>"
  },
  "next_skills": ["/playbook:dns-tamper", "/playbook:phishing", "/review"]
}
JSON_EOF
```

- 保存先: `data/incidents/${INCIDENT_ID}/scenario-dns-spoof-phish__<ts>.json`
