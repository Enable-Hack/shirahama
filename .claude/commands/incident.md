---
description: 電話受電起点でログ取得 → analyzer → Mock → Claude → カテゴリ判定 → 推奨次手順を一気通貫で出す
---

# /incident — 汎用インシデント対応エントリ

引数: `<時間窓> <ホスト>`
例: `/incident 13:00-13:30 victor`

## やること（このファイルは Claude Code 自身に対する指示書）

以下の手順を順番に実行してください。

---

## §0. 本番環境定数（全 spoke コマンドが参照する）

| 項目 | 値 |
|---|---|
| ドメイン | `com1.local` |
| **victor** (Web/Mail/DHCP) | `10.1.1.2`（Rocky Linux）/ manage は **sudo 可** / パス `sh1Ra8mA` / root パス `KCom10sT` |
| **bravo** (DNS/掲示板) | `10.1.1.1`（FreeBSD）/ manage は **sudo 不可** → root が必要なら `ssh root@10.1.1.1` 直ログイン |
| サーバ帯 | `10.1.1.0/24` |
| ユーザ帯 | `10.1.11.0/24` |
| RTX1200 (GW) | `10.1.1.254` |
| ESXi | `10.1.1.201` |
| **❌ 触禁: CIC DNS** | `10.1.130.1` (forwarder 先 / 管理対象外) |
| **❌ 触禁: VPN 入口** | `133.42.49.151` (運営機器) |
| 報告先 PukiWiki | `http://133.42.49.140/trouble_ticket_137/index.php` (whiskey / E5mA9cF3) |

## §0.5 既侵害前提（重要 / 18_§9 由来）

- **配布アカウント (manage / root / admin / vty / enable) を使った攻撃は来ない** — これらの IP / user 由来のシグナルは Mock backend で drop してよい
- **攻撃は別アカウント / 不審 IP から来る** — `last`/`who` で **配布アカウント以外のログイン**、特に `10.1.11.x` 配布レンジ外の送信元を最重要監視
- 受電内容は「未知の侵害が初めて起きた」ではなく **「既に潜伏していた攻撃者が動き出した」** 前提で処理する（テスト環境では 4/24 深夜に obuchi/manage が `10.1.129.10` から両機にログイン痕跡があった）
- 通報者には「攻撃が拡大した」と説明、「初めて起きた」と断定しない

## §0.6 「触らない」哲学（18_§4.3 由来）

- demo / 共有環境の脆弱性は **出題前提として残されている可能性** が高い
- 観察した脆弱性をその場で塞ぐと、出題シナリオが進まなくなる
- 当日見つけた脆弱性は **即座に塞がず、報告書ドラフトに書き留める**
- **対策コマンドを提示する場合は必ず冒頭に「リーダー承認後」を明記**
- settings.json で破壊系コマンドは `deny` / `ask` で物理的にブロック済 — Claude が善意で `nsupdate` `systemctl stop` `dnf install` を提示しても実行されない

## §0.7 全 spoke 共通の §0 参照ルール

- `/playbook:wp-tamper` `/playbook:dns-tamper` `/playbook:ddos` `/playbook:phishing` `/playbook:ransomware` を呼ぶ前に、必ず本ファイルの §0〜§0.6 を読み返す
- 各 spoke の §0 にある「対象ホスト」「sudo 可否」「特殊注意」を確認
- カテゴリ未確定の場合は先に `/check:<vuln>` (例 `/check:wp-xmlrpc-brute`) で痕跡確認 → playbook へ

---

### 1. ログ取得

引数で指定された時間窓と対象ホスト（victor または bravo）に対し、必要なログを取得する:

```bash
# victor (Rocky Linux, 10.1.1.2) の場合
ssh manage@10.1.1.2 'tail -2000 /var/log/httpd/access_log'  > /tmp/incident_access.log
ssh manage@10.1.1.2 'tail -1000 /var/log/secure'           > /tmp/incident_secure.log
ssh manage@10.1.1.2 'tail -1000 /var/log/maillog'          > /tmp/incident_maillog.log

# bravo (FreeBSD, 10.1.1.1) の場合
ssh manage@10.1.1.1 'tail -2000 /var/log/named.log'         > /tmp/incident_named.log
ssh manage@10.1.1.1 'tail -1000 /var/log/auth.log'          > /tmp/incident_auth.log
ssh manage@10.1.1.1 'tail -1000 /var/log/httpd-error.log'   > /tmp/incident_httpd_err.log
```

### 2. 時間窓フィルタ + JSONL 化

`scripts/preprocess/parse_*.py` を使ってテキストログを JSONL に変換し、指定時間窓だけ抽出:

```bash
python scripts/preprocess/parse_clf.py /tmp/incident_access.log \
  | jq --arg start "$START" --arg end "$END" 'select(.timestamp >= $start and .timestamp <= $end)' \
  > /tmp/incident_access.jsonl
```

他のログも同様。

### 3. analyzer 起動

```bash
python -c "
from agent import analyzer
signals = analyzer.run('/tmp')
print(f'検出シグナル: {len(signals)} 件')
for s in signals:
    print(f'  [{s.severity}] {s.type} @ {s.path[:80]}')
"
```

### 4. Mock 二段ふるい + Claude 集約

```bash
python -c "
from agent import analyzer
from agent.backends.mock_backend import MockBackend
from agent.backends.claude_backend import ClaudeBackend
from agent.validator import validate_patches

signals = analyzer.run('/tmp')

# Mock で whitelist drop + known-bad 即出し
mock = MockBackend()
mock_patches = mock.propose_patches(signals)

# grey シグナルだけ Claude に集約
known_bad_targets = {p.target for p in mock_patches}
grey = [s for s in signals if s.path not in known_bad_targets]
claude_patches = ClaudeBackend().propose_patches(grey) if grey else []

all_patches = mock_patches + claude_patches
validated = validate_patches(all_patches)

for p in validated:
    print(f'[{p.action}] {p.rule_id} conf={p.confidence:.2f}')
    print(f'  target: {p.target}')
    print(f'  match: {p.match_type} {p.match_operator} {p.match_value!r}')
    print(f'  rationale: {p.rationale_ja}')
"
```

### 5. カテゴリ判定 + 次に叩くべき skill 提示

**二段ルーティング**: analyzer 出力の pattern_tag を見て、まず `/check:*` でピンポイント痕跡確認 → 🚨 確定なら該当 `/playbook:*` で深掘りに進む。

#### 5.1 ★最初に必ず叩く★ 既侵害前提の check (§0.5 の根拠)

`/incident` 起動時、analyzer 結果に関わらず以下を最優先で並行起動する:

| 観点 | /check |
|---|---|
| 10.1.129.0/24 由来の活動 (obuchi/manage 既侵害) | `/check:check-known-attacker-ip` |
| ログ自体の汚染疑い (514/UDP 注入) | `/check:check-syslog-udp-injection` |

→ 🚨 注入確定なら、後続 check の判定信頼度を **下げて** 解釈すること。

#### 5.2 pattern_tag → check → playbook ルーティング表

| analyzer pattern_tag (主) | 補助条件 | 1. /check | 2. 確定後 /playbook |
|---|---|---|---|
| `webapp/xmlrpc` + `webapp/auth-bruteforce` | — | `check-wp-xmlrpc-brute` | `wp-tamper` |
| `webapp/author-scan` | — | `check-wp-rest-author-scan` | `wp-tamper` |
| `xss/*` | path に `/rain/` | `check-rainloop-cve29360` | `wp-tamper` + `phishing` |
| `webapp/dotfile-access` | path に `.my.cnf` | `check-mycnf-leak` + `check-mysql-x-direct` | `wp-tamper` + `ransomware` |
| `webapp/dotfile-access` | path に `wp-config` | `check-wp-config-leak` | `wp-tamper` + `ransomware` |
| `webapp/dotfile-access` | path に `.htaccess` | `check-htaccess-rce` | `wp-tamper` |
| `webapp/upload-php` | uploads/ 配下 | `check-htaccess-rce` + `check-php-allow-url-fopen` | `wp-tamper` + `ransomware` |
| `webapp/scanner-ua` | path に `backup_html` | `check-backup-html-exposure` | `wp-tamper` |
| `path_traversal` / `cmdi` | — | `check-php-allow-url-fopen` | `wp-tamper` + `ransomware` |
| `dns/unauthorized-update` / `dns/update-denied` | — | `check-bind-allow-update` | `dns-tamper` |
| `dns/axfr-attempt` | — | `check-bind-axfr` | `dns-tamper` |
| `dns/amplification-bait` / `dns/amplification-ratio` | — | (check 未作成 / 暫定で playbook 直行) | `ddos` |
| `privesc/pkexec-attempt` | — | `check-pkexec-pwnkit` | `ransomware` |
| `privesc/sudo-unauthorized` / `persist/at-job` | — | (check なし / Second priority `at-job-persist`) | `ransomware` |
| `mail/relay-attempt` / `mail/relay-denied` / `mail/burst` | — | `check-sendmail-open-relay` | `phishing` |
| `mail/burst` | from=apache@/dovecot@ 等 | `check-aliases-root-forward` | `phishing` + `wp-tamper` |
| `mail/sasl-failed` | imap-login 経路 | `check-courier-imap-plain` + `check-dovecot-passdb-pam` | `phishing` |
| `mail/spf-fail` / `mail/dkim-fail` 単発 | — | `check-sendmail-open-relay` | `phishing` |
| `auth/ssh-failed` / `auth/ssh-invalid-user` | user=obuchi | `check-obuchi-777-hijack` + `check-known-attacker-ip` | `ransomware` |
| `auth/ssh-failed` | user=toor (bravo) | `check-toor-uid0` | `ransomware` |
| `auth/ssh-bruteforce` | — | `check-known-attacker-ip` | `ransomware` |
| `protocol/telnet-access` | — | `check-telnet-plain-auth` | `ransomware` |
| 同一 IP からの request burst のみ (tag 不在) | — | (check なし) | `ddos` |

#### 5.3 analyzer tag 不在でも観察すべき (手動起動)

以下は analyzer が直接 tag を返さないが、状況証拠で叩く check:

- 受電内容に「内部 IP 帯のクライアントが偽サイトに飛ばされた」が含まれる → `check-rogue-dhcp`
- backup_html / 旧 BBS への到達ログを発見 → `check-backup-html-exposure`
- SNMP recon 痕跡や 161 への異常接続 → `check-snmp-public-walk`
- 上記いずれにも該当しない → 人間判断 → リーダー相談

#### 5.4 複数 tag 同時発火

複数 tag が同時に出た場合、上記表で **複数 check を並行起動して良い**。例:
- `webapp/xmlrpc` + `webapp/dotfile-access` → `check-wp-xmlrpc-brute` と `check-mycnf-leak` を両方
- `auth/ssh-bruteforce` + `mail/sasl-failed` → `check-known-attacker-ip` と `check-dovecot-passdb-pam` を両方

#### 5.5 check が未作成のカテゴリ

暫定で playbook 直行を提示し、不足を `memory/detection_skill_design.md` の Yellow priority に追記する。

### 6. 状況サマリ生成

```bash
python -c "
from agent.backends.claude_backend import ClaudeBackend
print(ClaudeBackend().explain_to_operator_ja(signals, validated))
"
```

→ この出力を `01_受電ヒアリングシート.md` に追記し、リーダーに報告。

## 参照
- `19_AIパイプライン実装ガイド.md` — 詳細手順
- `18_キャンプ知見の白浜活用方針.md` — 思想
- `03_シナリオ別対応プレイブック.md` — カテゴリ別の対応手順
