# shirahama — 情報危機管理コンテスト 白浜 whiskey 班

> ⚠️ Private repo（チーム限定）。テスト/本番の認証情報を含むため public 化禁止。

セキュリティ・キャンプ 2026 ミニ B トラックで学んだ AI ログ分析パイプライン（観測→判断→検証→提案）を、白浜の **電話受電起点で複数攻撃カテゴリに対応する半自動インシデント対応** に応用するリポジトリ。

---

## 0. 三つの環境（最初に読む）

このプロジェクトは「環境」が 3 種類あり、ドキュメント・コード・設定がそれぞれ別の環境を指しているので最初に区別する。

| 用語 | 実体 | 役割 | 認識 |
|---|---|---|---|
| **本番** | SCCS2026 Booth 1 の競技環境（PDF `docs/参加者配布資料_whiskey.pdf` 由来） | 5/5 当日に実際に AI パイプラインを投入する対象 | bravo は **FreeBSD**、両機 10.1.1.0/24、参加者 VPN 10.1.11.50-99 |
| **テスト** | 主催者が今年の参加者向けに公開した「研究してよい」環境 | 脆弱性インベントリの源泉。チームは構築せず観測のみ | docs の `14_サーバ調査レポート` `16_本番環境クイックリファレンス` `16_攻撃分析と既存ファイルレビュー` 等で記述 |
| **デモ** | OCI + Akamai に再構築した検証用ラボ（**現在 build 中**） | analyzer.py を本番投入前に E2E テストする場 | bravo / victor は **Rocky Linux 8.10**（OCI ap-osaka-1）、attack-vm は Ubuntu（Akamai） |

**重要:**
- `.md` ドキュメントの設定値はほぼ**テスト**を指す（書かれた当時のスナップショット）
- PDF は**本番**を定義する（5/5 まで触れない）
- コードを動かす対象は今は**デモ**（OCI Rocky）。本番（FreeBSD）に移すときはログパスや IP が変わる
- ホスト名 (bravo / victor) と機能（DNS/Mail vs Web）は 3 環境で共通だが、**OS が違うのでログ取得パスが違う**

デモ進捗はメモリ `demo_progress.md` に記録。2026-05-02 時点で **wp-tamper シナリオのみ E2E 通過**、dns-tamper / phishing / ddos / ransomware は未着手。

---

## 1. ディレクトリ構成（実物）

```
shirahama/
├── README.md                              ← このファイル
├── .gitignore
│
├── docs/                                  ← 既存ドキュメント（多くはテスト環境を記述）
│   ├── 00_目次.md                         ← 全 docs のインデックス
│   ├── 14〜16_*.md                        ← テスト環境の脆弱性インベントリ
│   ├── 18_キャンプ知見の白浜活用方針.md
│   ├── 19_今後やること.md
│   ├── 20_VPN_SSH接続手順_5_5.md          ← 本番接続手順
│   ├── 21_システム解説.md                  ← パイプライン解説
│   └── 参加者配布資料_whiskey.pdf          ← 本番定義（外部アップロード禁止）
│
├── agent/                                 ← AI ログ分析パイプライン本体
│   ├── analyzer.py                        ← 観測層: 45 regex / 38 pattern_tag + 4 集約 tag
│   ├── llm.py                             ← 型定義 (LLMBackend / Signal / PatchProposal)
│   ├── validator.py                       ← 検証層: 壊れた提案を弾く
│   ├── patcher.py                         ← 統合オーケストレータ
│   ├── prompts.py                         ← Claude system prompt
│   ├── backends/
│   │   ├── mock_backend.py                ← 判断層: ルールベース + whitelist
│   │   ├── claude_backend.py              ← 判断層: Anthropic Claude (haiku-4-5)
│   │   └── swallow_backend.py             ← 残存（現状未使用、将来ローカル LLM フォールバック用）
│   └── renderers/
│       └── nginx_renderer.py              ← PatchProposal → nginx ルール（実装済、現在は Claude が直接コマンド出力するため未使用）
│
├── scripts/
│   ├── preprocess/                        ← テキストログ → JSONL
│   │   ├── _common.py                     ← emit() / stream_lines() 共通
│   │   ├── parse_clf.py                   ← Apache CLF
│   │   ├── parse_secure.py                ← /var/log/secure
│   │   ├── parse_maillog.py               ← postfix/sendmail
│   │   ├── parse_named.py                 ← BIND
│   │   └── parse_syslog.py                ← 汎用 syslog
│   ├── feed/
│   │   ├── fetch_cve.py                   ← CISA KEV から取得
│   │   └── run_daily.sh
│   └── run_analyzer.sh                    ← /incident の実体（時間窓+ホストで一気通貫）
│
├── .claude/                               ← Claude Code 設定とコマンド
│   ├── settings.json                      ← ★現在アクティブ（build mode、デモ build 中は緩い）
│   ├── settings.production.json           ← ★本番モード（厳格、5/5 前に必ずコピーして上書き）
│   └── commands/                          ← slash commands（三段ルーティング）
│       ├── incident.md                    ← /incident（受電起点エントリ）
│       ├── playbook/                      ← カテゴリ別 対応書（5 ファイル）
│       │   ├── wp-tamper.md  dns-tamper.md  phishing.md  ransomware.md  ddos.md
│       ├── scenario/                      ← キルチェーン横断（3 ファイル、複数 check を束ねる）
│       │   ├── killchain-recon-rce-dbexfil.md  (Web RCE → 横展開 → DB 持ち出し)
│       │   ├── dns-spoof-phish.md              (内部 MITM → DNS 書換 → フィッシング)
│       │   └── vpn-uplink-abuse.md             (VPN 経路 → 上流信頼悪用)
│       └── check/                         ← 個別脆弱性 痕跡確認（35+ ファイル、`ls .claude/commands/check/` で最新数を確認、read-only）
│           └── check-<vuln>.md
│
├── tests/
│   ├── extract_test_logs.py               ← テスト env 偵察ログ抽出
│   └── fixtures/
│       ├── test_env_baseline/             ← テスト環境の設定スナップショット 35 ファイル（増加中、`ls .claude/commands/check/` で最新数を確認）
│       ├── expected_attacks/              ← 空（Phase 3 で整備）
│       └── attack_generators/             ← 空（同上）
│
├── templates/
│   └── ssh_config_sccs2026.conf           ← ~/.ssh/config 追記テンプレ（本番接続用）
│
├── data/cve/                              ← CVE feed キャッシュ（gitignore）
└── reference/                             ← 参考コード（白浜本体では使わない）
```

---

## 2. 設計の核

### 2.1 全体タイムライン（受電 → 完了報告）

```
T+0:00  ☎ 電話受電「サイトが見られない」
T+0:01  [電話応対] 01_受電シート に時間窓+ホスト記入 → 「13:00-13:30 / victor」
T+0:02  [技術調査] /incident 13:00-13:30 victor
        │
        │  ▼ Claude Code が incident.md §1〜§6 を順に実行
        │
T+0:03  §1 ログ取得 (ssh victor / bravo + tail)
T+0:04  §2 parse_*.py で JSONL 化、時間窓フィルタ
T+0:05  §3 analyzer.run() → Signal リスト
T+0:06  §4 MockBackend.propose_patches()
            ├ 配布アカウント / 自チーム IP whitelist drop
            ├ 既知 type は即 block 提案
            └ grey signal を ClaudeBackend へ
T+0:08  §5 二段ルーティング
            ├ §5.1 必須 2 本（known-attacker-ip, syslog-udp-injection）
            └ §5.2 pattern_tag → 該当 /check:* を提示
T+0:10  §6 状況サマリ生成
        │
T+0:12  [技術調査] 提示された /check:* を順次叩く（read-only）
T+0:18  [指揮]    🚨 確定 → check の §4 が指す /playbook:* へ
T+0:20  [対応]    settings.json の deny / ask が物理ゲート
T+0:30  [報告]    PukiWiki 133.42.49.140/trouble_ticket_137 に投稿
```

### 2.2 データフロー（ログ → シグナル → 提案 → アクション）

```
                /var/log/* (テキスト)
                ──── ssh ────▶ scripts/preprocess/parse_*.py
                                       │ JSONL
                                       ▼
                          agent/analyzer.py（観測層）
                          45 regex / 38 pattern_tag + 4 集約タグ
                            ├ SQLI / XSS / PathTraversal / CMDI
                            ├ webapp/* (dotfile, upload, auth, scanner, xmlrpc, author-scan)
                            ├ dns/*    (update, axfr, amplification)
                            ├ auth/*   (ssh-failed/invalid/brute), protocol/telnet
                            ├ privesc/* (pkexec, sudo), persist/at-job
                            └ mail/*   (spf, dkim, sasl, relay, burst)
                                       │ list[Signal]
                                       ▼
                  agent/backends/mock_backend.py（判断層 1）
                    ① filter_known_good() — whitelist
                       ├ user ∈ {manage,root,admin,vty,enable}  ← drop
                       └ ip   ∈ 10.1.11.50-99（自チーム）        ← drop ※
                    ② type 別ハンドラ → 既知 → block/log/advisory 提案
                    ③ rule_id ハッシュで重複抑止 → advisory に降格
                                   │
                          ┌────────┴───────────┐
                          │                    │
                       既知 type             grey
                       即提案                 ▼
                          │     agent/backends/claude_backend.py（判断層 2）
                          │     temperature=0、JSON 厳格パース
                          │              │
                          └──────┬───────┘
                                 ▼
                       agent/validator.py（検証層）
                       action allowlist / regex 構文 / ReDoS チェック
                                 │ list[PatchProposal]
                                 ▼
                       Claude Code（実行系）
                       Bash / Edit を発行
                                 ▼
                       .claude/settings.json（物理ゲート）
                       ┌─────┬─────┬───────┐
                       │deny │ ask │ allow │
                       └──┬──┴──┬──┴──┬────┘
                          ▼     ▼     ▼
                       拒否  確認  即実行
```

※ Mock backend の自チーム IP 範囲 (10.1.11.50-99) は**本番想定値**。デモ環境（attack-vm = 161.33.12.212）では範囲外なので自然に通る。本番投入時に再確認する。

---

## 3. `.claude/commands/` — 三段ルーティング

`.claude/commands/<name>.md` は Claude Code の slash command 実装。Markdown だが Claude 自身への命令文として機能する。**最大 4 段構造**:

```
受電
  ▼
/incident <時間窓> <ホスト>          ← 入口（分岐器）
  ▼ analyzer の pattern_tag で判定
  ▼ 単一カテゴリなら直接 ↓、複合キルチェーンなら scenario へ
/scenario:<chain>                     ← 横断シナリオ（複数 check を並行起動。新設、現状 1 ファイル）
  ▼
/check:check-<vuln> <時間窓> <ホスト> ← 個別脆弱性の痕跡確認（判定器、read-only、35 個前後）
  ▼ check の §3 で 🚨 確定
/playbook:<category>                  ← カテゴリ対応（対応器、5 個）
```

| 層 | 個数 | 役割 | 出力 |
|---|---|---|---|
| **incident** | 1 | 受電後最初に叩く分岐器。analyzer 起動 + 次に叩く check / scenario を提示 | check / scenario の候補リスト |
| **scenario** | 3 | 既知キルチェーン全体を束ねて複数 check を並行起動 | 横断結果サマリ |
| **playbook** | 5 | カテゴリ単位の深掘り + 封じ手案 + 通報 + 報告書ドラフト | 対応シナリオ |
| **check** | 35± | 1 ファイル = 1 脆弱性の痕跡確認 (read-only) | ✅ / ⚠️ / 🚨 判定 |

### incident.md（入口）の内訳

| § | やること |
|---|---|
| §0 | 環境定数（ドメイン / IP / パスワード / 触禁ホスト） |
| §0.5 | **既侵害前提**：配布アカウント由来は drop、別 IP/別 user を最重要監視 |
| §0.6 | **「触らない」哲学**：脆弱性は出題前提の可能性、対策は必ずリーダー承認後 |
| §1 | ログ取得（ssh + tail） |
| §2 | JSONL 化 + 時間窓フィルタ |
| §3 | analyzer.run() |
| §4 | Mock + Claude 二段ふるい |
| §5 | **§5.1 必須 2 check ＋ §5.2 pattern_tag → check ルーティング表** |
| §6 | 状況サマリ生成 |

### playbook（5 ファイル）

| コマンド | 何を見るか |
|---|---|
| **`/playbook:wp-tamper`** | victor の httpd-access/error log、dotfile 直叩き、wp-login brute、uploads 配下 webshell、PHP 設定、rainloop SALT |
| **`/playbook:dns-tamper`** | bravo の named.conf（allow-update 致命設定）、動的更新の approved/denied、AXFR 試行、ANY クエリ |
| **`/playbook:ddos`** | TCP 接続スナップ、同一 IP 集計、ANY 比率、DHCP/SNMP 異常、RTX1200 syslog |
| **`/playbook:phishing`** | maillog の SPF/DKIM/DMARC 失敗、SASL brute、Open Relay、`/etc/aliases` 不審転送 |
| **`/playbook:ransomware`** | 直近 1h の mtime、ランサム置き手紙、pkexec PwnKit、sudo 不正、UID 0 重複、cron/at/SUID |

### check（35 ファイル（増加中、`ls .claude/commands/check/` で最新数を確認） — メモリ `detection_skill_design.md` で全数管理）

4 グループに分類：

- **Category A — 既侵害前提 / Story-bait（5 ファイル）**: known-attacker-ip / syslog-udp-injection / dovecot-passdb-pam / aliases-root-forward / backup-html-exposure
- **Category B — Top priority（8 ファイル）**: wp-xmlrpc-brute / wp-rest-author-scan / rainloop-cve29360 / bind-allow-update / bind-axfr / pkexec-pwnkit / sendmail-open-relay / mysql-x-direct
- **Category C — Second priority（10 ファイル）**: php-allow-url-fopen / htaccess-rce / mycnf-leak / obuchi-777-hijack / snmp-public-walk / toor-uid0 / rogue-dhcp / telnet-plain-auth / courier-imap-plain / wp-config-leak
- **Category D — Yellow priority（5 ファイル、追加実装済）**: allow-query-amplification / mariadb-3306-direct / rainloop-domain-relay / at-job-persist / userdir-listing
- **Category E — 横断 / 静的検査（増加中）**: baseline-hardening（SELinux/pf/firewalld/iptables）/ bind-version / mariadb-eol / squid-installed-not-running / sendmail-old-cf / nkf-rpm-residue / vm-detection（ハイパーバイザ検出）/ ほか

> ⚠️ check ファイルは **build phase 中に随時追加されている**ため、上の分類は 2026-05-02 時点のスナップショット。最新の全数は `ls .claude/commands/check/` で確認すること。メモリ `detection_skill_design.md` の Yellow / Green priority も実装済みのものを含むため、同メモリも次回更新が必要。

各 check の構造は **§0 前提 / §1 収集 (read-only) / §2 検知パターン / §3 判定 (✅⚠️🚨) / §4 次のアクション**。🚨 確定で playbook を呼び出す。

### 共通設計ルール

- §0 で**対象ホスト・sudo 可否・触禁ルール**を必ず明記。bravo（**本番では FreeBSD・manage は sudo 不可**）と victor（Rocky・sudo 可）の区別が肝
- 触禁: CIC DNS（10.1.130.1）、参加者 VPN 入口（133.42.49.151）
- §1 はすべて read-only。状態を変えるコマンドは入れない
- 封じ手は必ず「リーダー承認後」を明記

---

## 4. `.claude/settings.json` — 二段運用（build / production）

Claude が破壊的コマンドを善意で提案しても**物理的に実行できない**ようにするゲート。**二つのファイルを目的別に切り替えて使う**。

| ファイル | モード | deny | ask | allow | 用途 |
|---|---|---:|---:|---:|---|
| `.claude/settings.json` | **build**（現在アクティブ） | 15 | 6 | 91 | デモ build 中。`dnf install` `systemctl` `Edit(/etc)` 等を一時許可 |
| `.claude/settings.production.json` | **production**（真正版） | 67 | 37 | 64 | 本番運用。`nsupdate` `systemctl stop` `mysql DDL` 等を全部 deny |

`env.SHIRAHAMA_MODE` で現在モードが分かる（`"build"` / `"production"`）。

### ⚠️ 5/5 本番投入前に必ずやる切替

```bash
cp .claude/settings.production.json .claude/settings.json
# SHIRAHAMA_MODE が "production" になることを確認
```

これを忘れると Claude が `nsupdate` `systemctl stop` `Edit /etc/named.conf` 等を実行できてしまう。production 版は `21_システム解説.md §3.7` の「触らない哲学の物理化」を実装した真正版で、**絶対に編集しない**こと。

### build mode で何が緩いか（抜粋）

```jsonc
"allow": [
  "Bash(dnf *)", "Bash(yum *)", "Bash(systemctl *)",   ← 本番では deny
  "Bash(mysql *)", "Bash(mysqldump *)",                ← 本番では SELECT 以外 deny
  "Edit(/etc/**)", "Write(/etc/**)",                   ← 本番では deny
  "Bash(setenforce *)",                                ← 本番では deny
  ...
]
```

build 中も**残してある deny**: `rm -rf /*` `shutdown` `mkfs` `dd of=/dev/sd*` `: > /var/log/*` 等、母艦やルートを破壊する系。

---

## 5. `agent/analyzer.py` — 観測層

LLM 非依存のルールベース検出器。**45 regex を 12 カテゴリ・38 pattern_tag に整理**、加えて集約検出が 4 タグ。

| 入力ログ | analyzer 関数 | 主な pattern_tag |
|---|---|---|
| Apache access_log (JSONL) | `analyze_nginx()` | `sqli/*`(3) `xss/*`(4) `path_traversal/*`(3) `cmdi/*`(7) `webapp/dotfile-access` `webapp/upload-php` `webapp/auth-endpoint` `webapp/xmlrpc` `webapp/author-scan` `webapp/scanner-ua` ＋集約 `webapp/auth-bruteforce` |
| BIND named.log | `analyze_named()` | `dns/unauthorized-update` `dns/update-denied` `dns/axfr-attempt` `dns/amplification-bait` ＋集約 `dns/amplification-ratio` |
| /var/log/secure, auth.log | `analyze_secure()` | `auth/ssh-failed` `auth/ssh-invalid-user` `protocol/telnet-access` `privesc/pkexec-attempt` `privesc/sudo-unauthorized` `persist/at-job` ＋集約 `auth/ssh-bruteforce` |
| postfix/sendmail maillog | `analyze_maillog()` | `mail/spf-fail` `mail/dkim-fail` `mail/relay-attempt` `mail/relay-denied` `mail/sasl-failed` ＋集約 `mail/burst` |
| WordPress camp-logger.php | `analyze_wordpress()` | `idor` |

`run(log_dir)` が観測層のメインエントリで、上記すべてを実行して `list[Signal]` を返す。Signal は `type` / `path` / `severity` / `evidence` / `timestamp` を持ち、`evidence["pattern_tag"]` が check ルーティングの主キー。

**設計方針**: 過去環境固有の CVE 名（`rainloop-known` 等）に過学習せず**カテゴリ単位の汎用 pattern** で本番別環境にも対応する（[analyzer.py:117-122](agent/analyzer.py#L117-L122) コメント参照）。

---

## 6. デモ build 進捗（2026-05-02 時点）

OCI 上で本番に近い構成を再構築し、analyzer.py を E2E 検証している。

| シナリオ | E2E 状態 | 必要な構築 |
|---|---|---|
| **wp-tamper** | ✅ 通過（2026-05-02） | victor: Apache 2.4.37 + PHP 7.2.24 EOL + MariaDB 10.3 + WordPress 4.9.4。SELinux Enforcing |
| dns-tamper | ⏳ 未着手 | bravo に BIND 必要（1GB RAM なので慎重に） |
| phishing | ⏳ 未着手 | bravo + victor に Sendmail / Dovecot |
| ddos | ⏳ 部分（HTTP flood は再現可、DNS amp は BIND 後） | — |
| ransomware | ⏳ 未着手 | pkexec PwnKit 植え + sudo 痕跡 + at-job |

### デモ環境の実機

| ホスト | クラウド | 役割 | OS | 公開 IP | 内部 IP |
|---|---|---|---|---|---|
| `attack-vm` | Akamai | 攻撃発信元 | Ubuntu 24.04 | 161.33.12.212 | 10.0.0.25 |
| `bravo` | OCI ap-osaka-1 | DNS/Mail/User-hosting | **Rocky Linux 8.10** | 161.33.24.15 | 10.1.10.124 |
| `victor` | OCI ap-osaka-1 | Web/WP/RainLoop | Rocky Linux 8.10 | 168.138.42.63 | 10.1.10.79 |

bravo を本番では FreeBSD で動かすが、デモは Rocky に統一（FreeBSD cloud-init が OCI metadata を読まない問題のため）。**本番投入時にログパスが変わる**（例: `/var/log/secure` → `/var/log/auth.log`）ので preprocess パスを書き換えること。

---

## 7. 使い方

### 7.1 本番接続（5/5 当日）

```bash
# 1. VPN 接続（運営機器 133.42.49.151）
# 2. SSH 設定追加（templates/ssh_config_sccs2026.conf を ~/.ssh/config に追記）
cat templates/ssh_config_sccs2026.conf >> ~/.ssh/config && chmod 600 ~/.ssh/config

# 3. settings.json を本番モードに戻す（重要）
cp .claude/settings.production.json .claude/settings.json

# 4. 動通確認
ssh bravo  ssh victor
```

### 7.2 デモ build（現在）

```bash
# OCI ホストへ ssh
ssh bravo    # ~/.ssh/bravo 鍵
ssh victor   # ~/.ssh/victor 鍵
ssh attack-vm

# settings.json は build モードのまま OK
# (dnf install / systemctl start / Edit(/etc) が許可されている)
```

### 7.3 インシデント対応フロー（共通）

```
1. 受電 → docs/01_受電ヒアリングシート.md に時間窓 + 影響ホスト記入
2. Claude Code: /incident 13:00-13:30 victor
   → analyzer 起動 + 次に叩くべき /check:* を提示
3. 提示された /check:check-<vuln> を順次叩く
   → §3 で ✅ / ⚠️ / 🚨 判定
4. 🚨 確定 → check の §4 が指す /playbook:<category> へ
5. リーダー Go/NoGo 判断 → 破壊系は settings.json の deny/ask が物理ゲート
6. 状況サマリ（Claude 生成）→ 整形して送信
7. 完了報告を PukiWiki (133.42.49.140/trouble_ticket_137) に投稿
```

### 7.4 開発者向け：analyzer 単体テスト

```bash
# テスト env ベースラインで誤検知 0 確認
python -c "from agent import analyzer; print(len(analyzer.run('tests/fixtures/test_env_baseline/')))"
# → 0 が正解（ベースラインは攻撃を含まない設定スナップショット）

# Claude backend 動通確認（ANTHROPIC_API_KEY 要、ユーザに事前確認）
# (memory: ANTHROPIC_API_KEY を勝手に grep / find / env 走査しない)
```

---

## 8. ロードマップ

詳細は [docs/19_今後やること.md](docs/19_今後やること.md):

- ✅ **Phase A**: コード持ち込み
- ✅ **Phase B**: ログ前処理（5 parser）
- ⏳ **Phase B'**: CVE feed — `fetch_cve.py` のみ。`cve_to_pattern.py` 未実装
- ✅ **Phase C**: analyzer 6 カテゴリ拡張（45 regex / 38 tag）
- ✅ **Phase D**: slash command 三段化（incident + 5 playbook + 23 check）
- ✅ **Phase E**: 安全ゲート二段化（build / production）
- ✅ **Phase F**: docs/19_今後やること.md
- 🚧 **Phase G**: デモ環境構築（**現在**） — wp-tamper ✅、dns/phishing/ddos/ransomware 残
- ⏳ **Phase H**: 5 人体制リハーサル（予選〜決勝期間に実施）

### 5/5 本番投入前チェックリスト

- [ ] `cp .claude/settings.production.json .claude/settings.json`（モード切替）
- [ ] `SHIRAHAMA_MODE` が `"production"` になっていることを確認
- [ ] preprocess の対象ログパスを FreeBSD 用に書き換え（bravo）
- [ ] mock_backend の自チーム IP レンジ（10.1.11.50-99）が PDF 配布値と一致するか確認
- [ ] VPN 接続確認、`ssh bravo` `ssh victor` 動通

---

## 参考

- セキュリティ・キャンプ 2026 ミニ B トラック教材（4 層アーキ + 10 ループ）
- [docs/18_キャンプ知見の白浜活用方針.md](docs/18_キャンプ知見の白浜活用方針.md) — 全体方針
- [docs/19_今後やること.md](docs/19_今後やること.md) — タスクリスト
- [docs/21_システム解説.md](docs/21_システム解説.md) — パイプライン解説（settings.json 物理化の元）
