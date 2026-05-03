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
- 三段ルーティング: `/incident` → (`/check:*` 単発 or `/scenario:*` 連鎖アグリゲータ) → `/playbook:*`
- カテゴリ未確定の場合は先に `/check:check-<vuln>` (例 `/check:check-wp-xmlrpc-brute`) で痕跡確認 → playbook へ
- 複数 check を並行起動するキルチェーンが疑われる場合は `/scenario:<chain>` (例 `/scenario:killchain-recon-rce-dbexfil`) で一括起動

---

### 1. ログ取得

引数 $2 (ホスト) は「主要嫌疑」のヒント。横展開検出のため**両ホストから全関連ログを取得**する。
SSH 接続先は環境変数で切替（`build` 時は OCI alias、`production` 時は本番 manage@10.1.1.x）。

```bash
# 環境変数（settings.json env で設定済 / 未設定なら本番デフォルト）
SSH_VICTOR="${SSH_VICTOR:-manage@10.1.1.2}"
SSH_BRAVO="${SSH_BRAVO:-manage@10.1.1.1}"
SHIRAHAMA_DIR="${SHIRAHAMA_DIR:-/Users/ryu/Desktop/shirahama}"
cd "$SHIRAHAMA_DIR"

echo "─── /incident §1 ログ取得 ───"
echo "victor: $SSH_VICTOR / bravo: $SSH_BRAVO"

# victor (Web/Mail/DHCP) のログ群 — 接続失敗しても続行
ssh -o ConnectTimeout=5 "$SSH_VICTOR" 'sudo tail -2000 /var/log/httpd/access_log 2>/dev/null'  > /tmp/incident_access.log     2>/dev/null || true
ssh -o ConnectTimeout=5 "$SSH_VICTOR" 'sudo tail -1000 /var/log/httpd/error_log  2>/dev/null'  > /tmp/incident_httpd_err.log  2>/dev/null || true
ssh -o ConnectTimeout=5 "$SSH_VICTOR" 'sudo tail -1000 /var/log/secure           2>/dev/null'  > /tmp/incident_secure.log     2>/dev/null || true
ssh -o ConnectTimeout=5 "$SSH_VICTOR" 'sudo tail -1000 /var/log/maillog          2>/dev/null'  > /tmp/incident_maillog.log    2>/dev/null || true
ssh -o ConnectTimeout=5 "$SSH_VICTOR" 'sudo tail -500  /var/log/messages         2>/dev/null'  > /tmp/incident_messages.log   2>/dev/null || true

# bravo (DNS/掲示板) のログ群 — Rocky=/var/log/secure, FreeBSD=/var/log/auth.log の両対応
ssh -o ConnectTimeout=5 "$SSH_BRAVO"  'sudo tail -2000 /var/log/named.log        2>/dev/null'  > /tmp/incident_named.log      2>/dev/null || true
ssh -o ConnectTimeout=5 "$SSH_BRAVO"  'sudo tail -1000 /var/log/secure           2>/dev/null'  > /tmp/incident_auth.log       2>/dev/null || true
ssh -o ConnectTimeout=5 "$SSH_BRAVO"  'sudo tail -1000 /var/log/auth.log         2>/dev/null'  >> /tmp/incident_auth.log      2>/dev/null || true
ssh -o ConnectTimeout=5 "$SSH_BRAVO"  'sudo tail -1000 /var/log/maillog          2>/dev/null'  >> /tmp/incident_maillog.log   2>/dev/null || true

# 取得結果サマリ（0 行なら接続失敗 or 該当ログ無し）
echo "─── 取得結果 ───"
for f in /tmp/incident_*.log; do
    [ -f "$f" ] && echo "  $f: $(wc -l < $f) 行"
done
```

### 2. 時間窓フィルタ + JSONL 化

引数 $1 (例 `13:00-13:30`) を ISO 8601 (UTC) に変換して jq でフィルタ。

```bash
# 引数 $1 = "HH:MM-HH:MM" 形式
WINDOW="$1"
START_TIME="${WINDOW%-*}:00"
END_TIME="${WINDOW#*-}:00"
TODAY="$(date -u +%Y-%m-%d)"

# ★前提: ログのタイムスタンプは UTC (+00:00、Rocky/FreeBSD デフォルト)
#   入力時刻も UTC のまま使う。JST で考えてるなら手動で -9h して渡すこと
#   例: 通報「23:30 JST 頃から」 → 引数は "14:30-14:40"
START="${TODAY}T${START_TIME}+00:00"
END="${TODAY}T${END_TIME}+00:00"
echo "─── /incident §2 時間窓フィルタ ───"
echo "時間窓: $START 〜 $END (UTC)"

# nginx access_log → /tmp/access.log
# ★重要: ファイル名は /tmp/access.log にすること
#   agent/analyzer.py の analyze_nginx() は "access.log" のみ拾う
#   /tmp/incident_access.jsonl に書くと analyzer に読まれない
python scripts/preprocess/parse_clf.py /tmp/incident_access.log \
  | jq --arg s "$START" --arg e "$END" 'select(.timestamp >= $s and .timestamp <= $e)' \
  > /tmp/access.log

echo "  /tmp/access.log: $(wc -l < /tmp/access.log) 行 (フィルタ後)"

# secure / named / maillog / auth は raw のままで OK
# (agent/analyzer.py の run() が incident_*.log 名を fname 配列に登録済 — 行ベース)
for f in /tmp/incident_secure.log /tmp/incident_named.log /tmp/incident_maillog.log /tmp/incident_auth.log; do
    [ -f "$f" ] && echo "  $f: $(wc -l < $f) 行 (フィルタなし、analyzer が処理)"
done
```

### 3. analyzer 起動

shirahama ディレクトリ配下で `PYTHONPATH=.` を付けて実行する（`agent` モジュール解決のため）。

```bash
cd "${SHIRAHAMA_DIR:-/Users/ryu/Desktop/shirahama}"
PYTHONPATH=. python3 -c "
from agent import analyzer
signals = analyzer.run('/tmp')
print(f'─── /incident §3 analyzer ───')
print(f'検出シグナル: {len(signals)} 件')
for s in signals:
    tag = s.evidence.get('pattern_tag', '?')
    ip  = s.evidence.get('ip', '?')
    print(f'  [{s.severity:8}] {s.type:20} tag={tag:30} ip={ip}')
"
```

### 4. Mock 二段ふるい + Claude 集約

`.env` から ANTHROPIC_API_KEY を読み込み（無ければ Mock 層だけで完走）。

```bash
cd "${SHIRAHAMA_DIR:-/Users/ryu/Desktop/shirahama}"
[ -f .env ] && export $(grep -v '^#' .env | xargs)

PYTHONPATH=. python3 -c "
import os
from agent import analyzer
from agent.backends.mock_backend import MockBackend
from agent.validator import validate_patches

signals = analyzer.run('/tmp')

# Mock で whitelist drop + known-bad 即出し
mock = MockBackend()
mock_patches = mock.propose_patches(signals)

# grey シグナルだけ Claude に集約 (API キーがあれば)
known_bad_targets = {p.target for p in mock_patches}
grey = [s for s in signals if s.path not in known_bad_targets]
claude_patches = []
if os.environ.get('ANTHROPIC_API_KEY') and grey:
    from agent.backends.claude_backend import ClaudeBackend
    claude_patches = ClaudeBackend().propose_patches(grey)

all_patches = mock_patches + claude_patches
validated = validate_patches(all_patches)

print(f'─── /incident §4 判断層 ───')
print(f'Mock: {len(mock_patches)} / Claude: {len(claude_patches)} / 検証通過: {len(validated)}')
print()
for p in validated:
    print(f'[{p.action:10}] conf={p.confidence:.2f}  rule_id={p.rule_id}')
    print(f'  target: {p.target}')
    print(f'  match : {p.match_type}:{p.match_operator}:{p.match_value!r}')
    print(f'  理由  : {p.rationale_ja[:200]}')
    print()
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
| `xss/*` | path に `/rain/` | `check-rainloop-cve29360` + `check-rainloop-domain-relay` | `wp-tamper` + `phishing` |
| `webapp/dotfile-access` | path に `.my.cnf` | `check-mycnf-leak` + `check-mysql-x-direct` + `check-mariadb-3306-direct` | `wp-tamper` + `ransomware` |
| `webapp/dotfile-access` | path に `wp-config` | `check-wp-config-leak` | `wp-tamper` + `ransomware` |
| `webapp/dotfile-access` | path に `.htaccess` | `check-htaccess-rce` | `wp-tamper` |
| `webapp/upload-php` | uploads/ 配下 | `check-htaccess-rce` + `check-php-allow-url-fopen` | `wp-tamper` + `ransomware` |
| `webapp/scanner-ua` | path に `backup_html` | `check-backup-html-exposure` | `wp-tamper` |
| `webapp/scanner-ua` | path に `/~user/` | `check-userdir-listing` | `wp-tamper` |
| `path_traversal` / `cmdi` | — | `check-php-allow-url-fopen` | `wp-tamper` + `ransomware` |
| `dns/unauthorized-update` / `dns/update-denied` | — | `check-bind-allow-update` | `dns-tamper` |
| `dns/axfr-attempt` | — | `check-bind-axfr` | `dns-tamper` |
| `dns/amplification-bait` / `dns/amplification-ratio` | — | `check-allow-query-amplification` | `ddos` |
| `privesc/pkexec-attempt` | — | `check-pkexec-pwnkit` | `ransomware` |
| `privesc/sudo-unauthorized` | — | (check なし) | `ransomware` |
| `persist/at-job` | — | `check-at-job-persist` | `ransomware` |
| `mail/relay-attempt` / `mail/relay-denied` | — | `check-sendmail-open-relay` + `check-sendmail-old-cf` | `phishing` |
| `mail/burst` | from=apache@/dovecot@ 等 | `check-aliases-root-forward` | `phishing` + `wp-tamper` |
| `mail/burst` | 通常メール | `check-sendmail-open-relay` | `phishing` |
| `mail/sasl-failed` | imap-login 経路 | `check-courier-imap-plain` + `check-dovecot-passdb-pam` | `phishing` |
| `mail/spf-fail` / `mail/dkim-fail` 単発 | — | `check-sendmail-open-relay` | `phishing` |
| `auth/ssh-failed` / `auth/ssh-invalid-user` | user=obuchi | `check-obuchi-777-hijack` + `check-known-attacker-ip` | `ransomware` |
| `auth/ssh-failed` | user=toor (bravo) | `check-toor-uid0` | `ransomware` |
| `auth/ssh-bruteforce` | — | `check-known-attacker-ip` | `ransomware` |
| `protocol/telnet-access` | — | `check-telnet-plain-auth` | `ransomware` |
| 同一 IP からの request burst のみ (tag 不在) | — | (check なし) | `ddos` |

#### 5.2bis キルチェーン疑い → /scenario:* (複数 check 並行起動)

複数 pattern_tag がカテゴリをまたいで同時発火している場合、個別 check を 1 つずつ叩くより **`/scenario:*` で連鎖一括起動** が効率的:

| 同時発火パターン | /scenario | 想定キルチェーン |
|---|---|---|
| `webapp/scanner-ua` + `webapp/dotfile-access` + `path_traversal/cmdi` | `/scenario:killchain-recon-rce-dbexfil` | 偵察 → Web RCE → DB 持ち出し |
| `dns/unauthorized-update` + (受電「サイト見た目変」) + `mail/spf-fail` | `/scenario:dns-spoof-phish` | 内部 MITM → DNS 書換 → フィッシング |
| `auth/ssh-bruteforce` + `protocol/telnet-access` + `privesc/pkexec-attempt` | `/scenario:vpn-uplink-abuse` | VPN 経路 → 上流信頼悪用 → 権限昇格 |

#### 5.3 analyzer tag 不在でも観察すべき (手動起動)

以下は analyzer が直接 tag を返さないが、状況証拠で叩く check:

- 受電内容に「内部 IP 帯のクライアントが偽サイトに飛ばされた」 → `check-rogue-dhcp`
- backup_html / 旧 BBS への到達ログを発見 → `check-backup-html-exposure`
- SNMP recon 痕跡や 161 への異常接続 → `check-snmp-public-walk`
- ログ自体に矛盾 (時刻逆行 / hostname 不整合) → `check-syslog-udp-injection`
- 受電内容に「DB が空になった」 → `check-mariadb-3306-direct`
- 受電内容に「外部メール (gmail 等) のパスワードが盗まれた」 → `check-rainloop-domain-relay`
- 受電内容に「Squid プロキシが勝手に起動」 → `check-squid-installed-not-running`
- 受電直後の状況把握 (ホスト防御の前提条件確認) → `check-baseline-hardening`
- 上記いずれにも該当しない → 人間判断 → リーダー相談

**バージョン静的確認 (slim 版 / 報告書記載用)**: `check-mariadb-eol` / `check-bind-version` / `check-sendmail-old-cf` / `check-nkf-rpm-residue` / `check-vm-detection`

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

### 7. 📞 受電係への打ち返し: 顧客に追加で聞くべきこと

**§5 のルーティング・§6 のサマリだけでは判断できない「顧客にしか分からない事実」を、Claude が自動でリストアップし、受電係に渡す**。受電係はそのまま顧客に折り返し電話するためのスクリプトとして使う。

#### 出力フォーマット (Claude が生成)

```
─── 📞 受電係に依頼: 顧客に追加で聞くべきこと ───
□ <時刻> 頃に <ホスト/サービス> で <業務> を行う予定はありましたか?
□ <試行された ID> アカウントを使う社員は本日出社/作業中でしたか?
□ <観測された IP / UA> に心当たりはありますか? (取引先 / リモート社員 / 委託業者など)
□ 直近で <設定変更 / アカウント追加 / 端末変更> はありましたか?
□ 同種の症状を他の社員からも報告されていますか?
□ <影響サービス> が止まると業務にどの程度影響しますか? (封じ込め判断材料)
```

#### 生成ルール (Claude への指示)

1. **検出された pattern_tag と攻撃者 IP / 試行 ID から、顧客にしか答えられない質問だけを抽出**
   - ✅ 「obuchi 氏は本日出社?」 (顧客の人事情報)
   - ✅ 「14:37 UTC に WP 管理画面で作業予定?」 (顧客の業務予定)
   - ❌ 「161.33.12.212 はどこから?」 (これは whois でわかる、聞くな)
   - ❌ 「ログのこの行は何?」 (技術調査係が読むべき、聞くな)

2. **3〜6 個に絞る**。多すぎると電話が長くなり顧客対応力評価で不利。
3. **時刻は JST に変換**。顧客は UTC で作業時刻を覚えていない。
4. **封じ込め前なら「サービス停止許容度」を必ず 1 つ入れる** (Phase 3 リーダー判断で必要)。
5. **既侵害 (§0.5) の前提 — 「初めて起きたか?」とは聞かない**。代わりに「直近で似た症状の前兆はありましたか?」と聞く。
6. **生成できる質問が 0 件なら、空リストではなく「□ 追加聞き取り不要 (検出シグナルから業務影響/帰属が明確)」と出す**。

#### pattern_tag → 質問テンプレ早見表

| pattern_tag | 顧客に聞く質問の型 |
|---|---|
| `webapp/auth-bruteforce` (wp-login 等) | 該当時刻に管理画面を使う予定があったか / 該当 ID は誰の管理か |
| `mail/sasl-failed` (IMAP brute) | 試行された ID の本人の在席状況 / メールクライアント設定変更の有無 |
| `dns/unauthorized-update` | DNS レコードの正規変更予定があったか / 更新権限を持つ管理者は誰か |
| `auth/ssh-bruteforce` `auth/ssh-failed` | 試行 ID 利用者の作業状況 / 委託業者からの SSH 接続予定 |
| `webapp/scanner-ua` `webapp/dotfile-access` | 該当 IP は社内/取引先か / バックアップ・調査ツール起動予定 |
| `mail/burst` `mail/relay-attempt` | 大量送信を伴うキャンペーン業務予定 / 社内 DM の有無 |
| 同一 IP 多発 (tag 不在 / DDoS 疑い) | サービス停止許容度 / 営業時間ピーク / 緊急用連絡手段 |

→ この出力を **電話応対係のホワイトボード or 02 引き継ぎテンプレ末尾に転記** し、即折り返し電話。

## 参照
- `19_AIパイプライン実装ガイド.md` — 詳細手順
- `18_キャンプ知見の白浜活用方針.md` — 思想
- `03_シナリオ別対応プレイブック.md` — カテゴリ別の対応手順
