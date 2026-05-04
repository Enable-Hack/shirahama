---
model: claude-sonnet-4-6
description: 電話受電起点でログ取得 → analyzer → Mock → Claude → カテゴリ判定 → 推奨次手順を一気通貫で出す
---

# /incident — 汎用インシデント対応エントリ

引数: `<時間窓> [<ホスト>...]`

| 例 | 意味 |
|---|---|
| `/incident 13:00-13:30` | ホスト省略 = **両機嫌疑**（受電で「どっちがやられたか不明」のとき） |
| `/incident 13:00-13:30 victor` | victor が主要嫌疑（bravo も横展開検出のため一応取得） |
| `/incident 13:00-13:30 bravo` | bravo が主要嫌疑（同上） |
| `/incident 13:00-13:30 victor bravo` | 両機が主要嫌疑（DDoS 同時被弾 / 一往復号シナリオ） |

**注意**: ログは引数に関わらず **常に両機から取得** する（横展開検出のため）。
引数のホストは「INCIDENT_ID ラベル」と「Claude 推論時の主要嫌疑ヒント」として使う。受電時点で
不明なら省略 = `both` で問題ない。後段の `/review` 突合で主要嫌疑が確定する。

## やること（このファイルは Claude Code 自身に対する指示書）

以下の手順を順番に実行してください。

---

**本番環境前提 (必読)**: 本 skill を呼ぶ前に必ず `docs/booth1_production.md` を Read ツールで読む。Booth1 (com1.local) のネットワーク構成 / 認証情報 / OS 差分 / 触禁機器 / DHCP 配布範囲 / CIC DNS 関係 / 既侵害前提などの本番固有情報をすべて踏まえてから判断・コマンド生成する。本番接続前に必ず Read。

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

## §0.4 /preflight 直前状態の取り込み

`/preflight` が直前に走っていれば、`agent/preflight_io.py` 経由で /tmp/preflight_state.json
を読み、§4 Claude 推論に渡す。未実行ならスキップ (後方互換)。

```bash
PREFLIGHT_CONTEXT="$(PYTHONPATH="$SHIRAHAMA_DIR" python3 -c '
import json
from agent.preflight_io import load_preflight_context, summarize_for_incident
state = load_preflight_context()
if state is None:
    print("")
else:
    summary = summarize_for_incident(state)
    print("─── /incident §0.4 /preflight 直前状態 ───")
    for a in summary["anomalies"]:
        print(f"  [{a[\"host\"]}] {a[\"severity\"]} {a[\"kind\"]}: {a[\"detail\"]}")
    if summary["etc_changed_recently"]:
        print("  ⚠️ /etc 直近変更:")
        for f in summary["etc_changed_recently"]:
            print(f"    {f}")
    print("")
    # JSON 文字列として export (後段 python に渡る)
    import sys; sys.stderr.write(json.dumps(summary["outputs"], ensure_ascii=False))
' 2>&1 1>&2)"
export PREFLIGHT_CONTEXT
```

`PREFLIGHT_CONTEXT` は §4 の python で `os.environ['PREFLIGHT_CONTEXT']` 経由で
`ClaudeBackend.propose_patches(..., preflight_context=...)` に渡る。

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

## §0.7 単段ルーティング (要約)

`/incident` (本 skill) で attack_pattern まで判定 → `/review` に attack_pattern をヒントとして渡し、
ヒアリング ↔ 観測ログを 3 列突合して最終判定 (A/B/C/D) + 治しすぎないスコープ提案を得る。
具体的な復旧 / 封じ込めコマンドは `docs/recovery_cookbook.md` を人間が参照する (AI は提示しない)。

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

# tail_first_existing: 候補パスを順に試し、最初に存在するものから tail。
# Rocky/FreeBSD のログパス差を OS 判定なしで吸収する。
tail_first_existing() {
    local host="$1"; local n="$2"; local out="$3"; shift 3
    local paths="$*"
    ssh -o ConnectTimeout=5 "$host" "for p in $paths; do
        if sudo test -r \"\$p\"; then sudo tail -$n \"\$p\"; exit 0; fi
    done; exit 1" > "$out" 2>/dev/null || true
}

# 「主要嫌疑ホスト」に関わらず、両機・両サービスから取得する (横展開検出のため)。
# ファイル名は victor_*.log / bravo_*.log で分離 — analyzer.py は両方を自動で読む。

# victor (Web/Mail) — 本番 Rocky / 将来 FreeBSD 化に備え両対応
tail_first_existing "$SSH_VICTOR" 2000 /tmp/victor_access.log    /var/log/httpd/access_log /var/log/httpd-access.log
tail_first_existing "$SSH_VICTOR" 1000 /tmp/victor_httpd_err.log /var/log/httpd/error_log  /var/log/httpd-error.log
tail_first_existing "$SSH_VICTOR" 1000 /tmp/victor_secure.log    /var/log/secure /var/log/auth.log
tail_first_existing "$SSH_VICTOR" 1000 /tmp/victor_maillog.log   /var/log/maillog
tail_first_existing "$SSH_VICTOR" 500  /tmp/victor_messages.log  /var/log/messages

# bravo (DNS/掲示板) — 本番 FreeBSD / デモ Rocky を OS 判定なしで吸収
# bravo にも httpd / mariadb 等が動いているケース (デモ環境) があるので Web ログも取る
tail_first_existing "$SSH_BRAVO"  2000 /tmp/bravo_access.log     /var/log/httpd/access_log /var/log/httpd-access.log
tail_first_existing "$SSH_BRAVO"  1000 /tmp/bravo_httpd_err.log  /var/log/httpd/error_log  /var/log/httpd-error.log
tail_first_existing "$SSH_BRAVO"  2000 /tmp/bravo_named.log      /var/log/named.log /var/log/named/named.log /var/named/log
tail_first_existing "$SSH_BRAVO"  1000 /tmp/bravo_auth.log       /var/log/auth.log /var/log/secure
tail_first_existing "$SSH_BRAVO"  1000 /tmp/bravo_maillog.log    /var/log/maillog
tail_first_existing "$SSH_BRAVO"   500 /tmp/bravo_messages.log   /var/log/messages

# 取得結果サマリ（0 行なら接続失敗 or 該当ログ無し）
echo "─── 取得結果 ───"
for f in /tmp/victor_*.log /tmp/bravo_*.log; do
    [ -f "$f" ] && echo "  $f: $(wc -l < $f) 行"
done
```

### 2. 時間窓フィルタ + JSONL 化

引数 $1 (例 `13:00-13:30`) を ISO 8601 (JST / +09:00) に変換して jq でフィルタ。

```bash
# 引数 $1 = "HH:MM-HH:MM" 形式
WINDOW="$1"
START_TIME="${WINDOW%-*}:00"
END_TIME="${WINDOW#*-}:00"
TODAY="$(TZ=Asia/Tokyo date +%Y-%m-%d)"

# ★前提: 入力もログのタイムスタンプも JST (+09:00)
#   受電時に聞いた時刻 (例「13:30 頃から」) をそのまま `/incident 13:30-13:40` で渡せる。
#   サーバ側 (Rocky / FreeBSD / OCI) の locale が JST であることを前提にしている。
#   もしログが UTC だった場合は parse_clf.py / syslog filter 側で吸収する必要がある。
START="${TODAY}T${START_TIME}+09:00"
END="${TODAY}T${END_TIME}+09:00"
echo "─── /incident §2 時間窓フィルタ ───"
echo "時間窓: $START 〜 $END (JST)"

# nginx access_log → /tmp/access.log (両機合流)
# ★重要: ファイル名は /tmp/access.log にすること
#   agent/analyzer.py の analyze_nginx() は "access.log" のみ拾う
{
    [ -s /tmp/victor_access.log ] && python scripts/preprocess/parse_clf.py /tmp/victor_access.log
    [ -s /tmp/bravo_access.log ]  && python scripts/preprocess/parse_clf.py /tmp/bravo_access.log
} | jq --arg s "$START" --arg e "$END" 'select(.timestamp >= $s and .timestamp <= $e)' \
  > /tmp/access.log

echo "  /tmp/access.log: $(wc -l < /tmp/access.log) 行 (フィルタ後、両機合流)"

# secure / named / maillog / auth は syslog 形式 (年なし)。
# 「今日の月日 + HH:MM 範囲」で絞る (古い brute 痕跡が時間窓内のシグナルに混ざらないように)
# analyzer.py は victor_*.log / bravo_*.log を両方自動で読む (run_with_unmatched の fname パターン参照)
START_HM="${WINDOW%-*}"
END_HM="${WINDOW#*-}"
TODAY_PREFIX="$(LC_ALL=C TZ=Asia/Tokyo date +'%b %e')"   # "May  3" (BSD/GNU 共通の space-padded 形式 = syslog と同じ。LC_ALL=C で ja_JP locale を回避 / TZ で JST 固定)

filter_syslog() {
    local f="$1"
    [ ! -f "$f" ] && return
    local before=$(wc -l < "$f")
    awk -v today="$TODAY_PREFIX" -v start="$START_HM" -v end="$END_HM" '
        index($0, today) == 1 {
            hm = substr($3, 1, 5)
            if (hm >= start && hm <= end) print
        }' "$f" > "${f}.win" && mv "${f}.win" "$f"
    echo "  $f: $before → $(wc -l < $f) 行 (時間窓フィルタ後)"
}

# 両機の syslog 系を時間窓フィルタ
for f in /tmp/victor_secure.log /tmp/victor_maillog.log /tmp/victor_messages.log \
         /tmp/bravo_auth.log    /tmp/bravo_named.log    /tmp/bravo_maillog.log /tmp/bravo_messages.log; do
    filter_syslog "$f"
done
```

### 3. analyzer 起動

shirahama ディレクトリ配下で `PYTHONPATH=.` を付けて実行する（`agent` モジュール解決のため）。

```bash
cd "${SHIRAHAMA_DIR:-/Users/ryu/Desktop/shirahama}"
PYTHONPATH=. ${SHIRAHAMA_PY:-python3} -c "
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

### 4. Mock 二段ふるい + Claude 集約 + attack_pattern 判定

`.env` から ANTHROPIC_API_KEY を読み込み（無ければ Mock 層だけで完走）。

このフェーズで以下 2 つを同時に出す:
- **patches** (Mock + Claude が個別シグナルから生成する処置候補)
- **attack_pattern** / **attack_subpattern** (全シグナルを束ねた **シナリオ全体** の判定 — `/review` への引き継ぎ用)

未分類ログ (analyzer の 41 pattern にマッチしなかった行) は **Claude に丸投げするとトークン爆発** するので、Mock で次の 3 段ふるいを通す:

1. システムノイズ (pam_unix session / sshd preauth disconnect / systemd-user session 等) を `_NOISE_PATTERNS` で drop
2. 配布アカウント / 自チーム IP (10.1.11.50-99) を drop (既存)
3. **時間窓ベースの cross-reference**:
   - 窓内 → 保持
   - 窓外でも `attacker_ips` (signals に出現した IP) を含む → 保持 (forensic context)
   - 窓外でも `10.1.129.0/24` (§0.5 既知侵害 IP) を含む → 保持
   - それ以外の窓外 → drop

実測: 1896 件 → 63 件 (97% 削減) で動作確認済。

```bash
cd "${SHIRAHAMA_DIR:-/Users/ryu/Desktop/shirahama}"
[ -f .env ] && export $(grep -v '^#' .env | xargs)

# §2 で計算した START / END を python に渡す (ISO 8601 JST / +09:00)
export INCIDENT_WINDOW_START="$START"
export INCIDENT_WINDOW_END="$END"

PYTHONPATH=. ${SHIRAHAMA_PY:-python3} -c "
import os
from agent import analyzer
from agent.backends.mock_backend import MockBackend
from agent.validator import validate_patches

signals, unmatched = analyzer.run_with_unmatched('/tmp')

# Mock で whitelist drop + known-bad 即出し
mock = MockBackend()
mock_patches = mock.propose_patches(signals)

# grey シグナルだけ Claude に集約 (API キーがあれば)
known_bad_targets = {p.target for p in mock_patches}
grey = [s for s in signals if s.path not in known_bad_targets]

# attacker_ips を signals.evidence.ip から抽出 (forensic cross-ref 用)
attacker_ips = set()
for s in signals:
    ip = (s.evidence or {}).get('ip', '') if hasattr(s, 'evidence') else ''
    if ip:
        attacker_ips.add(ip)

# 未分類ログを 3 段ふるい (ノイズ + 時間窓 + attacker_ips cross-ref)
win_start = os.environ.get('INCIDENT_WINDOW_START')
win_end   = os.environ.get('INCIDENT_WINDOW_END')
time_window = (win_start, win_end) if win_start and win_end else None
filtered_unmatched = mock.filter_known_good_logs(
    unmatched,
    time_window=time_window,
    attacker_ips=attacker_ips,
)

claude_patches = []
if os.environ.get('ANTHROPIC_API_KEY') and (grey or filtered_unmatched):
    from agent.backends.claude_backend import ClaudeBackend
    # §0.4 で export された PREFLIGHT_CONTEXT を取り込む (未設定なら None)
    import json as _json
    preflight_ctx = None
    _pf_raw = os.environ.get('PREFLIGHT_CONTEXT', '').strip()
    if _pf_raw:
        try:
            preflight_ctx = _json.loads(_pf_raw)
        except Exception:
            preflight_ctx = None
    claude_patches = ClaudeBackend().propose_patches(grey, filtered_unmatched, preflight_context=preflight_ctx)

all_patches = mock_patches + claude_patches
validated = validate_patches(all_patches)

print(f'─── /incident §4 判断層 ───')
print(f'Mock: {len(mock_patches)} / Claude: {len(claude_patches)} / 検証通過: {len(validated)}')
print(f'未分類ログ: raw={len(unmatched)} → filter後={len(filtered_unmatched)} 件 (Claude へ)')
print(f'  攻撃者 IP cross-ref: {attacker_ips or \"(none)\"}')
print()
for p in validated:
    print(f'[{p.action:10}] conf={p.confidence:.2f}  rule_id={p.rule_id}')
    print(f'  target: {p.target}')
    print(f'  match : {p.match_type}:{p.match_operator}:{p.match_value!r}')
    print(f'  理由  : {p.rationale_ja[:200]}')
    print()
"
```

### 4.2 attack_pattern 判定 (シナリオ全体の分類)

§4 の patches とは別に、**全 signals + filtered_unmatched + preflight_context + 受電内容** を束ねて
「この事案は 5 カテゴリのどれか」を Claude に 1 文字列で答えさせる。出力は次段 `/review` に渡るので
ここでブレると下流が全部ズレる — **必ず以下の判定基準を使うこと**。

#### 4.2.1 attack_pattern enum (必須 / 1 つだけ)

| 値 | 主な観測シグナル / 受電トリガ |
|---|---|
| `ddos` | 同一 IP からの大量 GET/POST、SYN_RECV 多発、ANY クエリ比率異常、サービス応答鈍化の通報 |
| `dns-tamper` | named.log に `update.*(approved\|forwarded)` / `transfer\|axfr\|ixfr` / SOA serial 変動 / 主要 A レコード書換 |
| `phishing` | maillog に SASL brute / SPF・DKIM fail / mail-burst / 不審メール本文の通報 / 受信者ピボット |
| `ransomware` | `*.encrypted/.locked/.crypt` 出現、`README_*/DECRYPT_*/HOW_TO_*` 置き手紙、pkexec PwnKit、sudo 不正、UID 0 重複、`/home/obuchi` 経由横展開 |
| `wp-tamper` | wp-login/xmlrpc への POST brute、rainloop CVE-2022-29360、PHP RFI/LFI、`uploads/*.php` 出現、`.htaccess` AddHandler 改変 |
| `unknown` | 上記いずれにも有意に該当しない / シグナルが薄すぎて断定不可 |

#### 4.2.2 attack_subpattern (任意 / 高解像度な内訳)

| attack_pattern | attack_subpattern 候補 | 判別シグナル |
|---|---|---|
| `ddos` | `http-flood` | 同一 IP × 同一 URL への GET/POST が秒あたり閾値超 / User-Agent 偏り |
| `ddos` | `dns-amplification` | `query: ANY` の比率 > 30% / 外部偽装ソースからの ANY クエリ集中 |
| `ddos` | `syn-flood` | `ss -tan state syn-recv` 多発 / `netstat -s` の listen overflow / RTX `syn-flood\|exceeded` syslog |
| `dns-tamper` | `nsupdate-driven` | `update.*approved` あり (allow-update が広い設定が成立) / 動的ゾーン mtime 更新 |
| `dns-tamper` | `axfr-leak` | `transfer\|axfr\|ixfr` 痕跡 / 外部から `dig AXFR` が成功 |
| `dns-tamper` | `cache-poison` | forwarders 経由の異常応答 / SOA serial 不整合 / 主要 A レコードが管理外 IP を返す |
| `phishing` | `inbound-spear` | 特定アカウント宛の偽装 From / 業務文脈に沿った標的型本文 / 1 通単位の通報 |
| `phishing` | `broad-cast` | mail-burst (短時間に同一送信元から大量) / SPF・DKIM fail 多発 / 全社展開の苦情 |
| `phishing` | `receiver-pivot` | SASL brute 成功後のアカウント乗っ取り → 受信側からの再送信 / SMTP AUTH 認証失敗→成功遷移 |
| `ransomware` | `actual-encryption` | `*.encrypted/.locked` ファイル出現 + 置き手紙 + 業務ファイルの mtime 集中変更 |
| `ransomware` | `lateral-only` | 暗号化痕跡なし、pkexec / sudo 不正 / `/home/obuchi/.ssh/authorized_keys` 追加 / UID 0 重複 |
| `ransomware` | `internal-misuse` | 配布アカウント外の社内 IP からの権限昇格、業務時間外の admin 操作、外部 C2 通信なし |
| `wp-tamper` | `rainloop-cve` | rainloop 1.12.0 への CVE-2022-29360 系パス / `/?Admin` への異常アクセス |
| `wp-tamper` | `php-rfi-lfi` | `?page=http://` `?file=../../` `php://filter` `data://` 系 / error_log の include 失敗 |
| `wp-tamper` | `xmlrpc-brute` | `POST /xmlrpc.php` 連発 / `system.multicall` ペイロード / wp-login と並走 |
| `wp-tamper` | `htaccess-rce` | `.htaccess` に `AddHandler\|AddType .*php` 追記 / uploads 配下から PHP 実行成立 |

サブパターン不明 / 複合 (例: ddos の中で http-flood + syn-flood 同時) は **空文字 or 主たる方** を入れる。

#### 4.2.3 Claude 投入用プロンプト (attack_pattern 判定)

```bash
cd "${SHIRAHAMA_DIR:-/Users/ryu/Desktop/shirahama}"
PYTHONPATH=. ${SHIRAHAMA_PY:-python3} -c "
import os, json
from agent.backends.claude_backend import ClaudeBackend
# signals / filtered_unmatched は §4 の python ブロックで定義済 — 同一プロセス前提なら再利用可
# 別プロセスなら analyzer.run_with_unmatched('/tmp') で取り直す
result = ClaudeBackend().classify_attack_pattern(
    signals=signals,
    unmatched=filtered_unmatched,
    preflight_context=preflight_ctx,
)
print(f'─── /incident §4.2 attack_pattern 判定 ───')
print(f'attack_pattern    : {result[\"attack_pattern\"]}')
print(f'attack_subpattern : {result.get(\"attack_subpattern\", \"\")}')
print(f'reasoning         :')
for line in result['reasoning'].splitlines():
    print(f'  {line}')
# 後段 §5 / §8 に env で渡す
os.environ['INCIDENT_ATTACK_PATTERN'] = result['attack_pattern']
os.environ['INCIDENT_ATTACK_SUBPATTERN'] = result.get('attack_subpattern', '')
"
export INCIDENT_ATTACK_PATTERN
export INCIDENT_ATTACK_SUBPATTERN
```

`classify_attack_pattern` には Claude に次の指示を渡すこと:

```text
あなたはインシデントトリアージの分類器です。以下の観測情報を見て、
事案全体を 1 つの attack_pattern (ddos / dns-tamper / phishing / ransomware / wp-tamper / unknown)
に分類し、可能なら attack_subpattern も付けてください。

判定基準:
- ddos        : 同一 IP からの大量リクエスト、SYN_RECV 多発、ANY クエリ集中、サービス応答鈍化
  - http-flood        : HTTP GET/POST が同一 URL に集中
  - dns-amplification : ANY クエリ比率 > 30% / 偽装ソース
  - syn-flood         : SYN_RECV 多発 / listen overflow
- dns-tamper  : BIND の動的更新成立、AXFR 試行、SOA/A レコード書換
  - nsupdate-driven : update.*approved 痕跡 + allow-update が広い
  - axfr-leak       : transfer/axfr/ixfr で外部にゾーン漏洩
  - cache-poison    : forwarders 経由で異常応答 / SOA 不整合
- phishing    : SASL brute / SPF・DKIM fail / mail-burst / 不審メール通報
  - inbound-spear  : 特定アカウント宛の偽装 From、標的型本文
  - broad-cast     : 短時間に大量送信、全社展開の苦情
  - receiver-pivot : SASL brute 成功後の乗っ取りからの再送信
- ransomware  : 暗号化拡張子出現、置き手紙、pkexec PwnKit、sudo 不正、UID 0 重複、横展開
  - actual-encryption : 暗号化ファイル + 置き手紙 + 業務ファイル mtime 集中変更
  - lateral-only      : 暗号化なし、権限昇格 / authorized_keys 追加 / UID 0 重複のみ
  - internal-misuse   : 配布アカウント外の社内 IP からの権限濫用、外部 C2 なし
- wp-tamper   : wp-login/xmlrpc brute、rainloop CVE、PHP RFI/LFI、uploads PHP、.htaccess 改変
  - rainloop-cve  : rainloop 1.12.0 への CVE-2022-29360 系
  - php-rfi-lfi   : ?page=http:// / ../../ / php://filter / data://
  - xmlrpc-brute  : POST /xmlrpc.php 連発 / system.multicall
  - htaccess-rce  : .htaccess に AddHandler/AddType .*php 追記、uploads から PHP 実行
- unknown     : 上記いずれも有意に成立しない / シグナル不足

出力 (JSON):
{
  "attack_pattern":    "ddos|dns-tamper|phishing|ransomware|wp-tamper|unknown",
  "attack_subpattern": "<上の表の値 or 空文字>",
  "reasoning":         "どのシグナル(pattern_tag / IP / ファイル名 / 受電内容)が決め手だったかを 3〜6 行で。
                        該当しないカテゴリを除外した理由も短く併記すること。"
}

注意:
- 配布アカウント (manage / root / admin / vty / enable) 由来のシグナルは無視 (§0.5)
- /etc/passwd の UID 0 重複 (toor) は ransomware ではなく既知の常設脆弱性 — 単独では unknown 寄り
- preflight_context に「直前の異常」があればそれを最優先 (受電前から動いていた攻撃が顕在化した可能性)
- 複合シナリオ (例: wp-tamper → ransomware への遷移) は **より深い段階** を返す (= ransomware)
```

### 4.1 フィルタの設計トレードオフ (重要)

| ケース | 挙動 | 根拠 |
|---|---|---|
| 窓外 + 既知侵害 IP (10.1.129.x) | **保持** | §0.5 既侵害前提。obuchi/manage の 4/24 ログイン痕跡を見逃さない |
| 窓外 + analyzer signals に出現した IP | **保持** | 同 IP 主体の pre-window recon / persistence を Claude が時系列で見る |
| 窓外 + 完全に未知の IP | drop | 受電窓トリアージの範疇外。後段 `/review` で必要なら追加収集 |
| ts パース失敗 (raw に時刻なし or 異常 format) | **保持** | 落とすと攻撃の pivot 行を見逃すリスク。Claude に raw を渡して判定 |

**「窓外 + 完全未知 IP」が抜ける** のは意図的: `/incident` は受電窓のトリアージに集中する。深掘り forensic が必要なら `/review` 段階で人間が追加 SSH 収集を判断する。

### 4.5 signal の `raw_log_excerpt` 必須化 (2026-05-05)

各 signal の `evidence` に **`raw_log_excerpt`** (string、1〜3 行の生ログ抜粋) を必ず含める。これは HTML ダッシュボードの /incident カードで「📜 生ログ抜粋」として展開表示され、人間が pattern 判定の根拠を直接目視できる。

```json
{
  "pattern_tag": "ddos/http-flood",
  "severity": "🚨",
  "evidence": {
    "ip": "161.33.12.212",
    "count": 2480,
    "raw_log_excerpt": "161.33.12.212 - - [04/May/2026:12:10:41 +0000] \"GET / HTTP/1.1\" 200 53169 \"TESTING_PURPOSES_ONLY\" \"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0; SLCC2)\""
  }
}
```

ルール:
- 1 signal につき **1〜3 行**。長すぎると視認性が落ちる
- 元のログをそのまま貼る (truncate しない、AI が要約しない)
- 改行込みで JSON 文字列にエスケープ (`\n`)
- mail/syslog/access_log どのログ種でも同じフィールド名で統一

### 5. 推奨次手順: 必ず /review に渡す

`/incident` のゴールは **attack_pattern を確定し、`/review` に引き継ぐこと**。
個別の `/check:*` や `/playbook:*` は廃止済 (archive/ に保管) — 本 skill から提示しない。

`/review` はヒアリングシート ↔ 観測ログ ↔ attack_pattern を 3 列突合し、A/B/C/D 4 択判定 +
「治しすぎない」スコープ提案を出す。具体的な復旧 / 封じ込めコマンド一覧は
`docs/recovery_cookbook.md` を人間がリーダー承認後に参照する。

```bash
echo "─── /incident §5 推奨次手順 ───"
echo "  attack_pattern    : ${INCIDENT_ATTACK_PATTERN}"
echo "  attack_subpattern : ${INCIDENT_ATTACK_SUBPATTERN:-(none)}"
echo
echo "  次に必ず叩く: /review --attack-pattern ${INCIDENT_ATTACK_PATTERN}"
echo "  (attack_subpattern が出ていれば --attack-subpattern も併記)"
echo
echo "  封じ込め / 復旧コマンドは docs/recovery_cookbook.md を人間が参照すること。"
echo "  AI からは具体コマンドを提示しない (治しすぎない / settings.production.json で deny)。"
```

判定が `unknown` の場合も **必ず `/review` を叩く** こと。`/review` 側で
ヒアリング情報と突合して人間が attack_pattern を上書き確定する余地がある。

### 6. 状況サマリ生成

```bash
PYTHONPATH=. ${SHIRAHAMA_PY:-python3} -c "
from agent.backends.claude_backend import ClaudeBackend
print(ClaudeBackend().explain_to_operator_ja(signals, validated, filtered_unmatched))
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
   - ✅ 「14:37 JST に WP 管理画面で作業予定?」 (顧客の業務予定)
   - ❌ 「161.33.12.212 はどこから?」 (これは whois でわかる、聞くな)
   - ❌ 「ログのこの行は何?」 (技術調査係が読むべき、聞くな)

2. **3〜6 個に絞る**。多すぎると電話が長くなり顧客対応力評価で不利。
3. **時刻は JST のまま**。顧客は JST で作業時刻を覚えている (本 skill は全段 JST で動く)。
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

---

## §8. JSON 出力 (HTML aggregator 連携 / D-1 共通スキーマ)

§3 analyzer signals / §4 patches / §5 routing / §6 SOC summary / §7 customer Q を 1 つの JSON に集約し、`data/incidents/<incident_id>/incident__<timestamp>.json` に保存する。HTML aggregator (`docs/incident_dashboard.html`) はこの JSON を読み込んで incident 一覧 + 詳細パネルを描画する。

### 8.1 incident_id の確定

```bash
# /incident 起動時に確定 (時間窓 + ホスト) — ホスト引数は省略可・複数可
TODAY="$(TZ=Asia/Tokyo date +%Y-%m-%d)"
WINDOW_START="${INCIDENT_WINDOW_START:-$(TZ=Asia/Tokyo date +%H:%M)}"   # 引数 $1 から HH:MM 抽出 (JST)

# 引数 $2..$N をホスト群として捕捉。省略時は "both"
shift                                # $1 (時間窓) 消費
HOSTS_RAW="$*"                       # "victor bravo" or "victor" or "" or "both"
[ -z "$HOSTS_RAW" ] && HOSTS_RAW="both"
# ホスト名を sort + uniq + 区切りで正規化 (順不同で同じ INCIDENT_ID にする)
HOST_LABEL="$(echo "$HOSTS_RAW" | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' '_' | sed 's/_$//')"
[ -z "$HOST_LABEL" ] && HOST_LABEL="both"

INCIDENT_ID="${TODAY}_${WINDOW_START}_${HOST_LABEL}"
INCIDENT_DIR="data/incidents/${INCIDENT_ID}"
mkdir -p "$INCIDENT_DIR"
echo "INCIDENT_ID=${INCIDENT_ID}"
echo "INCIDENT_DIR=${INCIDENT_DIR}"
echo "PRIMARY_HOSTS=${HOSTS_RAW} (label=${HOST_LABEL})"
```

**正規化例**:
- `/incident 13:00-13:30` → `2026-05-04_13:00_both`
- `/incident 13:00-13:30 victor` → `2026-05-04_13:00_victor`
- `/incident 13:00-13:30 victor bravo` → `2026-05-04_13:00_bravo_victor` (sort 後、順不同で同じ ID)
- `/incident 13:00-13:30 bravo victor` → `2026-05-04_13:00_bravo_victor` (同上)

このシェル変数を **§1〜§7 の全段階で export** しておけば、後段の /review / /report / /ticket が同じディレクトリに JSON を書ける。

### 8.2 JSON 書き出し（helper 経由）

§7 完了後、Claude が **skill 固有部分のみ** を JSON として組み立て、`scripts/emit_skill_json.sh` に stdin で渡す。helper がメタデータ (`skill / incident_id / timestamp / actor`) を補完して `${INCIDENT_DIR}/incident__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh incident --actor ai_human
{
  "inputs": {
    "window": "14:00-14:30",
    "host": "victor",
    "logs_collected": ["access_log", "secure", "named.log", "maillog"]
  },
  "outputs": {
    "analyzer_signals": [
      {"pattern_tag": "...", "evidence": {...}, "count": "...", "severity": "..."}
    ],
    "mock_patches": ["..."],
    "claude_patches": ["..."],
    "attack_pattern":    "ddos|dns-tamper|phishing|ransomware|wp-tamper|unknown",
    "attack_subpattern": "http-flood|dns-amplification|syn-flood|nsupdate-driven|axfr-leak|cache-poison|inbound-spear|broad-cast|receiver-pivot|actual-encryption|lateral-only|internal-misuse|rainloop-cve|php-rfi-lfi|xmlrpc-brute|htaccess-rce|",
    "attack_pattern_reasoning": "<§4.2 で Claude が出した 3〜6 行の根拠>",
    "soc_summary": "1-2 段落の人間向け要約",
    "customer_questions": ["...", "..."],
    "preflight_anomalies_count": 0
  },
  "verdict": {
    "status": "🚨|⚠️|✅|info",
    "summary": "<1-2 行: 何が起きてるか + attack_pattern + 「次は /review」>"
  },
  "next_skills": ["/review"]
}
JSON_EOF
```

helper が補完するメタデータ:
- `skill`: `"incident"` (引数で指定)
- `incident_id`: `INCIDENT_ID` env 経由で §8.1 で確定した値
- `timestamp`: 実行時の ISO 8601 JST (+09:00)
- `actor`: `ai_human` (AI 提案 → 人間最終判断 + 顧客折り返し)

保存先: `data/incidents/${INCIDENT_ID}/incident__<YYYYMMDDTHHMMSSZ>.json`

※ `outputs.preflight_anomalies_count` は §0.4 で取り込んだ preflight 異常件数を入れておくと dashboard で「直前状態と整合」表示に使える。

### 8.3 後段 skill への伝播

INCIDENT_ID は env var で後段に渡す:

```bash
export INCIDENT_ID="${INCIDENT_ID}"
export INCIDENT_DIR="${INCIDENT_DIR}"
```

/review / /report / /ticket は `${INCIDENT_ID}` が渡されていれば同じディレクトリに JSON を追記する。

---

## 参照
- `19_AIパイプライン実装ガイド.md` — 詳細手順
- `18_キャンプ知見の白浜活用方針.md` — 思想
- `03_シナリオ別対応プレイブック.md` — カテゴリ別の対応手順
- `docs/incident_dashboard.html` — JSON を集約表示する HTML aggregator
