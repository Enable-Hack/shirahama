---
model: claude-sonnet-4-6
description: 受電ヒアリング ↔ /preflight ↔ /incident のログ実態を 4 列突合し、attack_pattern を踏まえた 4 択判定 (A/B/C/D) と「治しすぎない」スコープ提案を出す主動線。AI が自発的 read-only ssh で補強調査もする。
---

# /review — ヒアリング ↔ 観測 突合 + 自発的補強調査 + 判定推奨 + 3 バケット出力

引数: `[<incident-id>]`
省略時: `data/incidents/` 配下の最新ディレクトリ (mtime 降順)

例:
- `/review`
- `/review 2026-05-04_12:00_victor`

---

## このスキルが解決する問題

- ヒアリング ↔ ログ実態の突合が **リーダーの頭の中** だけで起きていた → 再現性なし、引き継ぎ不能
- 「治しすぎない」原則 (lab は意図的に過剰 seed) を **個人判断** で運用していた → in_scope / out_of_scope の境界が人によって揺れる
- 4 択判定 (A/B/C/D) を **AI に委ねる**経路が無かった → HTML 仕様書 §2.1.2 「判定は人間」原則の物理化が不十分
- 既侵害 (受電窓より前から動いていた攻撃) と急性発症 (受電窓内で顕在化) の区別が曖昧 → /preflight の baseline と /incident のログ実態を分けて並べることで切り分ける
- /incident の時間窓に閉じた検出だけでは突合の ❓情報不足 を埋められなかった → AI 自発的 read-only ssh で補強調査
- 指揮係に「具体コマンド + 理由」を渡せていなかった → 3 バケット出力 ([A] 確認済 / [B] 人間確認 / [C] 実行候補) で物理化

本スキルは「**AI が突合 + 補強調査 + コマンド提案を機械的に作り、最終判定は人間がラジオ選択する**」という分業を物理化する。
ACTOR: **AI Auto** (突合 / 補強調査 / コマンド提案は完全自動、最終 A/B/C/D 採択 + コマンド実行は人間)

JPCERT インシデントハンドリング 4 段階のうち **2.2 トリアージ** の品質保証層であり、`/incident` の直後に必ず叩く主動線。具体的な復旧 / 封じ込めコマンドは §4 [C] バケットで事案固有の 1-shot を出す。汎用テンプレートは引き続き AI から提示しない (cookbook の役割)。

---

## §0. 前提

- 入力 1: 受電 JSON — `data/incidents/<id>/` 配下の **任意のファイル名** の JSON で `"skill": "hearing"` を含むもの。受電台本タブの「💾 hearing__*.json として保存」ボタンで自動生成 (`hearing__*.json`) もできるが、**他人が手で作って任意名で置いた JSON でも識別する** (例: `intake_山田.json` / `phone_call_001.json` などでも OK)。**markdown は読まない (ノイズ源のため、2026-05-04 廃止)**
- 入力 2: `/preflight` 出力 (`data/incidents/<id>/preflight__*.json`) — 受電直前のベースライン異常 flag
- 入力 3: `/incident` 出力 (`data/incidents/<id>/incident__*.json`) — 受電窓のログ実態 + attack_pattern
- 出力: stdout に 6 セクション (突合表 / 補強調査 / **被害範囲確定** / 判定推奨 / 4 バケット) + JSON 1 ファイル
- /tmp/incident_*.log や ~/Desktop/shirahama_test.md は **参照しない** (incident フォルダ内の 3 JSON のみで完結)
- 「治しすぎない」原則: lab は意図的に複数の脆弱性が seed されている。受電と関係する分のみ in_scope / [C] バケットに分類

**被害範囲確定の責任**: 旧 `/check` / `/playbook` を凍結したため、「いつからいつまで」「どこまで広がったか」「何が漏れたか」を出す責任は **/review に集約された**。これが無いと /report が顧客向けメールに「○時○分から○時○分まで○○が発生」と書けない。§2.6 で必ず出す。

---


**本番環境前提 (必読)**: 本 skill を呼ぶ前に必ず `docs/booth1_production.md` を Read ツールで読む。Booth1 (com1.local) のネットワーク構成 / 認証情報 / OS 差分 / 触禁機器 / DHCP 配布範囲 / CIC DNS 関係 / 既侵害前提などの本番固有情報をすべて踏まえてから判断・コマンド生成する。
本番接続前に必ず Read。

## §1. 入力読み込み

```bash
SHIRAHAMA_DIR="${SHIRAHAMA_DIR:-/Users/ryu/Desktop/shirahama}"
INCIDENT_ID="${1:-}"
cd "$SHIRAHAMA_DIR"

if [ -z "$INCIDENT_ID" ]; then
    if [ -f "data/incidents/.current_id" ]; then
        INCIDENT_ID="$(cat data/incidents/.current_id)"
    fi
    [ -z "$INCIDENT_ID" ] && INCIDENT_ID="$(ls -1t data/incidents/ 2>/dev/null | grep -v '^\.' | head -1)"
fi
export INCIDENT_ID  # ← emit_skill_json.sh helper に渡すため必須 (export 漏れ = _unscoped 配下に書かれるバグの原因)
INCIDENT_DIR="data/incidents/${INCIDENT_ID}"

if [ ! -d "$INCIDENT_DIR" ]; then
    echo "❌ incident dir が無い: $INCIDENT_DIR"
    exit 1
fi

# 受電 JSON はファイル名問わず "skill": "hearing" で識別 (他人が任意名で置いた JSON も拾う)
HEARING_FILE="$(
  for f in ${INCIDENT_DIR}/*.json; do
    [ -f "$f" ] || continue
    if python3 -c "import json,sys; sys.exit(0 if json.load(open('$f')).get('skill')=='hearing' else 1)" 2>/dev/null; then
      stat -f '%m %N' "$f" 2>/dev/null || stat -c '%Y %n' "$f" 2>/dev/null
    fi
  done | sort -rn | head -1 | awk '{print $2}'
)"
PREFLIGHT_FILE="$(ls -1t ${INCIDENT_DIR}/preflight__*.json 2>/dev/null | head -1)"
INCIDENT_FILE="$(ls -1t ${INCIDENT_DIR}/incident__*.json 2>/dev/null | head -1)"

if [ -z "$HEARING_FILE" ]; then
    echo "❌ 受電 JSON が無い: ${INCIDENT_DIR}/"
    echo "   この skill は \"skill\": \"hearing\" を含む JSON をファイル名問わず識別します。"
    echo "   - 受電台本タブの「💾 hearing__*.json として保存」で自動生成、または"
    echo "   - 他のフォーマットで作って手で ${INCIDENT_DIR}/ に置いてください (任意ファイル名 OK)。"
    exit 1
fi
if [ -z "$INCIDENT_FILE" ]; then
    echo "❌ incident__*.json が無い: ${INCIDENT_DIR}/"
    echo "   /incident <時間窓> <ホスト> を先に実行してください"
    exit 1
fi

echo "─── /review §1 入力 (incident フォルダ内のみ) ───"
echo "  incident_id  : ${INCIDENT_ID}"
echo "  hearing      : ${HEARING_FILE} (任意ファイル名、skill=hearing で識別)"
echo "  preflight    : ${PREFLIGHT_FILE:-<未実行 — preflight 列は skipped で進行>}"
echo "  incident     : ${INCIDENT_FILE}"
```

その後 Claude は **Read ツール**で 3 JSON のみ読む:
1. `${HEARING_FILE}` — 受電 (顧客名 / トーン / 影響 / 時間窓 / 自由記述)
2. `${PREFLIGHT_FILE}` (存在すれば) — `outputs.<host>.anomalies[]`
3. `${INCIDENT_FILE}` — `outputs.attack_pattern` / `outputs.attack_subpattern` / `outputs.signals[]`

抽出ルール:
- hearing JSON の `outputs.customer_keywords` を突合表の引用源にする (生 markdown を読まない)
- hearing JSON の `outputs.customer_tone` を判定推奨の信頼度補正と /call_close の入力にする
- preflight__*.json の `outputs.victor.anomalies[]` / `outputs.bravo.anomalies[]` を `kind` ごとに集計
- incident__*.json の `outputs.attack_pattern` / `outputs.attack_subpattern` / `outputs.signals[]` を抽出

**markdown / /tmp ログは絶対に Read しない**。3 JSON で足りない情報は §2.5 の補強調査で取りに行く。

---

## §2. 出力セクション 1: ヒアリング ↔ 観測 突合表 (4 列)

```text
─── /review §2 ヒアリング ↔ 観測 突合 ───
```

4 列突合表を Markdown table で出す。`preflight` 列が baseline (受電直前)、`incident` 列が受電窓内の検出を示す。両者を並べると「既侵害 (preflight 時点で既にあった)」と「急性発症 (incident 窓で初めて出た)」が一目で分かる。

```text
| 観点              | 顧客発言        | preflight        | incident             | 突合     |
|------------------|----------------|------------------|----------------------|---------|
| 影響サービス      | "メール"        | dovecot active   | Dovecot brute ✅      | 一致     |
| 時間              | "19:30 頃"     | —                | 19:01 開始            | ⚠️ 30分前 |
| obuchi 業務       | "今日休み"     | last に 10.1.129.10 ★ | authorized_keys 5/3 08:53 改竄 | 🚨 不一致 |
| 10.1.129.10 IP   | "知らない"     | last に同 IP (既侵害) | 4/24 から活動継続    | 🚨 顧客盲点 |
| ssh sshd        | —              | sshd active      | brute 痕跡なし         | ✅ 整合  |
| /etc/named.conf | —              | skipped          | mtime 30min ago      | ❓ 情報不足 |
```

**列の意味:**
- `顧客発言` — hearing JSON `outputs.customer_keywords` および `outputs.free_text` の引用 (要約 OK / 改ざん NG)
- `preflight` — `/preflight` が baseline で観測したもの。anomaly があれば「kind: detail」で書く。anomaly 無し = `—`、`/preflight` 未実行 = `skipped`
- `incident` — `/incident` analyzer が受電窓内で観測したもの (signals / patches / attack_pattern 関連シグナル)
- `突合` — 4 者 (顧客発言 / preflight / incident / 既侵害前提) の整合判定

**突合状態の語彙:**
- `一致` (✅) — 顧客発言と incident ログが整合 (preflight も矛盾しない)
- `⚠️ 部分一致` — 時刻ズレ / 影響範囲のズレ等、矛盾はないが完全一致でもない
- `🚨 不一致` — 顧客発言と incident ログが明確に矛盾 (顧客が嘘をついているか、攻撃が顧客の認知範囲外)
- `🚨 顧客盲点` — incident ログには明確な侵害痕跡があるが顧客が認識していない (攻撃が進行中の可能性)
- `❓ 情報不足` — 顧客発言もログも不十分で判断不能 (§2.5 補強調査の trigger)

**「不一致」「顧客盲点」「情報不足」が §2.5 補強調査の trigger** — それぞれ何を確認するか §2.5 で決める。

---

## §2.5. AI 自発的 read-only 補強調査 (NEW)

### 起動条件 (gap-driven)
§2 突合表に以下のいずれかが出ている場合に追加調査を起動する:
- ❓ 情報不足 が 1 件以上
- 🚨 不一致 が 1 件以上
- 🚨 顧客盲点 が 1 件以上
- ⚠️ 部分一致 で attack_pattern が `unknown`

3 件以上の trigger があれば全件調査、2 件以下なら全件 + attack_pattern 補強で 8 ssh 上限以内。

### 許可されるコマンド (read-only のみ)
許可リスト:
- `grep -nE 'pattern' /var/log/*` 系 (read)
- `find /etc /var/www /home -mmin -<window>` (read)
- `cat /etc/passwd /etc/group /etc/sudoers` (read、特に sudoers / passwd の UID 0 重複)
- `ls -la /home/*/.ssh/` (read、authorized_keys 改竄痕跡)
- `ss -tlnp` / `ss -anp` (現在の接続状況)
- `last -ai` / `journalctl -u <unit> --since "<time>"` (最近のログイン / サービスログ)
- `systemctl status <unit>` / `systemctl list-unit-files --state=enabled`
- `awk '...'` / `sort` / `uniq` / `head` / `tail` / `wc` (集計)
- `stat <file>` / `find -mmin` (mtime 確認)

**禁止リスト** (絶対に実行しない、settings.json で deny されていなくても):
- `iptables -j DROP|-A|-I` (変更系)
- `systemctl stop|start|restart|enable|disable|mask|unmask`
- `rm` / `mv` / `cp` (改変系)
- `chmod` / `chown` / `usermod` / `passwd`
- `kill` / `pkill`
- 通信を発信する系 (curl / wget / dig +short / nc) — verifier として使う場合のみ別途許諾必要 (基本 OFF)

### 実行ポリシー
- 1 incident につき最大 8 ssh 往復 (multi-trigger でも上限)
- 各調査に「なぜ走らせたか」「何が分かったか」「next 候補」を記録 (JSON `outputs.investigations[]`)
- 失敗 (timeout / permission) も記録、再試行はしない
- ssh エイリアス: `victor` / `bravo` (settings.json で `Bash(ssh victor *)` `Bash(ssh bravo *)` 許可済の前提)
- attack_pattern が `unknown` のときは闇雲に 8 全部使い切らない (3 件 + 「pattern 確定後に追加調査推奨」と明記)

### **必須**: §4 [C] コマンド提案前のツール在庫確認

§4 [C] バケットで具体コマンドを提案する場合、**該当ツールが対象ホストに存在することを §2.5 で確認**しないと「`command not found`」で人間が困る。投資コスト 1 ssh 往復:

```bash
# 例: IP 遮断系を提案する前
ssh victor 'for c in iptables /usr/sbin/iptables nft firewall-cmd; do
              echo -n "$c: "; command -v $c 2>/dev/null || echo "(なし)"
            done'

# 例: メール再送制御を提案する前
ssh bravo 'for c in postsuper postcat postqueue; do
             echo -n "$c: "; command -v $c 2>/dev/null || echo "(なし)"
           done'
```

確認した結果に応じて [C] コマンドを **存在するツールで** 組み立てる。OCI Rocky 9 では多くの場合 firewall 系が未インストール (cloud NSG 任せ) なので、Apache `Require not ip` や `<Directory>` Deny 等の **アプリ層代替**を提案する。

### 出力形式
```text
─── /review §2.5 AI 自発的補強調査 (read-only) ───

[#1] trigger : ❓情報不足 (axis: /etc/named.conf mtime)
     query   : ssh bravo 'sudo find /etc -mmin -90 -type f | head -20'
     finding : /etc/named.conf 30 分前 mtime + /etc/resolv.conf 8h 前
     impact  : incident.attack_pattern=dns-tamper の補強材料、§4 [C-1] 候補

[#2] trigger : 🚨顧客盲点 (axis: 10.1.129.10 IP)
     query   : ssh victor 'last -ai | grep 10.1.129'
     finding : 4/24 から 12 件のログイン痕跡 (obuchi 4 件 + manage 8 件)
     impact  : 既侵害前提 (incident.md §0.5) を裏付け、§4 [B-1] 顧客への確認材料
```

各 investigation はストイックに「事実だけ」記録する。判断は §3 / §4 で行う。

---

## §2.6. 被害範囲確定 (impact_assessment) — 旧 /check + /playbook の代替

旧 `/check` (個別脆弱性 forensic) と `/playbook` (カテゴリ別深掘り) を凍結したため、**「いつからいつまで」「どこまで広がったか」「何が漏れたか」を体系的に出す責任は /review に集約された**。/report が顧客向けメールに「○時○分から○時○分まで○○が発生」と書くための **必須出力**。

§2.5 の補強調査結果 + incident.signals + preflight.anomalies を統合して、以下 5 軸を必ず埋める:

### 出力形式
```text
─── /review §2.6 被害範囲確定 (旧 /check + /playbook 代替) ───

[1] 発生時刻 (window)
    開始: 2026-05-04T12:10:41+09:00 (incident.signals[#0] first_seen)
    終了: 2026-05-04T12:50:00+09:00 (§2.5 #X で 12:50 以降 0 req 確認)
    継続: 約 40 分

[2] 影響資産 (affected_assets)
    - victor (com1.local Web) — 応答遅延 (severity: high)
    - bravo (DNS / Mail)        — 影響なし (確認済 §2.5 #N)

[3] 横展開 (lateral_movement)
    無し — §2.5 #M で /var/log/secure / last に他ホスト侵入痕跡なし
    (or: 有り — 詳細)

[4] データ漏洩 / 認証情報漏洩 (exfiltration / credentials)
    無し — status コード全 200 + GET / のみ、POST / 大量 GET の cookie 送信なし
    (or: 有り — どのデータがいつどこへ)

[5] 顧客向け一行サマリ (/report が直接引用)
    "12:10〜12:50 (約40分) に com1.local Web の応答遅延が発生。改ざん・データ漏洩なし。"
```

### 必須 5 軸の埋め方

1. **window (発生時刻)** — incident.signals の `first_seen` / `last_seen` を起点に、§2.5 で「いつ収束したか」を確認 (例: `ssh victor 'tail -100 /var/log/httpd/access_log | tail'` で直近 req 確認)。`unknown` は禁止 — 不明なら「現在も継続中」と明記
2. **affected_assets** — incident.signals の host + analyzer pattern_tag から導出。各 asset に `severity: low/medium/high/critical` を付ける
3. **lateral_movement** — bravo / victor 両方に検出シグナルがあれば 🚨 横展開。preflight.anomalies の既侵害 IP ログイン (10.1.129.0/24) は別 incident と整理
4. **exfiltration** — POST 大量 / 不審な outbound (curl / wget) / DB 異常 query を §2.5 で確認。確証なければ "確認できず" と書く ("無し" は確認したときだけ)
5. **customer_facing_summary** — 「いつから / いつまで / 何が / どこまで」を 1-2 行に圧縮。/report がメール本文にそのまま貼る前提で書く (専門用語は避ける)

### NG パターン
- "詳細不明" を出さない — 5 軸全部に何かしら入れる (確認できなければ「確認できず」と明記、空欄 NG)
- customer_facing_summary に「攻撃」「侵害」を直接書かない (顧客通知では「不審なアクセス」「リクエスト連打」等の中立語に置換)
- 複数 incident をまとめない — 1 review JSON = 1 incident_id = 1 customer_facing_summary

---

## §3. 出力セクション 2: 4 択判定推奨

### §3.0 attack_pattern (incident §4 から継承)

incident__*.json の `outputs.attack_pattern` と `outputs.attack_subpattern` を読み込み、本セクション冒頭でそのまま提示する。これが §3.1 判定推奨と §4 [C] コマンド提案の **主レンズ** になる。

```text
─── /review §3.0 attack_pattern 引き継ぎ ───
attack_pattern    : ransomware
attack_subpattern : lateral-only
incident reasoning: <incident.md §4.2 で Claude が出した 3〜6 行の根拠>
```

attack_pattern の取扱い:
- `ddos` / `dns-tamper` / `phishing` / `ransomware` / `wp-tamper` のいずれかが確定していれば、§3.1 判定 + §4 提案はその pattern 前提で組む
- `unknown` の場合、**判定は C (追加情報待ち) に寄せる**。ただし §2 突合表に 🚨 が複数 + §2.5 補強調査で確証があれば D に上げてよい (alternative に出す)

### §3.1 判定推奨

```text
─── /review §3.1 4 択判定推奨 ───

D. 対応必要 (信頼度 0.85)
理由: 不一致 2 件 (obuchi 鍵改竄 + 既侵害 IP 顧客未認知) + attack_pattern=ransomware/lateral-only
      + §2.5 #2 で 10.1.129.10 由来 12 件ログイン確認
代替案: C. 追加情報待ち (obuchi 氏に直接確認できる場合)

⚠️ 判定タブで人間がラジオ選択するのが原則 (HTML 仕様書 §2.1.2)。/review はあくまで推奨。
最終判断はリーダー。
```

**判定推奨ロジック:**
- 🚨 不一致 / 顧客盲点が **1 件以上** + attack_pattern が `unknown` 以外 + §2.5 補強で裏付け → **D (対応必要)** 推奨
- 🚨 不一致 / 顧客盲点が 1 件以上だが attack_pattern が `unknown` → **C (追加情報待ち)** 推奨 + 代替に D
- ⚠️ 部分一致のみ + 顧客が「初めて」と言ってる → **C (追加情報待ち)** 推奨
- 全件一致 + 軽微な症状のみ → **B (情報提供のみ)** 推奨
- ログに何も無い + 顧客が「念のため」と言ってる → **A (対応不要)** 推奨

信頼度 (confidence):
- 🚨 が複数 + attack_pattern 確定 + §2.5 で裏付け → 0.85-0.95
- 🚨 が 1 件のみ + attack_pattern 確定 → 0.7-0.85
- ⚠️ + 部分情報のみ → 0.4-0.7
- 情報不足が支配的 / attack_pattern が unknown → 0.2-0.4

`rationale` には §2 突合表の不一致と §2.5 補強調査の investigation 番号を必ず引用する (例: 「§2.5 #2 で確認」)。

**auto-pick は禁止**。`primary` + `confidence` + `rationale` + `alternative` + `alt_condition` の 5 要素を出すだけ。
最終 A/B/C/D の採択は人間がやる (採択結果は別 `review_human__*.json` で保存、HTML aggregator が読む)。

---

## §4. 出力セクション 3: アクション提案 (4 バケット構造)

§2 突合 + §2.5 補強調査 + §3 判定 を踏まえ、**4 バケット**に分けて出力する。これが指揮係の総合判断材料 + 人間が打つコマンドのソースになる。

**4 バケットの分担:**
- [A] AI 自走で **確認済み** (事実)
- [B] 担当が顧客/同僚に **質問**して情報を得る (受身 / 情報収集)
- [C] **担当 (技術側) が ssh で実行**するコマンド (能動 / インフラ操作)
- [D] **顧客 / エンドユーザに依頼**するアクション (能動 / クライアント側操作)

[B] と [D] の違い: [B] は情報を「もらう」、[D] は操作を「してもらう」。両方ともアウトプットは /report と /call_close が消費する。

### [A] AI が自走で確認済み (read-only、追加判断不要)
§2.5 で実行した調査の **結論サマリ**。「事実として確認済み」の項目だけ。

形式: `- <事実> (出典: §2.5 #N)`

例:
```text
[A-1] /etc/named.conf 30 分前に変更 (出典: §2.5 #1)
[A-2] 10.1.129.10 由来ログイン 12 件 / obuchi 4 件 / manage 8 件 (出典: §2.5 #2)
[A-3] /etc/passwd に UID 0 重複なし (toor: ロック中) (出典: §2.5 #3)
```

### [B] 人間に確認してほしい項目 (verification needed)
AI が ssh で見ても確証が持てない項目、または現場 / 顧客に裏取りすべき項目。
形式: 各項目に「何を確認するか」「誰に / どこを見るか」「想定される回答パターン」。

例:
```text
[B-1] axis      : obuchi 氏の業務予定 (今日休みは事実か)
      確認先    : 人事 or 本人 (連絡可なら)
      想定回答  : 「今日休み」と整合 → 鍵改竄は完全な侵害確定 / 「実は出勤」→ 業務利用の可能性

[B-2] axis      : 10.1.129.10 IP の認知度
      確認先    : 顧客 (ヒアリング再聴取)
      想定回答  : 「初めて見た」→ 既侵害前提強化 / 「関連会社」→ out_of_scope に降格
```

### [C] 実行候補コマンド (action proposals、人間が打つ)
事案固有の 1-shot 修復コマンド候補を理由付きで列挙。**汎用テンプレートは出さない** (それは cookbook の役割)。
各コマンドに `safety` タグ:
- `read-only` — 確認系、AI が §2.5 で既に走らせたものの再現コマンド (人間が再確認したい場合)
- `review` — リーダー承認後に手動実行を推奨 (1-shot の影響範囲が限定的)
- `destructive` — 必ずリーダー承認 + 顧客通知後に実行 (サービス影響あり)

形式 (§2.5 でツール在庫を確認した上で組み立てる):
```text
[C-1] safety: review
      reason: 161.33.12.212 から 2480 req 観測 (incident.signals[#0]) → 単一 IP 遮断で十分
      tool_check: §2.5 #X で iptables / nft / firewall-cmd が全て (なし) 確認 → Apache 側で遮断
      command:
        ssh victor "cat <<'EOF' | sudo tee /etc/httpd/conf.d/blocklist.conf >/dev/null
        <Location />
          <RequireAll>
            Require all granted
            Require not ip 161.33.12.212
          </RequireAll>
        </Location>
        EOF
        sudo httpd -t && sudo systemctl reload httpd"
      expected impact: 当該 IP からの HTTP/80 アクセスのみ 403 拒否、他クライアント影響なし
      verify after:
        ssh victor "ls -la /etc/httpd/conf.d/blocklist.conf && curl -sS -o /dev/null -w 'remote=%{remote_ip} http=%{http_code}\n' http://localhost/"

[C-2] safety: review
      reason: WordPress siteurl=168.138.42.63 → com1.local に修正 (§2.5 #2 で確認した設定ミス)
      tool_check: §2.5 #X で sudo mysql wordpress が読めること確認済
      command:
        ssh victor "sudo mysql wordpress <<'SQL'
        UPDATE wp_options SET option_value='http://com1.local' WHERE option_name IN ('siteurl','home');
        SQL"
      expected impact: WordPress 全リンクが com1.local に変わる (サービス影響なし)
      verify after:
        ssh victor "sudo mysql wordpress <<'SQL'
        SELECT option_name, option_value FROM wp_options WHERE option_name IN ('siteurl','home');
        SQL"
```

**クォート方針 (重要):**
- ssh 経由の **mysql / awk / 複数行コマンドは heredoc** を使う (`<<'SQL'`)。`'\''` の連鎖は人間がコピペで詰まる
- `ssh victor 'cmd'` の中で **シングルクォートを 1 段だけ**使う形が一番安全。多重クォートが必要なら heredoc に切り替える
- copy-paste 直前のテストとして AI も同じコマンドを ssh で叩いて成功を確認してから [C] に書く (= §2.5 投資の 1 件として記録)

`safety: destructive` のコマンドは **絶対に AI が auto-execute しない**。HTML ダッシュボードに表示するだけ。
人間が ssh で打つ前に **指揮係承認** が必要。

### [D] 顧客/エンドユーザに依頼するアクション (NEW)
顧客側で手を動かしてもらう必要があるアクション。担当が ssh で代行できないもの。
形式: 各項目に「何をしてほしいか」「対象者 (誰が)」「理由 / リスク」「依頼するタイミング」「想定所要時間」。

例:
```text
[D-1] action     : メールアカウントのパスワード変更 (obuchi 含む全配布アカウント 7 名)
      who        : 顧客 (各従業員)
      reason     : Dovecot brute force 痕跡 + obuchi 鍵改竄 → 認証情報漏洩の可能性
      when       : /call_close と同時に依頼 (T+0:30)、24h 以内に完了確認
      duration   : 1 アカウント 5 分、全員で 30-60 分
      risk_if_skip: 攻撃者が漏洩した認証情報で再侵入

[D-2] action     : 各社員の PC で「最近受信した不審メール」をクライアント側で削除
      who        : 顧客 (各社員、自席 PC)
      reason     : フィッシングメールが配信済の可能性 (本案件 attack_pattern が phishing の場合のみ)
      when       : 完了報告メールに削除手順を添付
      duration   : 5 分
      risk_if_skip: ユーザが誤クリックする可能性
```

[D] バケットの優先順位:
- 認証情報変更 (パスワード / 鍵) は最優先 ([D-1] 相当)
- 端末側操作 (ファイル削除 / 再起動 / 更新) は次
- 設定変更 (メーラのフィルタ / ブラウザのキャッシュクリア) は最後

[D] アクションは **絶対に AI が代行しない** — 顧客側の操作なので物理的に不可能、かつ顧客の同意なしに変更すると信頼破壊。

### General reference (cookbook §N)
attack_pattern → cookbook 章 1:1 マッピングは末尾に小さく残す。**[C] バケットの 1-shot コマンドが優先**、cookbook はテンプレ参照用 (リーダーが読み比べたい場合のみ開く)。

| attack_pattern | cookbook 章 |
|---|---|
| ddos | `docs/recovery_cookbook.md §1 DDoS` |
| dns-tamper | `docs/recovery_cookbook.md §2 DNS 改ざん` |
| phishing | `docs/recovery_cookbook.md §3 フィッシング` |
| ransomware | `docs/recovery_cookbook.md §4 ランサムウェア` |
| wp-tamper | `docs/recovery_cookbook.md §5 WordPress / RainLoop / PHP` |
| unknown | (該当章なし) — 「判断材料不足、cookbook 参照前に追加調査」と明記 |

### out_of_scope_logged (記録のみ、塞がない)
受電と直接関係しないが §2.5 で見つけた / preflight で出ていた anomaly は記録だけ残す。/report に「補足発見」として渡す。

```text
out_of_scope_logged:
- bravo toor:0:0:Backdoor Root (歴史的、現在ロック中)
- DNS evil/evil2/www-fake 注入 (受電と無関係なら別 incident で対応)
- AXFR allow-transfer any (恒久対応は別件)
```

---

## §5. JSON 出力 (HTML aggregator 連携 / 共通 helper 経由)

§2〜§4 の結果を JSON 化して helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/${INCIDENT_ID}/review__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh review
{
  "inputs": {
    "incident_id": "2026-05-04_12:00_victor",
    "hearing_consumed": true,
    "preflight_consumed": true,
    "incident_consumed": true
  },
  "outputs": {
    "attack_pattern_received": "ransomware",
    "attack_subpattern_received": "lateral-only",
    "comparison": [
      {"axis": "影響サービス", "customer": "メール", "preflight": "dovecot active", "incident": "Dovecot brute", "verdict": "match"},
      {"axis": "obuchi 業務", "customer": "今日休み", "preflight": "last に 10.1.129.10", "incident": "authorized_keys 5/3 08:53 改竄", "verdict": "mismatch"},
      {"axis": "10.1.129.10 IP", "customer": "知らない", "preflight": "last に同 IP (既侵害)", "incident": "4/24 から活動継続", "verdict": "customer_blindspot"}
    ],
    "investigations": [
      {"id": "#1", "trigger": "❓情報不足 (axis: /etc/named.conf mtime)", "query": "ssh bravo 'sudo find /etc -mmin -90 -type f'", "finding": "/etc/named.conf 30 分前 mtime", "impact": "attack_pattern=dns-tamper 補強"},
      {"id": "#2", "trigger": "🚨顧客盲点 (axis: 10.1.129.10 IP)", "query": "ssh victor 'last -ai | grep 10.1.129'", "finding": "4/24 から 12 件ログイン", "impact": "既侵害前提を裏付け"}
    ],
    "impact_assessment": {
      "window": {
        "start_jst": "2026-05-04T12:10:41+09:00",
        "end_jst": "2026-05-04T12:50:00+09:00",
        "duration_minutes": 40,
        "ongoing": false,
        "evidence": "incident.signals[#0] first_seen + §2.5 #X で 12:50 以降 0 req 確認"
      },
      "affected_assets": [
        {"asset": "victor (com1.local Web)", "impact": "応答遅延", "severity": "high"},
        {"asset": "bravo (DNS / Mail)", "impact": "影響なし", "severity": "none"}
      ],
      "lateral_movement": {"detected": false, "evidence": "§2.5 #M で他ホストへの侵入痕跡なし"},
      "exfiltration": {"detected": false, "credentials_compromised": false, "evidence": "status 全 200 + GET / のみ、POST 大量・outbound なし"},
      "customer_facing_summary": "12:10〜12:50 (約40分) に com1.local Web の応答遅延が発生。改ざん・データ漏洩なし。"
    },
    "judgment_recommendation": {
      "primary": "D",
      "confidence": 0.85,
      "rationale": "不一致 2 件 + attack_pattern=ransomware/lateral-only + §2.5 #2 で 10.1.129.10 由来 12 件ログイン確認",
      "alternative": "C",
      "alt_condition": "obuchi 氏に直接確認できる場合"
    },
    "action_proposals": {
      "confirmed_findings": [
        {"id": "A-1", "fact": "/etc/named.conf 30 分前に変更", "source": "§2.5 #1"},
        {"id": "A-2", "fact": "10.1.129.10 由来ログイン 12 件", "source": "§2.5 #2"}
      ],
      "verification_needed": [
        {"id": "B-1", "axis": "obuchi 氏の業務予定", "who": "人事 or 本人", "expected": "「今日休み」と整合 → 侵害確定 / 「実は出勤」→ 業務利用"},
        {"id": "B-2", "axis": "10.1.129.10 IP の認知度", "who": "顧客", "expected": "「初めて見た」/ 「関連会社」"}
      ],
      "user_actions": [
        {"id": "D-1", "action": "メールアカウントのパスワード変更 (配布アカウント 7 名)", "who": "顧客 (各従業員)", "reason": "Dovecot brute + obuchi 鍵改竄 → 認証情報漏洩の可能性", "when": "/call_close と同時 (T+0:30)、24h 以内", "duration": "全員 30-60 分", "risk_if_skip": "攻撃者が漏洩した認証情報で再侵入"}
      ],
      "commands": [
        {
          "id": "C-1",
          "safety": "review",
          "reason": "161.33.12.212 から 2480 req 観測 → 単一 IP 遮断で十分",
          "command": "ssh victor 'sudo iptables -I INPUT -s 161.33.12.212 -j DROP'",
          "expected_impact": "当該 IP のみ遮断、他は影響なし",
          "verify_after": "ssh victor 'sudo iptables -L INPUT -n | grep 161.33.12.212'"
        },
        {
          "id": "C-2",
          "safety": "destructive",
          "reason": "obuchi authorized_keys 改竄 (§2.5 #N) → 鍵を即時退避",
          "command": "ssh victor 'sudo mv /home/obuchi/.ssh/authorized_keys /home/obuchi/.ssh/authorized_keys.compromised.$(date +%Y%m%d)'",
          "expected_impact": "obuchi の SSH 公開鍵認証無効化",
          "verify_after": "ssh victor 'sudo ls -la /home/obuchi/.ssh/'"
        }
      ]
    },
    "scope_proposal": {
      "recommended_cookbook_chapter": "docs/recovery_cookbook.md §4 ランサムウェア",
      "out_of_scope_logged": ["bravo toor:0 Backdoor (歴史的)", "DNS evil 注入 (受電無関係)", "AXFR allow-transfer any (別件)"]
    }
  },
  "verdict": {
    "status": "🚨",
    "summary": "不一致 2 件 + attack_pattern=ransomware、判定 D 推奨、[C] コマンド 2 件提案"
  },
  "next_skills": ["/report", "/ticket"]
}
JSON_EOF
```

helper が補完するメタデータ:
- `skill`: `"review"`
- `incident_id`: `INCIDENT_ID` env 経由 (= /incident からの伝播)
- `timestamp`: 実行時の ISO 8601 JST (+09:00)
- `actor`: `ai_auto`

verdict.status の語彙は `comparison[].verdict` の集計結果と整合させること (HTML aggregator が両者を比較する)。

**verdict.status の決め方:**
- `🚨` — 不一致 / 顧客盲点が 1 件以上、または `safety: destructive` の [C] コマンドが 1 件以上
- `⚠️` — 部分一致のみ、または `safety: review` の [C] コマンドのみ
- `✅` — 全件一致 + 軽微 + [C] コマンドが read-only のみ
- `info` — 情報不足

**next_skills は固定:** `["/report", "/ticket"]`。/review は主動線の最終判定層なので、後段は報告書 (/report) とチケット (/ticket) のみ。

---

## §6. NG パターン (やってはいけない)

1. **auto-pick 禁止** — `primary` を出すのは推奨であって採択ではない。HTML 仕様書 §2.1.2「判定は人間」を物理化
2. **顧客発言を勝手に書き換えない** — 突合表の「顧客発言」列は hearing JSON の `customer_keywords` / `free_text` をそのまま引用 (要約は OK、改ざん NG)
3. **AI は cookbook の汎用テンプレート部分を Read しない / 引用しない** — 旧 /playbook 復活防止のため。
   ただし §4 [C] バケットの **事案固有の 1-shot コマンド** は安全 (read-only / review / destructive) タグ付きで出してよい。
   汎用テンプレと事案固有 1-shot の見分け方:
   - 汎用 = `iptables -I INPUT -p tcp --dport 80 -m connlimit --connlimit-above 20 -j DROP` のような pattern 一般論
   - 1-shot = `iptables -I INPUT -s 161.33.12.212 -j DROP` のような今回の事案固有値
4. **スコープ判定の根拠を必ず出す** — [C] コマンドに入れた発見は「ヒアリングのどの項目と直結しているか + どの調査 (§2.5 #N) で確認したか」を `reason` に明記
5. **既侵害前提を忘れない** — 4/24 10.1.129.10 由来痕跡 (incident.md §0.5) は常に背景にある。preflight 列に既侵害シグナルがあれば「初めて」と言われても §2.5 で last/journalctl で過去の同種ログを必ず照合
6. **「治しすぎない」を破らない** — out_of_scope_logged の発見を [C] に勝手に昇格しない。リーダーが必要と判断したら別 incident として上げ直す
7. **attack_pattern を勝手に書き換えない** — incident__*.json の値をそのまま `attack_pattern_received` に入れる。/review が pattern を再判定したい場合でも JSON 上書きはせず、`judgment_recommendation.rationale` に「pattern と突合表の不整合」として書く
8. **JSON を出さずに stdout だけで終わらせない** — HTML aggregator が読み込めなくなる。JSON 書き出しは必須 (`data/incidents/<id>/review__<ts>.json`)
9. **§2.5 で破壊系コマンドを実行しない** — 禁止リストに該当するものは ssh 経由でも実行しない (settings.json で deny されていなくても、本セクションの「禁止リスト」に該当するものは絶対に走らせない)
10. **§4 [C] のコマンドを auto-execute しない** — JSON に出力するだけ。指揮係承認 + 人間 ssh 実行が原則
11. **§2.5 ssh 上限 8 を超えない** — 8 を超えそうなら、6-7 で打ち切って `investigations` に「pattern 確定後に再起動推奨」を最後の entry として残す
12. **markdown ヒアリング (~/Desktop/shirahama_test.md) や /tmp/incident_*.log を Read しない** — 2026-05-04 廃止。3 JSON で完結するのが正

---

## §7. 仕様書接続 + メモリ参照

- 仕様書 docs/25_システム仕様書.html §2.1.2「判定は人間」原則の物理化 — /review が推奨を出すが採択はしない
- 仕様書 §3.2 コマンドリファレンスに `/review` を主動線として記載
- 仕様書 §4 ワークドエグザンプル T+0:08 に /review を差し込む (/incident 直後 / /report・/ticket 前)
- **上流契約**: 受電タブ (HTML 仕様書 受電台本タブ) の `saveHearingJson()` ボタン → `hearing__*.json` を生成
- **上流契約**: `incident.md §4.2 attack_pattern` — incident__*.json の `outputs.attack_pattern` / `outputs.attack_subpattern` がそのまま `attack_pattern_received` として review__*.json に入る
- **上流契約**: `preflight.md §8 JSON 永続化` — preflight__*.json の `outputs.<host>.anomalies[]` を §2 突合表 preflight 列に展開
- **下流契約**: /report が review__*.json の `outputs.action_proposals.confirmed_findings` (= 完了報告本論 ②) と `outputs.action_proposals.verification_needed` (= 残作業) を読む
- **下流契約**: /call_close (将来) が `outputs.judgment_recommendation` + `customer_tone` (hearing JSON) を読んで第一声テンプレを決める
- **下流契約**: /ticket が review__*.json + 各 [C] コマンドの実行ログを集約

メモリ参照:
- `memory/lab_vulnerabilities_to_plant.md` — 脆弱性表 (out_of_scope 候補の判断材料)
- `memory/demo_progress.md` — 過去シナリオの判定実績
- `memory/MEMORY.md` — 索引
- `memory/simplification_2026-05-04.md` — 5 commands 構成、/check 凍結の経緯

---

## §8. 次に打つコマンド (案内)

```text
─── 次のステップ ───
  1. ブラウザで採択カードの A/B/C/D を選んで「採択を保存」 → mv ~/Downloads/review_human__*.json data/incidents/<id>/
  2. 対応カードの [C] コマンドを 📋 copy → ssh で実行 (人間)
  3. /review                  ← verify (実行後の確認、3 回目)
  4. /report                  ← 文書 4 種 + verified/unverified
  5. /call_close              ← 顧客への電話台本
  6. /ticket                  ← PukiWiki マークアップ
```
