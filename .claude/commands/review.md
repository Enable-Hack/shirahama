---
description: 受電ヒアリング ↔ /incident と /check のログ実態を 3 列突合し、4 択判定 (A/B/C/D) と「治しすぎない」スコープ提案を出す
---

# /review — ヒアリング ↔ 観測 突合 + 判定推奨 + スコープ提案

引数: `[<hearing-path>] [<incident-id>]`
省略時:
- hearing-path = `~/Desktop/shirahama_test.md`
- incident-id = `data/incidents/` 配下の最新ディレクトリ (mtime 降順)

例:
- `/review`
- `/review ~/Desktop/shirahama_test.md`
- `/review ~/Desktop/shirahama_test.md 2026-05-04_14:00_victor`

---

## このスキルが解決する問題

- ヒアリング ↔ ログ実態の突合が **リーダーの頭の中** だけで起きていた → 再現性なし、引き継ぎ不能
- 「治しすぎない」原則 (lab は意図的に過剰 seed) を **個人判断** で運用していた → in_scope / out_of_scope の境界が人によって揺れる
- 4 択判定 (A/B/C/D) を **AI に委ねる**経路が無かった → HTML 仕様書 §2.1.2 「判定は人間」原則の物理化が不十分

本スキルは「**AI が突合 + 推奨を機械的に作り、最終判定は人間がラジオ選択する**」という分業を物理化する。
ACTOR: **AI Auto** (突合 + 推奨は完全自動、最終 A/B/C/D 採択は人間)

JPCERT インシデントハンドリング 4 段階のうち **2.2 トリアージ** の品質保証層。**2.3 レスポンス**は別 (/playbook を人間が実施)。

---

## §0. 前提

- 入力 1: 受電ヒアリングシート (`shirahama_test.md` または `01_受電ヒアリングシート.md` 構造、パターン A/B/C/D 4 分類)
- 入力 2: `/incident` 出力 (`/tmp/incident_*.log`、`data/incidents/<id>/incident__*.json` があれば優先)
- 入力 3: `/check` 出力 (`data/incidents/<id>/check-*__*.json` 全件)
- 出力: stdout に 3 セクション (突合表 / 判定推奨 / スコープ提案) + JSON 1 ファイル
- 「治しすぎない」原則: lab は意図的に約 18 件の脆弱性が seed されている。受電と関係する分のみ in_scope に分類

---

## §1. 入力読み込み

```bash
SHIRAHAMA_DIR="${SHIRAHAMA_DIR:-/Users/ryu/Desktop/shirahama}"
HEARING_PATH="${1:-$HOME/Desktop/shirahama_test.md}"
INCIDENT_ID="${2:-}"
cd "$SHIRAHAMA_DIR"

if [ ! -f "$HEARING_PATH" ]; then
    echo "❌ ヒアリング報告が見つからない: $HEARING_PATH"
    echo "   /incident 起動 → /tmp/incident_*.log → ヒアリング md の順で揃えてください"
    exit 1
fi

# incident-id 自動検出 (引数省略時)
if [ -z "$INCIDENT_ID" ]; then
    INCIDENT_ID="$(ls -1t data/incidents/ 2>/dev/null | head -1)"
fi
INCIDENT_DIR="data/incidents/${INCIDENT_ID}"

echo "─── /review §1 入力 ───"
echo "  hearing      : $HEARING_PATH ($(wc -l < $HEARING_PATH) 行)"
echo "  incident_id  : ${INCIDENT_ID:-<未指定 / data/incidents/ が空>}"
echo "  incident_dir : ${INCIDENT_DIR}"
echo "  incident json: $(ls -1 ${INCIDENT_DIR}/incident__*.json 2>/dev/null | wc -l) 件"
echo "  check json   : $(ls -1 ${INCIDENT_DIR}/check-*__*.json 2>/dev/null | wc -l) 件"
echo "  /tmp ログ    : $(ls -1 /tmp/incident_*.log 2>/dev/null | wc -l) 件"
```

その後 Claude は以下を **Read ツール**で読む:
1. `$HEARING_PATH` — 受電ヒアリングの全文
2. `${INCIDENT_DIR}/incident__*.json` — analyzer signals + Mock + Claude 判定
3. `${INCIDENT_DIR}/check-*__*.json` — 個別 check 結果
4. (補助) `/tmp/incident_*.log` の冒頭 30 行ずつ — JSON 化されてないログの直接参照

抽出ルール:
- ヒアリングが Markdown 構造化されてない場合は **緩く解釈** (キーワードベース)
- パターン (A-D) / 時間窓 / 影響サービス / 顧客の主観 (「初めて」「何度目か」「他社員からも」) を最低限拾う
- 配布アカウント該当者の業務予定 (誰が今日出社/作業中か) を拾えれば「ログ ↔ 業務予定」の不一致を検出可

---

## §2. 出力セクション 1: ヒアリング ↔ 観測 突合表

```text
─── /review §2 ヒアリング ↔ 観測 突合 ───
```

3 列突合表を Markdown table で出す:

```text
| 観点              | 顧客発言        | ログ実態          | 突合     |
|------------------|----------------|------------------|---------|
| 影響サービス      | "メール"        | Dovecot brute ✅  | 一致     |
| 時間              | "19:30 頃"     | 19:01 開始       | ⚠️ 30分前 |
| obuchi 業務       | "今日休み"     | authorized_keys 5/3 08:53 改竄 | 🚨 不一致 |
| 10.1.129.10 IP   | "知らない"     | 4/24 から活動    | 🚨 顧客盲点 |
```

**突合状態の語彙:**
- `一致` (✅) — 顧客発言とログが整合
- `⚠️ 部分一致` — 時刻ズレ / 影響範囲のズレ等、矛盾はないが完全一致でもない
- `🚨 不一致` — 顧客発言とログが明確に矛盾 (顧客が嘘をついているか、攻撃が顧客の認知範囲外)
- `🚨 顧客盲点` — ログには明確な侵害痕跡があるが顧客が認識していない (攻撃が進行中の可能性)
- `❓ 情報不足` — 顧客発言もログも不十分で判断不能 (追加収集が必要)

**「不一致」「顧客盲点」が最重要** — 顧客が見えてない侵害が進行中の可能性が高い。

抽出する観点 (最低 5 軸、揃えば 8 軸):
1. 影響サービス (Web/Mail/DNS/SSH/その他)
2. 時間窓 (HH:MM-HH:MM)
3. 攻撃元 IP (顧客が知っているか)
4. 配布アカウント該当者の業務予定 vs 該当アカウントのログ
5. 症状の客観性 (顧客が見たもの vs ログが示すもの)
6. 影響範囲 (顧客は単発と認識、ログは横展開)
7. 既侵害前提との整合 (4/24 10.1.129.10 由来痕跡、§0.5)
8. 過去の発生有無 ("初めて" vs last/journalctl で過去の同種ログ)

---

## §3. 出力セクション 2: 4 択判定推奨

```text
─── /review §3 4 択判定推奨 ───

D. 対応必要 (信頼度 0.85)
理由: 不一致 2 件 (obuchi 鍵改竄 + 既侵害 IP 顧客未認知) → 顧客には見えてない侵害が進行中、即対応必要
代替案: C. 追加情報待ち (obuchi 氏に直接確認できる場合)

⚠️ 判定タブで人間がラジオ選択するのが原則 (HTML 仕様書 §2.1.2)。/review はあくまで推奨。
最終判断はリーダー。
```

**判定推奨ロジック:**
- 🚨 不一致 / 顧客盲点が **1 件以上** → **D (対応必要)** 推奨
- ⚠️ 部分一致のみ + 顧客が「初めて」と言ってる → **C (追加情報待ち)** 推奨
- 全件一致 + 軽微な症状のみ → **B (情報提供のみ)** 推奨
- ログに何も無い + 顧客が「念のため」と言ってる → **A (対応不要)** 推奨

信頼度 (confidence):
- 🚨 が複数 + 既侵害前提の補強あり → 0.85-0.95
- 🚨 が 1 件のみ → 0.7-0.85
- ⚠️ + 部分情報のみ → 0.4-0.7
- 情報不足が支配的 → 0.2-0.4

**auto-pick は禁止**。`primary` + `confidence` + `rationale` + `alternative` + `alt_condition` の 5 要素を出すだけ。
最終 A/B/C/D の採択は人間がやる (採択結果は別 `review_human__*.json` で保存、HTML aggregator が読む)。

---

## §4. 出力セクション 3: 「治しすぎない」スコープ提案

```text
─── /review §4 「治しすぎない」スコープ提案 ───

[今回 (受電と関係) 塞ぐ]
- obuchi/.ssh/authorized_keys 退避 + 空にする (永続化対策)
- Dovecot disable_plaintext_auth=yes (運用影響、リーダー判断)

[発見したが今回は塞がない (報告書に記録のみ)]
- bravo toor:0:0:Backdoor Root (歴史的、現在ロック中)
- DNS evil/evil2/www-fake 注入 (受電と無関係なら別 incident で対応)
- AXFR allow-transfer any (恒久対応は別件)

理由: 過剰修正は環境破壊 + 出題シナリオ進行を阻害する
out_of_scope は /report に「補足発見」として残す
```

**スコープ判定ロジック:**
- 受電影響サービス (in_scope の主軸) と **直接関係** する発見 → `in_scope`
- それ以外で 🚨 確定 の発見 → `out_of_scope_logged` (報告書に書く、playbook では塞がない)
- ⚠️ / ✅ の発見 → 言及のみ (詳細は /report に投げる)

「触らない哲学」 (incident.md §0.6) との整合:
- 攻撃テンポはチーム進捗に追従 → 早く塞ぎすぎると次のキルチェーンが来る
- 「重要なやつだけ対応した = 勝ち」、「全部塞いだ」は逆効果
- in_scope に入れる根拠 (どのヒアリング項目と直結しているか) を明記する

---

## §5. JSON 出力 (HTML aggregator 連携 / 共通 helper 経由)

§2〜§4 の結果を JSON 化して helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/${INCIDENT_ID}/review__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh review
{
  "inputs": {
    "hearing_path": "~/Desktop/shirahama_test.md",
    "incident_window": "14:00-14:08",
    "host": "victor",
    "checks_consumed": ["check-known-attacker-ip", "check-bind-allow-update"]
  },
  "outputs": {
    "comparison": [
      {"axis": "影響サービス", "customer": "メール", "log": "Dovecot brute", "verdict": "match"},
      {"axis": "obuchi 業務", "customer": "今日休み", "log": "authorized_keys 5/3 08:53 改竄", "verdict": "mismatch"}
    ],
    "judgment_recommendation": {
      "primary": "D",
      "confidence": 0.85,
      "rationale": "不一致 2 件 + 既侵害 IP 顧客未認知",
      "alternative": "C",
      "alt_condition": "obuchi 氏に直接確認できる場合"
    },
    "scope_proposal": {
      "in_scope": ["obuchi/.ssh/authorized_keys 退避", "Dovecot disable_plaintext_auth"],
      "out_of_scope_logged": ["bravo toor:0 Backdoor", "DNS evil 注入", "AXFR allow-transfer any"]
    }
  },
  "verdict": {
    "status": "🚨",
    "summary": "不一致 2 件、判定 D 推奨"
  },
  "next_skills": ["/playbook:phishing", "/playbook:ransomware"]
}
JSON_EOF
```

helper が補完するメタデータ:
- `skill`: `"review"`
- `incident_id`: `INCIDENT_ID` env 経由 (= /incident からの伝播)
- `timestamp`: 実行時の ISO 8601 UTC
- `actor`: `ai_auto` (デフォルト。AI 自動判定)

verdict.status の語彙は `comparison[].verdict` の集計結果と整合させること (HTML aggregator が両者を比較する)。

**verdict.status の決め方:**
- `🚨` — 不一致 / 顧客盲点が 1 件以上
- `⚠️` — 部分一致のみ
- `✅` — 全件一致 + 軽微
- `info` — 情報不足

**next_skills の決め方:**
- 判定 D → 影響サービスに対応する `/playbook:*` を 1-2 個推奨
- 判定 C → 追加情報収集の `/check:*` を推奨
- 判定 B → `/report` (情報提供メール文面)
- 判定 A → なし (記録のみで終了)

---

## §6. NG パターン (やってはいけない)

1. **auto-pick 禁止** — `primary` を出すのは推奨であって採択ではない。HTML 仕様書 §2.1.2「判定は人間」を物理化
2. **顧客発言を勝手に書き換えない** — 突合表の「顧客発言」列はヒアリング原文をそのまま引用 (要約は OK、改ざん NG)
3. **スコープ判定の根拠を必ず出す** — in_scope に入れた発見は「ヒアリングのどの項目と直結しているか」を明記
4. **既侵害前提を忘れない** — 4/24 10.1.129.10 由来痕跡 (§0.5) は常に背景にある。「初めて」と言われても last/journalctl で過去の同種ログを必ず照合
5. **「治しすぎない」を破らない** — out_of_scope_logged の発見を in_scope に勝手に昇格しない。リーダーが必要と判断したら別 incident として上げ直す
6. **JSON を出さずに stdout だけで終わらせない** — HTML aggregator が読み込めなくなる。JSON 書き出しは必須 (`data/incidents/<id>/review__<ts>.json`)

---

## 仕様書接続 (docs/25_システム仕様書.html)

- §2.1.2「判定は人間」原則の物理化 — /review が推奨を出すが採択はしない
- §3 コマンドリファレンスに `/review` を §3.4.5 として追加 (時間あれば HTML 修正、当面はこの md が正)
- §4 ワークドエグザンプル T+0:09 に /review を差し込む (既存スイムレーン T+0:10-0:13 合議の前段)

## メモリ参照

- `memory/lab_vulnerabilities_to_plant.md` — 18 件脆弱性表 (out_of_scope 候補の判断材料)
- `memory/demo_progress.md` — 過去シナリオの判定実績
- `memory/MEMORY.md` — 索引
