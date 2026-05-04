---
model: claude-sonnet-4-6
description: 受電と対称の「完了電話 (closing call)」台本を生成する。/report の文書出力とは別に、口頭で読み上げるためのリズム・クッション・想定 Q&A・NG 言い換えを揃える
---

# /call_close — 顧客への完了一次連絡 (口頭) 台本生成

引数: `[<incident-id>]`
省略時: `data/incidents/` 配下の最新ディレクトリ (mtime 降順)

例:
- `/call_close`
- `/call_close 2026-05-04_12:00_victor`

---

## このスキルが解決する問題

- `/report` は **文書 (メール / 経営層向け要約 / ユーザ向け注意喚起)** を出す。電話で話す場合は読み上げ向きでない (リズム / クッション / 想定 Q&A 不足)
- 受電台本 (intake / `受電台本.html` / `電話応対_統合版_120点完成版.md`) は仕組み化されているのに、**完了電話 (closure) は属人化**していた
- 「結局、書いた内容を読んだだけで顧客が安心しなかった」事故を防ぐ — 口頭は **第一声・3 点完結・想定 Q&A・NG 言い換え** が文書とは別に必要
- 受電で **「聞いた」**ことに対して、closure では **「言う」**。両端を同じ精度で仕組み化することで、対応全体の見え方を顧客に揃える

JPCERT インシデントハンドリング 4 段階のうち **2.5 完了一次連絡** の電話モードを担当。文書モード (メール / wiki) は `/report` が、技術記録は `/ticket` が、それぞれ別フェーズで担当する。

ACTOR: **AI Auto** (台本生成は完全自動、実際の電話発信と読み上げは人間)
受電 (`受電`) と対称: 受電は人間が **聞く**、完了電話は人間が **話す** — 台本は AI が用意するが、電話口で出るのは人間の声と判断。

---

## §0. 前提

- 入力 1: `data/incidents/<id>/incident__*.json` — `outputs.attack_pattern` / `outputs.attack_subpattern` / `outputs.signals[]` / `outputs.preflight_context` (原因と影響範囲の事実ベース)
- 入力 2: `data/incidents/<id>/review__*.json` — `outputs.comparison[]` (顧客盲点 = `verdict: blindspot` を要 §3 反映) / `outputs.judgment_recommendation.primary` (A/B/C/D) / `outputs.scope_proposal` (in_scope = 実施した措置の元、out_of_scope_logged = §6 ハンドオフメモへ)
- 入力 3: `data/incidents/<id>/report__*.json` — `outputs.templates.customer` / `outputs.completion_mode` (完全完了 / 一次対応完了)。文書のキー結論を口頭サイズに圧縮する
- 入力 4: 受電ヒアリング (`~/Desktop/shirahama_test.md` などの `/incident` 入力 md) — 顧客トーン (不安 / 冷静 / 怒り) と受電時の不安事項 (改ざんでは?・漏えいでは? 等)。ヒアリングが構造化されてなくても緩く解釈してよい
- 出力: stdout に 6 セクション (§2 第一声 / §3 報告本論 / §4 想定 Q&A / §5 NG 言い換え / §6 ハンドオフメモ / §7 JSON 結果サマリ) + JSON 1 ファイル (`data/incidents/<id>/call_close__<ts>.json`)
- 「治しすぎない」哲学 (incident.md §0.6) と整合: out_of_scope_logged の発見は **電話で顧客に積極的に伝えない** (別 incident で扱う)。§6 ハンドオフメモにのみ書く

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
export INCIDENT_ID  # ← emit_skill_json.sh helper に渡すため必須
INCIDENT_DIR="data/incidents/${INCIDENT_ID}"

# 受電 / incident / review / report の各最新 JSON を識別
HEARING_FILE="$(
  for f in ${INCIDENT_DIR}/*.json; do
    [ -f "$f" ] || continue
    if python3 -c "import json,sys; sys.exit(0 if json.load(open('$f')).get('skill')=='hearing' else 1)" 2>/dev/null; then
      stat -f '%m %N' "$f" 2>/dev/null || stat -c '%Y %n' "$f" 2>/dev/null
    fi
  done | sort -rn | head -1 | awk '{print $2}'
)"
INCIDENT_FILE="$(ls -1t ${INCIDENT_DIR}/incident__*.json 2>/dev/null | head -1)"
REVIEW_FILE="$(ls -1t ${INCIDENT_DIR}/review__*.json 2>/dev/null | head -1)"
REPORT_FILE="$(ls -1t ${INCIDENT_DIR}/report__*.json 2>/dev/null | head -1)"

echo "─── /call_close §1 入力 ───"
echo "  incident_id : ${INCIDENT_ID}"
echo "  hearing     : ${HEARING_FILE:-<欠落 — トーン推定が外れる>}"
echo "  incident    : ${INCIDENT_FILE:-<欠落>}"
echo "  review      : ${REVIEW_FILE:-<欠落>}"
echo "  report      : ${REPORT_FILE:-<欠落>}"
```

その後 Claude は **Read ツール**で 4 JSON のみ読む。欠落ファイルがあれば後段 §2-§5 で「(<該当 JSON 不足のため推定)」と注記する。

抽出ルール (§2 以降で使う):
- 受電トーン: ヒアリング原文から「不安 / 冷静 / 怒り」のいずれかを 1 つだけ選ぶ。判定根拠 (引用フレーズ) を保持
- 顧客盲点リスト: review の `comparison[].verdict == "blindspot"` を抽出 (§3 ② で必ず触れる素材)
- 実施措置: review の `scope_proposal.in_scope[].action` をそのまま使う (cookbook 章番号は電話では言わない)
- 完了モード: report の `completion_mode == "complete"` か `"first_response_only"` かで §2 第一声と §3 ③ 現状の文末を切り替える

---

## §2. 出力セクション 1: 第一声テンプレ (受電と対称、クッション必須)

受電台本の第一声 (`電話応対_統合版_120点完成版.md §4-1`) と **対称** に組む。受電は「お電話ありがとうございます」、完了電話は「先ほどご連絡いただいた件で〜」。

[このセクションで Claude は **3 通り** のテンプレを並べる。ヒアリングから推定した受電トーンに応じて 1 番目を「推奨」とマークする。]

```text
─── §2 第一声 (受電と対称、クッション必須) ───

[推奨: <不安 / 冷静 / 怒り> トーン用]

「お世話になっております、白浜の対応窓口の <name> です。
  先ほど <HH:MM> 頃にご連絡いただいた <事象 1 行サマリ> の件、
  現時点での結果がまとまりましたのでお電話差し上げました。
  3 分ほどお時間よろしいでしょうか?」

[代替 1: <別トーン>]
[代替 2: <別トーン>]
```

**3 通りの分岐ルール:**
- 不安トーン (「大丈夫でしょうか?」「漏れてないですか?」が複数回出ているヒアリング) → **クッション 2 段重ね** (「お忙しいところ恐れ入ります」+「ご心配をおかけしておりました件」)。冒頭で「ご安心ください」と言わない (空約束に聞こえる)
- 冷静トーン (淡々とした症状報告) → 上記の標準形でよい。技術担当者向けに **時刻と事象だけ先に**
- 怒りトーン (「なんでこんなことに」「すぐ対応して」が出ているヒアリング) → **「ご迷惑をおかけしました」を先頭に置く**。長い前置きは入れない、3 点報告にすぐ入る

**第一声で言ってはいけないこと (§5 と重複防止):**
- 「もう大丈夫です」 — 結論を先に言わない、3 点報告で根拠を先に出す
- 「攻撃を受けました」 — 「不審なリクエストを観測しました」に置換
- 推定の固有名詞 (顧客の担当者名・社員名) — ヒアリングに書かれていない名前は出さない

**完了モード別の文末:**
- `complete` (報告 JSON `completion_mode == "complete"`) → 「現時点での結果がまとまりましたので」
- `first_response_only` → 「**一次対応** が完了しましたので、現時点の状況をご報告します」

---

## §3. 出力セクション 2: 報告本論 3 点 (① 原因 / ② 顧客の心配事への返答 / ③ 取った措置と現状)

[長くしない。各項目 50-100 字、口頭サイズ。電話で 1 分以内に読み終える分量にする。]

```text
─── §3 報告本論 (3 点で完結。長くしない) ───

① 原因
   <attack_pattern を口頭用に翻訳した 1-2 文。技術名は技術用語の言い換え表 (§5 と
   電話応対_統合版_120点完成版.md §11) を経由>

② 顧客の心配事への返答
   <ヒアリング + review.comparison[verdict=blindspot] を反映した 1-2 文。
   顧客が「改ざんでは?」と心配していたなら、ここで明確に「現時点で改ざんは確認されていません」を
   根拠 (ファイル mtime / 静的差分) と共に伝える>

③ 取った措置と現状
   <review.scope_proposal.in_scope[].action を口頭サイズに圧縮した 1-2 文 +
   現在の運用状態 (正常稼働 / 制限稼働 / 監視継続中)>
```

**3 点ルール:**
- **3 点を超えない** — 4 つ目以降は §6 ハンドオフメモか、Q&A で出てから答える
- **数字を 1 つは入れる** — 「2480 件のリクエスト」「12:10 から 30 分間」「観測時刻 HH:MM」など。経営層向け文書 (`/report` テンプレ 2) と同じ哲学
- **顧客盲点 (review.comparison[].verdict == "blindspot") は ② で必ず触れる** — 例: 顧客が「改ざんされた」と言っていたが ddos/http-flood で改ざんなしのとき、「改ざんは確認されておりません」を根拠付きで明示。曖昧に流すと顧客が後日「改ざんされたのに対応してもらえなかった」と認識する
- **attack_pattern 別の言い回し:**
  - `ddos` → 「特定の IP から短時間に多量のリクエストが集中していました」
  - `dns-tamper` → 「DNS 応答の一部が想定外のものに書き換わっていました」
  - `phishing` → 「弊社を装う不審メールが <件数> 件、外部に送られた疑いがあります」
  - `ransomware` → 「一部ファイルが暗号化されている状態を確認しました」
  - `wp-tamper` → 「公開サイトの一部表示が書き換わっていました」
  - `unknown` → 「原因については現在も調査を継続しております」(推測しない)

例 (DDoS / 161.33.12.212 ケースから):
> ① 原因: 「お昼前後に、特定の 1 つの送信元から 30 分間で 2,480 件のアクセスがまとめて届き、サイトの応答が遅くなる時間帯がありました」
> ② 顧客の心配事への返答: 「ご心配いただいていた改ざんについては、公開ファイルの更新履歴を確認した結果、現時点で書き換わった痕跡は見つかっておりません」
> ③ 取った措置と現状: 「該当の送信元を遮断し、今は通常通りご覧いただける状態です。引き続き同種のアクセスがないか監視を続けます」

---

## §4. 出力セクション 3: 想定 Q&A (最低 4 問 + attack_pattern 別追加)

[電話の後半で顧客から来る追加質問への模範回答。Q ごとに 1-3 行で簡潔に。]

```text
─── §4 顧客から想定される追加質問 + 模範回答 ───

Q1. 「データは漏れていない?」
A1. <漏えい確認の根拠 (どのログを見たか) + 「現時点で確認できる範囲では」のクッション>

Q2. 「いつまで安全?」
A2. <監視継続の期間 + 再発時の連絡経路。「絶対」「100%」は使わない>

Q3. 「再発したらどうなる?」
A3. <観測体制 + 同じ送信元なら自動遮断する旨 + 第一報の所要時間>

Q4. 「報告書はもらえる?」
A4. <文書版 (`/report` のメールテンプレ) は別途送る旨 + 期日 (本日中 / 翌営業日)>
```

**attack_pattern 別の追加 Q (1-2 問):**
- `ddos` → 「うちが標的だった?」(A: 標的型と判断する根拠が現時点でないこと、ジオロケーションや UA を踏まえた所感、ただし断定しない)
- `dns-tamper` → 「他のサイトでも同じことが起きてる?」(A: 自社管理範囲のみ確認済み、外部 DNS は権限外)
- `phishing` → 「他にもメール来てる?」(A: ヒアリング時点で確認できた件数 + 追加情報の収集経路)
- `ransomware` → 「データは戻る?」(A: バックアップからの復元状況。完了モードによって「復元完了」「復元中」「未着手 (一次対応のみ)」を切り替え)
- `wp-tamper` → 「投稿者情報は漏れた?」(A: REST API / xmlrpc の確認結果)
- `unknown` → 「原因は分かった?」(A: 「現時点で確定していない」「追加調査の方針 (ログ保全 / 経過監視)」)

**Q&A の作法:**
- **「分かりません」と言わない** — 「現時点では断定できないため、確認してご報告します」(電話応対 §10 NG 言い換えと同期)
- **「絶対に」「100%」「断言します」を使わない** — 緊急時の専門家言葉として不適切。代わりに「現時点で確認できる範囲では」を必須
- **顧客から具体的な技術用語が飛んできたら** (例: 「ファイアウォールは?」「DNS の TTL は?」) → 「担当から改めてご説明します」で逃げてよい (経営層対応のコツ、`docs/04_完了報告テンプレート.md` テンプレ 2 と同じ)

---

## §5. 出力セクション 4: NG 言い換え (受電台本と同期 + 完了報告版に再構成)

受電台本 §F (= `電話応対_統合版_120点完成版.md §10 NG発言と言い換え`) を完了報告の文脈に再構成する。完了電話特有の NG (例: 「改ざんはありません」と断定) を補う。

```text
─── §5 NG 言い換え ───

❌「攻撃ですね」                    → ⭕「不審なリクエスト連打を観測しました」
❌「サーバが落ちました」              → ⭕「応答が遅くなる時間帯がありました」
❌「改ざんはありません」              → ⭕「公開ファイルの更新履歴を確認した範囲では、書き換えの痕跡は見つかっておりません」
❌「もう絶対大丈夫です」              → ⭕「同種のアクセスを継続して監視しています」
❌「原因は完全に分かりました」          → ⭕「現時点で原因として有力なのは <pattern> です」
❌「漏えいはありません」              → ⭕「現時点で確認できる範囲では、漏えいの痕跡は確認されていません」
❌「すぐ折り返します」                → ⭕「<HH:MM> までに改めてご連絡します」
❌「たぶん直りました」                → ⭕「<HH:MM> に <action> を実施し、正常動作を確認しています」
❌「ご迷惑をおかけし、担当を処分します」  → ⭕「再発防止策を <期日> までにご提案します」
```

**特記:**
- **「改ざんはありません」は完了電話特有の罠** — 顧客が「改ざんされた」と思い込んでいるケース (review.comparison[].verdict == "blindspot") では、断定すると「言い切ったのに後で出てきたら虚偽報告」になる。クッション必須
- **「攻撃」を口頭で使わない** — 法的含意 (犯罪としての攻撃行為) が顧客の経営判断に過剰影響する。技術事実としては「不審なリクエスト」「異常なアクセス」が正確
- 受電台本 §F と差が出てはいけない — 矛盾を見つけた場合は両者を揃える更新を別タスクで上げる

---

## §6. 出力セクション 5: ハンドオフメモ (記録係 → /ticket への引き継ぎ)

[電話直後に記録係が PukiWiki / 引き継ぎテンプレに書く用のメモ。/ticket の入力にもなる。]

```text
─── §6 ハンドオフメモ ───

[今回の電話で言ったこと (要約)]
- 第一声: <HH:MM> に <顧客担当> 様へ架電
- 報告本論: ① <原因 1 行> / ② <顧客盲点への返答 1 行> / ③ <措置 1 行>
- Q&A で実際に出た質問: <なし or 1-N 件>

[フォロー責任者]
- 一次窓口: <name>
- 技術担当: <name or 役割>

[次回アクション]
- <アクション 1: 例「文書版の報告メール送付」期日 <YYYY-MM-DD HH:MM>>
- <アクション 2: 例「24h 監視継続、再発時は即時連絡」>
- <アクション 3: 例「out_of_scope_logged の発見を別 incident で起票」>

[期日]
- 文書版報告: <YYYY-MM-DD HH:MM JST>
- 次回経過連絡: <YYYY-MM-DD HH:MM JST or 「再発時のみ」>
- /ticket 投稿: <本日中 / 大会終了前>
```

**メモの作法:**
- **review.scope_proposal.out_of_scope_logged の発見をここに書く** — 電話では顧客に伝えていないが、記録係には引き継ぐ。「治しすぎない」哲学を運用上維持するため、別 incident として起票する候補リストになる
- **期日は必ず JST 24h** (`memory/timezone_jst_convention.md` 準拠)
- **次回アクションが空にならないようにする** — 完了モード `complete` でも最低 1 件 (文書版送付) は残るはず

---

## §7. JSON 出力 (HTML aggregator 連携 / 共通 helper 経由)

§2-§6 の結果を JSON 化して helper に渡す。helper がメタデータ (skill / incident_id / timestamp / actor) を補完して `data/incidents/${INCIDENT_ID}/call_close__<ts>.json` に保存する。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh call_close
{
  "inputs": {
    "incident_json": "incident__<ts>.json",
    "review_json": "review__<ts>.json",
    "report_json": "report__<ts>.json",
    "hearing_path": "~/Desktop/shirahama_test.md",
    "completion_mode_received": "complete | first_response_only",
    "customer_tone": "不安 | 冷静 | 怒り"
  },
  "outputs": {
    "first_voice": {
      "recommended": "<§2 推奨テンプレ全文>",
      "alternatives": ["<別トーン 1>", "<別トーン 2>"]
    },
    "three_points": {
      "cause": "<§3 ① 1-2 文>",
      "blindspot_response": "<§3 ② 1-2 文 (顧客盲点に対する答え)>",
      "actions_and_status": "<§3 ③ 1-2 文>"
    },
    "qa": [
      {"q": "データは漏れていない?", "a": "<模範回答>"},
      {"q": "いつまで安全?", "a": "<模範回答>"},
      {"q": "再発したら?", "a": "<模範回答>"},
      {"q": "報告書は?", "a": "<模範回答>"},
      {"q": "<attack_pattern 別追加 Q>", "a": "<模範回答>"}
    ],
    "ng_phrases": [
      {"ng": "攻撃ですね", "ok": "不審なリクエスト連打を観測しました"},
      {"ng": "改ざんはありません", "ok": "公開ファイルの更新履歴を確認した範囲では、書き換えの痕跡は見つかっておりません"}
    ],
    "handoff": {
      "primary_owner": "<一次窓口 name>",
      "technical_owner": "<技術担当 name or 役割>",
      "next_actions": [
        {"action": "<次回アクション 1>", "due_jst": "<YYYY-MM-DD HH:MM>"}
      ],
      "deferred_findings": ["<out_of_scope_logged から引き継ぐ発見>"]
    }
  },
  "verdict": {
    "status": "✅ | ⚠️ | 🚨",
    "summary": "<台本生成の状態を 1 行で>"
  },
  "next_skills": ["/ticket"]
}
JSON_EOF
```

helper が補完するメタデータ:
- `skill`: `"call_close"` (ファイル名は `call_close__<ts>.json`)
- `incident_id`: `INCIDENT_ID` env 経由 (= /incident からの伝播)
- `timestamp`: 実行時の ISO 8601 JST (+09:00) — `memory/timezone_jst_convention.md` 準拠
- `actor`: `ai_auto` (台本生成は AI、電話発信は人間)

**verdict.status の決め方:**
- `✅` — 4 入力 (incident / review / report / hearing) すべてあり、§2-§6 すべて生成完了
- `⚠️` — 1-2 入力欠落、該当セクションに「(推定)」注記入りで生成
- `🚨` — incident__*.json または review__*.json 自体が無い → 基礎データ不足、台本を出さず再生成 (= /incident or /review の再実行) を促す

**next_skills は固定:** `["/ticket"]`。完了電話の後は技術記録 (PukiWiki チケット) フェーズへ進む。`/report` は **同列の文書出力** であって後段ではないので入れない。

---

## §8. NG パターン (このスキル自身の自戒)

1. **顧客の名前を fabricate しない** — 受電シートに書かれていない担当者名・社員名を台本に出さない。`<name>` のままにして人間が手で埋める
2. **attack_pattern が `unknown` のときは「原因は調査中」と明記、推測しない** — `/incident §0.6` 触らない哲学と整合
3. **`/report` の文面を逐語コピーしない** — 文書を口頭で読み上げると不自然になる。各文を 50-100 字に圧縮し、リズム (一文 → 一呼吸) を意識
4. **顧客盲点 (review.comparison[].verdict == "blindspot") を曖昧に流さない** — 必ず §3 ② で言及。曖昧化は後日「言わなかった」とトラブル化する
5. **NG 言い換えで「絶対に」「100%」「断言します」を使わない** — 緊急時の専門家言葉として不適切
6. **`docs/recovery_cookbook.md` の章番号を口頭で言わない** — 内部運用語彙を顧客に向けない (§3 ③ の措置説明では cookbook_ref を文章化する)
7. **out_of_scope_logged の発見を電話で積極的に伝えない** — §6 ハンドオフメモには書くが、顧客に「他にも色々ありました」と話さない (「治しすぎない」哲学の電話版)
8. **完了モード `first_response_only` で「対応完了」と言わない** — 「**一次対応**完了」と必ず言う。`/report §3` 完了判定チェックリストの ❌ が 1 つでもあれば `first_response_only` モード
9. **JSON を出さずに stdout だけで終わらせない** — HTML aggregator (`docs/incident_dashboard.html`) が読み込めなくなる。JSON 書き出しは必須

---

## §9. 仕様書接続 + メモリ参照

- 仕様書 `docs/25_システム仕様書.html` §3.x に `/call_close` セクションを追加 (TOC リナンバ込み)。位置は `/report` の直後、`/ticket` の直前
- 仕様書 §4 ワークドエグザンプル T+0:28 (= /report の直後) に /call_close を差し込む
- 仕様書 review タブ判定ダッシュボード (`docs/incident_dashboard.html`) で `call_close__*.json` を 1 カードとして描画 (verdict.status と outputs.three_points を主に表示)
- **上流契約**:
  - `incident.md §4` — `outputs.attack_pattern` / `outputs.signals[]` が §3 ① の素材
  - `review.md §3-§4` — `outputs.comparison[].verdict == "blindspot"` が §3 ② の必須素材、`outputs.scope_proposal.in_scope[]` が §3 ③ の素材、`out_of_scope_logged[]` が §6 deferred_findings の素材
  - `report.md §3` — `completion_mode` が §2 第一声の文末・§3 ③ の現状表現を切り替える
- **下流契約**: `/ticket` が `call_close__*.json` の `outputs.handoff` を読み、PukiWiki マークアップの「対処内容」「関連事項」に反映する
- **横並び (同列)**: `/report` は文書出力、`/call_close` は口頭出力。両者は同じ完了一次連絡フェーズの 2 モードであり、どちらかを省略してはいけない

メモリ参照:
- `memory/system_scope.md` — フロー位置 (T+0:28、/report と /ticket の間)
- `memory/json_output_convention.md` — JSON envelope (skill / incident_id / timestamp / actor / inputs / outputs / verdict / next_skills)
- `memory/timezone_jst_convention.md` — 全時刻 JST 24h
- `memory/review_skill_design.md` — verdict 語彙 (✅ / ⚠️ / 🚨 / blindspot / mismatch) と HTML aggregator 同期ルール
- `memory/html_aggregator_design.md` — `docs/incident_dashboard.html` カード描画
- `memory/preflight_incident_integration.md` — 電話完了後の preflight ベースライン更新は別フェーズ (本スキル管轄外)

---

## 参照

- `docs/04_完了報告テンプレート.md` — 文書版テンプレ集 (本スキルとは目的が違うが、テンプレ 1 = 顧客担当者向け短文 と語彙を揃える)
- `電話応対_統合版_120点完成版.md` §4-6 / §9-3 / §10 / §11 — 復旧報告 + NG 言い換え + 技術用語の言い換え。本スキルの §3 / §5 と同期する
- `受電台本.html` — 受電 (intake) の台本。本スキルは closure として対称構造を取る
- `docs/recovery_cookbook.md` — 措置の根拠資料 (本スキルは AI が Read しない、章番号も口頭で言わない)
- `.claude/commands/incident.md` — 上流のトリアージ
- `.claude/commands/review.md` — 顧客盲点と in_scope の根拠を提供
- `.claude/commands/report.md` — 文書版完了報告 (横並び、同列フェーズ)
- `.claude/commands/ticket.md` — 下流の技術記録フェーズ
- `docs/incident_dashboard.html` — JSON を集約表示する HTML aggregator

---

## §11. 次に打つコマンド (案内)

```text
─── 次のステップ ───
  1. 顧客に折返し電話 (この台本を読み上げ、人間操作)
  2. /ticket                  ← PukiWiki トラブルチケット 生成
  3. ⏹ ブラウザ補助セクションで「インシデント完了」ボタン
  4. 次のインシデント来たら /new_incident <時刻> <host>
```
