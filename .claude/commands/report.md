---
model: claude-haiku-4-5
description: トリアージ出力 (shirahama_test.md 等) を読み込んで 04_完了報告テンプレート.md の各テンプレを実データで自動充填する
---

# /report — 完了報告書ドラフト自動生成

引数: `[<triage-report-path>]`
省略時: `~/Desktop/shirahama_test.md`

例:
- `/report` (デフォルトパス)
- `/report ~/Desktop/incident_2026-05-04.md`

## このスキルが解決する問題

`/incident` は §6 SOC summary で停止する。そこから先 (顧客・経営層・ユーザ への完了報告) は手で 04 テンプレに転記していた。本スキルは **トリアージ報告 → 04 テンプレ全種類埋め** を自動化する。

JPCERT インシデントハンドリング 4 段階のうち **2.4 報告/情報公開** をカバー。**2.3 レスポンス (実対応)** は別 (03 playbook を人間が実施)。

---

## §0. 前提

- 入力 1 (**第一優先、必須**): `data/incidents/<id>/review__*.json` — `outputs.impact_assessment` (時刻・影響資産・横展開・漏洩・customer_facing_summary) を読み、メール本文に「○時○分から○時○分まで○○が発生」を **必ず** 書く
- 入力 2 (必須): `data/incidents/<id>/` の **任意ファイル名 + `"skill": "hearing"`** の JSON — 顧客名・組織・受電パターン・トーン・自由記述
- 入力 3 (任意): `~/Desktop/shirahama_test.md` 同等の Markdown (旧フロー互換、上記 JSON が無い場合のフォールバックのみ)
- 出力は **画面表示のみ** (ファイルには書き込まない、Claude が画面で各テンプレを並べる) + JSON 1 ファイル (`data/incidents/<id>/report__<ts>.json`)
- 04 テンプレートの **完了判定チェックリスト** に照らし、欠けている項目があれば「一次対応完了」テンプレに切り替える

**被害範囲を必ず書く根拠**: 旧 /check + /playbook を凍結したため、被害範囲確定の責任は /review §2.6 に集約された。/report はそれを **必ず** メール文面に展開する責任がある。「いつから」「いつまで」「何が」「どこまで」の 4 軸を欠いた完了報告は受領を拒否する。

---


**本番環境前提 (必読)**: 本 skill を呼ぶ前に必ず `docs/booth1_production.md` を Read ツールで読む。Booth1 (com1.local) のネットワーク構成 / 認証情報 / OS 差分 / 触禁機器 / DHCP 配布範囲 / CIC DNS 関係 / 既侵害前提などの本番固有情報をすべて踏まえてから判断・コマンド生成する。
本番接続前に必ず Read。

## §1. 入力読み込み

```bash
SHIRAHAMA_DIR="${SHIRAHAMA_DIR:-/Users/ryu/Desktop/shirahama}"
INCIDENT_ID="${1:-}"
cd "$SHIRAHAMA_DIR"

# incident_id 自動検出 (引数省略時)
if [ -z "$INCIDENT_ID" ]; then
    if [ -f "data/incidents/.current_id" ]; then
        INCIDENT_ID="$(cat data/incidents/.current_id)"
    fi
    [ -z "$INCIDENT_ID" ] && INCIDENT_ID="$(ls -1t data/incidents/ 2>/dev/null | grep -v '^\.' | head -1)"
fi
export INCIDENT_ID  # ← emit_skill_json.sh helper に渡すため必須 (export 漏れ = _unscoped 配下に書かれるバグの原因)
INCIDENT_DIR="data/incidents/${INCIDENT_ID}"

REVIEW_FILE="$(ls -1t ${INCIDENT_DIR}/review__*.json 2>/dev/null | head -1)"
# 受電 JSON はファイル名問わず "skill": "hearing" で識別
HEARING_FILE="$(
  for f in ${INCIDENT_DIR}/*.json; do
    [ -f "$f" ] || continue
    if python3 -c "import json,sys; sys.exit(0 if json.load(open('$f')).get('skill')=='hearing' else 1)" 2>/dev/null; then
      stat -f '%m %N' "$f" 2>/dev/null || stat -c '%Y %n' "$f" 2>/dev/null
    fi
  done | sort -rn | head -1 | awk '{print $2}'
)"
INCIDENT_FILE="$(ls -1t ${INCIDENT_DIR}/incident__*.json 2>/dev/null | head -1)"
# 旧フロー互換 (markdown フォールバック)
LEGACY_PATH="${2:-$HOME/Desktop/shirahama_test.md}"

if [ -z "$REVIEW_FILE" ] && [ ! -f "$LEGACY_PATH" ]; then
    echo "❌ review__*.json が無く、legacy markdown も無い: ${INCIDENT_DIR}/"
    echo "   /review を先に実行するか、引数でトリアージ md パスを指定してください"
    exit 1
fi

echo "─── /report §1 入力 ───"
echo "  incident_id   : ${INCIDENT_ID}"
echo "  review JSON   : ${REVIEW_FILE:-<未生成、legacy md fallback>}"
echo "  hearing JSON  : ${HEARING_FILE:-<未投入>} (任意ファイル名、skill=hearing で識別)"
echo "  incident JSON : ${INCIDENT_FILE:-<未生成>}"
echo "  legacy md     : ${LEGACY_PATH} ($([ -f "$LEGACY_PATH" ] && wc -l < "$LEGACY_PATH" || echo 0) 行) [fallback]"
echo "  template      : $SHIRAHAMA_DIR/docs/04_完了報告テンプレート.md"
```

その後 Claude は **以下を Read ツールで読む** (上から優先):
1. `$REVIEW_FILE` (**最優先**) — `outputs.impact_assessment.{window, affected_assets, lateral_movement, exfiltration, customer_facing_summary}` をそのままメール本文に展開
2. `$HEARING_FILE` — 顧客名 / 組織 / 受電パターン / トーン (メールの宛名・口調)
3. `$INCIDENT_FILE` — attack_pattern / signals (技術詳細)
4. `$SHIRAHAMA_DIR/docs/04_完了報告テンプレート.md` (テンプレ集)
5. (上記 1 が無いとき) `$LEGACY_PATH` (旧 markdown 互換)

**メール本文必須要素 (review.outputs.impact_assessment から):**
- 「○時○分から○時○分まで」 ← `window.start_jst` / `window.end_jst` / `window.duration_minutes`
- 「○○ という事象が発生」 ← `customer_facing_summary` の主語句 (中立語に整形済)
- 「対象は ○○」 ← `affected_assets[].asset` を列挙
- 「他への影響: 横展開なし / データ漏洩なし」 ← `lateral_movement.detected` + `exfiltration.detected`

**もう 1 つの必須要素: 「確認できたこと」「確認できなかったこと」を明示分離**

報告書には常に **2 つのリスト**を付ける (受電内容と /review §2.5 + §2.6 から導出):

1. **✅ 確認できたこと (verified findings)**
   - `review.outputs.action_proposals.confirmed_findings[]` (= [A] バケット) を全件列挙
   - `review.outputs.impact_assessment` で `detected: false` + `evidence` がある項目 (例: 横展開なし、改ざんなし) も列挙
   - 各項目に **どうやって確認したか** (出典: §2.5 #N) を必ず付ける
   - 例: 「✅ Web ページの書き換えは無し (`/var/www` 配下 PHP ファイルが過去 120 分以内に変更ゼロ、§2.5 #1)」

2. **❓ 確認できなかったこと (limitations / open items)**
   - `review.outputs.action_proposals.verification_needed[]` (= [B] バケット) を全件列挙
   - `review.outputs.impact_assessment.exfiltration.evidence` などで「確認できず」「確証なし」と書かれた項目
   - 各項目に **なぜ確認できないか** + **どうすれば確認できるか** を付ける
   - 例: 「❓ WP 管理画面ログイン試行の有無 — wp-login.php のアクセスログ保管期間が 7 日のため 5/2 以前の試行は確認不能。今後 90 日保管に拡張」

**書き分けの理由**: 顧客は「全部確認しました」と言われると逆に不安になる (それが本当なら何故攻撃された?)。「ここまでは確認できた、ここから先は技術的限界で見えない」と正直に書くほうが信頼される。CSIRT の鉄則。

---

## §2. 事実抽出 (Claude が実施)

トリアージ報告から以下を構造化して抽出する。**書かれていない項目は推測せず「(報告書記載なし)」と明記**。

| 抽出項目 | shirahama_test.md での出所 | 抽出方針 |
|---|---|---|
| 受電日時 | §1 受電情報 / 報告書冒頭の日時 | JST 表記に統一 (UTC なら +9h) |
| 通報内容 | §1 通報内容 | 「自発的検証」なら「定期監視で検知」と書き換えてよい (大会本番想定なら) |
| 影響ホスト | §1 影響ホスト, §2 標的 | victor / bravo / 両方 |
| 攻撃者 IP | §2.1 攻撃者 IP 特定 | 攻撃元のみ抽出。本人/管理者 IP は除外 |
| 攻撃時間窓 | §1 時間窓 / §2.2 時系列 | UTC → JST 変換、開始-終了時刻 |
| 攻撃手法 | §2.2 時系列の「内容」列 | "wp-login brute", "IMAP PLAIN brute" 等の自然文 |
| 突破ステータス | §7 突破ステータス | ✅ 未遂 / 🚨 突破確認 / ⚠️ 不明 |
| 影響範囲 (情報) | §7 + §6 統合解釈 | 漏えい確認の有無、根拠ログ |
| 影響範囲 (サービス) | (報告書に明示なければ「停止なし」) | 停止時間 / 影響利用者数 |
| 実施した対応 | §8 推奨封じ手 (リーダー承認後と書かれている分) | 「実施済」「未実施 (承認待ち)」を明確に分ける |
| 残タスク | §8 + §9 改善課題 | 短期 (本日中) / 中期 (今週) で分類 |
| 副次発見 | §5 追加発見 (toor / 777 home 等) | 「触らない」案件として残す |

---

## §3. 完了判定チェックリスト評価

04 テンプレの 18-30 行目のチェックリストを以下のロジックで埋める:

| 項目 | 判定方法 |
|---|---|
| 直接原因が特定できた | 攻撃者 IP + 攻撃手法 が抽出できれば ✅ |
| 拡大・再発しない状態 (封じ込め完了) | §8 の封じ手が **実施済** なら ✅、「リーダー承認後」止まりなら ❌ |
| 影響範囲が確定 | §7 突破ステータス全経路に判定が付いてれば ✅ |
| サービスが正常稼働 | 停止していなければ ✅、停止していて再開記載があれば ✅ |
| 残タスクが整理 | §8 §9 に列挙があれば ✅ |
| 追加質問への準備 | チェックリスト的に常に △ (人間判断) として表示 |
| 記録 | 入力ファイルが存在すれば ✅ |

❌ が **1 つでもあれば**「**一次対応完了**」モードに切替 → 04 テンプレ最後の「一次対応完了」テンプレ ([04:211-233](docs/04_完了報告テンプレート.md#L211-L233)) を採用。
全 ✅ なら通常完了モード → テンプレ 1〜5 を採用。

判定結果を最初に表で表示:

```
─── /report §3 完了判定 ───
モード: ✅ 完全完了 / ⚠️ 一次対応完了

[✅ or ❌] 直接原因特定
[✅ or ❌] 拡大・再発しない状態
...
```

---

## §4. テンプレ出力

完了判定の結果に応じて、以下を **画面に順番に出力**。各テンプレはコードブロックで囲み、コピペしやすくする。

### 4.1 完全完了モードの場合

順番に下記を出す:

1. **テンプレ 1: 顧客担当者向け (電話・短文)** — [04:34-64](docs/04_完了報告テンプレート.md#L34-L64) を実データで埋める
2. **テンプレ 2: 顧客経営層向け (電話・要点のみ)** — [04:68-91](docs/04_完了報告テンプレート.md#L68-L91)
3. **テンプレ 3: 一般ユーザ向け (電話)** — [04:102-120](docs/04_完了報告テンプレート.md#L102-L120) ※今回ユーザ影響がなければスキップして「該当なし」と表示
4. **テンプレ 4: 外部第三者通報者向け** — [04:131-146](docs/04_完了報告テンプレート.md#L131-L146) ※外部通報起点でなければスキップ
5. **テンプレ 5: メール (顧客担当者向け正式記録)** — [04:156-207](docs/04_完了報告テンプレート.md#L156-L207)

### 4.2 一次対応完了モードの場合

1. **「一次対応完了」テンプレ** — [04:211-233](docs/04_完了報告テンプレート.md#L211-L233) を実データで埋める
2. **継続中の作業リスト** — §8 の「リーダー承認後」項目を全部書き出す
3. **次回ご報告時刻** — 現在時刻 + 30 分を提案 (Claude 判断、根拠も書く)
4. (経営層/ユーザ向けは省略 — 一次対応では出さない方針)

### 4.3 共通の充填ルール

- 時刻は **必ず JST + 24 時制** で記載 (例: `2026-05-03 23:37`)
- 「現時点で確認できる範囲では」を**未確認項目に必ず添える** ([04:248-254](docs/04_完了報告テンプレート.md#L248-L254) NG リスト準拠)
- 「もう絶対に大丈夫です」「原因は完全に分かりました」は**禁止語** — もし候補に出たら自動で書き換え
- 経営層向けは **300 字以内** に収める。技術詳細は「担当から改めて」で逃げる
- ユーザ向けは **技術用語禁止** (PLAIN→「暗号化されてない通信」、IMAP→「メールの受信」等)
- メール件名は `【ご報告】<日付> <事象分類> 対応<完了/一次対応完了>のご連絡` の形式

---

## §5. 報告書ドラフト末尾の追記 (任意)

最後に Claude は以下を聞く:

```
─── /report §5 ───
このドラフトを <REPORT_PATH> の末尾に「## 完了報告ドラフト (生成: <現在時刻 JST>)」セクションとして
追記しますか？ (yes / no)
```

`yes` なら、§4 の出力をそのまま `>>` で追記。`no` なら表示のみで終了。

---

## §6. 報告先別の補足ガイド (大会本番想定)

[16_本番環境クイックリファレンス_whiskey.md](docs/16_本番環境クイックリファレンス_whiskey.md) から取得:

- 報告先 PukiWiki: `http://133.42.49.140/trouble_ticket_137/index.php` (whiskey / E5mA9cF3)
  → テンプレ 5 (メール正式記録) の本文を貼り付け
- 電話応対係には テンプレ 1〜3 をホワイトボードに掲示
- リーダーには **判定モード (完全完了 / 一次対応完了)** + **完了判定チェックリストの ❌ 項目** を口頭で先に伝える

---

## §7. NG パターン (このスキル自身の自戒)

- 入力ファイルに書かれていない事実を捏造しない (例: 「漏えいなし」を断定的に書く)
- 「攻撃元 IP のジオロケーションは US Akamai」のような外部 lookup を**勝手にしない** — トリアージ報告に書かれていなければ「(IP 素性は要確認)」と明記
- §0.6「触らない」哲学 (incident.md) と整合: **報告書に「対策コマンド実行済」と書く前に、リーダー承認の有無を必ず確認**
- 経営層向けで `🚨` `✅` 等の絵文字は使わない (公式文書なので)
- ユーザ向けで攻撃者 IP やドメイン名を**生で書かない**
- **`verified_findings` / `unverified_findings` を JSON output から省略しない** — §0 で必須化した。空でも空 array `[]` で出す。「全部確認できた」または「何も書かない」は両方 NG。`verified` が出ても `unverified` を併記する (CSIRT の鉄則: 限界の正直な開示)

---

## §8. JSON 出力 (HTML aggregator 連携 / 共通 helper 経由)

5 種テンプレ + 完了判定チェックリストを JSON 化して helper に渡す。actor は `ai_human` (AI 生成 → 人間最終確認 + 顧客送信)。

```bash
cat <<'JSON_EOF' | scripts/emit_skill_json.sh report --actor ai_human
{
  "inputs": {
    "triage_report_path": "~/Desktop/shirahama_test.md",
    "template_path": "docs/04_完了報告テンプレート.md"
  },
  "outputs": {
    "completion_mode": "complete | first_response_only",
    "checklist": {
      "事象概要": true, "影響範囲": true, "原因": true,
      "対応内容": true, "再発防止": false, "完了確認": false,
      "リーダー承認": true
    },
    "templates": {
      "customer": "顧客担当者向け文面 ...",
      "executive": "経営層向け 300 字 ...",
      "users": "ユーザ向け注意喚起 ...",
      "external": "外部通報元向け ...",
      "email_subject_body": "件名 + 本文"
    },
    "verified_findings": [
      {"id": "V-1", "fact": "Web ページ書き換えは無し", "evidence": "/var/www 配下 PHP ファイル過去 120 分以内変更ゼロ", "source": "review §2.5 #1"},
      {"id": "V-2", "fact": "SEO スパム本体は無し", "evidence": "WordPress トップページ HTML に casino/viagra 等のキーワードゼロ", "source": "review §2.5 #2"},
      {"id": "V-3", "fact": "WordPress siteurl=168.138.42.63 (OCI 生 IP の設定ミス) が顧客誤認の原因", "evidence": "wp_options siteurl/home 確認", "source": "review §2.5 #2/#5"},
      {"id": "V-4", "fact": "横展開無し (bravo への攻撃シグナル無し)", "evidence": "incident.signals は victor:80 のみ", "source": "review impact_assessment.lateral_movement"},
      {"id": "V-5", "fact": "blocklist.conf 適用済 (15:42:27)", "evidence": "httpd reload 確認 + Syntax OK", "source": "review §2.5 #5/#6"}
    ],
    "unverified_findings": [
      {"id": "U-1", "axis": "blocklist の遮断実績", "limitation": "攻撃が 12:12 に自然収束したため reload 後 (15:42) の同 IP 再アクセスが無く実効性は直接確認できなかった", "next_step": "攻撃者再試行時 / 想定: OCI NSG で恒久遮断"},
      {"id": "U-2", "axis": "WP 管理画面ログイン試行の有無", "limitation": "wp-login.php 専用ログの保管期間が短く 5/2 以前の試行は確認不能", "next_step": "アクセスログ保管期間を 90 日に拡張、念のため [D-1] で WP admin パスワード変更を依頼"},
      {"id": "U-3", "axis": "5/2-5/4 の他ホスト対する攻撃の有無", "limitation": "bravo の access_log は調査範囲外", "next_step": "中期 (今週中) に bravo 側ログを横展開有無として追加調査"}
    ],
    "remaining_items": ["再発防止策の確定 (OCI NSG 設定)", "完了確認の実施 ([D-1] 顧客 WP admin パスワード変更確認、[B-1][B-2] 顧客回答待ち)"]
  },
  "verdict": {
    "status": "✅ | ⚠️ | info",
    "summary": "完全完了 / 一次対応完了 / ドラフトのみ"
  },
  "next_skills": ["/ticket"]
}
JSON_EOF
```

helper が補完するメタデータ:
- `skill`: `"report"`
- `incident_id`: `INCIDENT_ID` env (= /incident からの伝播)
- `timestamp`: 実行時 ISO 8601 UTC
- `actor`: `ai_human` (AI 生成 → 人間が文面確認・送信)

保存先: `data/incidents/${INCIDENT_ID}/report__<ts>.json`

`completion_mode` の決め方 (§3 完了判定チェックリスト連動):
- 7 項目すべて true → `complete` (5 種テンプレすべて出す)
- 一部 false → `first_response_only` (顧客向け 1 種 + 残作業リスト)

---

## 参照

- `docs/04_完了報告テンプレート.md` — 充填対象
- `docs/03_シナリオ別対応プレイブック.md` — 「対応 (実施)」フェーズ。本スキルは扱わない
- `docs/05_全体チェックシート.md` — Phase 0-6 通し管理。本スキルは Phase 5-6 をカバー
- `.claude/commands/incident.md` — 上流のトリアージ。本スキルの入力を生成する
- `docs/incident_dashboard.html` — JSON を集約表示する HTML aggregator

---

## §10. 次に打つコマンド (案内)

```text
─── 次のステップ ───
  /call_close                 ← 顧客への電話台本 (第一声 / 報告本論 / 想定 Q&A / NG 言い換え)
  ↓
  /ticket                     ← PukiWiki トラブルチケット
  ↓
  ⏹ ブラウザ補助セクションで「インシデント完了」ボタン
```
