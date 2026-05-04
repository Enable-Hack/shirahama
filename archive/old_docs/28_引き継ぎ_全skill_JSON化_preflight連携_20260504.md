# 28. 次セッション引き継ぎ — 全 skill JSON 化 + /preflight ↔ /incident 連携 (2026-05-04 作成)

## 使い方

次回 Claude Code セッションで「下記プロンプト」をそのまま貼り付ける → 7 タスク (A → G) を順に実施できる。
このファイル自体が引き継ぎチャットの本体。

doc 27 完了後の積み残し対応。本番 5/5 前にやれると盤石、本番後の整備でも可。

---

## ▼ ここから次セッション貼り付け用プロンプト ▼

```
shirahama プロジェクトで全 skill の JSON 出力統一 + /preflight と /incident の自動連携を 7 タスクこなしてほしい。

# 前提（前セッション 5/3-5/4 で確立済み）

## 設計哲学

1. analyzer / Mock / Claude → 全部見つける（漏れ防止）
2. 判定 A/B/C/D → 人間が選別（HTML 仕様書 §2.1.2）
3. /playbook の mutation コマンドは settings.production.json deny で物理的に AI 実行禁止
4. 「触らない哲学」+「治しすぎない」: lab は意図的に過剰 seed (約 18 件)。受電と関係ない発見は記録のみ
5. 攻撃はチームの進捗に追従する想定 — 全部塞ぐと逆効果
6. 全 skill 出力は data/incidents/<id>/*.json に永続化、HTML dashboard が集約表示

## 実装済み（doc 26, 27 で完了）

- /incident §1〜§7 完走可能 (anthropic 0.97.0 in pyenv 3.12.6 / SHIRAHAMA_PY env で解決)
- 35 本の /check + 3 本の /scenario + 5 本の /playbook + /preflight + /review + /report + /ticket
- agent/cmd_validator.py (shell コマンド検証ゲート)
- settings.production.json — 封じ込め + 復旧コマンドを deny に
- /incident §2 で maillog/secure/named/auth に時間窓フィルタ
- 5 つの playbook §6 を ```text フェンス + 「人間実行のみ」注記
- /review skill (ヒアリング ↔ ログ突合 + A/B/C/D 推奨 + 「治しすぎない」スコープ提案)
- docs/incident_dashboard.html (data/incidents/*.json を fetch して時系列表示)
- /incident /review /report は JSON 出力済 (data/incidents/<id>/*.json)

## 残課題（このセッションで直す）

- **/check × 35 / /playbook × 5 / /scenario × 3 / /ticket / /preflight が JSON 未出力**
  → dashboard で受電全体像が見えない、/review が過去 check を再利用できない
- **/preflight と /incident が切れてる**
  → /incident.md §0 に preflight 参照ゼロ、preflight が見つけた直前異常 (例: /etc 配下 1h 以内更新) を analyzer が知らない
- 全 skill で JSON emit を inline で書くと重複が大きい
  → 共通 helper script で集約すべき

# 必読 (タスク開始前、上から順に)

- memory/MEMORY.md (auto-memory index)
- memory/json_output_convention.md (doc 27 で確立した JSON スキーマ)
- memory/html_aggregator_design.md (dashboard のデータソース要件)
- docs/27_引き継ぎ_復旧人間化_review_JSON集約_20260503.md §タスク D (JSON 規約の元)
- .claude/commands/incident.md §最終 (既存 JSON emit の書き方)
- .claude/commands/review.md (もう一つの既存 JSON emit)
- .claude/commands/preflight.md (連携対象)
- docs/incident_dashboard.html (fetch 対象、JSON フィールド名と整合させる必要)

# 設計原則

- JSON スキーマは doc 27 で決めた共通形式を踏襲:

  {
    "skill": "<skill_name>",
    "incident_id": "<YYYY-MM-DD_HH:MM_<host>>",
    "timestamp": "<ISO 8601 UTC>",
    "actor": "ai_auto" | "ai_human" | "human_only",
    "inputs": { ... skill 固有 ... },
    "outputs": { ... skill 固有 ... },
    "verdict": {
      "status": "🚨" | "⚠️" | "✅" | "info",
      "summary": "<1-2 行の人間向け要約>"
    },
    "next_skills": ["<推奨次手順>"]
  }

- 保存先: `data/incidents/<incident_id>/<skill_name>__<timestamp>.json`
- 既存の incident/review/report の JSON 出力構造は変えない、helper を介すよう refactor のみ
- /preflight は /incident と独立して動けるが、結果を /tmp/preflight_state.json に常時書き出して /incident が拾える形にする

# タスク A: scripts/emit_skill_json.sh 共通 helper 作成 (30 分)

## A-1. 役割

- stdin から skill 固有の JSON を受け取る
- メタデータ (skill / incident_id / timestamp / actor) を自動補完して wrap
- data/incidents/<incident_id>/<skill>__<ts>.json に保存
- 各 skill の md ファイルからは 4-5 行の bash でこれを呼ぶだけで済むように

## A-2. インターフェース

  scripts/emit_skill_json.sh <skill_name> [--actor <actor>] [--incident-id <id>]

  stdin: skill 固有の JSON (verdict, inputs, outputs, next_skills 等を含む)
  stdout: 保存したファイルパス
  exit: 0 = 成功 / 1 = JSON 不正 / 2 = 引数不正

## A-3. incident_id の解決順

1. `--incident-id` で明示指定 (最優先)
2. 環境変数 `INCIDENT_ID`
3. 自動生成: `${TODAY_UTC}_${WINDOW_START}_${HOST}` の組み合わせ
   - WINDOW_START / HOST は env から取る、無ければ "unknown"
   - 完全に未指定なら `${TODAY_UTC}T${HMS}_unscoped`

## A-4. 実装スケルトン (bash)

  #!/bin/bash
  set -euo pipefail
  
  SKILL_NAME="${1:?usage: emit_skill_json.sh <skill_name> [--actor X] [--incident-id Y]}"
  shift
  
  ACTOR="ai_auto"
  INCIDENT_ID=""
  while [ $# -gt 0 ]; do
    case "$1" in
      --actor) ACTOR="$2"; shift 2 ;;
      --incident-id) INCIDENT_ID="$2"; shift 2 ;;
      *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
  done
  
  : "${INCIDENT_ID:=${INCIDENT_ID_ENV:-${WINDOW_START:+$(date -u +%Y-%m-%d)_${WINDOW_START}_${HOST:-unknown}}}}"
  : "${INCIDENT_ID:=$(date -u +%Y-%m-%dT%H%M%S)_unscoped}"
  
  TS="$(date -u +%Y%m%dT%H%M%SZ)"
  DIR="data/incidents/${INCIDENT_ID}"
  mkdir -p "$DIR"
  OUT="${DIR}/${SKILL_NAME}__${TS}.json"
  
  # stdin の JSON を読んで wrap
  STDIN_JSON="$(cat)"
  
  # jq で metadata を merge (jq があれば)
  if command -v jq >/dev/null 2>&1; then
    jq -n \
      --arg skill "$SKILL_NAME" \
      --arg id "$INCIDENT_ID" \
      --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
      --arg actor "$ACTOR" \
      --argjson body "$STDIN_JSON" \
      '{skill:$skill, incident_id:$id, timestamp:$ts, actor:$actor} + $body' \
      > "$OUT"
  else
    # fallback: jq なし環境（本番では jq ありの想定）
    cat <<EOF > "$OUT"
  { "skill": "${SKILL_NAME}", "incident_id": "${INCIDENT_ID}", "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)", "actor": "${ACTOR}", "_warning": "jq 不在のため skill 固有 JSON は別ファイル parse 必要", "_raw": $(echo "$STDIN_JSON" | python3 -c "import json,sys; print(json.dumps(sys.stdin.read()))") }
  EOF
  fi
  
  echo "$OUT"

## A-5. smoke test

  echo '{"verdict":{"status":"🚨","summary":"test"},"outputs":{"foo":"bar"}}' \
    | scripts/emit_skill_json.sh test-skill --actor ai_auto --incident-id smoke_test
  
  cat data/incidents/smoke_test/test-skill__*.json
  # → metadata + body が merge されてること、ファイル名が正しいことを確認

# タスク B: /preflight の JSON 出力対応 (15 分)

## B-1. 役割

/preflight は現状 stdout のみ。下記 2 形式を常時生成するよう改修:

1. **/tmp/preflight_state.json** — 最新の状態。/incident.md §0 が読む
2. **data/incidents/<id>/preflight__<ts>.json** — incident と紐づく永続記録 (incident_id が判明している場合)

## B-2. JSON スキーマ (preflight 固有)

  {
    "skill": "preflight",
    "incident_id": "<id>",
    "timestamp": "<ISO 8601>",
    "actor": "ai_auto",
    "inputs": {
      "target": "both" | "victor" | "bravo",
      "mode": "full" | "brief" | "baseline" | "diff"
    },
    "outputs": {
      "victor": {
        "ping_ms": 1.2,
        "services": {"httpd":"active", "dovecot":"active", ...},
        "listen_ports": [22, 25, 80, ...],
        "etc_changed_recently": ["/etc/named.conf", ...],
        "load_avg": 0.5,
        "last_logins": [...],
        "anomalies": [
          {"severity":"🚨","kind":"service_down","detail":"named INACTIVE"},
          {"severity":"⚠️","kind":"recent_etc_change","detail":"/etc/named.conf modified 30 min ago"}
        ]
      },
      "bravo": { ... 同形式 ... }
    },
    "verdict": {
      "status": "🚨" | "⚠️" | "✅",
      "summary": "anomalies 集計の 1 行"
    },
    "next_skills": ["/incident <window> <host>"]
  }

## B-3. preflight.md の改修箇所

§3 (出力フォーマット) の後に新規 §4 として「JSON 永続化」セクション追加:

  ## 4. JSON 永続化（HTML dashboard 連携）

  ```bash
  # /tmp/preflight_state.json に常時書き出す（/incident §0 が読む）
  cat <<JSON_EOF | tee /tmp/preflight_state.json | scripts/emit_skill_json.sh preflight
  {
    "inputs": { "target": "$TARGET", "mode": "$MODE" },
    "outputs": { ...上の §1〜§3 の結果を Claude が JSON 化... },
    "verdict": {
      "status": "...",
      "summary": "..."
    },
    "next_skills": ["..."]
  }
  JSON_EOF
  ```

  - /tmp/preflight_state.json は incident_id 不明な状態でも書く（最新 1 件のみ保持）
  - data/incidents/<id>/preflight__*.json は INCIDENT_ID env が設定されているとき (= /incident からの呼び出し時) のみ生成

# タスク C: /incident.md §0 に /preflight 自動取り込み (15 分)

## C-1. 追加箇所

incident.md §0 (本番環境定数) と §0.5 (既侵害前提) の間に新規 §0.4 として挿入:

  ## §0.4 /preflight 直前状態の取り込み

  受電直後に /preflight が走っている場合、直前の異常を analyzer 判断材料として読み込む。

  ```bash
  if [ -f /tmp/preflight_state.json ]; then
      echo "─── /preflight 直前状態 (参考) ───"
      jq -r '.outputs | to_entries[] |
             "  [\(.key)]" ,
             ( .value.anomalies // []
               | .[] | "    \(.severity) \(.kind): \(.detail)" )' \
          /tmp/preflight_state.json
      echo ""
      # /etc 配下に直近変更があれば §3 analyzer の結果に手動でブースト
      ETC_CHANGES="$(jq -r '.outputs[] | .etc_changed_recently[]' /tmp/preflight_state.json 2>/dev/null | sort -u)"
      if [ -n "$ETC_CHANGES" ]; then
          echo "  ⚠️ 直近 1h で /etc 配下に変更があります:"
          echo "$ETC_CHANGES" | sed 's/^/    /'
          echo "  → §4 Claude 推論時に「改ざんの可能性」として渡す"
      fi
  else
      echo "─── /preflight 未実行 (推奨: /preflight 後に /incident) ───"
  fi
  ```

## C-2. §4 Claude 推論への文脈追加

§4 の python script (Mock + Claude 集約) で、preflight 異常を Claude に渡す:

  PREFLIGHT_CONTEXT=""
  if [ -f /tmp/preflight_state.json ]; then
      PREFLIGHT_CONTEXT="$(jq -c '.outputs' /tmp/preflight_state.json)"
  fi
  export PREFLIGHT_CONTEXT
  
  PYTHONPATH=. ${SHIRAHAMA_PY:-python3} -c "
  import os, json
  ...
  preflight_ctx = json.loads(os.environ.get('PREFLIGHT_CONTEXT', '{}'))
  # ClaudeBackend.propose_patches に preflight 異常を context として渡す
  # (要 ClaudeBackend.propose_patches シグネチャ拡張、または prompts.py のテンプレで参照)
  "

agent/backends/claude_backend.py の propose_patches メソッドに `preflight_context` 引数を追加。
受電直後の状態が「サービス落ちてる」「/etc 直近変更」を Claude プロンプトに含める。

# タスク D: /check × 35 に JSON emit を追加 (1 時間)

## D-1. 追加位置

各 .claude/commands/check/check-*.md の末尾 (§5 報告書テンプレ生成指示の後) に新規 §6 として追加:

  ## 6. JSON 永続化（HTML dashboard 連携）

  調査が完了したら、判定結果を JSON で出力し helper に渡す:

  ```bash
  cat <<'JSON_EOF' | scripts/emit_skill_json.sh check-<this-check-name>
  {
    "inputs": {
      "target_host": "victor" | "bravo" | "both",
      "known_ips": ["..."]
    },
    "outputs": {
      "patterns_matched": [
        {"id": "A", "label": "...", "verdict": "🚨" | "⚠️" | "❌"},
        ...
      ],
      "evidence": ["<ログ抜粋 1>", "<ログ抜粋 2>"]
    },
    "verdict": {
      "status": "🚨" | "⚠️" | "✅",
      "summary": "<§4 で出した判定 1-2 行を再掲>"
    },
    "next_skills": ["/playbook:..." または "/check:..."]
  }
  JSON_EOF
  ```

  - verdict.status は §4 の判定セクションと一致させる
  - patterns_matched は §3 の判定テーブル (A〜F 等) を JSON 化
  - evidence は §1 で取得した実ログから 2-3 行の重要なものを抜粋

## D-2. 一括追加方針

35 ファイル全部に同じパターンで挿入する。手順:

1. 1 本目 (例: check-known-attacker-ip.md) で template を完成させる
2. 各 check の固有部分 (skill_name / patterns_matched の構造) を check ごとに調整
3. 共通テンプレを残り 34 本に sed/手動で挿入
4. 各 check の §3 判定テーブル (パターン A/B/C/D/E/F) を抽出して patterns_matched に反映

時間配分:
- 1 本目を完成させるのに 15 分 (template 確立 + 検証)
- 残り 34 本に 1 本 1-2 分で適用 (45 分)

## D-3. smoke test

任意の check (例: check-known-attacker-ip) を実行 → data/incidents/<id>/check-known-attacker-ip__*.json が生成されることを確認:

  cat data/incidents/<id>/check-known-attacker-ip__*.json | jq .

# タスク E: /playbook × 5 に JSON emit (30 分)

## E-1. 追加位置

各 .claude/commands/playbook/*.md の末尾 (§7 cmd_validator gate の後) に新規 §8 として追加:

  ## 8. JSON 永続化（HTML dashboard 連携）

  ```bash
  cat <<'JSON_EOF' | scripts/emit_skill_json.sh playbook-<scenario-name> --actor ai_human
  {
    "inputs": {
      "scenario": "<wp-tamper | dns-tamper | ddos | phishing | ransomware>",
      "incident_id": "$INCIDENT_ID"
    },
    "outputs": {
      "proposed_commands": [
        "ssh manage@10.1.1.2 'sudo iptables -I INPUT -s 161.33.12.212 -j DROP'",
        ...
      ],
      "cmd_validator_result": {
        "exit_code": 0 | 1,
        "errors": [...],
        "warnings": [...]
      },
      "scope": {
        "in_scope": ["..."],
        "out_of_scope_logged": ["..."]
      }
    },
    "verdict": {
      "status": "🚨" | "⚠️" | "✅",
      "summary": "<提案 N 件 (validator PASS), 採用は人間判断>"
    },
    "next_skills": ["/report"]
  }
  JSON_EOF
  ```

actor は `ai_human` (AI 提案 → 人間実行)。提案コマンドは出すが実行はしない設計。

## E-2. cmd_validator 結果の取り込み

§7 の cmd_validator 実行結果 (exit code + errors + warnings) を JSON に含める。これで dashboard で「どのコマンドが提案されて、validator で何が引っかかったか」見える。

# タスク F: /scenario × 3 と /ticket に JSON emit (15 分)

## F-1. /scenario × 3

.claude/commands/scenario/{killchain-recon-rce-dbexfil, dns-spoof-phish, vpn-uplink-abuse}.md の末尾に追加:

  ## §<N>. JSON 永続化

  ```bash
  cat <<'JSON_EOF' | scripts/emit_skill_json.sh scenario-<name>
  {
    "inputs": {
      "checks_dispatched": ["check-XXX", "check-YYY", ...]
    },
    "outputs": {
      "killchain_phase_results": [
        {"phase": "recon", "checks": ["check-XXX"], "verdict": "🚨"},
        ...
      ]
    },
    "verdict": {
      "status": "🚨" | "⚠️" | "✅",
      "summary": "<キルチェーン全体の総括>"
    },
    "next_skills": ["/playbook:...", "/review"]
  }
  JSON_EOF
  ```

## F-2. /ticket

.claude/commands/ticket.md の末尾に追加:

  ## §<N>. JSON 永続化

  ```bash
  cat <<'JSON_EOF' | scripts/emit_skill_json.sh ticket --actor ai_human
  {
    "inputs": {
      "triage_report_path": "$REPORT_PATH"
    },
    "outputs": {
      "fields": {
        "occurrence_time": "...",
        "trouble_content": "...",
        "cause": "...",
        "actions_taken": [...],
        "recovery_verification": "..."
      },
      "pukiwiki_markup": "<生成されたマークアップ全文>",
      "submission_url": "http://133.42.49.140/trouble_ticket_137/index.php"
    },
    "verdict": {
      "status": "info",
      "summary": "PukiWiki マークアップ生成完了、人間が手で投稿"
    },
    "next_skills": []
  }
  JSON_EOF
  ```

actor は `ai_human` (AI 生成、投稿は人間)。

# タスク G: smoke test + dashboard 確認 (30 分)

## G-1. End-to-end smoke

仮の incident を 1 件流して全 skill が JSON を生成することを確認:

  # 1. preflight
  /preflight victor
  ls /tmp/preflight_state.json data/incidents/*/preflight__*.json
  
  # 2. incident
  /incident 10:05-10:08 victor
  ls data/incidents/2026-05-04_10:05_victor/
  
  # 3. check (1 本)
  /check:check-known-attacker-ip 10:05-10:08 victor
  
  # 4. review
  /review
  
  # 5. playbook (1 本、提案表示のみ、人間実行はしない)
  # /playbook:phishing
  
  # 6. report
  /report
  
  # 7. ticket
  /ticket
  
  # 全 JSON が data/incidents/<id>/ 配下にあることを確認
  ls -la data/incidents/2026-05-04_10:05_victor/

## G-2. dashboard 表示確認

  cd /Users/ryu/Desktop/shirahama
  ${SHIRAHAMA_PY:-python3} -m http.server 8765 &
  open http://127.0.0.1:8765/docs/incident_dashboard.html

dashboard で:
- 受電 1 件のカードが表示される
- preflight / incident / check / review / playbook / report / ticket すべての JSON が読み込まれる
- verdict 集約バッジ (🚨 / ⚠️ / ✅) が正しく表示される

## G-3. 不具合があれば

- helper script の incident_id 解決ロジックを点検 (環境変数 / args / 自動生成)
- JSON が malformed なら jq が読めない → dashboard が空表示。skill 側の HEREDOC quote を確認
- 古い incident dir が混ざるとカード乱発 → smoke test 後は data/incidents/smoke_test* を削除

# タスク完了基準

- A: scripts/emit_skill_json.sh が動く (smoke test PASS)
- B: /preflight が /tmp/preflight_state.json と data/incidents/<id>/preflight__*.json を生成
- C: /incident §0.4 で preflight 異常を表示、§4 Claude 推論に context として渡す
- D: 35 本の /check 全てが §6 JSON emit を持つ
- E: 5 本の /playbook 全てが §8 JSON emit を持つ
- F: 3 本の /scenario と /ticket が JSON emit を持つ
- G: end-to-end smoke で全 skill JSON が data/incidents/<id>/ に揃う、dashboard で表示される

# 注意事項

- helper script は jq に依存する。本番 PC に jq があることを事前確認 (which jq)
  → fallback は実装するが、本番では jq 必須でよい
- 既存の incident.md / review.md / report.md の JSON emit は helper を使うように refactor
  (古い inline 書き方は削除、helper 経由に統一)
- 35 本の /check への一括追加で個別の patterns_matched 構造を間違えると dashboard が読めない
  → 1 本完成 → smoke → 残り適用、の段階導入を厳守
- JSON helper の incident_id 解決は env > args > 自動生成 の順、これを変えると既存 skill の整合性が崩れる
- /preflight が /incident の前段になるので、本番運用フロー (HTML 仕様書 §4 ワークドエグザンプル) を更新する余裕があれば対応

# 参考ファイル

- memory/MEMORY.md
- memory/json_output_convention.md (doc 27 で確立した JSON スキーマ詳細)
- memory/html_aggregator_design.md (dashboard のデータソース要件)
- memory/review_skill_design.md (/review が consume する JSON 形式)
- docs/27_引き継ぎ_復旧人間化_review_JSON集約_20260503.md タスク D
- .claude/commands/incident.md (既存 JSON emit、helper 化の参照)
- .claude/commands/preflight.md (B 改修対象)
- docs/incident_dashboard.html (G の表示確認対象)

タスク A → B → C → D → E → F → G の順で進めてください。各タスク完了時に進捗を memory/demo_progress.md に追記。
セッション終了時に memory に新規 entry を追加: emit_skill_json_helper / preflight_incident_integration など
```

## ▲ ここまで貼り付け用プロンプト ▲

---

## 補足メモ (Claude には見せなくていい)

### なぜこの順番か

- A は他全部の前提（helper が無いと B〜F が呼べない）
- B は C の前提（preflight が JSON 吐かないと incident が読めない）
- C は preflight ↔ incident 連携の本体
- D/E/F は並行可能だが順次でも問題ない
- G は最後に統合確認

### 想定所要時間

| タスク | 所要 | 必須? |
|---|---|---|
| A (helper script) | 30 分 | 必須 |
| B (preflight JSON) | 15 分 | 必須 |
| C (incident 連携) | 15 分 | 必須 |
| D (/check × 35) | 1 時間 | 必須 |
| E (/playbook × 5) | 30 分 | 必須 |
| F (/scenario × 3 + /ticket) | 15 分 | 必須 |
| G (smoke + dashboard) | 30 分 | 必須 |
| 合計 | **3-3.5 時間** | — |

### 失敗時のフォールバック

- A で jq 依存が問題 → python3 fallback 実装は doc 内にスケルトンあり
- D で 35 本一括が時間切れ → /incident §5.2 ルーティング表で頻出する 10-15 本だけ先行対応
- C で claude_backend.py のシグネチャ変更が大きい → preflight 異常を unmatched_logs に注入する形で迂回（ClaudeBackend は既に unmatched 受け取れる）
- G で dashboard が JSON 読めない → schema mismatch、jq parse エラーログを dashboard に表示する診断 div を追加

### doc 26/27 との関係

| doc | 内容 | 状態 |
|---|---|---|
| 26 | 脆弱化シミュレーション + /preflight 追加 | 完了 (5/3) |
| 27 | 復旧コマンド人間化 + /review skill + JSON 集約 (3 skill 分) | 完了 (5/4) |
| 28 | **全 skill JSON 化 + /preflight ↔ /incident 連携** | 本セッションで実施予定 |

### 5/5 本番までのマイルストーン (更新)

| 日付 | 必須 | 余力あれば |
|---|---|---|
| 5/3 | doc 26 完了 | — |
| 5/4 | doc 27 完了 | — |
| 5/5 朝 | doc 28 完了 (3-3.5h) + 起動前チェック + リハーサル 1 周 | 仕様書 25 §3 に /review /preflight 連携追記 |
| 5/5 演習 | 本番運用 | — |

3-3.5h は朝の時間枠で十分収まる。doc 28 を本番直前に入れることで、JSON 集約と /preflight 連携が本番初の通報から有効になる。

### このタスクの本質

doc 27 が「safety + cleanliness + review」を片付けたのに対し、doc 28 は「**fidelity + connectivity**」を担当。受電全件の調査経過が dashboard で見える + preflight ↔ incident が連動する = チーム協調が再現性を持つ。本番運用での「**チーム間のコンテキスト共有**」が完成する位置付け。
