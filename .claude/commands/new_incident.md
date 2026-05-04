---
model: claude-haiku-4-5
description: 新規インシデント開始 — incident_id を生成して data/incidents/<id>/ を作成、以降のスキル全てがこの id 配下に書く。受電直後にこれを 1 発打つだけで OK。
---

# /new-incident — 新規インシデント開始

引数: 任意。形式は柔軟に解釈:
- `/new_incident`                    — auto: `<TODAY>_<HHMM>_both` (host 不明時のデフォルト = 両機嫌疑)
- `/new_incident victor`             — `<TODAY>_<HHMM>_victor`
- `/new_incident bravo`              — `<TODAY>_<HHMM>_bravo`
- `/new_incident victor bravo`       — 両機被弾明示: `<TODAY>_<HHMM>_victor_bravo`
- `/new_incident 1300`               — 時刻のみ指定、host = `both`
- `/new_incident 1300 victor`        — 時刻 + host
- `/new_incident 2026-05-05_1305_custom`  — 完全 id 指定 (詳細制御)

**実運用の推奨**: 受電中は host 判明前に `/new_incident` を打つので、引数なし (= `both`) でいい。host 判明したら id を rename しない (上書きすると過去の preflight/incident が孤児になる)。代わりに、その incident_id 配下のままで /review が両機を見る。/review は host を hearing__*.json の `affected_hosts` から拾う。

例:
- 受電開始の瞬間: `/new_incident` (auto: `2026-05-05_1300_both`)
- 受電中に時間窓判明: そのまま `/incident 13:00-13:30` (host 引数なし = 両機ログ取得)
- host 確定 (例: victor のみ): id は `_both` のままで OK。/incident に `victor` を渡すだけ
- 両機被弾確定: `/incident 13:00-13:30 victor bravo`

---

## このスキルが解決する問題

- 大会で複数インシデントが連続で来る前提では、毎回手で `mkdir + export INCIDENT_ID` が手間
- ブラウザの「+ 新規」ボタンは clipboard コピーまでしかできない (sandbox 制限)
- スラッシュコマンドにすれば、Claude Code の中で 1 単語で完了 + 各 skill 自動継承

ACTOR: AI Auto (人間がコマンド 1 つ打つだけ。AI が解釈 + ディレクトリ作成 + 全 skill 自動継承を仕込む)

---

## §0. 前提

- 出力: `data/incidents/<id>/` 作成 + `data/incidents/.current_id` に id を書き込み (各 skill が読む)
- 各 skill (preflight / incident / review / report / call_close / ticket) は `INCIDENT_ID` env を見るが、未設定なら `data/incidents/.current_id` を fallback で読む
- これにより、ターミナルで `export` しなくても全 skill が同じ id にぶら下がる
- ブラウザのダッシュボードは `.current_id` を 3 秒ごとに polling してヘッダ事案 ID を自動切替する (実装次第)

---

## §1. id 生成 + ディレクトリ作成 + .current_id 書込み

```bash
SHIRAHAMA_DIR="${SHIRAHAMA_DIR:-/Users/ryu/Desktop/shirahama}"
cd "$SHIRAHAMA_DIR"

TODAY="$(date +%Y-%m-%d)"
HHMM="$(date +%H%M)"
ARGS="$*"

# 引数解釈 (空 / host のみ / 時刻+host / 完全id 形式)
if [ -z "$ARGS" ]; then
  NEW_ID="${TODAY}_${HHMM}_both"   # 受電開始時 host 不明 → デフォルト両機嫌疑
elif [[ "$ARGS" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}_ ]]; then
  # 完全 id 指定 (例: "2026-05-05_1305_custom")
  NEW_ID="$ARGS"
elif [[ "$1" =~ ^[0-9]{4}$ ]]; then
  # 第 1 引数が時刻 (HHMM)、残りが host(s)
  TIME="$1"
  shift
  if [ $# -eq 0 ]; then
    NEW_ID="${TODAY}_${TIME}_both"
  else
    HOSTS=$(echo "$@" | tr ' ' '_')
    NEW_ID="${TODAY}_${TIME}_${HOSTS}"
  fi
else
  # 第 1 引数から全部 host(s)
  HOSTS=$(echo "$ARGS" | tr ' ' '_')
  NEW_ID="${TODAY}_${HHMM}_${HOSTS}"
fi

INCIDENT_DIR="data/incidents/${NEW_ID}"
mkdir -p "$INCIDENT_DIR"

# .current_id に書き込み — 全 skill がこれを fallback で読む
echo "${NEW_ID}" > "data/incidents/.current_id"

# (必須ではないが) 環境変数も export しておく (同シェル内で別 skill 打つ場合)
export INCIDENT_ID="${NEW_ID}"

echo "─── /new-incident ───"
echo "  ✓ incident_id    : ${NEW_ID}"
echo "  ✓ ディレクトリ    : ${INCIDENT_DIR}"
echo "  ✓ .current_id    : data/incidents/.current_id に書込み済"
echo "  ✓ INCIDENT_ID env : ${NEW_ID}"
```

---

## §2. ブラウザ連携の挙動

- ダッシュボード (review タブ) のヘッダ事案 ID は `.current_id` を 3 秒間隔で polling して、変わったら自動切替する (実装次第、未実装ならヘッダで手で貼り付け)
- 受電台本タブの 💾 hearing JSON 保存ボタンは、ヘッダ事案 ID を読んで JSON envelope に書き込む

---

## §3. 次のステップ案内

```text
─── 次のステップ ───

  1. ブラウザ受電台本タブで Phase 1〜2 + 💾 4 項目を埋めて hearing JSON 保存
     (ダウンロード後 mv ~/Downloads/hearing__*.json data/incidents/<id>/)

  2. host が後で判明したら id を rename:
     /new-incident <新id>     ← 同じ skill で id 指定して上書き

  3. /preflight                ← 引数なしで自動的に上記 id 配下に書く
  4. /incident <時間窓> <host>
  5. /review                   ← 主動線
  6. 採択 → 対応 → /report → /call_close → /ticket
  7. ⏹ インシデント完了 (ブラウザ補助セクションのボタン)
```

---

## §4. NG パターン

1. **同じ id を 2 回打って既存を上書きしない** — `/new-incident` は `mkdir -p` なので既存があっても壊さないが、`.current_id` を上書きするので「過去の incident に巻き戻す」用途には使わない (それはヘッダで手動切替)
2. **ホスト名は小文字、`_` 区切り** — `Victor` や `victor-bravo` (ハイフン) は禁止、`victor_bravo` で
3. **時刻は 4 桁 HHMM** — `13:00` や `1:00` は受け付けない、`1300` `0900` で
4. **`_pending` は仮の host 不明状態** — 受電内容で判明したら別 id に rename (`/new-incident 1300 victor` でやり直し)

---

## §5. 仕様書接続

- 全 skill (preflight / incident / review / report / call_close / ticket) は §1 入力読み込み bash で:
  ```bash
  if [ -z "${INCIDENT_ID:-}" ]; then
      INCIDENT_ID="$(cat data/incidents/.current_id 2>/dev/null)"
      [ -z "$INCIDENT_ID" ] && INCIDENT_ID="$(ls -1t data/incidents/ | grep -v '^\.' | head -1)"
  fi
  export INCIDENT_ID
  ```
  の順で id を解決する。`.current_id` が最優先、次にディレクトリ mtime 最新、最後 fallback。
