#!/bin/bash
# emit_skill_json.sh — 全 skill 共通の JSON 永続化 helper
#
# usage:
#   echo '<skill 固有 JSON>' | scripts/emit_skill_json.sh <skill_name> \
#       [--actor ai_auto|ai_human|human_only] [--incident-id <id>]
#
# stdin: skill 固有の JSON (verdict / inputs / outputs / next_skills 等を含む)
# stdout: 保存したファイルパス
# exit: 0=成功 / 1=JSON 不正 / 2=引数不正
#
# 保存先: data/incidents/<incident_id>/<skill>__<timestamp>.json
# 全タイムスタンプ JST (Asia/Tokyo)。incident_id / file ts / JSON 内 timestamp 全部揃える。
# incident_id 解決順:
#   1) --incident-id 明示指定
#   2) 環境変数 INCIDENT_ID
#   3) 自動生成 ${TODAY_JST}_${WINDOW_START}_${HOST}
#   4) fallback ${TODAY_JST}T${HMS}_unscoped

set -euo pipefail

if [ $# -lt 1 ]; then
    echo "usage: emit_skill_json.sh <skill_name> [--actor X] [--incident-id Y]" >&2
    exit 2
fi

SKILL_NAME="$1"
shift

ACTOR="ai_auto"
INCIDENT_ID_ARG=""
while [ $# -gt 0 ]; do
    case "$1" in
        --actor)
            ACTOR="${2:?--actor requires a value}"
            shift 2
            ;;
        --incident-id)
            INCIDENT_ID_ARG="${2:?--incident-id requires a value}"
            shift 2
            ;;
        *)
            echo "unknown arg: $1" >&2
            exit 2
            ;;
    esac
done

# --- incident_id 解決 ----------------------------------------------------
RESOLVED_ID=""
if [ -n "$INCIDENT_ID_ARG" ]; then
    RESOLVED_ID="$INCIDENT_ID_ARG"
elif [ -n "${INCIDENT_ID:-}" ]; then
    RESOLVED_ID="$INCIDENT_ID"
elif [ -n "${WINDOW_START:-}" ]; then
    RESOLVED_ID="$(TZ=Asia/Tokyo date +%Y-%m-%d)_${WINDOW_START}_${HOST:-unknown}"
else
    RESOLVED_ID="$(TZ=Asia/Tokyo date +%Y-%m-%dT%H%M%S)_unscoped"
fi

# --- 保存先決定 ---------------------------------------------------------
# JST 時刻で揃える (incident_id と一貫性を持たせる)。dashboard の正規表現は Z? を許容するので
# Z なし = ローカル時刻 (本 skill 群では JST 固定) として扱う。
TS_FILE="$(TZ=Asia/Tokyo date +%Y%m%dT%H%M%S)"
TS_ISO="$(TZ=Asia/Tokyo date +%Y-%m-%dT%H:%M:%S+09:00)"

# Repo root (scripts/ の親) を基準に data/incidents/ を解決
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="${REPO_ROOT}/data/incidents/${RESOLVED_ID}"
mkdir -p "$DIR"
OUT="${DIR}/${SKILL_NAME}__${TS_FILE}.json"

# --- stdin 読み込み + 構文検証 -------------------------------------------
STDIN_JSON="$(cat)"
if [ -z "$STDIN_JSON" ]; then
    echo "stdin is empty — skill 固有 JSON が必要" >&2
    exit 1
fi

if command -v jq >/dev/null 2>&1; then
    # jq でメタデータ merge (既存 incident/review/report の構造を踏襲)
    if ! printf '%s' "$STDIN_JSON" | jq empty >/dev/null 2>&1; then
        echo "stdin JSON が malformed です" >&2
        printf '%s\n' "$STDIN_JSON" | head -c 400 >&2
        exit 1
    fi
    jq -n \
        --arg skill "$SKILL_NAME" \
        --arg id "$RESOLVED_ID" \
        --arg ts "$TS_ISO" \
        --arg actor "$ACTOR" \
        --argjson body "$STDIN_JSON" \
        '{skill:$skill, incident_id:$id, timestamp:$ts, actor:$actor} + $body' \
        > "$OUT"
else
    # fallback (本番では jq 必須前提だがダウングレード環境向けに)
    PYBIN="${SHIRAHAMA_PY:-python3}"
    if ! command -v "$PYBIN" >/dev/null 2>&1; then
        echo "jq も python3 も無い — JSON merge 不能" >&2
        exit 1
    fi
    SKILL_NAME_ENV="$SKILL_NAME" \
    RESOLVED_ID_ENV="$RESOLVED_ID" \
    TS_ISO_ENV="$TS_ISO" \
    ACTOR_ENV="$ACTOR" \
    "$PYBIN" - "$OUT" <<'PYEOF' <<<"$STDIN_JSON"
import json, os, sys
out_path = sys.argv[1]
body_raw = sys.stdin.read()
try:
    body = json.loads(body_raw)
except Exception as e:
    print(f"stdin JSON parse error: {e}", file=sys.stderr)
    sys.exit(1)
merged = {
    "skill": os.environ["SKILL_NAME_ENV"],
    "incident_id": os.environ["RESOLVED_ID_ENV"],
    "timestamp": os.environ["TS_ISO_ENV"],
    "actor": os.environ["ACTOR_ENV"],
}
merged.update(body)
with open(out_path, "w", encoding="utf-8") as f:
    json.dump(merged, f, ensure_ascii=False, indent=2)
PYEOF
fi

echo "$OUT"
