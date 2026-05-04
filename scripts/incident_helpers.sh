# shirahama incident helpers — source from ~/.zshrc to enable shell shortcuts
#
# Setup (one-time):
#   echo 'source ~/Desktop/shirahama/scripts/incident_helpers.sh' >> ~/.zshrc
#   exec zsh   # or open new terminal
#
# Usage:
#   new-incident                       # auto: 2026-05-05_HHMM_pending
#   new-incident victor                # 2026-05-05_HHMM_victor
#   new-incident 1305 victor           # 2026-05-05_1305_victor
#   new-incident 1305 victor bravo     # 2026-05-05_1305_victor_bravo
#   new-incident <full-id>             # explicit
#
# Effect:
#   1) mkdir -p data/incidents/<id>/
#   2) export INCIDENT_ID=<id>
#   3) cd into shirahama dir if not already there
#   4) print next-step hints (open dashboard / fill hearing form / run /preflight)

# 大会本番のシェル直下作業を 1 単語に圧縮するためのヘルパー
new-incident() {
  local SHIRAHAMA="${SHIRAHAMA_DIR:-$HOME/Desktop/shirahama}"
  if [ ! -d "$SHIRAHAMA/data/incidents" ]; then
    echo "❌ $SHIRAHAMA/data/incidents が無い。SHIRAHAMA_DIR を確認" >&2
    return 1
  fi
  cd "$SHIRAHAMA" || return 1

  local TODAY=$(date +%Y-%m-%d)
  local HHMM=$(date +%H%M)

  local ID
  case $# in
    0)
      ID="${TODAY}_${HHMM}_pending"
      ;;
    1)
      # 引数 1 つ: ホスト名 or 既存 id 完全形 or 時刻
      if [[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}_ ]]; then
        ID="$1"   # 完全 id 指定
      elif [[ "$1" =~ ^[0-9]{4}$ ]]; then
        ID="${TODAY}_$1_pending"   # 時刻のみ
      else
        ID="${TODAY}_${HHMM}_$1"   # ホスト名のみ
      fi
      ;;
    *)
      # 引数 2+ : 時刻 + host(s) or host + host
      if [[ "$1" =~ ^[0-9]{4}$ ]]; then
        local TIME="$1"; shift
        local HOSTS=$(echo "$@" | tr ' ' '_')
        ID="${TODAY}_${TIME}_${HOSTS}"
      else
        local HOSTS=$(echo "$@" | tr ' ' '_')
        ID="${TODAY}_${HHMM}_${HOSTS}"
      fi
      ;;
  esac

  mkdir -p "data/incidents/$ID"
  export INCIDENT_ID="$ID"

  echo "✓ 新規インシデント開始: $ID"
  echo "✓ export INCIDENT_ID=\"$ID\""
  echo "✓ data/incidents/$ID/ 作成済"
  echo ""
  echo "次のステップ:"
  echo "  1. ブラウザ事案 ID を $ID にセット (ヘッダで貼り付け or ＋ 新規ボタン)"
  echo "  2. 受電台本タブで 💾 hearing JSON 保存 → mv ~/Downloads/hearing__*.json data/incidents/$ID/"
  echo "  3. /preflight              ← 引数なしで自動的に $ID 配下に書く"
  echo "  4. /incident <window> [host...]"
  echo "  5. /review → 採択 → 対応 → /report → /call_close → /ticket"
}

# host が後から判明したときの id rename
rename-incident() {
  if [ $# -lt 1 ]; then
    echo "usage: rename-incident <new_id_or_suffix>" >&2
    return 1
  fi
  if [ -z "${INCIDENT_ID:-}" ]; then
    echo "❌ INCIDENT_ID が未設定。new-incident で開始してください" >&2
    return 1
  fi
  local SHIRAHAMA="${SHIRAHAMA_DIR:-$HOME/Desktop/shirahama}"
  local OLD="$INCIDENT_ID"
  local NEW
  # 引数が完全 id 形式なら直接、suffix だけなら _pending を置換
  if [[ "$1" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}_ ]]; then
    NEW="$1"
  else
    NEW="${OLD/_pending/_$1}"
  fi
  if [ "$OLD" = "$NEW" ]; then
    echo "⚠️ 変更なし ($OLD)" >&2
    return 0
  fi
  if [ ! -d "$SHIRAHAMA/data/incidents/$OLD" ]; then
    echo "❌ data/incidents/$OLD が無い" >&2
    return 1
  fi
  mv "$SHIRAHAMA/data/incidents/$OLD" "$SHIRAHAMA/data/incidents/$NEW"
  export INCIDENT_ID="$NEW"
  echo "✓ rename: $OLD → $NEW"
  echo "✓ export INCIDENT_ID=\"$NEW\""
}

# 現在のインシデントを表示
current-incident() {
  if [ -z "${INCIDENT_ID:-}" ]; then
    echo "(INCIDENT_ID 未設定)"
    return 1
  fi
  echo "INCIDENT_ID=$INCIDENT_ID"
  local SHIRAHAMA="${SHIRAHAMA_DIR:-$HOME/Desktop/shirahama}"
  local DIR="$SHIRAHAMA/data/incidents/$INCIDENT_ID"
  if [ -d "$DIR" ]; then
    echo "$DIR の中身:"
    ls -la "$DIR" | tail -n +2
  else
    echo "(まだディレクトリ無し)"
  fi
}
