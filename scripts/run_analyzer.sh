#!/bin/bash
# 時間窓 + ホスト指定で「ログ取得 → JSONL → analyzer → Mock + Claude」を一気通貫
# /incident slash command の実体

set -e

if [ $# -lt 2 ]; then
    echo "Usage: $0 <time_window> <host>"
    echo "  例: $0 13:00-13:30 victor"
    exit 1
fi

TIME_WINDOW="$1"
HOST="$2"

case "$HOST" in
    victor)
        TARGET_IP="10.1.1.2"
        LOG_PATHS=(
            "/var/log/httpd/access_log"
            "/var/log/secure"
            "/var/log/maillog"
        )
        ;;
    bravo)
        TARGET_IP="10.1.1.1"
        LOG_PATHS=(
            "/var/log/named.log"
            "/var/log/auth.log"
            "/var/log/maillog"
        )
        ;;
    *)
        echo "[error] unknown host: $HOST (victor or bravo)"
        exit 1
        ;;
esac

WORK_DIR="/tmp/incident_$$"
mkdir -p "$WORK_DIR"

echo "[$(date)] Fetching logs from $HOST ($TARGET_IP) for window $TIME_WINDOW"

# TODO: ssh で実機からログを取得（接続情報は VPN_SSH_manual.md 参照）
# for log_path in "${LOG_PATHS[@]}"; do
#     ssh manage@$TARGET_IP "tail -2000 $log_path" > "$WORK_DIR/$(basename $log_path)"
# done

# JSONL 化
# python3 scripts/preprocess/parse_clf.py "$WORK_DIR/access_log" > "$WORK_DIR/access.jsonl"
# python3 scripts/preprocess/parse_secure.py "$WORK_DIR/secure" > "$WORK_DIR/secure.jsonl"
# 等々

# analyzer 起動
# python3 -c "
# from agent import analyzer
# signals = analyzer.run('$WORK_DIR')
# print(f'検出: {len(signals)} 件')
# "

echo "[$(date)] (skeleton: 実装は Phase B/C で完成させる)"
echo "Work dir: $WORK_DIR"
