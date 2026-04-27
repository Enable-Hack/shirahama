#!/bin/bash
# 競技開始前 + 毎日 1 回実行する CVE feed 更新スクリプト
# Loop1 (Threat Intel) の実体

set -e

cd "$(dirname "$0")/../.."

echo "[$(date)] CVE feed update start"

# CISA KEV から取得
python3 scripts/feed/fetch_cve.py --output data/cve/

# TODO (Phase B'): cve_to_pattern.py で agent/patterns.yaml に追記
# python3 scripts/feed/cve_to_pattern.py \
#     --input data/cve/ \
#     --merge agent/patterns.yaml

echo "[$(date)] CVE feed update done"
