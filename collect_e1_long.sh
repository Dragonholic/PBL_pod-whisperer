#!/usr/bin/env bash
# collect_e1_long.sh - v2.2 (E1-3): long normal run for false alarms per hour.
# Streams all Hubble flows (hubble observe --follow) while the normal scenario is
# repeated with a pause; every iteration's start/end time is logged so the stream
# can be cut into run-sized segments for evaluation.
# Usage: ./collect_e1_long.sh [seconds=3600] [pause=30]
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${BASE_REPO:-$(cd "${ROOT_DIR}/../Practical-Cloud-Security-PBL" && pwd)}"
NS="${NS:-pbl-security}"
DUR="${1:-3600}"; PAUSE="${2:-30}"
OUT="${DATA_DIR:-${ROOT_DIR}/data_e1}"; mkdir -p "${OUT}"
STREAM="${OUT}/long_stream.json"; ITER="${OUT}/long_iterations.csv"
echo "iteration,start_epoch,end_epoch" > "${ITER}"
hubble observe --follow --since 1s -o json > "${STREAM}" 2>/dev/null &
HP=$!
trap 'kill ${HP} 2>/dev/null || true' EXIT
sleep 3
T0=$(date +%s); i=0
while [ $(( $(date +%s) - T0 )) -lt "${DUR}" ]; do
  i=$((i+1)); s=$(date +%s)
  NS="${NS}" "${REPO_ROOT}/category2/normal.sh" >/dev/null 2>&1 || true
  e=$(date +%s)
  echo "${i},${s},${e}" >> "${ITER}"
  sleep "${PAUSE}"
done
sleep 3
echo "done iterations=${i}"
