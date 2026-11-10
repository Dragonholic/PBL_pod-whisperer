#!/usr/bin/env bash
# collect_e1.sh - v2.2 (E1-1): collect extra NORMAL runs under shifted conditions.
# Does not touch NetworkPolicy. Workload changes (restart, replica) are reverted.
#
# Usage: ./collect_e1.sh <variant> [reps]
#   later     plain normal run (collected days after the original data)
#   rounds    normal.sh with ROUNDS=6 (more requests per run than the default 3)
#   restart   rollout-restart frontend/backend/db first, then normal runs
#   replica2  backend scaled to 2 replicas, then normal runs (scaled back after)
# Output: data_e1/<variant>_<run>.json and data_e1/manifest.csv
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${BASE_REPO:-$(cd "${ROOT_DIR}/../Practical-Cloud-Security-PBL" && pwd)}"
NS="${NS:-pbl-security}"
DATA_DIR="${DATA_DIR:-${ROOT_DIR}/data_e1}"
MANIFEST="${DATA_DIR}/manifest.csv"
VARIANT="${1:?variant}"
REPS="${2:-5}"
mkdir -p "${DATA_DIR}"
[[ -f "${MANIFEST}" ]] || echo "scenario,run,label,variant,start_time,end_time,data_file" > "${MANIFEST}"

wait_ready() {
  for d in frontend backend db; do
    kubectl -n "${NS}" rollout status "deploy/${d}" --timeout=180s
  done
  sleep 20
}

case "${VARIANT}" in
  later) ;;
  rounds) export ROUNDS=6 ;;
  restart)
    kubectl -n "${NS}" rollout restart deploy/frontend deploy/backend deploy/db
    wait_ready ;;
  replica2)
    trap 'kubectl -n "${NS}" scale deploy/backend --replicas=1 >/dev/null; kubectl -n "${NS}" rollout status deploy/backend --timeout=180s' EXIT
    kubectl -n "${NS}" scale deploy/backend --replicas=2
    wait_ready ;;
  *) echo "unknown variant ${VARIANT}" >&2; exit 1 ;;
esac

for run in $(seq 1 "${REPS}"); do
  echo "=== [e1] shift_${VARIANT} run=${run}/${REPS} ==="
  start_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  NS="${NS}" "${REPO_ROOT}/category2/normal.sh" >/dev/null
  sleep 3
  end_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  out="${DATA_DIR}/shift_${VARIANT}_${run}.json"
  hubble observe --since "${start_time}" -o json > "${out}" 2>/dev/null || true
  echo "shift_${VARIANT},${run},normal,${VARIANT},${start_time},${end_time},${DATA_DIR#${ROOT_DIR}/}/shift_${VARIANT}_${run}.json" >> "${MANIFEST}"
  echo "[e1] $(wc -l < "${out}") flow lines"
done
