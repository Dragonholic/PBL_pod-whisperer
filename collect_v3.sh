#!/usr/bin/env bash
# collect_v3.sh - v3 data collection (E5-1, E5-3, E5-4), sequential on purpose:
# Hubble records the whole cluster, so normal and attack runs must not overlap.
# Writes only to data_v3/ . No NetworkPolicy change. Restart/replica changes are reverted.
set -uo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export DATA_DIR="${ROOT_DIR}/data_v3"; mkdir -p "${DATA_DIR}"
LOG="${DATA_DIR}/progress.log"
step() { echo "$(date -u +%FT%TZ) $*" | tee -a "${LOG}"; }
cd "${ROOT_DIR}"
step "A1 fp_1..3 x10"; for s in fp_1 fp_2 fp_3; do ./collect.sh "$s" 10 >>"${LOG}" 2>&1; done
step "A2 normal stream 3600s pause 30s"; ./collect_e1_long.sh 3600 30 >>"${LOG}" 2>&1
step "A3 restart x5"; ./collect_e1.sh restart 5 >>"${LOG}" 2>&1
step "A4 replica2 x5"; ./collect_e1.sh replica2 5 >>"${LOG}" 2>&1
step "B attacks x10 each"
for s in abnormal_1 abnormal_2 abnormal_3 k8s_1 k8s_2 k8s_3 evasion_2 abnormal_4 evasion_1; do
  step "B $s"; ./collect.sh "$s" 10 >>"${LOG}" 2>&1
done
step "ALL DONE"
