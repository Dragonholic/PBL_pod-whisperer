#!/usr/bin/env bash
# collect.sh - run a labeled traffic scenario N times and capture the
# resulting Hubble flow logs for later offline detection/evaluation.
#
# Usage:
#   ./collect.sh <scenario> [reps]
#
# <scenario> is one of:
#   normal, abnormal_1, abnormal_2, abnormal_3   (category2/*.sh, base PBL scenarios)
#   k8s_1, k8s_2, k8s_3, evasion_1, evasion_2    (scenarios/*.sh)
#   fp_1, fp_2, fp_3                             (inline "normal-but-varied"
#                                                  traffic patterns defined in
#                                                  this script, used to probe
#                                                  the false-positive rate --
#                                                  see docs/findings.md)
#
# [reps] defaults to 1. Running the full blueprint dataset (10 reps per
# scenario, all scenarios) is expensive -- see STATUS.md for what
# has actually been collected so far vs. what remains.
#
# For every run this script:
#   1. records a start timestamp
#   2. runs the scenario (script or inline function)
#   3. waits 3s for in-flight flows to be exported by Hubble
#   4. runs `hubble observe --since <start> -o json` WITHOUT a --namespace
#      filter (node-targeted probes, e.g. kubelet/apiserver scans, would be
#      missed by a namespace filter since the destination is outside any
#      namespace -- see docs/findings.md) and saves it to data/<scenario>_<run>.json
#   5. appends a row to data/manifest.csv recording ground-truth label,
#      script used, and the time window.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Course base repo (provides category2/*.sh normal + abnormal_1-3).
# Override with BASE_REPO=/path/to/Practical-Cloud-Security-PBL.
REPO_ROOT="${BASE_REPO:-$(cd "${ROOT_DIR}/../Practical-Cloud-Security-PBL" && pwd)}"
DATA_DIR="${DATA_DIR:-${ROOT_DIR}/data}"   # v3: override to keep new data apart
NS="${NS:-pbl-security}"

MANIFEST="${DATA_DIR}/manifest.csv"

usage() {
  cat >&2 <<EOF
Usage: $0 <scenario> [reps]

Scenarios:
  Base (category2/):      normal abnormal_1 abnormal_2 abnormal_3
  New (scenarios/): k8s_1 k8s_2 k8s_3 evasion_1 evasion_2
  False-positive probes (inline): fp_1 fp_2 fp_3

reps defaults to 1.
EOF
  exit 1
}

[[ $# -ge 1 ]] || usage
SCENARIO="$1"
REPS="${2:-1}"

mkdir -p "${DATA_DIR}"
if [[ ! -f "${MANIFEST}" ]]; then
  echo "scenario,run,label,script,start_time,end_time,data_file" > "${MANIFEST}"
fi

# --- label + script resolution -------------------------------------------

label_for_scenario() {
  case "$1" in
    normal|fp_1|fp_2|fp_3) echo "normal" ;;
    *) echo "attack" ;;
  esac
}

script_for_scenario() {
  case "$1" in
    normal|abnormal_1|abnormal_2|abnormal_3)
      echo "${REPO_ROOT}/category2/$1.sh" ;;
    k8s_1) echo "${ROOT_DIR}/scenarios/k8s_1_apiserver.sh" ;;
    k8s_2) echo "${ROOT_DIR}/scenarios/k8s_2_kubelet.sh" ;;
    k8s_3) echo "${ROOT_DIR}/scenarios/k8s_3_cross_ns.sh" ;;
    evasion_1) echo "${ROOT_DIR}/scenarios/evasion_1_slow_scan.sh" ;;
    evasion_2) echo "${ROOT_DIR}/scenarios/evasion_2_allowed_abuse.sh" ;;
    abnormal_4) echo "${ROOT_DIR}/scenarios/abnormal_4_metadata.sh" ;;
    fp_1|fp_2|fp_3) echo "(inline:$1)" ;;
    *) echo "" ;;
  esac
}

# --- fp_* inline scenarios --------------------------------------------------
# These represent "normal but varied" traffic that a naive detector could
# mistake for recon, used to measure false positives (docs/analysis.md).

fp_1_repeated_healthcheck() {
  # Legitimate polling/health-check loop: same (src,dst,port) path repeated
  # quickly. Exercises R5 (frequency) false-positive risk without touching
  # R1-R4 at all (same path every time -> never "new", never fan-out).
  local fe
  fe="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"
  echo "[fp_1] rapid legitimate frontend -> backend health checks"
  for i in $(seq 1 30); do
    kubectl -n "${NS}" exec -c frontend "${fe}" -- wget -qO- -T 2 http://backend >/dev/null 2>&1 || true
  done
}

fp_2_dns_heavy() {
  # Legitimate but DNS-heavy behavior: many different DNS queries, all
  # resolved through the same kube-dns ClusterIP:53 path. Exercises whether
  # distinct destination_names are mistakenly treated as distinct
  # (dest,port) pairs for fan-out (R4) purposes.
  local fe
  fe="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"
  echo "[fp_2] legitimate DNS-heavy lookups (same dns path, different names)"
  for name in backend backend.pbl-security backend.pbl-security.svc.cluster.local \
              kubernetes.default kubernetes.default.svc.cluster.local; do
    kubectl -n "${NS}" exec -c frontend "${fe}" -- nslookup "${name}" >/dev/null 2>&1 || true
  done
}

fp_3_varied_but_allowed() {
  # Legitimate multi-destination burst within the pod's *allowed* egress set
  # (backend:80, kube-dns:53, loopback). Distinct (dest,port) pairs = 3,
  # which stays under the default fan-out threshold (N=5) but can trip a
  # stricter experiment_a setting (N=3) -- intentionally used as a
  # sensitivity probe for Experiment A.
  local fe
  fe="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"
  echo "[fp_3] legitimate but varied allowed-path burst"
  for i in 1 2 3; do
    kubectl -n "${NS}" exec -c frontend "${fe}" -- wget -qO- -T 2 http://backend >/dev/null 2>&1 || true
    kubectl -n "${NS}" exec -c frontend "${fe}" -- nslookup backend >/dev/null 2>&1 || true
    kubectl -n "${NS}" exec -c frontend "${fe}" -- wget -qO- -T 2 http://127.0.0.1/ >/dev/null 2>&1 || true
  done
}

run_scenario() {
  local scenario="$1"
  case "${scenario}" in
    fp_1) fp_1_repeated_healthcheck ;;
    fp_2) fp_2_dns_heavy ;;
    fp_3) fp_3_varied_but_allowed ;;
    *)
      local script
      script="$(script_for_scenario "${scenario}")"
      [[ -n "${script}" && -x "${script}" ]] || { echo "Unknown or non-executable scenario script: ${scenario} (${script})" >&2; exit 1; }
      NS="${NS}" "${script}"
      ;;
  esac
}

# --- hubble connectivity ---------------------------------------------------

ensure_hubble_portforward() {
  if hubble status >/dev/null 2>&1; then
    return
  fi
  echo "[collect] hubble relay not reachable on localhost; starting 'cilium hubble port-forward'"
  nohup cilium hubble port-forward >"${ROOT_DIR}/.hubble-portforward.log" 2>&1 &
  disown
  for i in $(seq 1 15); do
    sleep 1
    hubble status >/dev/null 2>&1 && { echo "[collect] hubble relay is reachable"; return; }
  done
  echo "[collect] WARNING: hubble still not reachable after waiting; continuing anyway" >&2
}

# --- main loop ---------------------------------------------------------

label="$(label_for_scenario "${SCENARIO}")"
script="$(script_for_scenario "${SCENARIO}")"
[[ -n "${script}" ]] || usage

ensure_hubble_portforward

for run in $(seq 1 "${REPS}"); do
  echo "=== [collect] scenario=${SCENARIO} run=${run}/${REPS} label=${label} ==="
  start_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  run_scenario "${SCENARIO}"

  echo "[collect] sleeping 3s to let in-flight flows reach hubble"
  sleep 3
  end_time="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  out_file="${DATA_DIR}/${SCENARIO}_${run}.json"
  echo "[collect] capturing: hubble observe --since ${start_time} -o json (no --namespace filter)"
  # hubble observe --output json emits one JSON object per line (JSON Lines).
  # It is normal for this to return 0 flows for very fast/blocked scenarios.
  hubble observe --since "${start_time}" -o json > "${out_file}" 2>"${out_file}.stderr" || true

  n_flows="$(wc -l < "${out_file}" || echo 0)"
  echo "[collect] captured ${n_flows} flow lines -> ${out_file}"

  echo "${SCENARIO},${run},${label},${script#${ROOT_DIR}/},${start_time},${end_time},${out_file#${ROOT_DIR}/}" >> "${MANIFEST}"
done

echo "[collect] done. Manifest: ${MANIFEST}"
