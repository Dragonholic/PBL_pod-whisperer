#!/usr/bin/env bash
# evasion_1_slow_scan: the same multi-target, multi-port probe as
# category2/abnormal_3.sh, but spread out with a 15s sleep between each
# attempt. This is meant to defeat a naive fixed-window fan-out rule (R4):
# if the detection window W is small (e.g. 10s), a slow scan never produces
# enough distinct (dest,port) pairs inside any single window to trip R4, even
# though the total number of probed targets/ports is identical to abnormal_3.
set -euo pipefail

NS="${NS:-pbl-security}"
SLEEP_SECONDS="${SLEEP_SECONDS:-15}"

FRONTEND="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"

TARGETS=(
  backend
  db
  "$(kubectl -n "${NS}" get pod -l app=backend -o jsonpath='{.items[0].status.podIP}')"
  "$(kubectl -n "${NS}" get pod -l app=db -o jsonpath='{.items[0].status.podIP}')"
)
while IFS= read -r node_ip; do
  [[ -n "${node_ip}" ]] && TARGETS+=("${node_ip}")
done < <(kubectl get nodes -o jsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}')
PORTS=(22 443 2379 10250 3306 6379)

echo "[evasion_1_slow_scan] frontend pod: ${FRONTEND}"
echo "[evasion_1_slow_scan] same targets/ports as abnormal_3, ${SLEEP_SECONDS}s apart"

for target in "${TARGETS[@]}"; do
  for port in "${PORTS[@]}"; do
    echo "probe target=${target} port=${port} (sleeping ${SLEEP_SECONDS}s after)"
    kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- nc -z -w 1 "${target}" "${port}" >/dev/null 2>&1 || true
    sleep "${SLEEP_SECONDS}"
  done
done

echo "[evasion_1_slow_scan] done; this scenario exists to test fan-out (R4) detection *blind spots* under evasive timing."
