#!/usr/bin/env bash
# k8s_2_kubelet: probe every node's kubelet API port (10250) and the legacy
# read-only kubelet port (10255) from inside the frontend pod. A compromised
# workload pod reaching out to node IPs on these ports is a strong
# lateral-movement / node-compromise signal.
set -euo pipefail

NS="${NS:-pbl-security}"

FRONTEND="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"
echo "[k8s_2_kubelet] frontend pod: ${FRONTEND}"

NODE_IPS=()
while IFS= read -r ip; do
  [[ -n "${ip}" ]] && NODE_IPS+=("${ip}")
done < <(kubectl get nodes -o jsonpath='{range .items[*]}{.status.addresses[?(@.type=="InternalIP")].address}{"\n"}{end}')

echo "[k8s_2_kubelet] node IPs: ${NODE_IPS[*]}"

PORTS=(10250 10255)

for ip in "${NODE_IPS[@]}"; do
  for port in "${PORTS[@]}"; do
    echo "[k8s_2_kubelet] nc -z ${ip}:${port}"
    kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- nc -z -w 1 "${ip}" "${port}" >/dev/null 2>&1 || true
  done
done

echo "[k8s_2_kubelet] done; inspect with: hubble observe --since 5m | grep -E ':(10250|10255)'"
