#!/usr/bin/env bash
# k8s_1_apiserver: repeated probing of the Kubernetes API server from the
# frontend pod, both via the in-cluster DNS name and the apiserver ClusterIP.
# This mimics an attacker inside a compromised pod enumerating the control
# plane (a classic lateral-movement / internal-recon step).
set -euo pipefail

NS="${NS:-pbl-security}"
ROUNDS="${ROUNDS:-5}"

FRONTEND="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"
APISERVER_IP="$(kubectl get svc kubernetes -n default -o jsonpath='{.spec.clusterIP}')"

echo "[k8s_1_apiserver] frontend pod: ${FRONTEND}"
echo "[k8s_1_apiserver] apiserver ClusterIP (looked up, not hardcoded): ${APISERVER_IP}"

for i in $(seq 1 "${ROUNDS}"); do
  echo "[k8s_1_apiserver ${i}/${ROUNDS}] nc -z kubernetes.default.svc:443"
  kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- nc -z -w 1 kubernetes.default.svc 443 >/dev/null 2>&1 || true

  echo "[k8s_1_apiserver ${i}/${ROUNDS}] nc -z ${APISERVER_IP}:443"
  kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- nc -z -w 1 "${APISERVER_IP}" 443 >/dev/null 2>&1 || true
done

echo "[k8s_1_apiserver] done; inspect with: hubble observe --since 5m | grep -i kube-apiserver"
