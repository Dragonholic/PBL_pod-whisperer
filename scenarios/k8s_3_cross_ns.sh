#!/usr/bin/env bash
# k8s_3_cross_ns: attempt lateral movement across namespace boundaries.
# Ensures a victim workload exists in a separate namespace (pbl-other), then
# tries to reach it from the frontend pod in pbl-security. Because the
# pbl-security NetworkPolicy set is default-deny egress (only DNS + backend:80
# are allowed), this request is expected to be DROPPED -- we still issue it so
# the DROPPED flow is captured by Hubble for the detector to classify.
set -euo pipefail

NS="${NS:-pbl-security}"
OTHER_NS="${OTHER_NS:-pbl-other}"

echo "[k8s_3_cross_ns] ensuring namespace ${OTHER_NS} and victim workload exist"
kubectl get ns "${OTHER_NS}" >/dev/null 2>&1 || kubectl create ns "${OTHER_NS}"

if ! kubectl -n "${OTHER_NS}" get deployment victim >/dev/null 2>&1; then
  kubectl -n "${OTHER_NS}" create deployment victim --image=nginx:1.27-alpine --port=80
fi
if ! kubectl -n "${OTHER_NS}" get svc victim >/dev/null 2>&1; then
  kubectl -n "${OTHER_NS}" expose deployment victim --port=80 --target-port=80
fi

echo "[k8s_3_cross_ns] waiting for victim deployment to be ready"
kubectl -n "${OTHER_NS}" rollout status deployment/victim --timeout=120s

FRONTEND="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"
echo "[k8s_3_cross_ns] frontend pod: ${FRONTEND}"

echo "[k8s_3_cross_ns] attempting frontend (${NS}) -> victim.${OTHER_NS} (expected: DROPPED by default-deny egress)"
if kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- wget -T 3 -O - "http://victim.${OTHER_NS}"; then
  echo "Unexpected success: cross-namespace egress was NOT blocked." >&2
else
  echo "[k8s_3_cross_ns] blocked as expected (or timed out); inspect the DROPPED flow in Hubble."
fi

echo "[k8s_3_cross_ns] done; inspect with: hubble observe --since 5m | grep -i ${OTHER_NS}"
