#!/usr/bin/env bash
# abnormal_4_metadata (v3): one request from the frontend pod to the cloud
# instance-metadata address 169.254.169.254:80. Mimics the "query the Cloud
# Instance Metadata API" step of the Hildegard campaign (MITRE ATT&CK T1552.005)
# in its harmless form: a kind cluster has no metadata service, so the request
# goes nowhere (default-deny egress drops it). Only the root path is requested;
# no credential path is queried and no tool is run.
set -euo pipefail

NS="${NS:-pbl-security}"
FRONTEND="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"
echo "[abnormal_4_metadata] frontend pod: ${FRONTEND}"
echo "[abnormal_4_metadata] one request to http://169.254.169.254/ (root path only)"
kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- wget -qO- -T 2 http://169.254.169.254/ >/dev/null 2>&1 || true
echo "[abnormal_4_metadata] done"
