#!/usr/bin/env bash
# evasion_2_allowed_abuse: abuse of an *allowed* communication path
# (frontend -> backend:80) at high frequency. No NetworkPolicy violation
# (R1), no new path (R2 baseline already contains frontend->backend:80), and
# not a sensitive port (R3). This is meant to stress-test the false-positive
# rate of frequency-based rules (R5) and show that a pure allow/deny +
# fan-out detector may miss "living off the land" / allowed-path abuse unless
# a frequency rule is also enabled.
set -euo pipefail

NS="${NS:-pbl-security}"
REQUESTS="${REQUESTS:-200}"

FRONTEND="$(kubectl -n "${NS}" get pod -l app=frontend -o jsonpath='{.items[0].metadata.name}')"
echo "[evasion_2_allowed_abuse] frontend pod: ${FRONTEND}"
echo "[evasion_2_allowed_abuse] issuing ${REQUESTS} back-to-back frontend -> backend:80 requests (allowed path abuse)"

kubectl -n "${NS}" exec -c frontend "${FRONTEND}" -- sh -c "
  i=0
  while [ \$i -lt ${REQUESTS} ]; do
    wget -qO- -T 2 http://backend >/dev/null 2>&1 || true
    i=\$((i+1))
  done
"

echo "[evasion_2_allowed_abuse] done; inspect with: hubble observe --since 2m --from-pod ${NS}/${FRONTEND} --to-label app=backend | wc -l"
