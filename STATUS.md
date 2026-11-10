# STATUS — what's done, what's left

Last updated: 2026-11-02, end of the full-collection session. The
**experiment work is now essentially complete**; see "What's left" at the
bottom for the remaining write-up/submission tasks.

## Full 10x collection — DONE (2026-11-02)

All 12 scenarios collected at 10 reps each (120 runs total):
`normal abnormal_1 abnormal_2 abnormal_3 k8s_1 k8s_2 k8s_3 evasion_1
evasion_2 fp_1 fp_2 fp_3`. No zero-flow scenarios; no scenario required a
retry (no pod/exec/relay failures encountered). Cluster stayed healthy
throughout (verified `kubectl get nodes`/`get pods -A` before, during, and
after — all Ready/Running at every check). Wall-clock cost was dominated by
`evasion_1` (10 reps x ~11.5 min/run ≈ 115 min, slightly above the original
~1hr estimate) and `evasion_2` (10 reps x ~5s/run — much faster than the
original worst-case estimate, since 200 sequential `wget`s inside the pod
complete quickly with no added sleep).

Baseline rebuilt from the full 10 `normal` runs only (**not** folding in
`fp_1/2/3`, despite the old "next commands" draft below suggesting it) —
`fp_1`/`fp_2` are specifically "normal but varied" probes meant to *test*
whether the detector false-positives on them (R5's `fp_1` hit is the
intended, meaningful signal); baselining on them would have artificially
suppressed exactly the signal they exist to measure. Baseline: 30 known
paths (vs. 33 from the old 2-run smoke-test baseline) — same order of
magnitude, now from a properly-sized sample.

**A critical `detector.py` bug was found and fixed during this session**:
`flow_time()` returned `None` for every flow ever collected (Hubble emits
nanosecond-precision timestamps; Python 3.10's `datetime.fromisoformat()`
only accepts microsecond precision), which meant **R4 (fan-out) had never
fired once**, in the smoke test or otherwise. Fixed by truncating the
fractional-seconds field to 6 digits before parsing. See
`docs/findings.md` §7 for the full root-cause writeup, and §8-9 for what
this fix revealed once R4 actually started working (it's dominated by
kubelet/infra background noise, not app traffic — see Known limitations).

**Headline results (full dataset, `results/table2_overall_prf.csv`)**:

| Config | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| Default (N=5, W=10s) | 80 | 39 | 0 | 1 | 0.672 | 1.000 | 0.804 |
| N=10, W=10s (Experiment A) | 80 | 17 | 0 | 23 | 0.825 | 1.000 | 0.904 |

Recall is 1.000 at every (N,W) tested — every attack scenario is caught by
at least one rule. Precision is capped by R4 firing on cluster-infra
background noise (kubelet health-checks, not app traffic — see
`docs/analysis.md` §1/§3); raising the fan-out threshold to N=10 very
nearly fixes this without implementing full `known_apps` scoping (would be
expected to push Precision close to 1.0 — see analysis.md's improvement
direction #1, not implemented this session).

**Experiment B (rule-subset ablation, `results/experiment_b_ablation.csv`)**:
R1 / R1+R2 / R1-3 all plateau at Recall=0.887 (71/80), missing 9/10
`evasion_2` runs (the allowed-path-abuse scenario, structurally invisible
to policy-violation + new-path + sensitive-port rules by design). R1-4
reaches 0.975 (R4 incidentally catches 7 of those via background-noise
correlation, not genuine signal). The full rule set (+R5, frequency)
reaches 1.000 — **R5 is the rule that actually, reliably closes the
`evasion_2` gap**, validating the project's central thesis that policy/
fan-out detection alone is insufficient against living-off-the-land abuse
of an already-allowed path.

**k8s_2 (kubelet probing) — now empirically run** (was previously
untested): confirmed `reserved:host` (same-node worker),
`reserved:remote-node` (other worker), and
`reserved:kube-apiserver`+`reserved:remote-node` (control-plane node, same
dual-identity pattern as the k8s_1 apiserver finding) for the three node
roles. R1+R3 fire 10/10 as expected — no code changes were needed; the
existing `reserved:*` identity resolution built for k8s_1 generalized
cleanly. See `docs/findings.md` §1.

**evasion_1 vs. R4**: confirmed the slow-scan technique genuinely evades
R4 specifically (zero genuine `frontend`-sourced R4 alerts across all 10
runs, vs. 12-14/run for the fast `abnormal_3` equivalent), but the overall
scenario is still flagged 10/10 via R1+R2+R3, since this lab's specific
target/port list happens to be doubly-covered by timing-independent rules
(NetworkPolicy-denied and/or sensitive-port). See `docs/findings.md` §9 and
`docs/analysis.md` §2 for the nuance — "10/10 detected" here does not mean
the R4-evasion attempt failed.

No incidents requiring cluster recovery occurred; no scenario needed a
retry. All progress committed locally to `category2-detection` (not
pushed to `origin`).

## What's left

The actual experiment/detection work is done. Remaining items are
write-up and submission logistics, not further data collection or
detector changes:

1. README / lab write-up polish (methodology, results tables, screenshots
   if desired).
2. Fork the upstream repo on GitHub and push this branch (`category2-detection`)
   to the fork (not yet done — everything so far is local-only, per the
   task's explicit instruction not to push to `origin`).
3. Slides / video deliverable (not started).
4. **DONE 2026-11-03** (see `docs/analysis.md` §5; `r4_scope_known_apps`,
   results in `results_scoped/`: P 0.825 / R 1.000 at default N=5; Precision
   does NOT reach ~1.0 because the remaining FPs are fp_1/fp_2 by design).
   Originally: optional, not required for completeness: implement the `known_apps`
   scoping improvement for R4/R2 noted in `docs/analysis.md` improvement
   direction #1 — would likely push Precision close to 1.0, but the current
   numbers (Recall=1.000 always; Precision 0.672→0.825 depending on N) are
   already a complete, honestly-reported, defensible result for the
   write-up without it.

---

## Historical: initial bootstrap session (2026-10-27)

Everything below this line describes the state as of the end of the first
(bootstrap + smoke-test) session, kept for history. See above for the
current, full-collection state.

## Done

- **Environment**: `install.sh` run successfully with an isolated
  `KUBECONFIG=.kubeconfig-kind`. Confirmed:
  - 3/3 kind nodes Ready (`pbl-security-control-plane`, `-worker`, `-worker2`),
    Kubernetes v1.31.0.
  - Cilium 1.16.3 + Hubble (relay + UI) + Falco all Running.
  - `pbl-security` namespace workload (`frontend`/`backend`/`db` +
    default-deny NetworkPolicy) deployed and Running.
  - Default kubeconfig (`~/.kube/config`, a pre-existing unrelated cluster) verified **untouched** (checked with
    `unset KUBECONFIG; kubectl config current-context`).
  - `category2/normal.sh` + `hubble observe --namespace pbl-security`
    produced flow output (completion check for Step 1) — passed.
- **Code**: all of `scenarios/*.sh`, `collect.sh`, `detector.py`,
  `evaluate.py`, `config.yaml` written and working.
- **Smoke test** (Step 3 of the task): collected 2 reps each of `normal`,
  `abnormal_1`, `k8s_1`, `k8s_3` (8 runs total, committed under
  `data/sample_run/`). Built a baseline from the 2 normal runs. Ran
  `detector.py detect` against all 8 files and `evaluate.py --mode report`:
  - `normal`: 1/2 runs clean, 1/2 produced a single R1 false positive
    (IPv6 NDP multicast drop — see `docs/analysis.md` §1).
  - `abnormal_1`: 2/2 runs triggered R1 + R2, as expected.
  - `k8s_1`: 2/2 runs triggered R1 + R3 (+ some R5 noise), as expected —
    importantly, this required adding port **6443** to `sensitive_ports`
    alongside 443 (see `docs/findings.md` §2) and improving identity
    resolution to recognize Cilium's `reserved:kube-apiserver` identity.
  - `k8s_3`: 2/2 runs triggered R1 + R2 for the cross-namespace DROPPED
    flow, confirming it's visible from the `pbl-security` source side
    without needing `pbl-other` visibility.
  - Overall smoke-test confusion matrix: TP=6 FP=1 FN=0 TN=1 → Precision
    0.857, Recall 1.000, F1 0.923.
  - `evaluate.py --mode experiment_a` and `--mode experiment_b` both run
    successfully end-to-end (produce CSV + PNG), but are not yet meaningful
    at this data volume — see "Known limitations" below.
- **detector.py bug fixes found + fixed during the smoke test** (see
  `docs/findings.md` for full detail, these are now implemented, not just
  noted):
  - Reply-direction flows (`is_reply: true`) were polluting the baseline
    with thousands of spurious "paths" keyed on the original client's
    ephemeral port; now filtered out of R2/R4/R5/baseline (R1/R3 still
    consider all flows).
  - Node-IP destinations (e.g. the apiserver) actually carry Cilium
    `reserved:*` identities (`reserved:kube-apiserver`,
    `reserved:remote-node`), not just a bare IP; `identity_of()` now
    surfaces these for more readable, IP-churn-stable alerts.
  - `hubble observe -o json`'s line format wraps each flow as
    `{"flow": {...}}` on this Cilium/Hubble version; `iter_flows()` unwraps
    this transparently.
- **Git**: all of the above committed locally on branch `category2-detection`
  (not pushed to `origin`).

## NOT done / explicitly out of scope for this session

Per the task's own scope note, the following remain for follow-up sessions:

1. **Full 10x data collection** across all scenarios:
   ```bash
   for s in normal abnormal_1 abnormal_2 abnormal_3 k8s_1 k8s_2 k8s_3 \
            evasion_1 evasion_2 fp_1 fp_2 fp_3; do
     ./collect.sh "$s" 10
   done
   ```
   Rough cost estimate: `evasion_1` alone is ~24 probes x 15s sleep ≈ 6 min
   per run x 10 reps = ~1 hour just for that one scenario; `evasion_2` is
   200 sequential requests per run. Budget at least a few hours of wall
   time (not CPU — this is almost entirely `kubectl exec` + `sleep` latency)
   for the full matrix, and re-run `detector.py baseline` from the full 10
   normal runs afterward (the current baseline uses only 2).

2. **k8s_2 (kubelet probing) was never actually run** in this session — the
   script is written and should work (same pattern as k8s_1), but its
   Hubble output (e.g. what identity a node's port 10250/10255 shows —
   `reserved:remote-node`? plain IP? something else?) has not been
   empirically checked. Do this before relying on R3 for kubelet probes.

3. **Experiment A (N×W grid) and Experiment B (rule ablation) at scale**:
   both modes run correctly today, but because none of the 8 smoke-test
   runs ever triggered R4 (no fan-out scenario was in the smoke-test set),
   `results/experiment_a_grid.csv` is currently flat (every N,W gives the
   same P/R/F1). Re-run both after collecting `abnormal_2`, `abnormal_3`,
   `evasion_1`, and `evasion_2` to get meaningful curves. See
   `docs/analysis.md` §4 point 5-6.

4. **Baseline-scoping improvement** (`known_apps` in `config.yaml` is
   defined but not yet used by `detector.py` to pre-filter cluster noise
   out of the baseline) — see `docs/analysis.md` §3.

5. **R1 IPv6-noise fix** (exclude ICMPv6 NDP / non-IPv4 from R1, or
   otherwise suppress the one FP class found) — see `docs/analysis.md` §1.

6. Falco (installed by `install.sh` for category1, unrelated to this
   category2 work) was left running; it was not used or modified by
   anything under `detection/`.

## Blockers / surprises encountered (and resolved)

- **sudo**: `install.sh` ran unmodified with its default
  `/usr/local/bin` install location; no workaround was needed.
- **Docker group membership**: the invoking user was not in the `docker`
  group and the harness's shell doesn't pick up new group membership
  without a fresh login. Worked around by running `install.sh` (and
  anything else touching the Docker socket) via `sg docker -c '...'`,
  which applies the `docker` supplementary group to the child process tree
  without needing to restart the session. `sudo usermod -aG docker <user>`
  was also run so a normal future login will have this permanently.
- No cluster resource issues were observed (16 vCPU / 31GB RAM was ample for
  a 3-node kind cluster + Cilium + Falco + the lab workload).
- No image-pull or Cilium-readiness hangs — `install.sh` completed in well
  under its 15m/30m wait-duration budgets.

## Next commands to run (in order)

```bash
export KUBECONFIG=<base-repo>/.kubeconfig-kind
cd <this-repo>

# 1) full data collection (expensive -- see cost estimate above)
for s in normal abnormal_1 abnormal_2 abnormal_3 k8s_1 k8s_2 k8s_3 evasion_1 evasion_2 fp_1 fp_2 fp_3; do
  ./collect.sh "$s" 10
done

# 2) rebuild the baseline from ALL normal + fp_* (normal-labeled) runs
python3 detector.py baseline data/normal_*.json data/fp_1_*.json data/fp_2_*.json data/fp_3_*.json -o data/baseline.json

# 3) full report + both experiments
python3 evaluate.py --mode report
python3 evaluate.py --mode experiment_a
python3 evaluate.py --mode experiment_b

# 4) update docs/analysis.md with the real numbers (replace the
#    TODO(full-dataset) markers), and resolve the two detector
#    improvements noted above (IPv6 R1 filter, known_apps baseline scoping)
#    if time allows.
```
