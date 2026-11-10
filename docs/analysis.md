# Analysis — 오탐/미탐/한계/개선 방향

Status: **filled in from the full 10x collection matrix** (10 reps each of
all 12 scenarios: `normal`, `abnormal_1/2/3`, `k8s_1/2/3`, `evasion_1/2`,
`fp_1/2/3` — 120 runs total). This replaces the Step-3 smoke-test-only draft
(2 reps each of 4 scenarios); the smoke test itself remains committed under
`data/sample_run/` as a pipeline-correctness record.

Raw numbers below come from `results/table1_scenario_rule_matrix.csv`,
`table2_overall_prf.csv`, `experiment_a_grid.csv`, and `experiment_b_ablation.csv`,
generated from the full `data/` (manifest: 120 runs, 80 attack /
40 normal) with the baseline rebuilt from all 10 `normal` runs (30 known
paths). A significant `detector.py` bug (nanosecond-timestamp parsing,
silently disabling R4 entirely) was found and fixed during this run — see
`docs/findings.md` §7; all numbers below are post-fix.

**Headline (default config, N=5 fanout_threshold, W=10s window)**:
TP=80, FP=39, FN=0, TN=1 → **Precision=0.672, Recall=1.000, F1=0.804**.
At N=10 (still W=10s): TP=80, FP=17, FN=0, TN=23 → **Precision=0.825,
Recall=1.000, F1=0.904** — see Experiment A below for why raising N alone
is such a large, recall-free win.

## 1. 오탐 (False positives)

With all 5 rules at the default config, **FP=39 out of 40 normal/fp_\*
runs are flagged** (only 1 of 40 is a true negative). Breaking this down by
rule (Table 1):

**R4 (fan-out) is overwhelmingly the dominant FP source**, firing on
`normal` 10/10, `fp_1` 10/10, `fp_2` 8/10, `fp_3` 10/10. This is **not**
app-level fan-out at all — see `docs/findings.md` §8: across the full
dataset, 94.8% (2860/3016) of all R4 alerts are sourced from
`reserved:host`/`reserved:kube-apiserver` (kubelet/node health-check
traffic fanning out to Falco, Cilium's health port, Hubble UI, and the
lab's own pods' liveness probes), not from `pbl-security/frontend`
scanning anything. Because `detector.py` collects without a `--namespace`
filter (by design, to catch node-targeted probes) and R4's sliding window
is keyed on *every* source identity rather than only `known_apps`, this
infra noise is indistinguishable from real fan-out at the rule-firing
level. **Experiment A confirms this directly**: raising the fan-out
threshold from N=5 to N=10 drops FP from 39→17 with zero Recall cost,
because the background kubelet-probe bursts never exceed ~5-9 distinct
pairs per window while real multi-target scans comfortably exceed 10.

**R5 (frequency) false positives are real and match the design intent**:
`fp_1` (rapid legitimate `frontend→backend` health checks, 30x) triggers
R5 10/10 — inspecting the actual alert confirms it is exactly the path
`fp_1` was built to stress:
```
[ALERT] ... | R5 | pbl-security/frontend -> pbl-security/backend:80 | FREQUENCY_ANOMALY
```
This is the correctly-predicted trade-off: R5 is necessary to catch
`evasion_2`'s allowed-path abuse (see §2), but the same sensitivity means
any sufficiently bursty *legitimate* traffic on an allowed path will also
trip it. `fp_2` (DNS-heavy) shows only 1/10 R5 hits and `fp_3` (varied but
allowed, low volume) shows 0/10 — R5's FP risk is specifically tied to
*volume* on a single already-known path, not path diversity.

**R1 IPv6 NDP noise (previously found in the smoke test) did NOT reproduce**
in the full 10-run `normal` dataset: `normal` shows R1=0/10 this time (the
smoke test's single `backend -> ff02::2 DROPPED` FP was apparently a
one-off, not a reliably-reproducing background event in this cluster). The
refinement suggested in the smoke-test draft (exclude non-IPv4 protocols
from R1) is still reasonable defense-in-depth but is no longer empirically
required to explain the current FP count — R4 and R5 now fully explain it.

**R2 (new path) false positives**: `fp_2` (6/10) and `fp_1` (1/10) show
some R2 hits — DNS lookups against FQDN variants
(`backend.pbl-security.svc.cluster.local` vs. `backend`) resolve to the
same CoreDNS pod/port but Hubble's `destination_names` field is not
populated in this deployment (see findings.md §5), so these do not actually
add new (src,dst,port) tuples distinguishable from the baseline's DNS path
in a way that should trigger R2 — the 6/10 is more likely baseline-run
variance in *which* CoreDNS replica (there are 2) answered a given query,
which is a path-key stability issue, not the FQDN generalization fp_2 was
designed to test. `TODO`: key R2's baseline paths on `app=kube-dns` rather
than per-pod identity for DNS destinations to remove this noise source.

## 2. 미탐 (False negatives) and evasion analysis

Overall Recall=1.000 (FN=0) — **every attack scenario is flagged at least
once by the full 5-rule set** — but this masks an important, intentional
structural finding from Experiment B (rule-subset ablation on all 80 attack
runs):

| Subset | Rules | Recall | Missed |
|---|---|---|---|
| R1 | DROPPED only | 0.887 (71/80) | 9 `evasion_2` runs |
| R1+R2 | + new-path | 0.887 (71/80) | same 9 |
| R1-3 | + sensitive-port | 0.887 (71/80) | same 9 |
| R1-4 | + fan-out | 0.975 (78/80) | 2 `evasion_2` runs |
| R1-5 (full) | + frequency | 1.000 (80/80) | none |

This is exactly the result the lab blueprint predicts: **`evasion_2`
(200x allowed-path `frontend→backend:80` abuse) is structurally invisible
to R1/R2/R3** (nothing is DROPPED, the path is already in the baseline, 80
is not a sensitive port) and is the *only* scenario class R1-3 ever misses.
R4 incidentally catches 7 of those 9 missed runs — but inspecting those
alerts shows this is largely the same background-noise correlation as §1,
not genuine detection of the allowed-path-abuse pattern; **R5 is the rule
that genuinely and reliably closes this gap** (10/10 on `evasion_2`, firing
exactly on `frontend -> backend:80 | FREQUENCY_ANOMALY`, the real abused
path). This validates the project's central thesis: a pure allow/deny +
fan-out detector is insufficient against "living off the land" abuse of an
already-permitted path, and a frequency/volume rule is required to close
that gap.

**`evasion_1` (slow scan) partially evades R4 as designed, but the overall
scenario is still caught** — see `docs/findings.md` §9 for the full
breakdown. Isolating R4 to only `pbl-security/frontend`-sourced alerts:
`abnormal_3` (fast scan) produces 12-14 genuine fan-out alerts per run;
`evasion_1` (same targets/ports, 15s apart) produces **zero** — the 15s
gap is wider than the default 10s window, so R4 genuinely cannot see this
scan. However `evasion_1` is still flagged 10/10 overall via R1+R2+R3,
because every target in this lab's specific target list is *also* blocked
by the default-deny NetworkPolicy and/or a sensitive port — rules that
don't care about timing. **The evasion technique succeeds narrowly against
R4 specifically; it does not achieve full detection evasion in this lab's
threat model**, because the scan's targets happen to be doubly-covered by
timing-independent rules. A more sophisticated slow-scan evasion would need
to target only NetworkPolicy-*allowed*, non-sensitive destinations to fully
evade all of R1/R3/R4 — which is structurally the same gap `evasion_2`
already demonstrates (and would likewise require R5 to catch).

## 3. 한계 (Limitations)

- **[RESOLVED 2026-11-03: optional `detection.r4_scope_known_apps: true`
  in config.yaml; see §5]** R4 was not scoped to `known_apps`
  (see §1/findings.md §8) — this was, empirically, the single largest limitation:
  94.8% of all R4 alerts are cluster-infrastructure noise rather than
  signal. The `known_apps` allowlist in `config.yaml` is defined but still
  not used by `detector.py` to pre-filter sources before the fan-out
  window logic; wiring it in (treat any non-`known_apps`,
  non-attacker-controlled source's fan-out as out of scope) would likely
  push Precision close to 1.0 at the default N=5 without any Recall cost,
  based on the N=10 experiment A result already showing this direction
  works.
- **R2 DNS replica churn** (see §1) is a secondary, smaller noise source
  with the same root cause (no `known_apps`/service-level scoping).
- **Baseline size**: now rebuilt from the full 10 `normal` runs (30 known
  paths, vs. 33 from 2 runs in the smoke test) — materially more stable
  than before, but still cluster-wide (unscoped) rather than
  workload-scoped; see above.
- **R5's reliability** is now validated at a meaningful sample size (10
  baseline runs): it correctly fires on `evasion_2` (10/10, real signal)
  and `fp_1` (10/10, a real and expected trade-off), while staying mostly
  quiet on `normal` (0/10), `fp_2` (1/10), and `fp_3` (0/10). The
  R5-vs-R4-noise distinction matters: R5's hits are overwhelmingly on the
  actual path under test, unlike R4's.
- **Single-flow-per-packet DROPPED semantics**: R1 fires once per DROPPED
  packet, not once per connection attempt; a single blocked TCP handshake
  retried by `nc`/`wget` can generate 2+ near-identical R1 alerts a few ms
  apart. An alert de-duplication/aggregation pass (collapse by
  (src,dst,port) within a short window) would make the alert stream more
  operator-friendly; not implemented.
- **R1's IPv6 NDP false-positive risk did not reproduce at full scale**
  (0/10 on `normal`) but is not structurally prevented either — it remains
  a latent, environment-dependent risk (see §1) worth the same
  non-IPv4-exclusion refinement suggested previously, as defense-in-depth
  rather than an urgent fix.
- **k8s_2 (kubelet probing)**: now empirically run and confirmed to behave
  identically to k8s_1 (R1+R3, 10/10) — see `docs/findings.md` §1/§9(k8s_2
  sub-point). No surprises; the `reserved:*` identity-resolution logic
  built for the apiserver case generalized cleanly to kubelet-port probes
  against all three node roles (same-node host, remote-node, and the
  control-plane node's dual apiserver+remote-node identity).

## 4. 개선 방향 (Improvement directions)

1. **(Highest-value, now empirically justified)** Scope R4's fan-out window
   (and ideally R2's baseline-path matching) to `known_apps` plus any
   endpoint that is itself the source/destination of a `pbl-security` pod —
   this single change would eliminate the ~2860 infra-noise R4 alerts
   (94.8% of all R4 firings) while Experiment A already shows Recall stays
   at 1.000 under a stricter N, strongly suggesting Precision would land
   close to 1.0 once R4 is correctly scoped. Not implemented in this
   session (kept as a clearly-scoped follow-up, matching the existing
   `known_apps` config field that was defined for exactly this purpose).
2. Fix the R2 DNS-replica-churn noise by keying DNS destinations on the
   `kube-dns`/`coredns` app label rather than per-pod identity.
3. Exclude non-IPv4 / non-TCP-UDP protocols from R1 as defense-in-depth
   (latent risk, not currently manifesting at full scale — see §3).
4. Add alert de-duplication (collapse repeated identical (src,dst,port)
   alerts inside a short window into one).
5. **Done this session**: Experiment A re-run against the full dataset
   including `abnormal_2`, `abnormal_3`, and both `evasion_*` scenarios —
   confirms a clear, actionable N-sensitivity curve (N=5→10 nearly
   eliminates the dominant FP source at zero Recall cost); W (5/10/30s) has
   no measurable effect in this dataset, since both the real scan bursts
   and the infra-noise bursts cluster within a couple of seconds.
6. **Done this session**: Experiment B rule-subset ablation against the
   full dataset confirms the central thesis — R1-3 (any allow/deny +
   new-path + sensitive-port detector) misses `evasion_2`'s allowed-path
   abuse entirely (Recall 0.887, 9 FN), and only adding R5 closes the gap
   to Recall 1.000. This is the strongest evidence in the whole project for
   why frequency/volume-based detection is a necessary complement to
   policy-violation-based detection.

## 5. R4 `known_apps` 스코핑 실측 (2026-11-03)

`config.yaml`의 `detection.r4_scope_known_apps: true`로 R4 fan-out 윈도우를
`pbl-security/{frontend,backend,db}` 소스로 제한 (기본값 false = 위 §1~4의
기존 결과 재현). 새로 수집하지 않고 기존 120회 데이터를 오프라인 재평가
(`results_scoped/`).

| 설정 | TP | FP | FN | TN | Precision | Recall | F1 |
|---|---|---|---|---|---|---|---|
| 비스코프 N=5,W=10 (기존 기본) | 80 | 39 | 0 | 1 | 0.672 | 1.000 | 0.804 |
| 비스코프 N=10,W=10 | 80 | 17 | 0 | 23 | 0.825 | 1.000 | 0.904 |
| **스코프 N=5,W=10** | 80 | 17 | 0 | 23 | 0.825 | 1.000 | 0.904 |
| 스코프 N=3 | 80 | 37 | 0 | 3 | 0.684 | 1.000 | 0.812 |

- 스코핑만으로 N을 올리지 않고도 N=10 비스코프와 동일한 Precision 달성
  (인프라 노이즈 R4 경보 제거, Recall 비용 없음).
- **앞선 예측("Precision 1.0 근접")은 틀렸음**: 남은 FP 17건은 인프라
  노이즈가 아니라 의도적으로 만든 "정상이지만 변형된" 시나리오 —
  fp_1 10/10 (R5 빈도 규칙; 설계상 트레이드오프) + fp_2 7/10
  (R2 신규 경로 6건 / R1 1건 / R5 1건). 즉 남은 오탐은 규칙의 구조적 한계
  (정상 트래픽의 변동성)이며 스코핑으로 해결되지 않음.
- Ablation 재실험(스코프): R1, R1+R2, R1-3, R1-4 모두 Recall 0.887.
  비스코프에서는 R4가 인프라 노이즈 상관으로 evasion_2를 우연히 7건
  잡아 0.975였으나, 스코프 후 이 우연이 사라져 **R5만이 evasion_2를
  실제로 닫는다**는 가설이 더 깨끗하게 확인됨 (R1-4 0.887 → +R5 1.000).
- R4 스코프 시 k8s_2/abnormal_2/3은 10/10 유지, evasion_1은 R4 0/10
  (저속 스캔의 R4 회피는 그대로, R1+R2+R3로 탐지).
