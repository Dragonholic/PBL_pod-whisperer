# Findings — environment & Hubble visibility

Evidence gathered on 2026-10-27 against the local kind cluster built by
`install.sh` (`pbl-security`, Kubernetes v1.31.0, Cilium 1.16.3, kernel
5.15.0-1105-kvm, x86_64). All commands below were run with
`export KUBECONFIG=<base-repo>/.kubeconfig-kind`.

## 0. Isolation from the pre-existing cluster

Confirmed the isolated KUBECONFIG approach did not touch the machine's
default kubeconfig (which points at an unrelated cluster; details omitted). `unset KUBECONFIG; kubectl config current-context`
still returned the original context after setup.

`kind create cluster` (run via `install.sh` with `KUBECONFIG` exported to
`.kubeconfig-kind`) never wrote to `~/.kube/config`. All `detection/`
scripts (`collect.sh`, scenario scripts) assume `KUBECONFIG` is exported the
same way; see `README.md`.

## 1. Identity shown for node-IP / control-plane flows

**확인 필요: node IP(kubelet/apiserver) 대상 flow에서 identity가 어떻게 표시되는가?**

Probing the apiserver (`scenarios/k8s_1_apiserver.sh`) produced
flows like:

```json
{
  "IP": {"source": "10.244.1.159", "destination": "172.18.0.4"},
  "l4": {"TCP": {"destination_port": 6443, "flags": {"SYN": true}}},
  "source": {"namespace": "pbl-security", "labels": ["k8s:app=frontend", ...]},
  "destination": {"identity": 7, "labels": ["reserved:kube-apiserver", "reserved:remote-node"]},
  "verdict": "DROPPED",
  "drop_reason_desc": "POLICY_DENIED"
}
```

Key findings:

- The **destination carries no `k8s:` labels at all** (no namespace, no pod
  name) — Cilium assigns it the special **reserved identity**
  `reserved:kube-apiserver` (plus `reserved:remote-node`), not a regular pod
  identity. This is Cilium-specific: it recognizes the apiserver endpoint
  out of the box and tags it accordingly, independent of our workload's
  labels.
- `detector.py`'s `identity_of()` was updated to check for these
  `reserved:*` labels (see `reserved_identity_of()`) before falling back to
  a raw IP, so alerts read `pbl-security/frontend -> reserved:kube-apiserver:6443`
  instead of a bare, node-churn-sensitive IP address.
- **Confirmed empirically (full 10x run, `k8s_2_kubelet.sh` probing
  10250/10255 on all 3 node IPs from `frontend`)**: the identity shown
  depends on *which node* is probed relative to the prober's own node, not
  just "kubelet vs. apiserver":
  - The **worker node the `frontend` pod is actually scheduled on**
    (`172.18.0.3`) shows `reserved:host` — Cilium's identity for "this same
    node, from the local agent's point of view."
  - The **other worker node** (`172.18.0.2`, not running `frontend`) shows
    `reserved:remote-node`.
  - The **control-plane node** (`172.18.0.4`) shows **both**
    `reserved:kube-apiserver` *and* `reserved:remote-node` (same dual-label
    pattern as the k8s_1 apiserver finding above, since the apiserver and
    kubelet share the same node IP there).
  - All three are reported as `DROPPED` / `EGRESS` (blocked by the
    `pbl-security` default-deny egress policy, as expected), and
    `identity_of()`'s existing `reserved:*` priority list (`kube-apiserver`
    > `host` > `remote-node` > ...) already resolves all three cleanly, so
    **R3 (sensitive port, 10250/10255 are in `sensitive_ports`) correctly
    fires 10/10 runs** — confirmed via `detector.py detect` against
    `k8s_2_*.json`. No code change was needed for this scenario; the
    cross-session worry in STATUS.md ("not yet verified") is resolved.

## 2. Service port translation: 443 vs. 6443 (apiserver)

**확인 필요 (추가 발견):** `kubernetes.default.svc` presents port **443** as
the Service's ClusterIP port, but by the time Hubble observes the flow, the
destination has already been DNAT'd by Cilium's eBPF kube-proxy replacement
to the kind control-plane node's real IP (`172.18.0.4`, the node's Docker
bridge IP) **on port 6443**, not 443. `nc -z kubernetes.default.svc 443` and
`nc -z 10.96.0.1 443` (the apiserver ClusterIP, looked up dynamically) both
surface in Hubble as `destination_port: 6443`.

Consequence: `config.yaml`'s `sensitive_ports` list includes **both** 443
and 6443; a detector built only around the "textbook" K8s apiserver port
(443) would silently miss every apiserver probe on this cluster. This is
very likely kind-specific (a managed cluster typically fronts the apiserver
on 443 or 6443 consistently depending on distro) — worth re-checking against
any non-kind cluster.

## 3. Cross-namespace egress DROPPED flow — visible from the source side?

**확인 필요: k8s_3의 egress-DROPPED가 source 쪽에서 보이는가?**

Yes. Running `scenarios/k8s_3_cross_ns.sh` (frontend, in
`pbl-security`, reaching `victim.pbl-other`, blocked by the `pbl-security`
namespace's default-deny egress NetworkPolicy) produced a DROPPED flow
**captured by Hubble on the source (pbl-security) side**:

```json
{
  "verdict": "DROPPED",
  "drop_reason_desc": "POLICY_DENIED",
  "IP": {"source": "10.244.1.159", "destination": "10.244.2.95"},
  "l4": {"TCP": {"destination_port": 80, "flags": {"SYN": true}}},
  "source": {"namespace": "pbl-security", "labels": ["k8s:app=frontend", ...]}
}
```

The destination pod IP belongs to `pbl-other/victim`, and the flow is
visible without any `--namespace` filter on `hubble observe`. This confirms
Cilium enforces (and Hubble reports) egress policy at the source endpoint,
so a SOC watching only the `pbl-security` namespace's egress would still see
this attempted lateral movement — it does not require visibility into
`pbl-other`.

## 4. Why collecting WITHOUT `--namespace` matters (and its cost)

`abnormal_3` (the base multi-target/multi-port scan) targets node IPs
directly. A `hubble observe --namespace pbl-security` filter matches on
either endpoint being in that namespace; node IPs have no namespace at all,
so **this filter does not actually exclude node-targeted flows** in our
testing — but we deliberately avoided relying on it per the task brief, and
confirmed the cost of doing so:

Collecting with no filter at all captures substantial **cluster background
noise** unrelated to the scenario: CoreDNS health-checking the apiserver,
Falco's own flow telemetry, Hubble Relay's own node connections,
`local-path-provisioner`. For an 8-file, ~15s-window smoke test this noise
alone produced **164 distinct raw (src,dst,port) "paths"** in a naive
baseline built from just 2 normal runs.

Worse: a large fraction of that was **reply-direction flows**, where
Hubble's `destination_port` is actually the **original client's ephemeral
port** (because a reply flow has source/destination swapped). This
single effect accounted for the majority of the noise — ephemeral ports
in the tens of thousands, each looking like a distinct "new path" to a
naive R2 rule.

**Fix implemented**: `detector.py` now filters out `is_reply == true` flows
before computing baseline paths / R2 (new path) / R4 (fan-out) / R5
(frequency) keys. R1 (DROPPED) and R3 (sensitive port) are still evaluated
on all flows (a dropped flow is always the request leg; replies essentially
never land on a sensitive destination port). This reduced the 2-run normal
baseline from **164 paths down to 33** (after also folding node IPs into
`reserved:*` identities — see finding #1). See `detector.py`'s
`is_reply_flow()` docstring for the full rationale.

Remaining noise sources NOT yet filtered (documented as a TODO, not fixed in
this pass): CoreDNS/Falco/Hubble-Relay inter-component chatter is still
collected and still appears in the baseline (e.g.
`kube-system/coredns-... -> reserved:kube-apiserver:6443` legitimately
appears as "normal" because CoreDNS itself watches the apiserver). This is
accurate (it IS normal traffic) but means the baseline is cluster-wide, not
scoped to the `pbl-security` workload under test — a larger multi-run
baseline would average this out, but 2 runs is too small a sample (see
analysis.md).

## 5. DNS query names / L7 visibility

**확인 필요: DNS query 이름을 보려면 L7 가시성 어노테이션이 필요한가?**

Across all 8 smoke-test flow files, **no flow contained a
`destination_names` field or any DNS-specific L7 metadata** (no
`l7.dns.query`, no resolved names attached to the `kube-system/coredns-*`
flows). `install.sh` does not configure Cilium's DNS visibility/L7 proxy
(no `policy.cilium.io/proxy-visibility` pod annotation, no `toFQDNs` policy,
no `--enable-l7-proxy`-driven DNS parsing on this deployment). This
confirms: **yes, L7 visibility must be explicitly enabled** (via a
visibility annotation or a `toFQDNs`-based CiliumNetworkPolicy) for Hubble
to report resolved DNS query names; out of the box, DNS traffic is visible
only as plain L4 flows to `kube-system/coredns-*:53`, which is why
`collect.sh`'s `fp_2_dns_heavy` scenario exists — it exercises the
same (dest,port) path the detector actually sees (same tuple, every
different hostname queried), rather than relying on DNS name visibility
that isn't present in this setup.

## 6. Flow JSON wrapping (CLI quirk, not a K8s/Cilium finding but worth noting)

`hubble observe -o json` on this Hubble CLI/relay version (`v1.16.3`) emits
each line as `{"flow": {...}, "node_name": ..., "time": ...}`, i.e. the
actual flow fields are nested one level under `"flow"`, not at the top
level as some older examples in the wild assume. `detector.py`'s
`iter_flows()` normalizes this transparently.

## 7. Critical bug found in the full 10x run: R4 (fan-out) never fired at all

**Discovered while rebuilding the baseline and running the full report**:
before this session's fix, `detect()`'s `flow_time()` function returned
`None` for *every single flow in every file ever collected*, which silently
disabled R4 entirely (R4 is gated on `ts is not None`). Table 1 in the
smoke test correctly showed `0/2` for R4 on every scenario, but this had
been (incorrectly) read as "no fan-out scenario was in the smoke-test set"
(see the old STATUS.md item 3) rather than "R4 is dead code."

Root cause: Hubble emits **nanosecond-precision** fractional seconds in its
RFC3339 `time` field (e.g. `"2026-11-02T04:33:56.483740718Z"`, 9 fractional
digits), but Python 3.10's `datetime.fromisoformat()` (this environment's
interpreter, pre-3.11) only accepts up to **microsecond** precision (6
digits) and raises `ValueError` on anything longer — silently swallowed by
`flow_time()`'s broad `except Exception: return None`.

**Fix**: `flow_time()` now truncates the fractional-seconds component to 6
digits with a regex (`re.sub(r"(\.\d{6})\d+", r"\1", t)`) before parsing.
Verified against nanosecond, microsecond, and no-fraction timestamps.

**Impact of the fix**: R4 now fires — but almost entirely on **cluster
background noise**, not on the scenarios it was meant to catch. See finding
#8.

## 8. R4 (fan-out) is dominated by kubelet/infra background chatter, not app traffic

Once R4 was actually functional (see #7), running it against the full
120-file dataset showed it firing on **every single scenario, including
`normal` (10/10) and all three `fp_*` false-positive probes (8-10/10)** —
i.e. it looked like a useless, universally-firing rule. Inspecting the
actual alerts explained why:

```
[ALERT] ... | R4 | reserved:host -> falco/falco-9jvfn:8765              | FORWARDED
[ALERT] ... | R4 | reserved:host -> reserved:health:4240                | FORWARDED
[ALERT] ... | R4 | reserved:host -> kube-system/hubble-ui-...:8081      | FORWARDED
[ALERT] ... | R4 | reserved:host -> pbl-security/frontend:80            | FORWARDED  <- kubelet liveness probe, NOT the scan
```

The **source** of almost all R4 alerts is `reserved:host` or
`reserved:kube-apiserver` (the node's own kubelet/health-check agent),
fanning out to many different pods' probe ports (Falco's gRPC port, Cilium's
health port 4240, Hubble UI, the lab's own `frontend`/`backend`/`db`
liveness checks, etc.) within the same ~1-2s kubelet probe cycle — not
`pbl-security/frontend` (the actual compromised-pod identity under test)
scanning anything.

**Quantified across the full dataset** (`detector.py detect --rules R4`
against all 120 files): of **3016 total R4 alerts**, only **156 (5.2%)**
have `pbl-security/frontend` (or `backend`/`db`) as the source; the
remaining **2860 (94.8%)** are `reserved:host`/`reserved:kube-apiserver`
infra noise. This is because `detector.py` collects (by design, see
finding #4) without a `--namespace` filter and R4's sliding window is keyed
on *every* source identity seen, not just the lab's `known_apps` — exactly
the scoping gap already flagged (but not implemented) in STATUS.md/
analysis.md.

Practical consequence for Experiment A: raising the fan-out threshold `N`
from 5 to 10 (with `W` held at any of 5/10/30s — **W has no effect at all**
in this dataset, since the noise bursts and the real scan bursts both
cluster within a couple of seconds) nearly eliminates this false-positive
source (R4-driven FP drops from the default's contribution once N≥10),
because the background kubelet/health-check fan-out never reaches 10
distinct pairs in one window, while real multi-target scans
(`abnormal_2`/`abnormal_3`) comfortably do. See `docs/analysis.md` for the
full P/R/F1 numbers.

## 9. `evasion_1`'s slow-scan technique genuinely evades R4 (as designed) — but the scenario is still caught overall

Isolating R4 and filtering to only `pbl-security/frontend`-sourced alerts
(i.e. excluding the background noise from finding #8) shows a clean,
expected contrast:

- `abnormal_3` (fast scan, ~1s between probes): **12-14 genuine
  frontend-sourced R4 alerts per run** — real fan-out detection.
- `evasion_1` (identical target/port set, 15s between probes): **zero**
  frontend-sourced R4 alerts in any of the 10 runs. The 15s gap is wider
  than the default `window_seconds=10`, so the sliding window never
  accumulates ≥5 distinct (dst,port) pairs from `frontend` — R4 genuinely
  cannot see this scan, exactly as the scenario's docstring predicts.

However, **`evasion_1` is still flagged overall (10/10, via R1+R2+R3)**,
because every probed target/port in this lab's target list is *also*
blocked by the `pbl-security` default-deny egress NetworkPolicy (R1) and/or
a sensitive port (R3) — rules that don't care about timing at all. So in
this specific lab's threat model, defeating R4 alone is not sufficient to
evade detection; it would only matter against a detector relying on R4 as
its sole/primary signal, or against targets that are NetworkPolicy-allowed
but still sensitive (the lab's current scenario set doesn't have such a
target). This nuance is important: **do not read "evasion_1: 10/10
detected" in Table 1 as "the R4-evasion technique failed"** — it means "the
technique succeeded against R4 specifically, but other rules independently
covered the same traffic." See `docs/analysis.md` §2 for the full
breakdown.
