# PBL Category 2: lateral-movement / internal-recon detection

Rule-based detection of Kubernetes lateral movement and internal
reconnaissance using Cilium Hubble flow logs, built on top of the
course testbed [cclab-inu/Practical-Cloud-Security-PBL](https://github.com/cclab-inu/Practical-Cloud-Security-PBL)
(`install.sh`, `workload/`, `category2/`). Clone that repo **next to** this
one (`../Practical-Cloud-Security-PBL`) or set `BASE_REPO=/path/to/it` when
running `collect.sh`. This repo contains only the added work: extra
scenarios, collector, detector, evaluator, results and write-ups.

Full pipeline + full dataset: 12 scenarios x 10 runs (120 runs). Headline
result (any-rule-fires): **Recall 1.000**, Precision 0.672 (default) ->
0.825 (N=10, or R4 scoped to `known_apps`). Rule-subset ablation shows
R1-R4 plateau at Recall 0.887 and only the frequency rule (R5) closes the
allowed-path-abuse gap (`evasion_2`). See `docs/analysis.md` and `STATUS.md`.

## IMPORTANT — isolated KUBECONFIG

**This machine's default `kubectl` context (`~/.kube/config`) may point at
an unrelated cluster.** Every command below — `install.sh`,
`kubectl`, `kind`, `cilium`, `hubble`, and everything in this repo —
MUST be run with an isolated kubeconfig, or you risk `kind create cluster`
rewriting your default kubeconfig's current-context:

```bash
export KUBECONFIG=$(pwd)/.kubeconfig-kind   # from the repo root
```

Run this in every new shell before touching this project. To sanity check
you haven't clobbered anything:

```bash
unset KUBECONFIG
kubectl config current-context   # should print your original context, NOT pbl-security
```

## Reproduce from scratch

```bash
git clone https://github.com/cclab-inu/Practical-Cloud-Security-PBL.git
cd Practical-Cloud-Security-PBL
chmod +x install.sh category1/*.sh category2/*.sh category3/*.sh
export KUBECONFIG=$(pwd)/.kubeconfig-kind
./install.sh                      # creates kind cluster + Cilium/Hubble + Falco + pbl-security workload
kubectl get nodes                 # expect 3 Ready
kubectl get pods -A                # expect all Running

# start a Hubble relay port-forward (collect.sh will also auto-start this if missing)
cilium hubble port-forward &
hubble status

pip3 install --user pyyaml matplotlib pandas numpy   # if not already present

# smoke test: collect a couple of runs of a few scenarios
./collect.sh normal 2
./collect.sh abnormal_1 2
./collect.sh k8s_1 2
./collect.sh k8s_3 2

# build a baseline from the normal-labeled runs
python3 detector.py baseline data/normal_1.json data/normal_2.json -o data/baseline.json

# run the detector against one flow file
python3 detector.py detect data/k8s_1_1.json -b data/baseline.json -c config.yaml

# full report (Table 1 scenario x rule matrix, Table 2 overall P/R/F1)
python3 evaluate.py --mode report

# sensitivity experiments
python3 evaluate.py --mode experiment_a   # N x W grid -> results/experiment_a_grid.{csv,png}
python3 evaluate.py --mode experiment_b   # rule-subset ablation -> results/experiment_b_ablation.{csv,png}
```

A small sample dataset from exactly this smoke test is committed under
`data/sample_run/` (8 flow-JSON files + `manifest.csv` + `baseline.json`),
so `python3 evaluate.py --mode report` reproduces the numbers in
`docs/analysis.md` without re-running the cluster, as long as you point
`config.yaml`'s `paths.manifest_file` / `paths.baseline_file` at
`data/sample_run/manifest.csv` / `data/sample_run/baseline.json` (or copy
them back into `data/`, which is what `collect.sh` writes to by default and
what is `.gitignore`d going forward — see `.gitignore`).

## Layout

```
detection/
├── scenarios/            # new attack/evasion scenario scripts (busybox nc/wget only)
├── collect.sh            # run a scenario N times, capture Hubble flow JSON + manifest.csv
├── detector.py           # rule-based detector: baseline / detect subcommands
├── evaluate.py           # report / experiment_a / experiment_b modes
├── config.yaml           # thresholds, ports, paths
├── data/                 # flow JSON + manifest.csv (gitignored; data/sample_run/ is the exception)
├── results/              # evaluate.py output tables/plots
├── docs/
│   ├── findings.md       # what we actually observed about Hubble visibility on this cluster
│   └── analysis.md       # 오탐/미탐/한계/개선 방향, from the full 10x collection
└── STATUS.md             # what's done, what's left, blockers
```

## Scenarios

| name         | source                                 | label  | what it does |
|--------------|----------------------------------------|--------|---------------|
| normal       | `category2/normal.sh`                  | normal | frontend→backend→db happy path |
| abnormal_1   | `category2/abnormal_1.sh`              | attack | frontend→db (policy-denied path) |
| abnormal_2   | `category2/abnormal_2.sh`              | attack | rapid multi-target discovery, port 80 |
| abnormal_3   | `category2/abnormal_3.sh`              | attack | multi-target, multi-port scan |
| k8s_1        | `scenarios/k8s_1_apiserver.sh`         | attack | apiserver probing |
| k8s_2        | `scenarios/k8s_2_kubelet.sh`           | attack | kubelet port probing (10250/10255) |
| k8s_3        | `scenarios/k8s_3_cross_ns.sh`          | attack | cross-namespace egress (expected DROPPED) |
| evasion_1    | `scenarios/evasion_1_slow_scan.sh`     | attack | abnormal_3's scan, 15s apart (fan-out evasion) |
| evasion_2    | `scenarios/evasion_2_allowed_abuse.sh` | attack | 200x abuse of an allowed path |
| fp_1/fp_2/fp_3 | inline functions in `collect.sh`     | normal | false-positive probes (see `collect.sh` header) |

## Detection rules (`detector.py`)

- **R1** policy violation: `verdict == "DROPPED"`
- **R2** new path: `(src app, dst, port)` not in the baseline
- **R3** sensitive port: destination port in a control-plane/data-plane set
  (includes both 443 and 6443 — see `docs/findings.md` §2 for why)
- **R4** fan-out: ≥N distinct (dest,port) pairs from one source within W
  seconds (defaults N=5, W=10s)
- **R5** (optional) frequency: same-path count in a window ≥ baseline mean +
  kσ

## Status

Collection, detector and experiments are complete; see `STATUS.md` for
details. Optional R4 scoping: set `detection.r4_scope_known_apps: true` in
`config.yaml` (results in `results_scoped/`, analysis in `docs/analysis.md` §5).
Remaining: slides/video and submission.
