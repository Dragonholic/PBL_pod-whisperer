#!/usr/bin/env python3
"""v3 self test on the existing 120 runs: (1) options off == v2 detector, (2) signature unit check.
Writes experiments/v3_signature/results/selftest.md"""
import csv, sys
from collections import Counter, defaultdict
from pathlib import Path
ROOT = Path(__file__).resolve().parent; sys.path.insert(0, str(ROOT))
import detector as D, v3_core as C
OUT = ROOT / "experiments" / "v3_signature" / "results"; OUT.mkdir(parents=True, exist_ok=True)
runs = defaultdict(list)
for row in csv.DictReader(open(ROOT / "data" / "manifest.csv")):
    runs[row["scenario"]].append((int(row["run"]), C.parse(ROOT / row["data_file"])))
runs = {s: [r for _, r in sorted(v, key=lambda x: x[0])] for s, v in runs.items()}
base = D.build_baseline_from_records(runs["normal"])
V1 = dict(window_seconds=10, fanout_threshold=5, sensitive_ports=set(D.DEFAULT_SENSITIVE_PORTS), k_sigma=3.0)
bad = 0; n = 0
for scn, rs in runs.items():
    for r in rs:
        ref = D.detect_records(r, baseline=base, enabled_rules=C.ALL5, r4_scope=set(C.APPS), **V1)
        new, _ = C.detect3(r, base, C.ALL5, r4_scope=set(C.APPS))
        key = lambda al: sorted(((a.rule, a.src, a.dst, -1 if a.port is None else a.port, a.verdict, a.time_str) for a in al))
        n += 1; bad += key(ref) != key(new)
lines = [f"# v3 self test\n", f"- options off equals v2 detector (K2): {n - bad}/{n} runs identical alerts\n"]
sigs = C.load_yaml(ROOT / "experiments/v3_signature/signatures/signatures.yaml")["signatures"]
lines.append("\n## signature unit check (existing data, 10 runs per scenario): runs where the signature fires / alerts\n")
lines.append("| scenario | " + " | ".join(s["id"] for s in sigs) + " |\n| --- |" + " --- |" * len(sigs) + "\n")
for scn in ["normal", "fp_1", "fp_2", "fp_3", "abnormal_1", "abnormal_2", "abnormal_3", "k8s_1", "k8s_2", "k8s_3", "evasion_1", "evasion_2"]:
    cells = []
    for s in sigs:
        hit = [sum(1 for x in r if C.sig_match(s, x)) for r in runs[scn]]
        cells.append(f"{sum(1 for h in hit if h)}/{len(hit)} ({sum(hit)})")
    lines.append(f"| {scn} | " + " | ".join(cells) + " |\n")
open(OUT / "selftest.md", "w").write("".join(lines)); print("".join(lines))
