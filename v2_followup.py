#!/usr/bin/env python3
"""Follow-up checks for v2 (run after v2_experiments.py), same data, no cluster.

  E0-4b  like-for-like effect of learning on fewer / other normal runs
  E0-6b  admin-port list at port level (which scan ports each list covers)
  EXPL   exploratory rule subsets. These were looked at AFTER seeing the main
         results, so they are reported as exploratory, not as chosen settings.
"""
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import detector  # noqa: E402
import v2_experiments as X  # noqa: E402

OUT = X.OUT


def main():
    runs = X.load_runs()
    scn = X.ATTACK + X.NORMAL
    full = detector.build_baseline_from_records(runs["normal"])
    rng = random.Random(X.SPLIT_SEED)
    splits = [sorted(rng.sample(range(10), 5)) for _ in range(X.N_SPLITS)]
    out = []

    # ---- E0-4b: same evaluation set, baseline from all 10 vs 5 normal runs
    rows = []
    for name, kw in (("R1-R5, R4 scoped", {"r4_scope": X.KNOWN}),):
        for rules_name, rules in (("any rule", X.ALL5), ("R2 only", ["R2"]), ("R5 only", ["R5"])):
            def flagged(base, runs_list):
                return sum(1 for r in runs_list
                           if detector.detect_records(r, baseline=base, enabled_rules=rules, **{**X.V1, **kw}))
            fp_runs = [r for s in X.FP_SCENARIOS for r in runs[s]]
            v1way = flagged(full, fp_runs)
            split_fp, split_norm = [], []
            for tr in splits:
                base = detector.build_baseline_from_records([runs["normal"][i] for i in tr])
                split_fp.append(flagged(base, fp_runs))
                split_norm.append(flagged(base, [runs["normal"][i] for i in range(10) if i not in tr]))
            m_fp, m_n = X.mean_sd(split_fp), X.mean_sd(split_norm)
            rows.append([name, rules_name, f"{v1way}/30", f"{m_fp[0]:.1f}+-{m_fp[1]:.1f}/30",
                         "0/10 (learned on)", f"{m_n[0]:.2f}+-{m_n[1]:.2f}/5 (held out)"])
    hdr = ["rules", "rule set", "fp_1-3 flagged, learn 10", "fp_1-3 flagged, learn 5", "normal flagged, learn 10", "normal flagged, learn 5"]
    X.write_csv("e0_4b_like_for_like.csv", hdr, rows)
    out.append(("E0-4b same evaluation runs, baseline learned from 10 vs 5 normal runs", X.md_table(hdr, rows)))

    # ---- E0-6b: port-level coverage
    official = {6443, 2379, 2380, 10250, 10256, 10257, 10259} | set(range(30000, 32768))
    variants = [("v1 list", X.V1["sensitive_ports"]), ("official table + NodePort", official),
                ("official + 443", official | {443}),
                ("v1 minus non-Kubernetes (22, 3306, 6379)", X.V1["sensitive_ports"] - {22, 3306, 6379})]
    scan_ports = [22, 443, 2379, 3306, 6379, 6443, 10250, 10255]
    rows = []
    for name, ports in variants:
        al = X.detect_all(runs, full, X.ATTACK, ["R3"], sensitive_ports=ports)
        ab = X.alert_level(runs, al, "B")
        rows.append([name, ab["alert_tp"], ab["covered"], ab["paths"], f"{ab['path_recall']:.3f}",
                     " ".join(f"{p}:{'Y' if p in ports else 'n'}" for p in scan_ports)])
    hdr = ["R3 list", "alerts (all true)", "malicious paths covered", "malicious paths", "path recall (B)", "scan port in list?"]
    X.write_csv("e0_6b_port_coverage.csv", hdr, rows)
    out.append(("E0-6b R3 alone at path level (policy B)", X.md_table(hdr, rows)))

    # ---- EXPL: exploratory subsets (post hoc)
    rows = []
    subsets = [("R1", ["R1"]), ("R1+R3", ["R1", "R3"]), ("R1+R3+R6", ["R1", "R3", "R6"]),
               ("R1+R5", ["R1", "R5"]), ("R1+R3+R5+R6", ["R1", "R3", "R5", "R6"]),
               ("R1+R2+R3+R5+R6", ["R1", "R2", "R3", "R5", "R6"])]
    for name, rules in subsets:
        al = X.detect_all(runs, full, scn, rules)
        rl = X.run_level(al)
        ab = X.alert_level(runs, al, "B")
        out_missed = ", ".join(s for s in X.ATTACK if rl["per"][s][0] < 10) or "none"
        fp_by = ", ".join(f"{s}:{rl['per'][s][0]}" for s in X.NORMAL if rl["per"][s][0]) or "none"
        rows.append([name, f"{rl['tp']}/80", f"{rl['fp']}/40", X.fmt(rl["precision"]), X.fmt(rl["recall"]),
                     X.fmt(ab["alert_precision"]), out_missed, fp_by])
    hdr = ["rules (exploratory, chosen after seeing results)", "attack runs flagged", "normal runs flagged", "run precision",
           "run recall", "alert precision (B)", "attack scenarios not fully caught", "normal flagged by scenario"]
    X.write_csv("expl_subsets.csv", hdr, rows)
    out.append(("EXPL exploratory rule subsets (baseline learned from all 10 normal runs, so R2/R5 are optimistic)", X.md_table(hdr, rows)))

    text = "# v2 follow-up results\n\n" + "\n".join(f"## {t}\n\n{b}\n" for t, b in out)
    (OUT / "followup.md").write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
