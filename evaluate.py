#!/usr/bin/env python3
"""
evaluate.py - turn detector.py output into the tables/plots the PBL report
needs: per-scenario detection matrix, overall precision/recall/F1, and two
sensitivity experiments (A: N/W grid, B: rule-subset ablation).

Reads data/manifest.csv (written by collect.sh), which maps each
collected flow file to its scenario, run index, and ground-truth label
(normal/attack).

Modes (see --mode):
    report        Table 1 (scenario x rule matrix) + Table 2 (overall P/R/F1)
    experiment_a  Grid over fanout_threshold (N) x window_seconds (W) -> CSV + PNG
    experiment_b  Rule-subset ablation (R1 / R1+R2 / R1-3 / R1-4) -> Recall CSV + PNG
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import defaultdict
from pathlib import Path
from typing import Dict, List, Optional

import yaml

sys.path.insert(0, str(Path(__file__).parent))
import detector  # noqa: E402


def load_config(path: str) -> dict:
    with open(path) as f:
        return yaml.safe_load(f) or {}


def load_manifest(path: str) -> List[dict]:
    rows = []
    with open(path, newline="") as f:
        for row in csv.DictReader(f):
            rows.append(row)
    return rows


def scenario_ground_truth(label: str) -> bool:
    """True if this scenario run represents an actual attack (positive class)."""
    return label.strip().lower() == "attack"


def run_detector_for_row(row: dict, baseline: Optional[dict], window_seconds: int,
                          fanout_threshold: int, sensitive_ports: set, rules: List[str],
                          k_sigma: float, r4_scope: Optional[set] = None) -> List[detector.Alert]:
    data_file = row["data_file"]
    if not Path(data_file).exists():
        print(f"WARNING: missing data file {data_file}, skipping", file=sys.stderr)
        return []
    return detector.detect(
        data_file,
        baseline=baseline,
        window_seconds=window_seconds,
        fanout_threshold=fanout_threshold,
        sensitive_ports=sensitive_ports,
        enabled_rules=rules,
        k_sigma=k_sigma,
        r4_scope=r4_scope,
    )


# --------------------------------------------------------------------------
# mode: report
# --------------------------------------------------------------------------

def mode_report(args: argparse.Namespace) -> None:
    cfg = load_config(args.config)
    manifest = load_manifest(cfg["paths"]["manifest_file"])
    baseline = detector.load_baseline(cfg["paths"]["baseline_file"])
    window_seconds = cfg["detection"]["window_seconds"]
    fanout_threshold = cfg["detection"]["fanout_threshold"]
    sensitive_ports = set(cfg["detection"]["sensitive_ports"])
    k_sigma = cfg["detection"]["frequency"]["k_sigma"]

    # Table 1: scenario x rule -> did this scenario trigger that rule at least once?
    scenario_rule_hits: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
    scenario_runs: Dict[str, int] = defaultdict(int)
    scenario_label: Dict[str, str] = {}

    # Table 2 inputs: per-run, was it flagged at all (>=1 alert) vs. ground truth?
    tp = fp = fn = tn = 0
    per_scenario_confusion = defaultdict(lambda: {"TP": 0, "FP": 0, "FN": 0, "TN": 0})

    for row in manifest:
        scenario = row["scenario"]
        label = row["label"]
        scenario_label[scenario] = label
        scenario_runs[scenario] += 1

        alerts = run_detector_for_row(row, baseline, window_seconds, fanout_threshold,
                                       sensitive_ports, detector.ALL_RULES, k_sigma,
                                       r4_scope=detector.r4_scope_from_cfg(cfg))
        rules_hit = {a.rule for a in alerts}
        for r in rules_hit:
            scenario_rule_hits[scenario][r] += 1

        is_attack = scenario_ground_truth(label)
        flagged = len(alerts) > 0
        if is_attack and flagged:
            tp += 1
            per_scenario_confusion[scenario]["TP"] += 1
        elif is_attack and not flagged:
            fn += 1
            per_scenario_confusion[scenario]["FN"] += 1
        elif not is_attack and flagged:
            fp += 1
            per_scenario_confusion[scenario]["FP"] += 1
        else:
            tn += 1
            per_scenario_confusion[scenario]["TN"] += 1

    # --- print Table 1 ---
    print("\n=== Table 1: scenario x rule detection matrix (runs triggering each rule / total runs) ===")
    header = ["scenario", "label", "runs"] + detector.ALL_RULES
    print(",".join(header))
    for scenario in sorted(scenario_runs):
        total = scenario_runs[scenario]
        row_vals = [scenario, scenario_label[scenario], str(total)]
        for r in detector.ALL_RULES:
            hits = scenario_rule_hits[scenario].get(r, 0)
            row_vals.append(f"{hits}/{total}")
        print(",".join(row_vals))

    # --- print Table 2 ---
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    print("\n=== Table 2: overall confusion matrix + P/R/F1 (any-rule-fires = flagged) ===")
    print(f"TP={tp} FP={fp} FN={fn} TN={tn}")
    print(f"Precision={precision:.3f} Recall={recall:.3f} F1={f1:.3f}")

    results_dir = Path(cfg["paths"]["results_dir"])
    results_dir.mkdir(parents=True, exist_ok=True)
    with (results_dir / "table1_scenario_rule_matrix.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(header)
        for scenario in sorted(scenario_runs):
            total = scenario_runs[scenario]
            row_vals = [scenario, scenario_label[scenario], total]
            for r in detector.ALL_RULES:
                row_vals.append(scenario_rule_hits[scenario].get(r, 0))
            w.writerow(row_vals)
    with (results_dir / "table2_overall_prf.csv").open("w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["TP", "FP", "FN", "TN", "Precision", "Recall", "F1"])
        w.writerow([tp, fp, fn, tn, f"{precision:.3f}", f"{recall:.3f}", f"{f1:.3f}"])
    print(f"\nWrote {results_dir}/table1_scenario_rule_matrix.csv and table2_overall_prf.csv")


# --------------------------------------------------------------------------
# mode: experiment_a (N x W grid)
# --------------------------------------------------------------------------

def mode_experiment_a(args: argparse.Namespace) -> None:
    cfg = load_config(args.config)
    manifest = load_manifest(cfg["paths"]["manifest_file"])
    baseline = detector.load_baseline(cfg["paths"]["baseline_file"])
    sensitive_ports = set(cfg["detection"]["sensitive_ports"])
    k_sigma = cfg["detection"]["frequency"]["k_sigma"]
    n_values = cfg["experiment_a"]["fanout_threshold_values"]
    w_values = cfg["experiment_a"]["window_seconds_values"]

    results = []
    for n in n_values:
        for w in w_values:
            tp = fp = fn = tn = 0
            for row in manifest:
                alerts = run_detector_for_row(row, baseline, w, n, sensitive_ports,
                                               detector.ALL_RULES, k_sigma,
                                               r4_scope=detector.r4_scope_from_cfg(cfg))
                is_attack = scenario_ground_truth(row["label"])
                flagged = len(alerts) > 0
                if is_attack and flagged:
                    tp += 1
                elif is_attack and not flagged:
                    fn += 1
                elif not is_attack and flagged:
                    fp += 1
                else:
                    tn += 1
            precision = tp / (tp + fp) if (tp + fp) else 0.0
            recall = tp / (tp + fn) if (tp + fn) else 0.0
            f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
            results.append({"N": n, "W": w, "TP": tp, "FP": fp, "FN": fn, "TN": tn,
                             "Precision": precision, "Recall": recall, "F1": f1})
            print(f"N={n} W={w} -> TP={tp} FP={fp} FN={fn} TN={tn} P={precision:.3f} R={recall:.3f} F1={f1:.3f}")

    results_dir = Path(cfg["paths"]["results_dir"])
    results_dir.mkdir(parents=True, exist_ok=True)
    csv_path = results_dir / "experiment_a_grid.csv"
    with csv_path.open("w", newline="") as f:
        w_ = csv.DictWriter(f, fieldnames=["N", "W", "TP", "FP", "FN", "TN", "Precision", "Recall", "F1"])
        w_.writeheader()
        w_.writerows(results)
    print(f"Wrote {csv_path}")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import numpy as np

        grid = np.zeros((len(n_values), len(w_values)))
        for r in results:
            i = n_values.index(r["N"])
            j = w_values.index(r["W"])
            grid[i, j] = r["F1"]

        fig, ax = plt.subplots()
        im = ax.imshow(grid, cmap="viridis", vmin=0, vmax=1)
        ax.set_xticks(range(len(w_values)))
        ax.set_xticklabels(w_values)
        ax.set_yticks(range(len(n_values)))
        ax.set_yticklabels(n_values)
        ax.set_xlabel("Window W (s)")
        ax.set_ylabel("Fan-out threshold N")
        ax.set_title("Experiment A: F1 over (N, W) grid")
        for i in range(len(n_values)):
            for j in range(len(w_values)):
                ax.text(j, i, f"{grid[i, j]:.2f}", ha="center", va="center", color="white")
        fig.colorbar(im, ax=ax, label="F1")
        png_path = results_dir / "experiment_a_grid.png"
        fig.savefig(png_path, bbox_inches="tight", dpi=150)
        print(f"Wrote {png_path}")
    except ImportError:
        print("matplotlib not installed; skipped PNG plot", file=sys.stderr)


# --------------------------------------------------------------------------
# mode: experiment_b (rule-subset ablation -> recall)
# --------------------------------------------------------------------------

def mode_experiment_b(args: argparse.Namespace) -> None:
    cfg = load_config(args.config)
    manifest = load_manifest(cfg["paths"]["manifest_file"])
    baseline = detector.load_baseline(cfg["paths"]["baseline_file"])
    window_seconds = cfg["detection"]["window_seconds"]
    fanout_threshold = cfg["detection"]["fanout_threshold"]
    sensitive_ports = set(cfg["detection"]["sensitive_ports"])
    k_sigma = cfg["detection"]["frequency"]["k_sigma"]
    subsets = cfg["experiment_b"]["rule_subsets"]

    results = []
    for subset in subsets:
        name = subset["name"]
        rules = subset["rules"]
        tp = fn = 0
        for row in manifest:
            if not scenario_ground_truth(row["label"]):
                continue
            alerts = run_detector_for_row(row, baseline, window_seconds, fanout_threshold,
                                           sensitive_ports, rules, k_sigma,
                                           r4_scope=detector.r4_scope_from_cfg(cfg))
            if alerts:
                tp += 1
            else:
                fn += 1
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        results.append({"subset": name, "rules": "+".join(rules), "TP": tp, "FN": fn, "Recall": recall})
        print(f"{name:10s} rules={rules} -> TP={tp} FN={fn} Recall={recall:.3f}")

    results_dir = Path(cfg["paths"]["results_dir"])
    results_dir.mkdir(parents=True, exist_ok=True)
    csv_path = results_dir / "experiment_b_ablation.csv"
    with csv_path.open("w", newline="") as f:
        w_ = csv.DictWriter(f, fieldnames=["subset", "rules", "TP", "FN", "Recall"])
        w_.writeheader()
        w_.writerows(results)
    print(f"Wrote {csv_path}")

    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt

        fig, ax = plt.subplots()
        ax.bar([r["subset"] for r in results], [r["Recall"] for r in results], color="#4C72B0")
        ax.set_ylabel("Recall")
        ax.set_ylim(0, 1)
        ax.set_title("Experiment B: Recall by rule subset (attack scenarios only)")
        png_path = results_dir / "experiment_b_ablation.png"
        fig.savefig(png_path, bbox_inches="tight", dpi=150)
        print(f"Wrote {png_path}")
    except ImportError:
        print("matplotlib not installed; skipped PNG plot", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate detector.py output against data/manifest.csv")
    parser.add_argument("--mode", choices=["report", "experiment_a", "experiment_b"], default="report")
    parser.add_argument("-c", "--config", default=str(Path(__file__).parent / "config.yaml"))
    args = parser.parse_args()

    if args.mode == "report":
        mode_report(args)
    elif args.mode == "experiment_a":
        mode_experiment_a(args)
    elif args.mode == "experiment_b":
        mode_experiment_b(args)


if __name__ == "__main__":
    main()
