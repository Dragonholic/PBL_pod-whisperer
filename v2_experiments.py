#!/usr/bin/env python3
"""v2 experiments on the existing 120 runs (no cluster needed).

  E0-1  precision at a realistic attack share
  E0-2  evaluation unit and label policy (run / alert / path, policies A and B)
  E0-3  alert aggregation into incidents
  E0-4  learning vs evaluation split of the normal runs
  E0-5  R5 sensitivity (k sigma x number of learning runs)
  E0-6  sensitive-port list (R3)
  E2-1  consecutive failed first contacts (R6)
  E2-2  R4 fan-out: threshold N x window W (x scope)
  COMBO four rule combinations fixed before looking at any result

Usage: python3 v2_experiments.py        (writes experiments/v2_research/results/)
Rule names: R1 blocked connection, R2 new path, R3 admin port, R4 fan-out,
R5 request count, R6 consecutive failures. See experiments/v2_research/DESIGN.md.
"""
import csv
import random
import statistics
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import detector  # noqa: E402

OUT = ROOT / "experiments" / "v2_research" / "results"
OUT.mkdir(parents=True, exist_ok=True)

FE = "pbl-security/frontend"
KNOWN = {f"pbl-security/{a}" for a in ("frontend", "backend", "db")}
ATTACK = ["abnormal_1", "abnormal_2", "abnormal_3", "k8s_1", "k8s_2", "k8s_3", "evasion_1", "evasion_2"]
NORMAL = ["normal", "fp_1", "fp_2", "fp_3"]
FP_SCENARIOS = ["fp_1", "fp_2", "fp_3"]
SCAN_PORTS = {22, 443, 2379, 10250, 3306, 6379}
ALL5 = ["R1", "R2", "R3", "R4", "R5"]
SPLIT_SEED = 20261105
N_SPLITS = 30

cfg = detector.load_config(str(ROOT / "config.yaml"))
V1 = dict(
    window_seconds=cfg["detection"]["window_seconds"],
    fanout_threshold=cfg["detection"]["fanout_threshold"],
    sensitive_ports=set(cfg["detection"]["sensitive_ports"]),
    k_sigma=cfg["detection"]["frequency"]["k_sigma"],
)

configs_tried = []  # every (experiment, setting) evaluated, reported at the end


# ----------------------------------------------------------------- data
def load_runs():
    runs = defaultdict(list)
    with open(ROOT / "data" / "manifest.csv", newline="") as f:
        for row in csv.DictReader(f):
            runs[row["scenario"]].append((int(row["run"]), detector.flow_records(str(ROOT / row["data_file"]))))
    return {s: [r for _, r in sorted(v, key=lambda x: x[0])] for s, v in runs.items()}


def detect_all(runs, baseline, scenarios, rules, **kw):
    kw = {**V1, **kw}
    return {s: [detector.detect_records(r, baseline=baseline, enabled_rules=rules, **kw) for r in runs[s]]
            for s in scenarios}


# --------------------------------------------------------------- metrics
def prf(tp, fp, fn):
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return p, r, f


def run_level(alerts, rules=None):
    """A run is flagged if it has at least one alert (optionally only of `rules`)."""
    tp = fp = fn = tn = 0
    per = {}
    for s, lst in alerts.items():
        flagged = sum(1 for al in lst if any(rules is None or a.rule in rules for a in al))
        per[s] = (flagged, len(lst))
        if s in ATTACK:
            tp += flagged
            fn += len(lst) - flagged
        else:
            fp += flagged
            tn += len(lst) - flagged
    p, r, f = prf(tp, fp, fn)
    return dict(tp=tp, fp=fp, fn=fn, tn=tn, precision=p, recall=r, f1=f, per=per)


def label(policy, scn, src, dst, port):
    """Ground-truth label of one flow / alert, set from the scenario scripts
    (independent of the detector). Policy A: every frontend-origin flow in an
    attack run. Policy B: only the flows the script aims at its targets."""
    if scn not in ATTACK or src != FE:
        return False
    if policy == "A":
        return True
    if scn == "abnormal_1":
        return dst == "pbl-security/db"
    if scn == "abnormal_2":
        return port == 80 and not dst.startswith("kube-system/")
    if scn in ("abnormal_3", "evasion_1"):
        return port in SCAN_PORTS
    if scn == "k8s_1":
        return port in (443, 6443)
    if scn == "k8s_2":
        return port in (10250, 10255)
    if scn == "k8s_3":
        return dst.startswith("pbl-other/")
    if scn == "evasion_2":
        return dst == "pbl-security/backend" and port == 80
    return False


def alert_level(runs, alerts, policy, rules=None):
    """Alert precision and malicious-path coverage (paths = (src,dst,port))."""
    tp = fp = mal_paths = covered_paths = 0
    for s, lst in alerts.items():
        for recs, al in zip(runs[s], lst):
            al = [a for a in al if rules is None or a.rule in rules]
            for a in al:
                if label(policy, s, a.src, a.dst, a.port):
                    tp += 1
                else:
                    fp += 1
            if s in ATTACK:
                mal = {(r.src, r.dst, r.port) for r in recs if not r.reply and label(policy, s, r.src, r.dst, r.port)}
                cov = {(a.src, a.dst, a.port) for a in al}
                mal_paths += len(mal)
                covered_paths += len(mal & cov)
    return dict(alert_tp=tp, alert_fp=fp, alert_precision=tp / (tp + fp) if tp + fp else 0.0,
                paths=mal_paths, covered=covered_paths, path_recall=covered_paths / mal_paths if mal_paths else 0.0)


def mean_sd(xs):
    return (statistics.mean(xs), statistics.pstdev(xs)) if xs else (0.0, 0.0)


def fmt(x, nd=3):
    return f"{x:.{nd}f}"


def md_table(headers, rows):
    lines = ["| " + " | ".join(headers) + " |", "| " + " | ".join("---" for _ in headers) + " |"]
    lines += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(lines)


def write_csv(name, headers, rows):
    with open(OUT / name, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(headers)
        w.writerows(rows)


summary = []  # markdown sections


def section(title, body):
    summary.append(f"## {title}\n\n{body}\n")
    print(f"\n## {title}\n\n{body}\n")


# ------------------------------------------------------------------ main
def main():
    runs = load_runs()
    all_scn = ATTACK + NORMAL
    full_baseline = detector.build_baseline_from_records(runs["normal"])
    stored = detector.load_baseline(str(ROOT / "data" / "baseline.json"))
    assert full_baseline == stored or set(full_baseline["paths"]) == set(stored["paths"]), "baseline differs from data/baseline.json"

    # reference runs of the v1 settings (unscoped and scoped) on all 120 runs
    v1 = detect_all(runs, full_baseline, all_scn, ALL5)
    v1s = detect_all(runs, full_baseline, all_scn, ALL5, r4_scope=KNOWN)
    configs_tried.extend([("ref", "v1 default"), ("ref", "v1 scoped")])
    m1, m1s = run_level(v1), run_level(v1s)
    section("Reference (v1, recomputed)", md_table(
        ["setting", "TP", "FP", "FN", "TN", "precision", "recall", "F1"],
        [["v1 default", m1["tp"], m1["fp"], m1["fn"], m1["tn"], fmt(m1["precision"]), fmt(m1["recall"]), fmt(m1["f1"])],
         ["v1 R4 scoped", m1s["tp"], m1s["fp"], m1s["fn"], m1s["tn"], fmt(m1s["precision"]), fmt(m1s["recall"]), fmt(m1s["f1"])]]))
    assert (m1["tp"], m1["fp"], m1["fn"], m1["tn"]) == (80, 39, 0, 1), "v1 reference not reproduced"

    # ---------------------------------------------------------- E0-1
    rows = []
    for name, m in (("default", m1), ("R4 scoped / N=10", m1s)):
        tpr, fpr = m["tp"] / (m["tp"] + m["fn"]), m["fp"] / (m["fp"] + m["tn"])
        for p in (2 / 3, 0.1, 0.01, 0.001):
            rows.append([name, fmt(tpr), fmt(fpr), fmt(p, 4), fmt(tpr * p / (tpr * p + fpr * (1 - p)), 4)])
    write_csv("e0_1_base_rate.csv", ["setting", "TPR", "FPR", "attack_share", "precision"], rows)
    section("E0-1 precision at a realistic attack share (direction only, unit = run)",
            md_table(["setting", "TPR", "FPR", "attack share", "precision"], rows))
    configs_tried.append(("E0-1", "2 settings x 4 shares"))

    # ---------------------------------------------------------- E0-2
    rows = []
    sets = [("R1-R5 (v1 default)", v1, None), ("R1-R5, R4 scoped", v1s, None)]
    for rule in ALL5:
        sets.append((f"{rule} alone", v1, {rule}))
    for name, al, rules in sets:
        rl = run_level(al, rules)
        for pol in ("A", "B"):
            a = alert_level(runs, al, pol, rules)
            rows.append([name, pol, fmt(rl["precision"]), fmt(rl["recall"]), a["alert_tp"], a["alert_fp"],
                         fmt(a["alert_precision"]), a["covered"], a["paths"], fmt(a["path_recall"])])
    hdr = ["rules", "label policy", "run precision", "run recall", "alert TP", "alert FP", "alert precision",
           "malicious paths covered", "malicious paths", "path recall"]
    write_csv("e0_2_unit_and_label.csv", hdr, rows)
    section("E0-2 evaluation unit and label policy (A: all frontend flows in attack runs, B: only flows aimed at the scenario targets)",
            md_table(hdr, rows))
    configs_tried.append(("E0-2", f"{len(sets)} rule sets x 2 policies"))

    # ---------------------------------------------------------- E0-3
    def ts_of(a):
        return detector.flow_time({"time": a.time_str}) or 0.0

    def incidents(alerts, window):
        last, out = {}, []
        for a in sorted(alerts, key=ts_of):
            key, t = (a.rule, a.src, a.dst, a.port), ts_of(a)
            if window > 0 and key in last and t - last[key] <= window:
                last[key] = t
                continue
            out.append(a)
            last[key] = t
        return out

    rows = []
    for name, al in (("R1-R5 (v1 default)", v1), ("R1-R5, R4 scoped", v1s)):
        total_alerts = sum(len(a) for lst in al.values() for a in lst)
        for window in (0, 2, 120):
            n_inc = tp_inc = 0
            for s, lst in al.items():
                for a_list in lst:
                    inc = incidents(a_list, window)
                    n_inc += len(inc)
                    tp_inc += sum(1 for a in inc if label("B", s, a.src, a.dst, a.port))
            rows.append([name, window, total_alerts, n_inc, fmt(1 - n_inc / total_alerts, 4),
                         fmt(tp_inc / n_inc if n_inc else 0.0)])
    hdr = ["rules", "merge window (s)", "alerts", "incidents", "reduction", "incident precision (policy B)"]
    write_csv("e0_3_aggregation.csv", hdr, rows)
    section("E0-3 alert aggregation (same rule, source, destination, port merged within the window)", md_table(hdr, rows))
    configs_tried.append(("E0-3", "2 rule sets x 3 windows"))

    # ---------------------------------------------------------- E0-4 / COMBO split protocol
    rng = random.Random(SPLIT_SEED)
    splits = [sorted(rng.sample(range(10), 5)) for _ in range(N_SPLITS)]

    def split_eval(rules, **kw):
        """Learn from 5 of the 10 normal runs, evaluate on the other 5 + fp_1..3 + all attacks."""
        held_fp, held_rate, recall, a_prec = [], [], [], []
        by_rule = defaultdict(list)
        for tr in splits:
            base = detector.build_baseline_from_records([runs["normal"][i] for i in tr])
            held = [runs["normal"][i] for i in range(10) if i not in tr]
            ev = {"normal": held, **{s: runs[s] for s in FP_SCENARIOS}}
            al_n = {s: [detector.detect_records(r, baseline=base, enabled_rules=rules, **{**V1, **kw}) for r in rs]
                    for s, rs in ev.items()}
            n_runs = sum(len(v) for v in al_n.values())
            flagged = sum(1 for lst in al_n.values() for al in lst if al)
            held_fp.append(flagged)
            held_rate.append(flagged / n_runs)
            for rule in rules:
                by_rule[rule].append(sum(1 for lst in al_n.values() for al in lst if any(a.rule == rule for a in al)))
            al_a = detect_all(runs, base, ATTACK, rules, **kw)
            m = run_level(al_a)
            recall.append(m["recall"])
            tp = sum(1 for s, lst in al_a.items() for recs, al in zip(runs[s], lst) for a in al if label("B", s, a.src, a.dst, a.port))
            fp = sum(len(al) for al in (x for lst in al_n.values() for x in lst)) + \
                sum(1 for s, lst in al_a.items() for recs, al in zip(runs[s], lst) for a in al if not label("B", s, a.src, a.dst, a.port))
            a_prec.append(tp / (tp + fp) if tp + fp else 0.0)
        return dict(fp_rate=mean_sd(held_rate), fp_runs=mean_sd(held_fp), recall=mean_sd(recall),
                    alert_precision=mean_sd(a_prec), by_rule={k: mean_sd(v) for k, v in by_rule.items()})

    rows = []
    for name, kw in (("R1-R5 (v1 default)", {}), ("R1-R5, R4 scoped", {"r4_scope": KNOWN})):
        sp = split_eval(ALL5, **kw)
        full = run_level(detect_all(runs, full_baseline, ["normal"] + FP_SCENARIOS, ALL5, **kw))
        n_eval = sum(len(runs[s]) for s in ["normal"] + FP_SCENARIOS)
        rows.append([name, "learn = evaluate (v1 way)", f"{full['fp']}/{n_eval}", fmt(full["fp"] / n_eval), "-", "-", "-"])
        rows.append([name, f"learn 5 / evaluate 5 + fp (mean over {N_SPLITS} splits)",
                     f"{sp['fp_runs'][0]:.1f}+-{sp['fp_runs'][1]:.1f}/35", f"{sp['fp_rate'][0]:.3f}+-{sp['fp_rate'][1]:.3f}",
                     f"R2 {sp['by_rule']['R2'][0]:.1f}", f"R5 {sp['by_rule']['R5'][0]:.1f}", f"R4 {sp['by_rule']['R4'][0]:.1f}"])
        configs_tried.append(("E0-4", name))
    hdr = ["rules", "protocol", "flagged normal runs", "false-alarm run rate", "flagged by R2", "flagged by R5", "flagged by R4"]
    write_csv("e0_4_learn_eval_split.csv", hdr, rows)
    section("E0-4 learning vs evaluation split (normal runs flagged, any rule)", md_table(hdr, rows))

    # ---------------------------------------------------------- E0-5
    rows = []
    rng5 = random.Random(SPLIT_SEED + 5)
    for n in (3, 5, 10):
        n_rep = 1 if n == 10 else 20
        picks = [list(range(10))] if n == 10 else [sorted(rng5.sample(range(10), n)) for _ in range(n_rep)]
        for k in (2, 3, 4, 5):
            fpr_l, ev2_l, att_l = [], [], []
            for pick in picks:
                base = detector.build_baseline_from_records([runs["normal"][i] for i in pick])
                held = [runs["normal"][i] for i in range(10) if i not in pick]
                ev = {s: runs[s] for s in FP_SCENARIOS}
                if held:
                    ev["normal"] = held
                al_n = {s: [detector.detect_records(r, baseline=base, enabled_rules=["R5"], **{**V1, "k_sigma": k}) for r in rs]
                        for s, rs in ev.items()}
                nr = sum(len(v) for v in al_n.values())
                fpr_l.append(sum(1 for lst in al_n.values() for al in lst if al) / nr)
                al_a = detect_all(runs, base, ATTACK, ["R5"], k_sigma=k)
                ev2_l.append(sum(1 for al in al_a["evasion_2"] if al) / len(al_a["evasion_2"]))
                att_l.append(sum(1 for lst in al_a.values() for al in lst if al) / 80)
            configs_tried.append(("E0-5", f"n={n} k={k}"))
            rows.append([n, k, "fp_1-3" + (" + held-out normal" if n < 10 else " only (no held-out normal)"),
                         f"{mean_sd(fpr_l)[0]:.3f}+-{mean_sd(fpr_l)[1]:.3f}",
                         f"{mean_sd(ev2_l)[0]:.2f}+-{mean_sd(ev2_l)[1]:.2f}", f"{mean_sd(att_l)[0]:.3f}+-{mean_sd(att_l)[1]:.3f}"])
    hdr = ["learning runs", "k sigma", "false-alarm set", "R5 false-alarm run rate", "R5 detects evasion_2", "R5 detects any attack"]
    write_csv("e0_5_r5_sensitivity.csv", hdr, rows)
    section("E0-5 request-count rule (R5 only): k sigma x learning runs (20 random subsets for n<10)", md_table(hdr, rows))

    # ---------------------------------------------------------- E0-6
    official = {6443, 2379, 2380, 10250, 10256, 10257, 10259} | set(range(30000, 32768))
    variants = [("v1 list", V1["sensitive_ports"]),
                ("official table + NodePort range", official),
                ("official table + NodePort + 443", official | {443}),
                ("v1 list minus non-Kubernetes ports (22, 3306, 6379)", V1["sensitive_ports"] - {22, 3306, 6379})]
    rows = []
    for name, ports in variants:
        al = detect_all(runs, full_baseline, all_scn, ["R3"], sensitive_ports=ports)
        rl = run_level(al)
        ab = alert_level(runs, al, "B")
        per = ", ".join(f"{s}:{rl['per'][s][0]}" for s in ATTACK if rl["per"][s][0])
        rows.append([name, rl["tp"], rl["fp"], fmt(ab["alert_precision"]), per or "none"])
        configs_tried.append(("E0-6", name))
    hdr = ["R3 port list", "attack runs flagged (of 80)", "normal runs flagged (of 40)", "alert precision (B)", "attack runs flagged by scenario"]
    write_csv("e0_6_port_list.csv", hdr, rows)
    section("E0-6 admin-port list (R3 only)", md_table(hdr, rows))

    # ---------------------------------------------------------- E2-1 R6
    rows, attempts_rows = [], []
    for name, rules, kw in (("R6 alone", ["R6"], {}),
                            ("R6 alone, scoped", ["R6"], {"r6_scope": KNOWN}),
                            ("R4 alone (v1)", ["R4"], {}),
                            ("R4 alone, scoped", ["R4"], {"r4_scope": KNOWN})):
        al = detect_all(runs, full_baseline, all_scn, rules, **kw)
        rl = run_level(al)
        ab = alert_level(runs, al, "B")
        rows.append([name, rl["tp"], rl["fp"], fmt(rl["precision"]), fmt(ab["alert_precision"]),
                     ", ".join(f"{s}:{rl['per'][s][0]}" for s in all_scn if rl["per"][s][0]) or "none"])
        configs_tried.append(("E2-1", name))
        if rules == ["R6"] and not kw:
            for s in ATTACK:
                n_att = []
                for recs, a_list in zip(runs[s], al[s]):
                    for a in a_list:
                        seen, k_count = set(), 0
                        for r in recs:
                            if r.reply or r.port is None or r.src != a.src:
                                continue
                            if (r.dst, r.port) not in seen:
                                seen.add((r.dst, r.port))
                                k_count += 1
                                if r.time_str == a.time_str and (r.dst, r.port) == (a.dst, a.port):
                                    n_att.append(k_count)
                                    break
                attempts_rows.append([s, f"{rl['per'][s][0]}/10", f"{statistics.mean(n_att):.1f}" if n_att else "-"])
    hdr = ["rule", "attack runs flagged (of 80)", "normal runs flagged (of 40)", "run precision", "alert precision (B)", "runs flagged by scenario"]
    write_csv("e2_1_r6.csv", hdr, rows)
    section("E2-1 consecutive failed first contacts (R6) vs fan-out (R4), each rule alone", md_table(hdr, rows))
    section("E2-1 first contacts needed before R6 flags a source (mean over flagged runs; the paper reports about 4-5 for new addresses)",
            md_table(["scenario", "runs flagged", "mean first contacts until flagged"], attempts_rows))

    # ---------------------------------------------------------- E2-2
    rows = []
    for scope_name, scope in (("none", None), ("known apps", KNOWN)):
        for n in (5, 20):
            for w in (10, 60, 300):
                al = detect_all(runs, full_baseline, all_scn, ["R4"], fanout_threshold=n, window_seconds=w, r4_scope=scope)
                rl = run_level(al)
                configs_tried.append(("E2-2", f"scope={scope_name} N={n} W={w}"))
                rows.append([scope_name, n, w, rl["tp"], rl["fp"], f"{rl['per']['evasion_1'][0]}/10", f"{rl['per']['evasion_2'][0]}/10"])
    hdr = ["R4 scope", "N", "W (s)", "attack runs flagged (of 80)", "normal runs flagged (of 40)", "evasion_1", "evasion_2"]
    write_csv("e2_2_r4_grid.csv", hdr, rows)
    section("E2-2 fan-out rule (R4 alone): threshold N x window W x scope", md_table(hdr, rows))

    # ---------------------------------------------------------- COMBO
    combos = [("K1 v1 default: R1-R5", ALL5, {}),
              ("K2 v1 scoped: R1-R5, R4 scoped", ALL5, {"r4_scope": KNOWN}),
              ("K3 R1,R2,R3,R5,R6 (R4 replaced by R6)", ["R1", "R2", "R3", "R5", "R6"], {}),
              ("K4 R1-R6, R4 and R6 scoped", ALL5 + ["R6"], {"r4_scope": KNOWN, "r6_scope": KNOWN})]
    rows = []
    for name, rules, kw in combos:
        sp = split_eval(rules, **kw)
        configs_tried.append(("COMBO", name))
        rows.append([name, f"{sp['fp_rate'][0]:.3f}+-{sp['fp_rate'][1]:.3f}", f"{sp['recall'][0]:.3f}+-{sp['recall'][1]:.3f}",
                     f"{sp['alert_precision'][0]:.3f}+-{sp['alert_precision'][1]:.3f}"])
    hdr = ["combination (fixed in advance)", "false-alarm run rate (held-out normal + fp)", "run recall", "alert precision (policy B)"]
    write_csv("combo.csv", hdr, rows)
    section(f"COMBO learn 5 / evaluate rest, mean+-sd over {N_SPLITS} splits", md_table(hdr, rows))

    tried = defaultdict(int)
    for e, _ in configs_tried:
        tried[e] += 1
    section("Settings tried (report together with the results)",
            md_table(["experiment", "settings evaluated"], sorted(tried.items())) + f"\n\nTotal: {len(configs_tried)}")
    (OUT / "summary.md").write_text("# v2 results (existing 120 runs)\n\n" + "\n".join(summary), encoding="utf-8")
    print("wrote", OUT.relative_to(ROOT))


if __name__ == "__main__":
    main()
