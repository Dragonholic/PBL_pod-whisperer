#!/usr/bin/env python3
"""v3 experiments: evaluate the pre-registered combinations on NEW data (data_v3/).

  E5-2  false alarms: new normal runs (fp_1..3, restart, replica2) and a 1 h stream cut into 9 s windows
  E5-3  recall: 8 attack scenarios x 10 new runs, E5-4: abnormal_4 x 10
  E5-5  contribution of F1/F2/F3 (ablation, K2 + one option) and of S1-S5
  stats paired t-test over 30 learn/evaluate splits; prediction table vs actual

Learning data: the original 10 normal runs (data/), either all 10 or 5 of them (30 random splits, seed 20261105).
Usage: python3 v3_experiments.py   (writes experiments/v3_signature/results/)
"""
import csv
import random
import statistics
import sys
from collections import Counter, defaultdict
from multiprocessing import Pool
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import detector as D  # noqa: E402
import v3_core as C  # noqa: E402
import v2_experiments as X  # noqa: E402
from v2_2_experiments import paired_t  # noqa: E402

import os  # noqa: E402
DEV = bool(os.environ.get("V3_DEV"))  # smoke test on the OLD data (data/, data_e1/); never used for the reported results
OUT = ROOT / "experiments" / "v3_signature" / ("results_dev" if DEV else "results")
OUT.mkdir(parents=True, exist_ok=True)
V3 = ROOT / ("data_e1" if DEV else "data_v3")
SEG = 9.0
FE = "pbl-security/frontend"
ATT_OLD = ["abnormal_1", "abnormal_2", "abnormal_3", "k8s_1", "k8s_2", "k8s_3", "evasion_1", "evasion_2"]
ATT_ALL = ATT_OLD[:3] + ["abnormal_4"] + ATT_OLD[3:]
NEW_NORMAL = [("fp_1", "fp_1"), ("fp_2", "fp_2"), ("fp_3", "fp_3"), ("restart", "shift_restart"), ("replica2", "shift_replica2")]
SIG_IDS = C.SIGS


def label_b(scn, src, dst, port):
    if scn == "abnormal_4":  # one request to the metadata address; Hubble shows it as a world destination
        return src == FE and port == 80 and dst.startswith("reserved:")
    return X.label("B", scn, src, dst, port)


def load_old():
    runs = defaultdict(list)
    for row in csv.DictReader(open(ROOT / "data" / "manifest.csv")):
        runs[row["scenario"]].append((int(row["run"]), C.parse(ROOT / row["data_file"])))
    return {s: [r for _, r in sorted(v, key=lambda x: x[0])] for s, v in runs.items()}


def load_new():
    runs = defaultdict(list)
    mans = [V3 / "manifest.csv"] + ([ROOT / "data" / "manifest.csv"] if DEV else [])
    for man in mans:
        for row in csv.DictReader(open(man)):
            runs[row["scenario"]].append((int(row["run"]), C.parse(ROOT / row["data_file"])))
    return {s: [r for _, r in sorted(v, key=lambda x: x[0])] for s, v in runs.items()}


def load_segments():
    recs = [r for r in C.parse(V3 / "long_stream.json") if r.ts is not None]
    t0, t1 = min(r.ts for r in recs), max(r.ts for r in recs)
    n = int((t1 - t0) // SEG) + 1
    segs = [[] for _ in range(n)]
    for r in recs:
        segs[min(int((r.ts - t0) // SEG), n - 1)].append(r)
    return segs, (t1 - t0) / 3600.0


# ---------------------------------------------------------------- globals shared with workers
OLD = NEW = SEGS = None
ALLOW = SIGS = None
COMBOS = {}
HOURS = 0.0
SPLITS = []


def build_combos():
    c = C.combos(ALLOW, SIGS)
    kn = set(C.APPS)
    # ablation of single options on top of K2 (not in the pre-registered six; used only for E5-5)
    c["K2+F1"] = dict(rules=C.ALL5, r4_scope=kn, allowlist=ALLOW)
    c["K2+F2"] = dict(rules=C.ALL5, r4_scope=kn, r1_policy_only=True)
    c["K2+F3"] = dict(rules=C.ALL5, r4_scope=kn, r5_scope="app_nondns")
    return c


def summarize(alerts, tags, scn=None):
    main = [a for a in alerts if a.rule not in C.TIER_RULES]
    d = dict(flag=bool(main), n=len(main), rules=Counter(a.rule for a in main),
             tier=sum(1 for a in alerts if a.rule in C.TIER_RULES),
             app=sum(1 for a in main if a.src in C.APPS), multistep=len(tags))
    d["sys"] = d["n"] - d["app"]
    if scn is not None:
        tp = sum(1 for a in main if label_b(scn, a.src, a.dst, a.port))
        d["tp"], d["fp"] = tp, len(main) - tp
        d["by_rule_flag"] = {r for r in d["rules"]}
    return d


def task(bi):
    """All combinations for one learning baseline (bi = -1: all 10 normal runs)."""
    idx = SPLITS[bi] if bi >= 0 else list(range(10))
    base = D.build_baseline_from_records([OLD["normal"][i] for i in idx])
    res = {}
    for cname, spec in COMBOS.items():
        for g, scn in NEW_NORMAL:
            res[(cname, "normal", g)] = [summarize(*C.run_combo(spec, r, base)) for r in NEW.get(scn, [])]
        for scn in ATT_ALL:
            res[(cname, "attack", scn)] = [summarize(*C.run_combo(spec, r, base), scn=scn) for r in NEW.get(scn, [])]
        tot = Counter(); rules = Counter(); flagged = 0; app = sys_ = tier = 0
        for sg in SEGS:
            s = summarize(*C.run_combo(spec, sg, base))
            flagged += s["flag"]; tot["n"] += s["n"]; rules.update(s["rules"]); app += s["app"]; sys_ += s["sys"]; tier += s["tier"]
        res[(cname, "long", "stream")] = dict(n=tot["n"], flagged=flagged, segs=len(SEGS), rules=dict(rules), app=app, sys=sys_, tier=tier)
    return bi, res


def ms(xs):
    return (statistics.mean(xs), statistics.pstdev(xs)) if xs else (0.0, 0.0)


def fmt(x, nd=3):
    return f"{x:.{nd}f}"


def write_csv(name, hdr, rows):
    with open(OUT / name, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(hdr)
        w.writerows(rows)


def main():
    global OLD, NEW, SEGS, ALLOW, SIGS, COMBOS, HOURS, SPLITS
    OLD, NEW = load_old(), load_new()
    SEGS, HOURS = load_segments()
    ALLOW = C.load_yaml(ROOT / "experiments/v3_signature/allowlist.yaml")["allowlist"]
    SIGS = C.load_yaml(ROOT / "experiments/v3_signature/signatures/signatures.yaml")["signatures"]
    COMBOS = build_combos()
    rng = random.Random(X.SPLIT_SEED)
    SPLITS = [sorted(rng.sample(range(10), 5)) for _ in range(X.N_SPLITS)]
    counts = {k: len(v) for k, v in NEW.items()}
    print("new runs:", counts, "segments:", len(SEGS), "hours: %.3f" % HOURS, flush=True)
    with Pool(14) as p:
        out = dict(p.map(task, range(-1, X.N_SPLITS)))
    full = out[-1]
    names = list(COMBOS)
    md = ["# v3 results (new data only)\n", f"- new runs per scenario: {counts}\n",
          f"- long stream: {HOURS:.2f} h, {len(SEGS)} windows of {SEG:.0f} s\n",
          f"- combinations tried: {len(names)} ({', '.join(names)}); learning baselines: 1 (all 10) + {X.N_SPLITS} (learn 5)\n"]

    # ---- E5-2 new normal runs
    rows = []
    for cname in names:
        for g, scn in NEW_NORMAL:
            fl = [sum(1 for s in out[b][(cname, "normal", g)] if s["flag"]) for b in range(X.N_SPLITS)]
            n = len(full[(cname, "normal", g)])
            rl = Counter()
            for b in range(X.N_SPLITS):
                for s in out[b][(cname, "normal", g)]:
                    for r in s["rules"]:
                        rl[r] += 1
            m, sd = ms([f / n for f in fl]) if n else (0, 0)
            f10 = sum(1 for s in full[(cname, "normal", g)] if s["flag"])
            tier10 = sum(s["tier"] for s in full[(cname, "normal", g)])
            rows.append([cname, g, n, f"{f10}/{n}", f"{fmt(m)}+-{fmt(sd)}",
                         ", ".join(f"{k}:{v / X.N_SPLITS:.1f}" for k, v in sorted(rl.items())) or "none", tier10])
    hdr = ["combination", "new normal group", "runs", "flagged (learn all 10)", "flagged rate (learn 5, mean+-sd over 30 splits)",
           "runs flagged per rule (learn 5, mean)", "R1u tier alerts (learn 10)"]
    write_csv("e5_2_normal_runs.csv", hdr, rows)
    md.append("## E5-2 new normal runs\n\n" + X.md_table(hdr, rows) + "\n")

    # ---- E5-2 long stream
    rows = []
    for cname in names:
        f10 = full[(cname, "long", "stream")]
        ph = [out[b][(cname, "long", "stream")]["n"] / HOURS for b in range(X.N_SPLITS)]
        pf = [out[b][(cname, "long", "stream")]["flagged"] / len(SEGS) for b in range(X.N_SPLITS)]
        m, sd = ms(ph)
        pm, psd = ms(pf)
        rows.append([cname, f"{f10['n'] / HOURS:.0f}", f"{f10['flagged']}/{f10['segs']}", f"{m:.0f}+-{sd:.0f}", f"{fmt(pm)}+-{fmt(psd)}",
                     ", ".join(f"{k}:{v}" for k, v in sorted(f10["rules"].items())) or "none", f10["app"], f10["sys"], f10["tier"]])
    hdr = ["combination", "alerts/hour (learn 10)", "windows flagged (learn 10)", "alerts/hour (learn 5, mean+-sd)",
           "windows flagged rate (learn 5)", "alerts by rule (learn 10)", "alerts from apps", "alerts from system components", "R1u tier"]
    write_csv("e5_2_long.csv", hdr, rows)
    md.append("## E5-2 long normal stream (alerts per hour)\n\n" + X.md_table(hdr, rows) + "\n")

    # ---- E5-3 / E5-4 recall by scenario
    rows, prec_rows = [], []
    for cname in names:
        det10 = {s: sum(1 for x in full[(cname, "attack", s)] if x["flag"]) for s in ATT_ALL}
        detm = {s: ms([sum(1 for x in out[b][(cname, "attack", s)] if x["flag"]) / max(1, len(out[b][(cname, "attack", s)])) for b in range(X.N_SPLITS)]) for s in ATT_ALL}
        n10 = {s: len(full[(cname, "attack", s)]) for s in ATT_ALL}
        old8 = sum(det10[s] for s in ATT_OLD)
        nold = sum(n10[s] for s in ATT_OLD)
        rows.append([cname] + [f"{det10[s]}/{n10[s]} ({fmt(detm[s][0], 2)})" for s in ATT_ALL] + [f"{old8}/{nold}", f"{det10['abnormal_4']}/{n10['abnormal_4']}"])
        # alert precision (policy B): attack alerts labelled + all alerts in new normal runs as false positives
        tp = sum(x["tp"] for s in ATT_ALL for x in full[(cname, "attack", s)])
        fp_att = sum(x["fp"] for s in ATT_ALL for x in full[(cname, "attack", s)])
        fp_norm = sum(x["n"] for g, _ in NEW_NORMAL for x in full[(cname, "normal", g)])
        prec_rows.append([cname, tp, fp_att, fp_norm, fmt(tp / (tp + fp_att + fp_norm) if tp + fp_att + fp_norm else 0.0)])
    hdr = ["combination"] + [f"{s} (learn 10; mean over splits)" for s in ATT_ALL] + ["recall old 8 scenarios", "abnormal_4"]
    write_csv("e5_3_recall.csv", hdr, rows)
    md.append("## E5-3 / E5-4 detected runs per scenario\n\n" + X.md_table(hdr, rows) + "\n")
    hdr = ["combination", "attack alerts labelled B", "attack alerts not labelled", "alerts in 40 new normal runs", "alert precision"]
    write_csv("e5_3_alert_precision.csv", hdr, prec_rows)
    md.append("## alert precision (label policy B, learn 10)\n\n" + X.md_table(hdr, prec_rows) + "\n")

    # ---- E5-3 detected-by rules per scenario (K6)
    rows = []
    for cname in ("K2", "K5b", "K6"):
        for s in ATT_ALL:
            c = Counter()
            for x in full[(cname, "attack", s)]:
                for r in x["rules"]:
                    c[r] += 1
            rows.append([cname, s] + [c.get(r, 0) for r in C.ALL5 + C.SIGS])
    hdr = ["combination", "scenario"] + [f"{r} runs" for r in C.ALL5 + C.SIGS]
    write_csv("e5_3_rules_by_scenario.csv", hdr, rows)
    md.append("## runs in which each rule fired (learn 10)\n\n" + X.md_table(hdr, rows) + "\n")

    # ---- E5-5 contribution
    rows = []
    base_k2 = full[("K2", "long", "stream")]
    for cname in ("K2", "K2+F1", "K2+F2", "K2+F3", "K5a", "K5b"):
        f = full[(cname, "long", "stream")]
        rows.append([cname, f"{f['n'] / HOURS:.0f}", f"{(f['n'] - base_k2['n']) / HOURS:+.0f}", ", ".join(f"{k}:{v}" for k, v in sorted(f["rules"].items())), f["tier"]])
    hdr = ["combination", "alerts/hour", "change vs K2 per hour", "alerts by rule", "R1u tier"]
    write_csv("e5_5_filters.csv", hdr, rows)
    md.append("## E5-5 effect of F1/F2/F3 on the long stream (learn 10)\n\n" + X.md_table(hdr, rows) + "\n")

    rows = []
    for sid in SIG_IDS:
        det = {s: sum(1 for x in full[("K6", "attack", s)] if sid in x["rules"]) for s in ATT_ALL}
        new_norm = sum(x["rules"].get(sid, 0) for g, _ in NEW_NORMAL for x in full[("K6", "normal", g)])
        seg_alerts = full[("K6", "long", "stream")]["rules"].get(sid, 0)
        only = {s: sum(1 for k, x in enumerate(full[("K6", "attack", s)]) if sid in x["rules"] and not (set(full[("K5b", "attack", s)][k]["rules"]) & set(C.ALL5)))
                for s in ATT_ALL}
        rows.append([sid] + [f"{det[s]}/{len(full[('K6', 'attack', s)])}" for s in ATT_ALL] + [new_norm, seg_alerts, sum(only.values())])
    hdr = ["signature"] + ATT_ALL + ["alerts in new normal runs", "alerts in long stream", "runs caught only by this signature (not by K5b rules)"]
    write_csv("e5_5_signatures.csv", hdr, rows)
    md.append("## E5-5 signatures: runs where each fires\n\n" + X.md_table(hdr, rows) + "\n")

    # ---- stats
    rows = []
    for a, b_ in (("K2", "K5a"), ("K2", "K5b"), ("K5b", "K6")):
        for what in ("normal_runs", "long_windows"):
            xs, ys = [], []
            for b in range(X.N_SPLITS):
                if what == "normal_runs":
                    fa = sum(1 for g, _ in NEW_NORMAL for s in out[b][(a, "normal", g)] if s["flag"])
                    fb = sum(1 for g, _ in NEW_NORMAL for s in out[b][(b_, "normal", g)] if s["flag"])
                    n = sum(len(out[b][(a, "normal", g)]) for g, _ in NEW_NORMAL)
                else:
                    fa, fb, n = out[b][(a, "long", "stream")]["flagged"], out[b][(b_, "long", "stream")]["flagged"], len(SEGS)
                xs.append(fa / n); ys.append(fb / n)
            pt = paired_t(xs, ys)
            rows.append([f"{a} vs {b_}", what, fmt(statistics.mean(xs)), fmt(statistics.mean(ys)),
                         "all differences equal (test not possible)" if pt is None else f"t={pt[0]:.2f}, df={pt[1]}, p={pt[2]:.2g}"])
    hdr = ["comparison", "unit", "flagged rate A", "flagged rate B", "paired t-test over 30 learn/evaluate splits"]
    write_csv("e5_stats.csv", hdr, rows)
    md.append("## paired t-tests (splits are not independent; p is a reference value)\n\n" + X.md_table(hdr, rows) + "\n")

    # ---- prediction table vs actual (signature matrix) and Q1-Q10
    pred = {"abnormal_3": {"S1", "S2", "S3"}, "k8s_1": {"S3"}, "k8s_2": {"S1"}, "k8s_3": {"S4"}, "evasion_1": {"S1", "S2", "S3"}, "abnormal_4": {"S5"}}
    scn_all = ["normal", "fp_1", "fp_2", "fp_3", "abnormal_1", "abnormal_2", "abnormal_3", "k8s_1", "k8s_2", "k8s_3", "evasion_1", "evasion_2", "abnormal_4"]
    rows, wrong = [], []
    for scn in scn_all:
        cells = []
        for sid in SIG_IDS:
            if scn in ATT_ALL:
                rs = full[("K6", "attack", scn)]
                k = sum(1 for x in rs if sid in x["rules"])
                n = len(rs)
            elif scn == "normal":
                k = n = 0  # the plain normal scenario is represented by the long stream (handled below)
            else:
                rs = full[("K6", "normal", scn)]
                k = sum(1 for x in rs if sid in x["rules"])
                n = len(rs)
            exp = sid in pred.get(scn, set())
            if scn == "normal":
                seg = full[("K6", "long", "stream")]["rules"].get(sid, 0)
                act = seg > 0
                cells.append(f"pred {'O' if exp else '-'} / actual {'O' if act else '-'} ({seg} alerts in stream)")
                ok = exp == act
            else:
                act = k > 0
                cells.append(f"pred {'O' if exp else '-'} / actual {k}/{n}")
                ok = (exp and k == n) or (not exp and k == 0)
            if not ok:
                wrong.append(f"{scn} {sid}: predicted {'fires' if exp else 'silent'}, actual {cells[-1].split('actual ')[1]}")
        rows.append([scn] + cells)
    hdr = ["scenario"] + SIG_IDS
    write_csv("pred_vs_actual_signatures.csv", hdr, rows)
    md.append("## prediction table vs actual (signatures, K6, learn 10)\n\n" + X.md_table(hdr, rows) + "\n\nMismatches: " + ("; ".join(wrong) if wrong else "none") + "\n")

    def lp(c):
        return full[(c, "long", "stream")]["n"] / HOURS

    def run_flag(c, g):
        return sum(1 for s in full[(c, "normal", g)] if s["flag"])

    def r1flag(c, g):
        return sum(1 for s in full[(c, "normal", g)] if "R1" in s["rules"])
    rec = lambda c, sc: sum(1 for s in sc for x in full[(c, "attack", s)] if x["flag"]) / sum(len(full[(c, "attack", s)]) for s in sc)
    q = [
        ("Q1", "K5a alerts/hour <= 50% of K2", f"K5a {lp('K5a'):.0f} vs K2 {lp('K2'):.0f} ({lp('K5a') / lp('K2'):.0%})", lp("K5a") <= 0.5 * lp("K2")),
        ("Q2", "K5a <= K5b <= K2 alerts/hour", f"{lp('K5a'):.0f} / {lp('K5b'):.0f} / {lp('K2'):.0f}", lp("K5a") <= lp("K5b") <= lp("K2")),
        ("Q3", "F2 removes R1 false alarms in restart and replica2 runs", f"K2 R1-flagged runs restart {r1flag('K2', 'restart')}/5, replica2 {r1flag('K2', 'replica2')}/5; K5b {r1flag('K5b', 'restart')}/5, {r1flag('K5b', 'replica2')}/5",
         r1flag("K5b", "restart") == 0 and r1flag("K5b", "replica2") == 0),
        ("Q4", "evasion_2 stays detected by R5 under F3 (10/10)", f"{sum(1 for x in full[('K5b', 'attack', 'evasion_2')] if 'R5' in x['rules'])}/{len(full[('K5b', 'attack', 'evasion_2')])}",
         sum(1 for x in full[("K5b", "attack", "evasion_2")] if "R5" in x["rules"]) == len(full[("K5b", "attack", "evasion_2")])),
        ("Q5", "K6 run recall = 1.000 (8 old scenarios + abnormal_4); K6 normal alerts/hour = K5b", f"recall {rec('K6', ATT_ALL):.3f}; K6 {lp('K6'):.0f} vs K5b {lp('K5b'):.0f}",
         rec("K6", ATT_ALL) == 1.0 and abs(lp("K6") - lp("K5b")) < 1e-9),
        ("Q6", "K6-r3 run recall = 1.000", f"{rec('K6-r3', ATT_ALL):.3f}", rec("K6-r3", ATT_ALL) == 1.0),
        ("Q7", "K2 detects abnormal_4 10/10; S5 10/10", f"K2 {sum(1 for x in full[('K2', 'attack', 'abnormal_4')] if x['flag'])}/{len(full[('K2', 'attack', 'abnormal_4')])}; S5 {sum(1 for x in full[('K6', 'attack', 'abnormal_4')] if 'S5' in x['rules'])}/{len(full[('K6', 'attack', 'abnormal_4')])}",
         all(x["flag"] for x in full[("K2", "attack", "abnormal_4")]) and all("S5" in x["rules"] for x in full[("K6", "attack", "abnormal_4")])),
        ("Q8", "fp_1 flagged in >= 8/10 runs under K5b", f"{run_flag('K5b', 'fp_1')}/{len(full[('K5b', 'normal', 'fp_1')])}", run_flag("K5b", "fp_1") >= 8),
        ("Q9", "K7 changes no alert count (tags only)", f"K7 {lp('K7'):.0f} vs K6 {lp('K6'):.0f}; multistep incidents in attack runs {sum(x['multistep'] for s in ATT_ALL for x in full[('K7', 'attack', s)])}", abs(lp("K7") - lp("K6")) < 1e-9),
        ("Q10", "S1/S2/S3 fire 10/10 where predicted O", "see signature table", not any("S1" in w or "S2" in w or "S3" in w for w in wrong)),
    ]
    rows = [[i, t, a, "correct" if ok else "wrong"] for i, t, a, ok in q]
    write_csv("pred_vs_actual_Q.csv", ["id", "prediction", "actual", "result"], rows)
    md.append("## additional predictions Q1-Q10 vs actual\n\n" + X.md_table(["id", "prediction", "actual", "result"], rows) + "\n")

    # ---- other drops + R1u
    drops = Counter()
    for g, scn in NEW_NORMAL:
        for r in NEW.get(scn, []):
            for x in r:
                if x.verdict == "DROPPED":
                    drops[(g, x.drop_desc)] += 1
    rows = [[g, d, n] for (g, d), n in sorted(drops.items(), key=lambda t: (t[0][0], str(t[0][1])))]
    write_csv("e5_drop_reasons_normal.csv", ["group", "drop_reason_desc", "flows"], rows)
    md.append("## dropped flows in the new normal runs by reason\n\n" + X.md_table(["group", "drop_reason_desc", "flows"], rows) + "\n")

    (OUT / "summary.md").write_text("\n".join(md))
    print("\n".join(md))


if __name__ == "__main__":
    main()
