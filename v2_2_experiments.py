#!/usr/bin/env python3
"""v2.2 experiments: the items of the v2 design page that v2 did not run.

  E1-1  normal-distribution shift: extra normal runs (collect_e1.sh) under
        later / more rounds / restarted pods / 2 backend replicas
  E1-3  long normal run: false alarms per hour (data_e1/long_*.json)
  E3-1  statistical test of the combination differences (paired t-test over
        the 30 learn/evaluate splits; Fisher exact test for E1-1 vs held-out)
  E3-2  manual review of false-alarm samples (every alert is listed, a fixed
        number per rule and scenario is written to a review file)

Usage: python3 v2_2_experiments.py   (writes experiments/v2_2_research/results/)
Settings are the four combinations K1-K4 fixed in v2 (not re-chosen here).
"""
import csv
import math
import random
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import detector  # noqa: E402
import v2_experiments as X  # noqa: E402

OUT = ROOT / "experiments" / "v2_2_research" / "results"
OUT.mkdir(parents=True, exist_ok=True)
E1_DIR = ROOT / "data_e1"

COMBOS = [
    ("K1 v1 default: R1-R5", ["R1", "R2", "R3", "R4", "R5"], {}),
    ("K2 R1-R5, R4 scoped", ["R1", "R2", "R3", "R4", "R5"], {"r4_scope": X.KNOWN}),
    ("K3 R1,R2,R3,R5,R6", ["R1", "R2", "R3", "R5", "R6"], {}),
    ("K4 R1-R6, R4 and R6 scoped", ["R1", "R2", "R3", "R4", "R5", "R6"], {"r4_scope": X.KNOWN, "r6_scope": X.KNOWN}),
]
VARIANTS = ["later", "rounds", "restart", "replica2"]


# ------------------------------------------------------------ statistics
def _betacf(a, b, x):
    qab, qap, qam = a + b, a + 1, a - 1
    c, d = 1.0, 1.0 - qab * x / qap
    d = 1.0 / (d if abs(d) > 1e-300 else 1e-300)
    h = d
    for m in range(1, 300):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > 1e-300 else 1e-300)
        c = 1.0 + aa / c
        c = c if abs(c) > 1e-300 else 1e-300
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        d = 1.0 / (d if abs(d) > 1e-300 else 1e-300)
        c = 1.0 + aa / c
        c = c if abs(c) > 1e-300 else 1e-300
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 3e-12:
            break
    return h


def betainc(a, b, x):
    if x <= 0:
        return 0.0
    if x >= 1:
        return 1.0
    bt = math.exp(math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + a * math.log(x) + b * math.log(1 - x))
    if x < (a + 1) / (a + b + 2):
        return bt * _betacf(a, b, x) / a
    return 1 - bt * _betacf(b, a, 1 - x) / b


def paired_t(xs, ys):
    """two-sided paired t-test; returns (t, df, p) or None if all differences are equal."""
    d = [x - y for x, y in zip(xs, ys)]
    n = len(d)
    m = sum(d) / n
    var = sum((v - m) ** 2 for v in d) / (n - 1)
    if var == 0:
        return None if m == 0 else (math.inf, n - 1, 0.0)
    t = m / math.sqrt(var / n)
    df = n - 1
    p = betainc(df / 2, 0.5, df / (df + t * t))
    return t, df, p


def fisher_exact(a, b, c, d):
    """two-sided Fisher exact test for [[a, b], [c, d]]."""
    r1, r2, c1, n = a + b, c + d, a + c, a + b + c + d

    def pm(k):
        return math.comb(r1, k) * math.comb(r2, c1 - k) / math.comb(n, c1)
    p0 = pm(a)
    lo, hi = max(0, c1 - r2), min(r1, c1)
    return min(1.0, sum(pm(k) for k in range(lo, hi + 1) if pm(k) <= p0 * (1 + 1e-9)))


# ------------------------------------------------------------------ data
def load_e1():
    out = defaultdict(list)
    mf = E1_DIR / "manifest.csv"
    if not mf.exists():
        return out
    with open(mf, newline="") as f:
        for row in csv.DictReader(f):
            out[row["variant"]].append(detector.flow_records(str(ROOT / row["data_file"])))
    return out


def flagged(recs, base, rules, kw):
    return detector.detect_records(recs, baseline=base, enabled_rules=rules, **{**X.V1, **kw})


def main():
    runs = X.load_runs()
    e1 = load_e1()
    full = detector.build_baseline_from_records(runs["normal"])
    rng = random.Random(X.SPLIT_SEED)
    splits = [sorted(rng.sample(range(10), 5)) for _ in range(X.N_SPLITS)]
    md = ["# v2.2 results\n"]

    # ---------------- E1-1
    if e1:
        rows = []
        for cname, rules, kw in COMBOS:
            # reference: original normal runs held out of learning (5 per split)
            ref_rates, per_split = [], {v: [] for v in VARIANTS}
            by_rule = {v: Counter() for v in VARIANTS}
            for tr in splits:
                base = detector.build_baseline_from_records([runs["normal"][i] for i in tr])
                held = [runs["normal"][i] for i in range(10) if i not in tr]
                ref_rates.append(sum(1 for r in held if flagged(r, base, rules, kw)) / len(held))
                for v in VARIANTS:
                    if v not in e1:
                        continue
                    n = 0
                    for r in e1[v]:
                        al = flagged(r, base, rules, kw)
                        n += 1 if al else 0
                        for rule in {a.rule for a in al}:
                            by_rule[v][rule] += 1
                    per_split[v].append(n / len(e1[v]))
            for v in VARIANTS:
                if v not in e1:
                    continue
                al10 = [flagged(r, full, rules, kw) for r in e1[v]]
                n10 = sum(1 for al in al10 if al)
                m, sd = X.mean_sd(per_split[v])
                rm, rsd = X.mean_sd(ref_rates)
                rules_hit = ", ".join(f"{k}:{c / X.N_SPLITS:.1f}" for k, c in sorted(by_rule[v].items())) or "none"
                # Fisher: new shifted runs (learn 5, mean flagged) vs held-out original normal, rounded to counts
                rows.append([cname, v, len(e1[v]), f"{n10}/{len(e1[v])}", f"{m:.3f}+-{sd:.3f}", f"{rm:.3f}+-{rsd:.3f}", rules_hit])
        hdr = ["combination", "shift", "runs", "flagged (learn all 10)", "flagged rate (learn 5, mean+-sd over 30 splits)",
               "original held-out normal rate (same splits)", "mean runs flagged per rule (learn 5)"]
        write_csv("e1_1_shift.csv", hdr, rows)
        md.append("## E1-1 normal-distribution shift (new normal runs, no attacks)\n\n" + X.md_table(hdr, rows) + "\n")

    # ---------------- E1-3 long normal run, false alarms per hour
    stream, itf = E1_DIR / "long_stream.json", E1_DIR / "long_iterations.csv"
    if stream.exists() and itf.exists():
        recs = [r for r in detector.flow_records(str(stream)) if r.ts is not None]
        starts = [int(row["start_epoch"]) for row in csv.DictReader(open(itf))]
        t_first, t_last = min(r.ts for r in recs), max(r.ts for r in recs)
        hours = (t_last - t_first) / 3600.0
        # fixed 9-second windows: the original normal runs lasted 8-9 s, and R5 compares
        # per-run counts, so window length must match (a first try with ~35 s iteration
        # segments made R5 fire in every segment, a window-length artifact)
        SEG = 9.0
        n_seg = int((t_last - t_first) // SEG) + 1
        bounds = [t_first + k * SEG for k in range(n_seg + 1)]
        segs = [[r for r in recs if lo <= r.ts < hi] for lo, hi in zip(bounds[:-1], bounds[1:])]
        rows = []
        for cname, rules, kw in COMBOS:
            def count(base):
                tot = flg = 0
                by = Counter()
                for sg in segs:
                    al = flagged(sg, base, rules, kw)
                    tot += len(al)
                    flg += 1 if al else 0
                    for rule in {a.rule for a in al}:
                        by[rule] += 1
                return tot, flg, by
            t10, f10, by10 = count(full)
            ph, pf = [], []
            for tr in splits:
                base = detector.build_baseline_from_records([runs["normal"][i] for i in tr])
                t, f, _ = count(base)
                ph.append(t / hours)
                pf.append(f / len(segs))
            m, sd = X.mean_sd(ph)
            pm_, psd = X.mean_sd(pf)
            rows.append([cname, f"{hours:.2f}", len(segs), f"{t10 / hours:.0f}", f"{f10}/{len(segs)}",
                         f"{m:.0f}+-{sd:.0f}", f"{pm_:.3f}+-{psd:.3f}",
                         ", ".join(f"{k}:{c}" for k, c in sorted(by10.items())) or "none"])
        hdr = ["combination", "hours", "9-second segments", "alerts/hour (learn all 10)",
               "segments flagged (learn all 10)", "alerts/hour (learn 5, mean+-sd)", "segments flagged rate (learn 5)",
               "segments flagged by rule (learn all 10)"]
        write_csv("e1_3_long.csv", hdr, rows)
        md.append("## E1-3 long normal run: false alarms per hour (9-second windows, matching the original run length)\n\n" + X.md_table(hdr, rows) + "\n")

    # ---------------- E3-1 statistical tests on the K1-K4 split results
    per_combo = []
    for cname, rules, kw in COMBOS:
        rates = []
        for tr in splits:
            base = detector.build_baseline_from_records([runs["normal"][i] for i in tr])
            held = [runs["normal"][i] for i in range(10) if i not in tr]
            ev = held + [r for s in X.FP_SCENARIOS for r in runs[s]]
            rates.append(sum(1 for r in ev if flagged(r, base, rules, kw)) / len(ev))
        per_combo.append(rates)
    rows = []
    for i, j in ((0, 1), (1, 2), (1, 3), (2, 3)):
        res = paired_t(per_combo[i], per_combo[j])
        a, b = COMBOS[i][0].split()[0], COMBOS[j][0].split()[0]
        diff = sum(per_combo[i]) / X.N_SPLITS - sum(per_combo[j]) / X.N_SPLITS
        rows.append([f"{a} vs {b}", f"{diff:+.3f}", "identical in every split (no test possible)" if res is None
                     else f"t={res[0]:.2f}, df={res[1]}, p={res[2]:.2g}"])
    hdr = ["pair (false-alarm run rate over 30 splits)", "mean difference", "paired t-test"]
    write_csv("e3_1_ttest.csv", hdr, rows)
    md.append("## E3-1 paired t-test over the 30 learn/evaluate splits\n\n" + X.md_table(hdr, rows) + "\n")

    if e1 and "later" in e1:
        # Fisher exact: shifted runs vs original held-out normal, scoped combination K2, learn all 10 vs counts
        rows = []
        name, rules, kw = COMBOS[1]
        ref_flag = ref_n = 0
        for tr in splits:
            base = detector.build_baseline_from_records([runs["normal"][i] for i in tr])
            for i in range(10):
                if i not in tr:
                    ref_n += 1
                    ref_flag += 1 if flagged(runs["normal"][i], base, rules, kw) else 0
        for v in VARIANTS:
            if v not in e1:
                continue
            f = n = 0
            for tr in splits:
                base = detector.build_baseline_from_records([runs["normal"][i] for i in tr])
                for r in e1[v]:
                    n += 1
                    f += 1 if flagged(r, base, rules, kw) else 0
            # counts are pooled over splits (not independent), so the p-value is only a rough guide
            p = fisher_exact(f, n - f, ref_flag, ref_n - ref_flag)
            rows.append([v, f"{f / n:.3f}", f"{ref_flag / ref_n:.3f}", f"p={p:.2g}"])
        hdr = [f"shift ({name}, learn 5)", "flagged rate", "original held-out rate", "Fisher exact (pooled over splits, rough guide only)"]
        write_csv("e3_1_fisher.csv", hdr, rows)
        md.append("## E3-1b shifted normal vs original held-out normal\n\n" + X.md_table(hdr, rows) + "\n")

    # ---------------- E3-2 false-alarm review sample
    rows = []
    review = []
    name, rules, kw = COMBOS[1]  # scoped, the best fixed combination
    scn = ["normal", "fp_1", "fp_2", "fp_3"]
    counts = Counter()
    for tr_i, tr in enumerate(splits[:1]):  # one fixed split (the first) for a reproducible sample
        base = detector.build_baseline_from_records([runs["normal"][i] for i in tr])
        for s in scn:
            idxs = [i for i in range(10) if i not in tr] if s == "normal" else range(10)
            for i in idxs:
                al = flagged(runs[s][i], base, rules, kw)
                for a in al:
                    counts[(s, a.rule)] += 1
                    if counts[(s, a.rule)] <= 2:
                        review.append([s, i + 1, a.rule, a.src, a.dst, a.port, a.verdict, a.time_str])
    for (s, rule), c in sorted(counts.items()):
        rows.append([s, rule, c])
    hdr = ["normal scenario", "rule", "alerts (first split, K2)"]
    write_csv("e3_2_false_alarm_counts.csv", hdr, rows)
    hdr2 = ["scenario", "run", "rule", "src", "dst", "port", "verdict", "time"]
    write_csv("e3_2_review_sample.csv", hdr2, review)
    md.append("## E3-2 false alarms by scenario and rule (K2, learn split 1)\n\n" + X.md_table(hdr, rows) + "\n")
    md.append("Review sample (first two alerts per scenario and rule): e3_2_review_sample.csv\n")

    # ---------------- E3-2b who raises the false alarms: our apps or system components
    cat = Counter()
    for tr in splits:
        base = detector.build_baseline_from_records([runs["normal"][i] for i in tr])
        for sname in scn:
            idxs = [i for i in range(10) if i not in tr] if sname == "normal" else range(10)
            for i in idxs:
                for a in flagged(runs[sname][i], base, rules, kw):
                    cat[(a.rule, "our apps (frontend/backend/db)" if a.src.split("/")[-1] in ("frontend", "backend", "db") else "system components (host, coredns, falco, apiserver, ...)")] += 1
    rows = [[r, c, n, f"{n / sum(v for (rr, _), v in cat.items() if rr == r):.3f}"] for (r, c), n in sorted(cat.items())]
    hdr = ["rule", "alert source", "alerts (K2, 30 splits)", "share of the rule's alerts"]
    write_csv("e3_2b_alert_source.csv", hdr, rows)
    md.append("## E3-2b false alarms by alert source (K2, all 30 splits)\n\n" + X.md_table(hdr, rows) + "\n")

    (OUT / "summary.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md))


def write_csv(name, hdr, rows):
    with open(OUT / name, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(hdr)
        w.writerows(rows)


if __name__ == "__main__":
    main()
