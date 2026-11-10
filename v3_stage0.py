#!/usr/bin/env python3
"""v3 stage 0: what the existing 120 runs actually show (no cluster needed).
Writes experiments/v3_signature/results/stage0_*.csv and stage0.md."""
import csv, sys
from collections import Counter, defaultdict
from pathlib import Path
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import detector as D
OUT = ROOT / "experiments" / "v3_signature" / "results"; OUT.mkdir(parents=True, exist_ok=True)
PORTS = {10250, 10255, 443, 6443, 2379, 2380}

def short_labels(ep):
    if not ep: return "-"
    L = ep.get("labels") or []
    res = sorted(l.split(":", 1)[1] for l in L if l.startswith("reserved:"))
    if res: return "reserved:" + "+".join(res)
    d = D._label_dict(L)
    return f"{ep.get('namespace','?')}/{d.get('app') or d.get('k8s-app') or ep.get('pod_name') or '?'}"

rows = list(csv.DictReader(open(ROOT / "data" / "manifest.csv")))
ident = Counter()          # (scenario, port, src, dst_numeric_id, dst_labels)
drops = Counter(); drop_scn = defaultdict(Counter)
unk = Counter()            # (scenario, side, label)
reply_present = Counter()
n_flows = 0
for r in rows:
    scn = r["scenario"]
    for f in D.iter_flows(str(ROOT / r["data_file"])):
        n_flows += 1
        reply_present["is_reply key present" if "is_reply" in f else "is_reply key absent"] += 1
        if f.get("is_reply"): reply_present["is_reply true"] += 1
        dst, src = f.get("destination") or {}, f.get("source") or {}
        port = D.dest_port(f)
        if port in PORTS and not f.get("is_reply"):
            ident[(scn, port, short_labels(src), dst.get("identity"), short_labels(dst), f.get("verdict"))] += 1
        if f.get("verdict") == "DROPPED":
            k = (f.get("drop_reason_desc", "(absent)"), f.get("drop_reason", "(absent)"))
            drops[k] += 1; drop_scn[k][scn] += 1
        for side, ep in (("src", src), ("dst", dst)):
            labs = [l for l in (ep.get("labels") or []) if l in ("reserved:unknown", "reserved:init")]
            if ep.get("identity") in (0, 5) or labs:
                unk[(scn, side, ep.get("identity"), ",".join(labs) or "-", f.get("verdict"), short_labels(src) if side == "dst" else short_labels(dst))] += 1

def w(name, hdr, rs):
    with open(OUT / name, "w", newline="") as fh:
        c = csv.writer(fh); c.writerow(hdr); c.writerows(rs)
w("stage0_1_identity.csv", ["scenario", "dport", "src", "dst_identity_num", "dst_labels", "verdict", "flows"],
  sorted([list(k) + [v] for k, v in ident.items()], key=lambda x: (x[0], x[1], -x[6])))
w("stage0_2_drop_reason.csv", ["drop_reason_desc", "drop_reason", "flows", "by_scenario"],
  [[k[0], k[1], v, "; ".join(f"{s}:{c}" for s, c in sorted(drop_scn[k].items()))] for k, v in drops.most_common()])
w("stage0_3_unknown_init.csv", ["scenario", "side", "identity_num", "labels", "verdict", "other_side", "flows"],
  sorted([list(k) + [v] for k, v in unk.items()], key=lambda x: (x[0], x[1], -x[6])))
print("flows", n_flows, dict(reply_present))
print("DROP", drops.most_common())
print("UNK total", sum(unk.values()), Counter(k[0] for k in unk for _ in range(unk[k])).most_common())
