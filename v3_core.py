#!/usr/bin/env python3
"""v3 detector layer on top of detector.py (v2 rules R1-R6 are reused unchanged).

All options default to off; with every option off detect3() returns the same
alerts as detector.detect_records (checked by v3_selftest.py on the 120 runs).

  F1 allowlist     R2 and R5 skip flows that match an explicit allowlist entry
  F2 r1_policy_only R1 only for policy drops (POLICY_DENIED / POLICY_DENY);
                    flows with unresolved identity (unknown / init) are counted
                    as tier "R1u" and kept out of the main alerts
  F3 r5_scope      R5 only for app -> app paths, DNS (port 53) excluded
  S1-S5            signatures from signatures/signatures.yaml (request direction)
  C1 multistep     R4/R6 alert followed by S1-S5 from the same source in W s
"""
import json
import sys
from collections import namedtuple
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))
import detector as D  # noqa: E402

APPS = ("pbl-security/frontend", "pbl-security/backend", "pbl-security/db")
POLICY_DROP = {"POLICY_DENIED", "POLICY_DENY"}
TIER_RULES = {"R1u"}  # reported separately, not part of the main alert count

# first seven fields are the FlowRecord fields detector.detect_records reads
Rec3 = namedtuple(
    "Rec3",
    "src dst port verdict time_str ts reply "
    "proto drop_desc src_ns dst_ns src_sid dst_sid src_res dst_res dst_ip src_unres dst_unres dst_kapp",
)


def stable_id(ep, ip):
    """Pod-name independent identity (survives restarts/replicas)."""
    if not ep:
        return ip or "unknown"
    L = D._label_dict(ep.get("labels"))
    ns = ep.get("namespace")
    for key in ("app", "k8s-app", "app.kubernetes.io/name"):
        if L.get(key):
            return f"{ns}/{L[key]}" if ns else L[key]
    r = D.reserved_identity_of(ep)
    if r:
        return r
    wl = (ep.get("workloads") or [{}])[0].get("name")
    if wl:
        return f"{ns}/{wl}" if ns else wl
    return D.identity_of(ep, ip)


def reserved_set(ep):
    return frozenset(l.split(":", 1)[1] for l in ((ep or {}).get("labels") or []) if l.startswith("reserved:"))


def unresolved(ep):
    if not ep:
        return True
    res = reserved_set(ep)
    return bool(res & {"unknown", "init"}) or ep.get("identity") in (0, 5)


def proto_of(flow):
    l4 = flow.get("l4") or {}
    for p in ("TCP", "UDP", "ICMPv4", "ICMPv6", "SCTP"):
        if p in l4:
            return p
    return "-"


def parse(path):
    out = []
    for f in D.iter_flows(str(path)):
        ip = f.get("IP") or {}
        s, d = f.get("source"), f.get("destination")
        src, dst, port = D.flow_tuple(f)
        out.append(Rec3(
            src, dst, port, f.get("verdict", "UNKNOWN"), f.get("time", ""), D.flow_time(f), D.is_reply_flow(f),
            proto_of(f), f.get("drop_reason_desc"), (s or {}).get("namespace"), (d or {}).get("namespace"),
            stable_id(s, ip.get("source")), stable_id(d, ip.get("destination")), reserved_set(s), reserved_set(d),
            ip.get("destination"), unresolved(s), unresolved(d), D._label_dict((d or {}).get("labels")).get("k8s-app"),
        ))
    return out


# ------------------------------------------------------------ allowlist / signatures
def load_yaml(path):
    with open(path) as fh:
        return yaml.safe_load(fh)


def _sel(selector, sid, res):
    """selector 'reserved:host' matches a reserved label, otherwise the stable id."""
    if selector.startswith("reserved:"):
        return selector.split(":", 1)[1] in res
    return selector == sid


def allow_match(entries, r):
    for e in entries:
        if r.port != e["port"]:
            continue
        if e.get("proto") and r.proto not in e["proto"]:
            continue
        if any(_sel(s, r.src_sid, r.src_res) for s in e["src"]) and \
                any(_sel(d, r.dst_sid, r.dst_res) for d in e["dst"]):
            return True
    return False


def sig_match(sig, r):
    """Evaluate the generic match block of one signature on a request-direction flow."""
    m, ex = sig["match"], sig.get("exceptions") or {}
    if r.reply:
        return False
    if "dport_in" in m and r.port not in m["dport_in"]:
        return False
    if "dst_ip" in m and r.dst_ip != m["dst_ip"]:
        return False
    if "src_res_none_of" in m and (r.src_res & set(m["src_res_none_of"])):
        return False
    if "dst_res_any_of" in m and not (r.dst_res & set(m["dst_res_any_of"])):
        return False
    if "src_in" in m and r.src_sid not in m["src_in"]:
        return False
    if "src_ns" in m and r.src_ns != m["src_ns"]:
        return False
    if "dst_ns_not" in m and (r.dst_ns is None or r.dst_ns == m["dst_ns_not"]):
        return False
    for x in ex.get("dst_kapp_port", []):
        if r.dst_kapp == x["kapp"] and r.port == x["port"]:
            return False
    return True


# ------------------------------------------------------------------ detection
def detect3(records, baseline, rules, r4_scope=None, r6_scope=None, *, allowlist=None, r2_scope=None,
            r5_scope=None, r1_policy_only=False, signatures=None, multistep=None, extra_kw=None):
    """rules: subset of R1..R6 and S1..S5. r2_scope: restrict R2 (and R5 if r5_scope == 'src')
    to sources in the set. r5_scope: None | 'app_nondns' | 'src' (sources limited by r2_scope)."""
    kw = {**D_DEFAULTS, **(extra_kw or {})}
    alerts = []

    if "R1" in rules:
        for r in records:
            if r.verdict != "DROPPED":
                continue
            if r1_policy_only:
                if r.drop_desc not in POLICY_DROP:
                    continue
                if r.src_unres or r.dst_unres:
                    alerts.append(D.Alert(r.time_str, "R1u", r.src, r.dst, r.port, r.verdict))
                    continue
            alerts.append(D.Alert(r.time_str, "R1", r.src, r.dst, r.port, r.verdict))

    rest = [x for x in ("R3", "R4", "R6") if x in rules]
    if rest:
        alerts += D.detect_records(records, baseline=baseline, enabled_rules=rest, r4_scope=r4_scope,
                                   r6_scope=r6_scope, **kw)

    def sub(pred):
        return [r for r in records if pred(r)]

    if "R2" in rules:
        recs = records
        if allowlist:
            recs = sub(lambda r: not allow_match(allowlist, r))
        if r2_scope is not None:
            recs = [r for r in recs if r.src in r2_scope]
        alerts += D.detect_records(recs, baseline=baseline, enabled_rules=["R2"], **kw)
    if "R5" in rules:
        recs = records
        if allowlist:
            recs = sub(lambda r: not allow_match(allowlist, r))
        if r5_scope == "app_nondns":
            recs = [r for r in recs if r.src in APPS and r.dst in APPS and r.port != 53]
        elif r5_scope == "src" and r2_scope is not None:
            recs = [r for r in recs if r.src in r2_scope]
        alerts += D.detect_records(recs, baseline=baseline, enabled_rules=["R5"], **kw)

    for sig in (signatures or []):
        if sig["id"] not in rules:
            continue
        for r in records:
            if sig_match(sig, r):
                alerts.append(D.Alert(r.time_str, sig["id"], r.src, r.dst, r.port, r.verdict))

    tags = []
    if multistep:
        tags = multistep_incidents(alerts, multistep)
    return alerts, tags


def multistep_incidents(alerts, window):
    """C1: same source, a recon alert (R4/R6) followed within `window` s by a signature alert (S*)."""
    def t(a):
        return D.flow_time({"time": a.time_str}) or 0.0
    recon = sorted((a for a in alerts if a.rule in ("R4", "R6")), key=t)
    sigs = sorted((a for a in alerts if a.rule.startswith("S")), key=t)
    out, used = [], set()
    for rc in recon:
        for i, s in enumerate(sigs):
            if i in used or s.src != rc.src:
                continue
            if 0 <= t(s) - t(rc) <= window:
                out.append((rc.src, rc.rule, s.rule))
                used.add(i)
                break
    return out


D_DEFAULTS = dict(
    window_seconds=10, fanout_threshold=5, sensitive_ports=set(D.DEFAULT_SENSITIVE_PORTS), k_sigma=3.0,
)

# ------------------------------------------------------------------ combinations
ALL5 = ["R1", "R2", "R3", "R4", "R5"]
SIGS = ["S1", "S2", "S3", "S4", "S5"]


def combos(allowlist, signatures, window=60.0):
    kn = set(APPS)
    k2 = dict(rules=ALL5, r4_scope=kn)
    k5a = dict(rules=ALL5, r4_scope=kn, r2_scope=kn, r5_scope="src")
    k5b = dict(rules=ALL5, r4_scope=kn, allowlist=allowlist, r1_policy_only=True, r5_scope="app_nondns")
    k6 = dict(k5b, rules=ALL5 + SIGS, signatures=signatures)
    k6r3 = dict(k6, rules=[r for r in ALL5 + SIGS if r != "R3"])
    k7 = dict(k6, multistep=window)
    return {"K2": k2, "K5a": k5a, "K5b": k5b, "K6": k6, "K6-r3": k6r3, "K7": k7}


def run_combo(spec, records, baseline):
    spec = dict(spec)
    rules = spec.pop("rules")
    return detect3(records, baseline, rules, **spec)
