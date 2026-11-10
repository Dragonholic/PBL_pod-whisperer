#!/usr/bin/env python3
"""
detector.py - rule-based lateral-movement / internal-recon detector over
Cilium Hubble flow logs (JSON Lines, as produced by `hubble observe -o json`).

Subcommands:
    baseline   Build a baseline of "known-good" (src_app, dst, port) paths
               from normal-labeled flow files.
    detect     Run the rule set against one flow file (optionally using a
               baseline) and print [ALERT] lines.

Flow JSON fields used (see docs/findings.md for what was actually observed
in this cluster):
    time                                  RFC3339 timestamp
    verdict                               "FORWARDED" | "DROPPED" | "AUDIT" | ...
    IP.source / IP.destination            IPs
    l4.TCP.destination_port / l4.UDP.destination_port
    source.labels / destination.labels    e.g. ["k8s:app=frontend", ...]
    source.namespace / destination.namespace
    destination_names                     DNS names Hubble resolved, if any

Endpoints are identified by app label (k8s:app=<name>) wherever possible,
falling back to the raw IP (e.g. for node IPs / apiserver ClusterIP, which
carry no Kubernetes labels at all).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import defaultdict, deque, namedtuple
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

# NOTE: 6443 is included alongside 443 because on a kind cluster, Cilium's
# eBPF service DNAT rewrites kubernetes.default.svc:443 / the apiserver
# ClusterIP:443 to <control-plane-node-ip>:6443 before Hubble observes the
# flow -- so apiserver probes show up as destination_port=6443, not 443.
# See docs/findings.md.
DEFAULT_SENSITIVE_PORTS = {22, 443, 6443, 2379, 2380, 10250, 10255, 3306, 6379}
DEFAULT_WINDOW_SECONDS = 10
DEFAULT_FANOUT_THRESHOLD = 5

ALL_RULES = ["R1", "R2", "R3", "R4", "R5"]  # R6 (v2) is opt-in via enabled_rules

# R6 parameters from Jung et al. 2004 (TRW): benign success probability theta0,
# scanner success probability theta1, target false-alarm alpha, detection beta.
DEFAULT_TRW = {"theta0": 0.8, "theta1": 0.2, "alpha": 0.01, "beta": 0.99}


# --------------------------------------------------------------------------
# Config loading
# --------------------------------------------------------------------------

def load_config(path: Optional[str]) -> dict:
    if not path:
        return {}
    p = Path(path)
    if not p.exists():
        return {}
    if yaml is None:
        print("WARNING: PyYAML not installed; ignoring config file", file=sys.stderr)
        return {}
    with p.open() as f:
        return yaml.safe_load(f) or {}


def cfg_get(cfg: dict, *keys, default=None):
    cur = cfg
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


# --------------------------------------------------------------------------
# Flow parsing helpers
# --------------------------------------------------------------------------

def iter_flows(flow_file: str) -> Iterable[dict]:
    """Yields parsed flow dicts from a JSON-Lines hubble observe dump.
    Tolerates blank lines and non-JSON noise (e.g. hubble CLI banners)."""
    with open(flow_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            # `hubble observe -o json` wraps each flow as {"flow": {...}} on
            # some CLI versions, and emits the flow fields at top level on
            # others. Normalize to the inner flow dict either way.
            if isinstance(obj, dict) and "flow" in obj and isinstance(obj["flow"], dict):
                obj = obj["flow"]
            yield obj


def _label_dict(labels: Optional[List[str]]) -> Dict[str, str]:
    out = {}
    for lbl in labels or []:
        if "=" in lbl:
            k, v = lbl.split("=", 1)
            k = k.split(":", 1)[-1]  # strip "k8s:" prefix
            out[k] = v
    return out


def app_of(endpoint: Optional[dict]) -> Optional[str]:
    if not endpoint:
        return None
    labels = _label_dict(endpoint.get("labels"))
    return labels.get("app")


# Cilium assigns special "reserved:*" identities to endpoints that have no
# Kubernetes pod of their own -- notably the control plane. Empirically (see
# docs/findings.md), a kind control-plane node's apiserver IP carries
# labels ["reserved:kube-apiserver", "reserved:remote-node"], NOT a plain
# node IP with zero identity. Preferring these over a raw IP makes alerts
# readable (`-> reserved:kube-apiserver:6443` instead of `-> 172.18.0.4:6443`)
# and means R2/baseline keys for apiserver/host/world traffic are stable
# across node IP churn.
_RESERVED_PRIORITY = [
    "kube-apiserver",
    "host",
    "remote-node",
    "world",
    "unmanaged",
    "init",
]


def reserved_identity_of(endpoint: Optional[dict]) -> Optional[str]:
    if not endpoint:
        return None
    reserved = {
        lbl.split(":", 1)[1]
        for lbl in (endpoint.get("labels") or [])
        if lbl.startswith("reserved:")
    }
    if not reserved:
        return None
    for preferred in _RESERVED_PRIORITY:
        if preferred in reserved:
            return f"reserved:{preferred}"
    return f"reserved:{sorted(reserved)[0]}"


def identity_of(endpoint: Optional[dict], ip: Optional[str]) -> str:
    """Best-effort human-readable identity for an endpoint, in priority
    order: Kubernetes app label, Cilium reserved identity (e.g.
    reserved:kube-apiserver), pod_name, else raw IP (e.g. an otherwise
    unclassified node IP, which carries no k8s labels in Hubble's view)."""
    app = app_of(endpoint)
    if app:
        ns = (endpoint or {}).get("namespace")
        return f"{ns}/{app}" if ns else app
    reserved = reserved_identity_of(endpoint)
    if reserved:
        return reserved
    if endpoint and endpoint.get("pod_name"):
        ns = endpoint.get("namespace")
        pod = endpoint["pod_name"]
        return f"{ns}/{pod}" if ns else pod
    return ip or "unknown"


def dest_port(flow: dict) -> Optional[int]:
    l4 = flow.get("l4") or {}
    tcp = l4.get("TCP")
    if tcp and "destination_port" in tcp:
        return int(tcp["destination_port"])
    udp = l4.get("UDP")
    if udp and "destination_port" in udp:
        return int(udp["destination_port"])
    return None


def is_reply_flow(flow: dict) -> bool:
    """True for the reply/return leg of a connection. Hubble reports replies
    as their own flow with source/destination swapped, so a reply flow's
    "destination_port" is actually the ORIGINAL CLIENT's ephemeral port, not
    a meaningful service port. Without filtering these out, a naive
    (src,dst,port) baseline/path model explodes with thousands of spurious
    "new paths" (one per ephemeral port) -- this was observed empirically
    when collecting without a --namespace filter; see docs/findings.md."""
    return bool(flow.get("is_reply"))


def flow_tuple(flow: dict) -> Tuple[str, str, Optional[int]]:
    """(src_identity, dst_identity, dst_port) used as the baseline/path key."""
    ip = flow.get("IP") or {}
    src_ep = flow.get("source")
    dst_ep = flow.get("destination")
    src = identity_of(src_ep, ip.get("source"))
    dst = identity_of(dst_ep, ip.get("destination"))
    return src, dst, dest_port(flow)


def flow_time(flow: dict) -> Optional[float]:
    """Parse the flow's RFC3339 `time` field to a unix timestamp (float).
    Returns None if missing/unparsable (flow is still used, just excluded
    from window-based rules).

    Hubble emits nanosecond-precision fractional seconds (9 digits, e.g.
    "2026-11-02T04:33:56.483740718Z"), but Python's datetime.fromisoformat()
    on this runtime (3.10, pre-3.11) only accepts up to microsecond (6-digit)
    precision and raises ValueError on anything longer. Without truncating
    this, flow_time() silently returned None for EVERY flow, which meant R4
    (fan-out) -- gated on `ts is not None` -- never fired for ANY scenario,
    including abnormal_2/abnormal_3/evasion_1 which are specifically designed
    to trigger it. See docs/findings.md."""
    t = flow.get("time")
    if not t:
        return None
    try:
        from datetime import datetime
        t = t.replace("Z", "+00:00")
        t = re.sub(r"(\.\d{6})\d+", r"\1", t)
        return datetime.fromisoformat(t).timestamp()
    except Exception:
        return None


FlowRecord = namedtuple("FlowRecord", "src dst port verdict time_str ts reply")


def flow_records(flow_file: str) -> List[FlowRecord]:
    """Reduce a Hubble flow dump to the few fields the rules need. Parsing the
    JSON is the slow part, so callers that evaluate many settings over the same
    data (see v2_experiments.py) parse once and reuse the records."""
    out: List[FlowRecord] = []
    for flow in iter_flows(flow_file):
        src, dst, port = flow_tuple(flow)
        out.append(FlowRecord(src, dst, port, flow.get("verdict", "UNKNOWN"),
                              flow.get("time", ""), flow_time(flow), is_reply_flow(flow)))
    return out


# --------------------------------------------------------------------------
# Baseline
# --------------------------------------------------------------------------

def build_baseline(normal_flow_files: List[str]) -> dict:
    """Builds a baseline of allowed (src,dst,port) paths, plus per-path
    frequency stats (count per file/run) for the optional R5 rule."""
    return build_baseline_from_records([flow_records(ff) for ff in normal_flow_files])


def build_baseline_from_records(runs: List[List[FlowRecord]]) -> dict:
    paths = set()
    per_run_counts: Dict[Tuple[str, str, Optional[int]], List[int]] = defaultdict(list)

    for records in runs:
        run_counts: Dict[Tuple[str, str, Optional[int]], int] = defaultdict(int)
        for r in records:
            if r.reply:
                continue
            key = (r.src, r.dst, r.port)
            paths.add(key)
            run_counts[key] += 1
        for key, count in run_counts.items():
            per_run_counts[key].append(count)

    freq_stats = {}
    for key, counts in per_run_counts.items():
        n = len(counts)
        mean = sum(counts) / n
        var = sum((c - mean) ** 2 for c in counts) / n if n > 0 else 0.0
        freq_stats[key] = {"mean": mean, "stddev": var ** 0.5, "n_runs": n}

    def key_to_str(key: Tuple[str, str, Optional[int]]) -> str:
        return json.dumps(list(key))

    return {
        "paths": [key_to_str(k) for k in sorted(paths, key=lambda k: (k[0], k[1], k[2] or 0))],
        "frequency": {key_to_str(k): v for k, v in freq_stats.items()},
    }


def load_baseline(path: str) -> dict:
    p = Path(path)
    if not p.exists():
        return {"paths": [], "frequency": {}}
    with p.open() as f:
        return json.load(f)


def baseline_path_set(baseline: dict) -> set:
    return {tuple(json.loads(s)) for s in baseline.get("paths", [])}


def baseline_freq(baseline: dict) -> Dict[Tuple[str, str, Optional[int]], dict]:
    return {tuple(json.loads(k)): v for k, v in baseline.get("frequency", {}).items()}


# --------------------------------------------------------------------------
# Detection rules
# --------------------------------------------------------------------------

class Alert:
    def __init__(self, time_str: str, rule: str, src: str, dst: str, port: Optional[int], verdict: str):
        self.time_str = time_str
        self.rule = rule
        self.src = src
        self.dst = dst
        self.port = port
        self.verdict = verdict

    def __str__(self) -> str:
        port_s = self.port if self.port is not None else "?"
        return f"[ALERT] {self.time_str} | {self.rule} | {self.src} -> {self.dst}:{port_s} | {self.verdict}"

    def to_dict(self) -> dict:
        return {
            "time": self.time_str,
            "rule": self.rule,
            "src": self.src,
            "dst": self.dst,
            "port": self.port,
            "verdict": self.verdict,
        }


def detect(flow_file: str, **kwargs) -> List[Alert]:
    return detect_records(flow_records(flow_file), **kwargs)


def detect_records(
    records: List[FlowRecord],
    baseline: Optional[dict] = None,
    window_seconds: int = DEFAULT_WINDOW_SECONDS,
    fanout_threshold: int = DEFAULT_FANOUT_THRESHOLD,
    sensitive_ports: Optional[set] = None,
    enabled_rules: Optional[List[str]] = None,
    k_sigma: float = 3.0,
    r4_scope: Optional[set] = None,
    r6_scope: Optional[set] = None,
    trw: Optional[dict] = None,
) -> List[Alert]:
    sensitive_ports = sensitive_ports if sensitive_ports is not None else DEFAULT_SENSITIVE_PORTS
    enabled_rules = enabled_rules if enabled_rules is not None else ALL_RULES
    baseline_paths = baseline_path_set(baseline) if baseline else set()
    freq_stats = baseline_freq(baseline) if baseline else {}

    # R6 constants (Jung et al. 2004): a failed first contact multiplies the
    # likelihood ratio by (1-theta1)/(1-theta0), a successful one by
    # theta1/theta0; scanner at >= beta/alpha, benign at <= (1-beta)/(1-alpha).
    t = {**DEFAULT_TRW, **(trw or {})}
    fail_mult = (1 - t["theta1"]) / (1 - t["theta0"])
    ok_mult = t["theta1"] / t["theta0"]
    eta_scanner = t["beta"] / t["alpha"]
    eta_benign = (1 - t["beta"]) / (1 - t["alpha"])

    alerts: List[Alert] = []

    # Sliding window per source identity for R4 fan-out: deque of
    # (timestamp, (dst,port)) tuples.
    fanout_windows: Dict[str, deque] = defaultdict(deque)
    # Per-(src,dst,port) running count for the current flow_file's "run"
    # (used by R5 against baseline mean/stddev for that same run-length).
    path_counts: Dict[Tuple[str, str, Optional[int]], int] = defaultdict(int)
    # R6 state per source: first-contact (dst,port) pairs seen, likelihood
    # ratio, and whether the source was already reported.
    trw_state: Dict[str, dict] = {}

    for rec in records:
        src, dst, port = rec.src, rec.dst, rec.port
        key = (src, dst, port)
        verdict, tstr, ts, reply = rec.verdict, rec.time_str, rec.ts, rec.reply

        # R1: policy violation (DROPPED by a NetworkPolicy / Cilium policy).
        # Applied to all flows -- a dropped connection attempt is always the
        # request leg anyway (there is no reply to a dropped packet).
        if "R1" in enabled_rules and verdict == "DROPPED":
            alerts.append(Alert(tstr, "R1", src, dst, port, verdict))

        # R3: sensitive/control-plane port, unless it's a path already known
        # to be part of this app's normal baseline (e.g. ordinary HTTPS
        # egress that happens to use port 443 for a legitimate reason).
        # Applied to all flows: reply flows essentially never hit this since
        # their destination_port is an ephemeral client port, not a
        # sensitive port.
        if "R3" in enabled_rules and port in sensitive_ports:
            if not baseline or key not in baseline_paths:
                alerts.append(Alert(tstr, "R3", src, dst, port, verdict))

        # Everything below (R2 new-path, R4 fan-out, R5 frequency) keys on
        # (src,dst,port) as a stand-in for "service path", which is only
        # meaningful for the request/initiation leg of a connection -- a
        # reply flow's "destination_port" is the original client's ephemeral
        # port, not a service port, and would otherwise explode R2/R4 with
        # spurious "new paths" (observed empirically; see docs/findings.md).
        if reply:
            continue
        path_counts[key] += 1

        # R2: new path, i.e. not present in the baseline of normal traffic.
        if "R2" in enabled_rules and baseline and key not in baseline_paths:
            alerts.append(Alert(tstr, "R2", src, dst, port, verdict))

        # R4: fan-out -- distinct (dst,port) pairs from one src within a
        # sliding window of `window_seconds`.
        # If r4_scope is given, only sources in that set (known_apps) are
        # tracked -- cluster-infra sources (kubelet health checks etc.) are
        # out of scope and no longer produce fan-out noise.
        if "R4" in enabled_rules and ts is not None and (r4_scope is None or src in r4_scope):
            dq = fanout_windows[src]
            dq.append((ts, (dst, port)))
            while dq and ts - dq[0][0] > window_seconds:
                dq.popleft()
            distinct_pairs = {pair for (_, pair) in dq}
            if len(distinct_pairs) >= fanout_threshold:
                alerts.append(Alert(tstr, "R4", src, dst, port, verdict))
                dq.clear()  # avoid re-alerting on every subsequent flow in the same burst

        # R6: consecutive failed first contacts (v2). Only the first flow to
        # each new (dst,port) counts, DROPPED = failure, anything else =
        # success. Flows without a port (ICMP, NDP multicast) are skipped.
        # The walk restarts after a "benign" decision; one alert per source.
        if "R6" in enabled_rules and port is not None and (r6_scope is None or src in r6_scope):
            st = trw_state.setdefault(src, {"seen": set(), "lr": 1.0, "reported": False})
            if (dst, port) not in st["seen"]:
                st["seen"].add((dst, port))
                st["lr"] *= fail_mult if verdict == "DROPPED" else ok_mult
                if st["lr"] >= eta_scanner and not st["reported"]:
                    alerts.append(Alert(tstr, "R6", src, dst, port, verdict))
                    st["reported"] = True
                elif st["lr"] <= eta_benign:
                    st["lr"] = 1.0

        # R5 (optional): frequency anomaly vs. baseline mean/stddev for this
        # exact path, evaluated once per file after all flows are counted
        # (done after the loop, see below).

    if "R5" in enabled_rules and baseline:
        for key, count in path_counts.items():
            stats = freq_stats.get(key)
            if not stats or stats["n_runs"] == 0:
                continue
            threshold = stats["mean"] + k_sigma * stats["stddev"]
            if count >= max(threshold, stats["mean"] + 1):
                src, dst, port = key
                alerts.append(Alert(records[-1].time_str if records else "", "R5", src, dst, port, "FREQUENCY_ANOMALY"))

    return alerts


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def cmd_baseline(args: argparse.Namespace) -> None:
    baseline = build_baseline(args.normal_flows)
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w") as f:
        json.dump(baseline, f, indent=2)
    print(f"Wrote baseline with {len(baseline['paths'])} known paths to {out_path}")


def r4_scope_from_cfg(cfg: dict) -> Optional[set]:
    """Source identities R4 is limited to, or None for unscoped (legacy)."""
    if not cfg_get(cfg, "detection", "r4_scope_known_apps", default=False):
        return None
    ns = cfg_get(cfg, "namespace", default="")
    return {f"{ns}/{a}" if ns else a for a in cfg_get(cfg, "known_apps", default=[])}


def cmd_detect(args: argparse.Namespace) -> None:
    cfg = load_config(args.config)
    window_seconds = args.window if args.window is not None else cfg_get(cfg, "detection", "window_seconds", default=DEFAULT_WINDOW_SECONDS)
    fanout_threshold = args.fanout if args.fanout is not None else cfg_get(cfg, "detection", "fanout_threshold", default=DEFAULT_FANOUT_THRESHOLD)
    sensitive_ports = set(cfg_get(cfg, "detection", "sensitive_ports", default=sorted(DEFAULT_SENSITIVE_PORTS)))
    k_sigma = cfg_get(cfg, "detection", "frequency", "k_sigma", default=3)

    baseline = load_baseline(args.baseline) if args.baseline else None
    enabled_rules = args.rules.split(",") if args.rules else ALL_RULES

    alerts = detect(
        args.flow_file,
        baseline=baseline,
        window_seconds=window_seconds,
        fanout_threshold=fanout_threshold,
        sensitive_ports=sensitive_ports,
        enabled_rules=enabled_rules,
        k_sigma=k_sigma,
        r4_scope=r4_scope_from_cfg(cfg),
    )

    if args.json:
        print(json.dumps([a.to_dict() for a in alerts], indent=2))
    else:
        for a in alerts:
            print(a)
        print(f"# {len(alerts)} alert(s) from {args.flow_file}", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description="Rule-based lateral-movement detector over Hubble flow JSON")
    sub = parser.add_subparsers(dest="command", required=True)

    p_baseline = sub.add_parser("baseline", help="Build a baseline from normal-labeled flow files")
    p_baseline.add_argument("normal_flows", nargs="+", help="Path(s) to normal-labeled flow JSON files")
    p_baseline.add_argument("-o", "--output", default="data/baseline.json", help="Output baseline JSON path")
    p_baseline.set_defaults(func=cmd_baseline)

    p_detect = sub.add_parser("detect", help="Run detection rules against a single flow file")
    p_detect.add_argument("flow_file", help="Path to a flow JSON file (hubble observe -o json dump)")
    p_detect.add_argument("-b", "--baseline", default=None, help="Path to baseline.json (required for R2/R5)")
    p_detect.add_argument("-c", "--config", default=None, help="Path to config.yaml")
    p_detect.add_argument("--window", type=int, default=None, help="Override fan-out window (seconds)")
    p_detect.add_argument("--fanout", type=int, default=None, help="Override fan-out threshold")
    p_detect.add_argument("--rules", default=None, help="Comma-separated rule subset, e.g. R1,R2,R3")
    p_detect.add_argument("--json", action="store_true", help="Emit alerts as a JSON array instead of text")
    p_detect.set_defaults(func=cmd_detect)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
