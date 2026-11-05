#!/usr/bin/env python3
"""Measurement mode of the testbed: how long operations take, and when their
result becomes readable from other nodes.

Built on testbed.py: start a network with it first.

    testbed/testbed.py up --nodes 10 --k 3 --profile wan-eu
    testbed/measure.py publish --rounds 20    # publication time and availability
    testbed/measure.py publish --rounds 20 --watchers 0 --counters   # and what the nodes sent

See testbed/README.md, section "Measurement mode".
"""

import argparse
import concurrent.futures
import json
import statistics
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True  # no __pycache__ inside the repository
sys.path.insert(0, str(Path(__file__).resolve().parent))
from testbed import GENERATED, IMAGE, check_node, ctl, fail, load_config  # noqa: E402


def summary(values):
    """Median, 95th percentile and maximum of a list of milliseconds."""
    if not values:
        return "no samples"
    ordered = sorted(values)
    p95 = ordered[min(len(ordered) - 1, round(0.95 * (len(ordered) - 1)))]
    return f"median {statistics.median(ordered):.1f} ms, p95 {p95:.1f} ms, max {ordered[-1]:.1f} ms (n={len(ordered)})"


# Upper bounds of the check duration buckets, as in src/counters.rs.
CHECK_DURATION_BOUNDS_MS = [10, 25, 50, 100, 200, 500, 1000, 2000]


def all_counters(pool, nodes):
    """Counters of every node (`ctl <node> counters`), by node."""
    replies = pool.map(lambda n: (ctl(n, "counters", check=False) or {}).get("counters"), nodes)
    return dict(zip(nodes, replies))


def counters_delta(before, after):
    """What every node together sent between two snapshots of all_counters."""
    total = {"sent": {}, "resends_to_measured_peers": 0, "resends_to_unmeasured_peers": 0, "checks": {}}
    for node, last in after.items():
        first = before.get(node)
        if not last or not first:
            continue
        for kind, sent in last["sent"].items():
            was = first["sent"].get(kind, {"datagrams": 0, "bytes": 0})
            into = total["sent"].setdefault(kind, {"datagrams": 0, "bytes": 0})
            into["datagrams"] += sent["datagrams"] - was["datagrams"]
            into["bytes"] += sent["bytes"] - was["bytes"]
        for key in ("resends_to_measured_peers", "resends_to_unmeasured_peers"):
            total[key] += last[key] - first[key]
        for key, value in last["checks"].items():
            if isinstance(value, list):
                into = total["checks"].setdefault(key, [0] * len(value))
                for i, v in enumerate(value):
                    into[i] += v - first["checks"][key][i]
            else:
                total["checks"][key] = total["checks"].get(key, 0) + value - first["checks"][key]
    total["sent"] = {kind: sent for kind, sent in total["sent"].items() if sent["datagrams"]}
    return total


def print_counters(rounds):
    """Medians per publication of what the nodes sent, and the checks of all rounds."""
    counted = [r["counters"] for r in rounds if r.get("counters")]
    if not counted:
        return
    median = lambda values: statistics.median(values) if values else 0
    total_bytes = [sum(s["bytes"] for s in c["sent"].values()) for c in counted]
    total_datagrams = [sum(s["datagrams"] for s in c["sent"].values()) for c in counted]
    print(f"  sent by all nodes per publication (median of {len(counted)}): "
          f"{median(total_bytes) / 1024:.1f} KiB, {median(total_datagrams):.0f} datagrams")
    kinds = sorted({kind for c in counted for kind in c["sent"]})
    for kind in kinds:
        values = [c["sent"].get(kind, {"datagrams": 0, "bytes": 0}) for c in counted]
        print(f"    {kind:<16} {median([v['bytes'] for v in values]) / 1024:8.1f} KiB "
              f"{median([v['datagrams'] for v in values]):6.0f} datagrams")
    measured = sum(c["resends_to_measured_peers"] for c in counted)
    unmeasured = sum(c["resends_to_unmeasured_peers"] for c in counted)
    print(f"  resends in all rounds: {measured} to measured peers, {unmeasured} to peers never measured")
    checks = {}
    for c in counted:
        for key, value in c["checks"].items():
            if isinstance(value, list):
                into = checks.setdefault(key, [0] * len(value))
                for i, v in enumerate(value):
                    into[i] += v
            else:
                checks[key] = checks.get(key, 0) + value
    if checks:
        ended = ", ".join(f"{key} {checks[key]}" for key in
                          ("none_or_same", "other", "no_answer", "nobody_to_ask", "unbound") if key in checks)
        print(f"  checks in all rounds: {ended}")
        rounds_hist = checks.get("rounds", [])
        print("  check lookups by rounds: " + ", ".join(
            f"{i + 1}{'+' if i + 1 == len(rounds_hist) else ''}: {n}" for i, n in enumerate(rounds_hist)))
        durations = checks.get("duration_ms", [])
        labels = [f"<={b} ms" for b in CHECK_DURATION_BOUNDS_MS] + [f">{CHECK_DURATION_BOUNDS_MS[-1]} ms"]
        print("  check lookups by duration: " + ", ".join(
            f"{label}: {n}" for label, n in zip(labels, durations) if n))
        lookups = sum(rounds_hist)
        if lookups:
            print(f"  check lookup mean duration: {checks['duration_total_us'] / lookups / 1000:.1f} ms")


def print_read_counters(rounds):
    """What the nodes sent per remote read, over the reads after each publication."""
    counted = [(r["read_counters"], len(r["remote_read_ms"])) for r in rounds if r.get("read_counters")]
    remote = sum(n for _, n in counted)
    if not remote:
        return
    sent = {}
    for delta, _ in counted:
        for kind, value in delta["sent"].items():
            into = sent.setdefault(kind, {"datagrams": 0, "bytes": 0})
            into["datagrams"] += value["datagrams"]
            into["bytes"] += value["bytes"]
    total_bytes = sum(v["bytes"] for v in sent.values())
    total_datagrams = sum(v["datagrams"] for v in sent.values())
    print(f"  sent by all nodes per remote read (mean of {remote}; local reads send nothing): "
          f"{total_bytes / remote / 1024:.1f} KiB, {total_datagrams / remote:.1f} datagrams")
    for kind in sorted(sent):
        print(f"    {kind:<16} {sent[kind]['bytes'] / remote / 1024:8.2f} KiB "
              f"{sent[kind]['datagrams'] / remote:6.1f} datagrams")


def cmd_publish(args):
    """Each round: the owner creates a new DID; some nodes start reading it in
    a loop; the owner publishes it; then every other node reads it once."""
    config = load_config()
    check_node(args.owner, config)
    nodes = [f"node-{i}" for i in range(1, config["nodes"] + 1)]
    others = [n for n in nodes if n != args.owner]
    rounds = []
    print(
        f"publish: {args.rounds} rounds, owner {args.owner}, {config['nodes']} nodes, k={config['k']}, "
        f"profile {config['profile']}, image {config.get('image', IMAGE)}"
    )
    print(f"{'round':>5}  {'outcome':<10} {'publish':>9}  {'first read':>10}  {'reads after':>11}")
    if args.counters and args.watchers:
        print("note: the watchers' reads are counted too; --watchers 0 counts the publication alone")
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        for number in range(1, args.rounds + 1):
            did = ctl(args.owner, "new")["did"]
            start = (number - 1) * args.watchers
            watchers = [others[(start + i) % len(others)] for i in range(args.watchers)]
            watching = [pool.submit(ctl, w, "watch", did, str(args.watch_ms), check=False) for w in watchers]
            time.sleep(args.lead)  # let the watchers start reading before the publication
            before = all_counters(pool, nodes) if args.counters else None
            published = ctl(args.owner, "publish")
            after = None
            if args.counters:
                time.sleep(args.settle)  # answers still on their way when the owner returns
                after = all_counters(pool, nodes)
            seen = [f.result() or {} for f in watching]
            reads = list(pool.map(lambda n: ctl(n, "get", did, check=False) or {}, others))
            after_reads = all_counters(pool, nodes) if args.counters else None

            started = published["started_unix_ms"]
            delays = [w["found_unix_ms"] - started for w in seen if w.get("found")]
            entry = {
                "did": did,
                "outcome": published["outcome"],
                "publish_ms": published["ms"],
                "stored": published["stored"],
                "expected": published["expected_replicas"],
                "readable_after_ms": sorted(delays),
                "watchers_found": len(delays),
                "watchers": len(seen),
                "reads_found": sum(1 for r in reads if r.get("found")),
                "reads": len(reads),
                "remote_read_ms": [r["ms"] for r in reads if r.get("found") and not r.get("local_copy")],
            }
            if args.counters:
                entry["counters"] = counters_delta(before, after)
                entry["read_counters"] = counters_delta(after, after_reads)
            rounds.append(entry)
            first = f"{min(delays):.1f} ms" if delays else "never"
            print(
                f"{number:>5}  {entry['outcome']:<10} {entry['publish_ms']:>6.1f} ms  {first:>10}  "
                f"{entry['reads_found']}/{entry['reads']}"
            )

    count = lambda value: sum(1 for r in rounds if r["outcome"] == value)
    print("\nsummary")
    print("  outcomes: " + ", ".join(f"{o} {count(o)}" for o in sorted({r['outcome'] for r in rounds})))
    print(f"  publication time: {summary([r['publish_ms'] for r in rounds])}")
    firsts = [r["readable_after_ms"][0] for r in rounds if r["readable_after_ms"]]
    print(f"  readable by the first watcher, from the start of the publication: {summary(firsts)}")
    found = sum(r["watchers_found"] for r in rounds)
    watched = sum(r["watchers"] for r in rounds)
    print(f"  watchers that found it within {args.watch_ms} ms: {found}/{watched}")
    reads_found = sum(r["reads_found"] for r in rounds)
    reads = sum(r["reads"] for r in rounds)
    print(f"  reads by every other node right after the publication: {reads_found}/{reads} found")
    print(f"  remote read time: {summary([ms for r in rounds for ms in r['remote_read_ms']])}")
    print_counters(rounds)
    print_read_counters(rounds)
    GENERATED.mkdir(exist_ok=True)
    out = GENERATED / f"publish-{config['profile']}-{time.strftime('%Y%m%d-%H%M%S')}.json"
    out.write_text(json.dumps({"config": config, "rounds": rounds}, indent=2) + "\n")
    print(f"  details: {out}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    pb = sub.add_parser("publish", help="publication time and when the record becomes readable")
    pb.add_argument("--owner", default="node-1")
    pb.add_argument("--rounds", type=int, default=20)
    pb.add_argument("--watchers", type=int, default=3, help="nodes reading the DID in a loop during the publication")
    pb.add_argument("--watch-ms", type=int, default=10000, help="how long a watcher keeps reading")
    pb.add_argument("--lead", type=float, default=0.5, help="seconds between starting the watchers and publishing")
    pb.add_argument("--counters", action="store_true",
                    help="read every node's counters before and after each publication (image with counters)")
    pb.add_argument("--settle", type=float, default=0.3,
                    help="seconds to wait after the publication before reading the counters")
    pb.set_defaults(func=cmd_publish)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
