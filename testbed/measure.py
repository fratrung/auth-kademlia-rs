#!/usr/bin/env python3
"""Measurement mode of the testbed: how long operations take, and when their
result becomes readable from other nodes.

Built on testbed.py: start a network with it first.

    testbed/testbed.py up --nodes 10 --k 3 --profile wan-eu
    testbed/measure.py publish --rounds 20    # publication time and availability

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
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        for number in range(1, args.rounds + 1):
            did = ctl(args.owner, "new")["did"]
            start = (number - 1) * args.watchers
            watchers = [others[(start + i) % len(others)] for i in range(args.watchers)]
            watching = [pool.submit(ctl, w, "watch", did, str(args.watch_ms), check=False) for w in watchers]
            time.sleep(args.lead)  # let the watchers start reading before the publication
            published = ctl(args.owner, "publish")
            seen = [f.result() or {} for f in watching]
            reads = list(pool.map(lambda n: ctl(n, "get", did, check=False) or {}, others))

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
    pb.set_defaults(func=cmd_publish)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
