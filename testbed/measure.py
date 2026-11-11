#!/usr/bin/env python3
"""Measurement mode of the testbed: how long operations take, and when their
result becomes readable from other nodes.

Built on testbed.py: start a network with it first.

    testbed/testbed.py up --nodes 10 --k 3 --profile wan-eu
    testbed/measure.py publish --rounds 20    # publication time and availability
    testbed/measure.py publish --rounds 20 --watchers 0 --counters   # and what the nodes sent
    testbed/measure.py update --rounds 20     # rotation time, and which replicas hold the new version
    testbed/measure.py update --rounds 20 --rotations 2 --restart 1  # a replica restarted before the second
    testbed/measure.py update --rounds 20 --restart 1 --liars 1      # one replica lies in FindHash
    testbed/measure.py churn --duration 600 --liars 1                # copies over time while nodes crash
    testbed/measure.py outage --lost 4 8 12 --rounds 5               # owner offline, replicas lost at once

See testbed/README.md, section "Measurement mode".
"""

import argparse
import base64
import concurrent.futures
import hashlib
import json
import math
import random
import statistics
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True  # no __pycache__ inside the repository
sys.path.insert(0, str(Path(__file__).resolve().parent))
from testbed import GENERATED, IMAGE, check_node, container, ctl, fail, load_config, run  # noqa: E402
from attack import keys_of, wait_answering  # noqa: E402


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


def print_counters(rounds, per="publication"):
    """Medians per operation of what the nodes sent, and the checks of all rounds."""
    counted = [r["counters"] for r in rounds if r.get("counters")]
    if not counted:
        return
    median = lambda values: statistics.median(values) if values else 0
    total_bytes = [sum(s["bytes"] for s in c["sent"].values()) for c in counted]
    total_datagrams = [sum(s["datagrams"] for s in c["sent"].values()) for c in counted]
    print(f"  sent by all nodes per {per} (median of {len(counted)}): "
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
        # The outcomes of ADR 0005, then those of main (ADR 0004), so that the
        # same mode measures both images.
        ended = ", ".join(f"{key} {checks[key]}" for key in
                          ("accepted", "newer_claimed", "other_version", "not_following",
                           "holder_behind", "fetch_refused", "too_few_votes", "no_answer",
                           "nobody_to_ask", "invalid",
                           "none_or_same", "other", "unbound") if key in checks)
        print(f"  checks in all rounds: {ended}")
        if checks.get("fetches"):
            fetch_labels = [f"<={b} ms" for b in CHECK_DURATION_BOUNDS_MS] + [f">{CHECK_DURATION_BOUNDS_MS[-1]} ms"]
            print(f"  checks that fetched the version before: {checks['fetches']}, by whole check duration: " +
                  ", ".join(f"{label}: {n}" for label, n in zip(fetch_labels, checks.get("fetch_duration_ms", [])) if n))
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


def node_id(node):
    """The id of a testbed node, as testbed/node.rs derives it from its name."""
    return hashlib.sha256(f"testbed:{node}".encode()).digest()


def dht_key(did):
    """The DHT key of a DID: the decoded suffix of a self-certifying DID
    (ADR 0005, 43 characters), or the SHA-256 of the UUID (ADR 0004)."""
    suffix = did.removeprefix("did:iiot:")
    if len(suffix) == 43:
        return base64.urlsafe_b64decode(suffix + "=")
    return hashlib.sha256(suffix.encode()).digest()


def closest(nodes, key, count):
    """The `count` nodes closest to `key` by XOR distance: the replicas."""
    target = int.from_bytes(key, "big")
    return sorted(nodes, key=lambda n: int.from_bytes(node_id(n), "big") ^ target)[:count]


def version_label(versions):
    """Name a signing key by the version of the round's DID it belongs to."""
    def label(key):
        if key is None:
            return "none"
        if key == versions[-1]:
            return "current"
        return "older" if key in versions else "other"
    return label


def tally(labels):
    return {name: sum(1 for value in labels if value == name) for name in ("current", "older", "other", "none")}


def store_quorum(k):
    """The votes an empty replica needs when it asks the other k - 1 replicas
    (src/auth_handler/rules.rs, `store_quorum`)."""
    n = k - 1
    f = max(1, (n - 1) // 3)
    return max(2, min(n, math.ceil((n + f + 1) / 2)))


def set_liars(liars, lying):
    """Make `liars` lie in FindHash (`ctl <node> lie on`), or stop."""
    for liar in liars:
        ctl(liar, "lie", "on" if lying else "off", check=lying)


def cmd_update(args):
    """Each round: the owner creates and publishes a new DID, then rotates its
    key `--rotations` times. With `--restart M`, M replicas holding the current
    version crash and come back empty just before the last rotation. Then:
    what each replica holds, what each restarted replica holds, and what every
    other node reads. Replicas are the k nodes closest to the key."""
    config = load_config()
    check_node(args.owner, config)
    nodes = [f"node-{i}" for i in range(1, config["nodes"] + 1)]
    others = [n for n in nodes if n != args.owner]
    rounds = []
    print(
        f"update: {args.rounds} rounds, {args.rotations} rotation(s) each, {args.restart} replica(s) "
        f"restarted before the last, owner {args.owner}, {config['nodes']} nodes, k={config['k']}, "
        f"profile {config['profile']}, image {config.get('image', IMAGE)}"
    )
    print(f"{'round':>5}  {'outcome':<14} {'update':>9}  {'replicas cur/old/none':<22} "
          f"{'restarted cur/old/none':<23} {'reads cur/old/none'}")
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        for number in range(1, args.rounds + 1):
            did = ctl(args.owner, "new")["did"]
            replicas = [n for n in closest(nodes, dht_key(did), config["k"]) if n != args.owner]
            # The replicas closest to the key lie, the ones every check asks.
            liars = replicas[: args.liars]
            set_liars(liars, True)
            published = ctl(args.owner, "publish")
            versions = [published["record"]["signing_key"]]
            time.sleep(args.settle)
            rotations = []
            victims = []
            counters = None
            for rotation in range(1, args.rotations + 1):
                last = rotation == args.rotations
                if last and args.restart:
                    held = keys_of(replicas, did)
                    holders = [n for n in replicas if held[n] == versions[-1] and n not in liars]
                    start = (number - 1) % max(1, len(holders))
                    victims = (holders[start:] + holders[:start])[: args.restart]
                    # A crash: no Leave, and the node comes back with its id and no records.
                    for victim in victims:
                        run(["docker", "kill", container(victim)], capture=True)
                        run(["docker", "start", container(victim)], capture=True)
                    for victim in victims:
                        if not wait_answering(victim):
                            fail(f"{victim} did not come back")
                before = all_counters(pool, nodes) if last and args.counters else None
                update = ctl(args.owner, "update")
                if before is not None:
                    time.sleep(args.settle)  # answers still on their way when the owner returns
                    counters = counters_delta(before, all_counters(pool, nodes))
                rotations.append({"outcome": update["outcome"], "ms": update["ms"], "after_restart": bool(last and victims)})
                if update.get("to_key") and update["to_key"] != versions[-1]:
                    versions.append(update["to_key"])
                if not last:
                    time.sleep(args.settle)
            time.sleep(args.wait)
            set_liars(liars, False)

            label = version_label(versions)
            held = keys_of(replicas, did)
            reads = list(pool.map(lambda n: (ctl(n, "get", did, check=False) or {}).get("record"), others))
            entry = {
                "did": did,
                "liars": liars,
                "publish": published["outcome"],
                "publish_report": {field: published.get(field) for field in
                                   ("stored", "already_present", "unavailable", "conflicts", "stale",
                                    "newer_claimed", "invalid")},
                "versions": versions,
                "rotations": rotations,
                "victims": victims,
                "replicas": tally([label(held[n]) for n in replicas if n not in victims]),
                "restarted": tally([label(held[n]) for n in victims]),
                "reads": tally([label(r.get("signing_key") if r else None) for r in reads]),
            }
            if counters is not None:
                entry["counters"] = counters
            rounds.append(entry)
            fmt = lambda t: f"{t['current']}/{t['older']}/{t['none']}" + (f" +{t['other']} other" if t["other"] else "")
            print(
                f"{number:>5}  {rotations[-1]['outcome']:<14} {rotations[-1]['ms']:>6.1f} ms  "
                f"{fmt(entry['replicas']):<22} {fmt(entry['restarted']) if victims else '-':<23} {fmt(entry['reads'])}"
            )

    print("\nsummary")
    if args.liars:
        print(f"  liars: the {args.liars} replica(s) closest to the key, every round")
    publications = sorted({r["publish"] for r in rounds})
    print("  publication of version 0: " + ", ".join(
        f"{o} {sum(1 for r in rounds if r['publish'] == o)}" for o in publications))
    for field in ("stored", "unavailable", "newer_claimed", "conflicts", "stale"):
        values = [r["publish_report"].get(field) or 0 for r in rounds]
        print(f"    {field} replicas per publication: {summary_counts(values)}")
    last = [r["rotations"][-1] for r in rounds]
    outcomes = sorted({r["outcome"] for r in last})
    print("  last rotation: " + ", ".join(f"{o} {sum(1 for r in last if r['outcome'] == o)}" for o in outcomes))
    plain = [r["ms"] for rnd in rounds for r in rnd["rotations"] if not r["after_restart"]]
    print(f"  rotation time, no replica restarted: {summary(plain)}")
    if args.restart:
        print(f"  rotation time, after the restart: {summary([r['ms'] for r in last if r['after_restart']])}")
    for field, what in (("replicas", "replicas not restarted"), ("restarted", "restarted replicas"),
                        ("reads", "reads by every other node")):
        total = {name: sum(r[field][name] for r in rounds) for name in ("current", "older", "other", "none")}
        count = sum(total.values())
        if count:
            print(f"  {what}: current {total['current']}/{count}, older {total['older']}, "
                  f"other {total['other']}, none {total['none']}")
    print_counters(rounds, per="update")
    counted = [r["counters"]["sent"] for r in rounds if r.get("counters")]
    if counted:
        datagrams = sum(c.get("Update", {}).get("datagrams", 0) for c in counted)
        answers = sum(c.get("UpdateResult", {}).get("datagrams", 0) for c in counted)
        if answers:
            print(f"  Update datagrams per UpdateResult (fragments of an UPDATE, plus resends): "
                  f"{datagrams / answers:.2f}")
    GENERATED.mkdir(exist_ok=True)
    out = GENERATED / f"update-{config['profile']}-{time.strftime('%Y%m%d-%H%M%S')}.json"
    out.write_text(json.dumps({"config": config, "args": vars(args) | {"func": None}, "rounds": rounds}, indent=2) + "\n")
    print(f"  details: {out}")


def summary_counts(values):
    """Median and range of a list of counts."""
    if not values:
        return "no samples"
    return f"median {statistics.median(values):g}, min {min(values)}, max {max(values)} (n={len(values)})"


def cmd_churn(args):
    """Copies of one record over time while nodes crash and come back with no
    records (churn), with `--liars` of the replicas closest to the key lying in
    FindHash. The owner publishes a new DID, rotates `--rotations` times, then
    sends its current version again every `--republish-every` seconds, as the
    application does at least once every 24 hours (ADR 0005). Every
    `--churn-every` seconds a node other than the owner and the liars crashes
    and comes back empty. Every `--sample-every` seconds: what the k nodes
    closest to the key hold."""
    config = load_config()
    check_node(args.owner, config)
    nodes = [f"node-{i}" for i in range(1, config["nodes"] + 1)]
    k = config["k"]
    quorum = store_quorum(k)
    did = ctl(args.owner, "new")["did"]
    # The k nodes closest to the key, as in `update`: the owner, if one of
    # them, holds its own copy and is not counted.
    replicas = [n for n in closest(nodes, dht_key(did), k) if n != args.owner]
    liars = replicas[: args.liars]
    pool_of = replicas if args.churn_among == "replicas" else nodes
    candidates = [n for n in pool_of if n != args.owner and n not in liars]
    rng = random.Random(args.seed)
    samples, crashes, republications = [], [], []
    print(
        f"churn: {args.duration:g} s, a crash every {args.churn_every:g} s among the {args.churn_among}, "
        f"republication every {args.republish_every:g} s, {len(liars)} liar(s), {args.rotations} rotation(s), "
        f"owner {args.owner}, {config['nodes']} nodes, k={k} (quorum {quorum}), profile {config['profile']}, "
        f"image {config.get('image', IMAGE)}"
    )
    set_liars(liars, True)
    try:
        published = ctl(args.owner, "publish")
        versions = [published["record"]["signing_key"]]
        print(f"  publication of version 0: {published['outcome']}, stored {published['stored']}, "
              f"newer claimed {published['newer_claimed']}, unavailable {published['unavailable']}")
        for _ in range(args.rotations):
            time.sleep(args.settle)
            update = ctl(args.owner, "update")
            print(f"  rotation to version {update.get('seq')}: {update.get('outcome')}")
            if update.get("outcome") == "confirmed":
                versions.append(update["to_key"])
        time.sleep(args.settle)
        label = version_label(versions)
        print(f"{'time':>7}  {'replicas cur/old/other/none':<28} event")
        start = time.monotonic()
        next_sample, next_crash, next_republish = start, start + args.churn_every, start + args.republish_every
        while (now := time.monotonic()) < start + args.duration:
            event = ""
            if now >= next_crash and candidates:
                victim = rng.choice(candidates)
                # A crash: no Leave, and the node comes back with its id and no records.
                run(["docker", "kill", container(victim)], capture=True)
                run(["docker", "start", container(victim)], capture=True)
                if not wait_answering(victim):
                    fail(f"{victim} did not come back")
                crashes.append({"t": round(now - start, 1), "node": victim, "replica": victim in replicas})
                event = f"crash {victim}"
                next_crash += args.churn_every
            if now >= next_republish:
                again = ctl(args.owner, "republish")
                republications.append({"t": round(now - start, 1), "outcome": again.get("outcome"),
                                       "ms": again.get("ms")})
                event = (event + ", " if event else "") + f"republish: {again.get('outcome')}"
                next_republish += args.republish_every
            if now >= next_sample or event:
                held = keys_of(replicas, did)
                counts = tally([label(held[n]) for n in replicas])
                samples.append({"t": round(now - start, 1), **counts, "event": event})
                print(f"{now - start:>6.1f}s  {counts['current']}/{counts['older']}/{counts['other']}/"
                      f"{counts['none']:<22} {event}")
                if now >= next_sample:
                    next_sample += args.sample_every
            time.sleep(0.05)
    finally:
        set_liars(liars, False)

    current = [s["current"] for s in samples]
    print("\nsummary")
    print(f"  copies of the current version on the {len(replicas)} replicas besides the owner: "
          f"{summary_counts(current)}, "
          f"last {current[-1] if current else '-'}")
    below = sum(1 for c in current if c < quorum)
    print(f"  samples below the quorum ({quorum}): {below}/{len(current)}")
    print(f"  crashes: {len(crashes)}, of a replica {sum(1 for c in crashes if c['replica'])}")
    outcomes = sorted({r["outcome"] for r in republications if r["outcome"]})
    print("  republications: " + (", ".join(
        f"{o} {sum(1 for r in republications if r['outcome'] == o)}" for o in outcomes) or "none"))
    GENERATED.mkdir(exist_ok=True)
    out = GENERATED / f"churn-{config['profile']}-{time.strftime('%Y%m%d-%H%M%S')}.json"
    out.write_text(json.dumps({"config": config, "args": vars(args) | {"func": None}, "did": did,
                               "replicas": replicas, "liars": liars, "versions": versions,
                               "samples": samples, "crashes": crashes,
                               "republications": republications}, indent=2) + "\n")
    print(f"  details: {out}")


def cmd_outage(args):
    """The owner goes offline, frozen so that it keeps its versions, and
    `--lost` replicas holding the record restart empty at once, as in a power
    cut at one site. Then every replica that still holds it sends it to the k
    nodes closest to the key (`ctl <node> push`), as the hourly republication
    does, one after the other, and the script counts what the replicas hold.
    With `--owner-returns` the owner then comes back, sends its current version
    again (`ctl <node> republish`, images built since ADR 0005), and the
    replicas are counted once more. Replicas are the k nodes closest to the
    key, the owner left out."""
    config = load_config()
    check_node(args.owner, config)
    nodes = [f"node-{i}" for i in range(1, config["nodes"] + 1)]
    k = config["k"]
    quorum = store_quorum(k)
    rounds = []
    print(
        f"outage: replicas lost {args.lost}, {args.rounds} rounds each, owner {args.owner} offline"
        f"{', then back' if args.owner_returns else ''}, {config['nodes']} nodes, k={k} (quorum {quorum}), "
        f"profile {config['profile']}, image {config.get('image', IMAGE)}"
    )
    print(f"{'lost':>4} {'round':>5}  {'before':<9} {'after loss':<11} {'after push':<11} "
          f"{'owner back':<11} push answers")
    fmt = lambda t: f"{t['current']}/{t['older']}/{t['none']}" + (f"+{t['other']}" if t["other"] else "")
    for lost in args.lost:
        for number in range(1, args.rounds + 1):
            did = ctl(args.owner, "new")["did"]
            replicas = [n for n in closest(nodes, dht_key(did), k) if n != args.owner]
            published = ctl(args.owner, "publish")
            versions = [published["record"]["signing_key"]]
            for _ in range(args.rotations):
                time.sleep(args.settle)
                update = ctl(args.owner, "update")
                if update.get("outcome") == "confirmed" and update.get("to_key"):
                    versions.append(update["to_key"])
            time.sleep(args.settle)
            label = version_label(versions)
            held = keys_of(replicas, did)
            before = tally([label(held[n]) for n in replicas])
            holders = [n for n in replicas if held[n] == versions[-1]]
            begin = ((number - 1) * lost) % max(1, len(holders))
            victims = (holders[begin:] + holders[:begin])[:lost]
            run(["docker", "pause", container(args.owner)], capture=True)
            try:
                # A crash: no Leave, and the node comes back with its id and no records.
                for victim in victims:
                    run(["docker", "kill", container(victim)], capture=True)
                for victim in victims:
                    run(["docker", "start", container(victim)], capture=True)
                for victim in victims:
                    if not wait_answering(victim):
                        fail(f"{victim} did not come back")
                held = keys_of(replicas, did)
                after_loss = tally([label(held[n]) for n in replicas])
                answers = {}
                for holder in [n for n in replicas if held[n] == versions[-1]]:
                    reply = ctl(holder, "push", did, check=False) or {}
                    for answer, count in reply.get("answers", {}).items():
                        answers[answer] = answers.get(answer, 0) + count
                time.sleep(args.wait)
                held = keys_of(replicas, did)
                after_push = tally([label(held[n]) for n in replicas])
            finally:
                run(["docker", "unpause", container(args.owner)], capture=True)
            entry = {
                "did": did, "lost": lost, "replicas": len(replicas), "victims": victims,
                "versions": versions, "before": before, "after_loss": after_loss,
                "after_push": after_push, "push_answers": answers,
            }
            if args.owner_returns:
                again = ctl(args.owner, "republish", check=False) or {}
                entry["owner_republish"] = again.get("outcome", again.get("error"))
                time.sleep(args.wait)
                held = keys_of(replicas, did)
                entry["after_owner"] = tally([label(held[n]) for n in replicas])
            rounds.append(entry)
            print(f"{lost:>4} {number:>5}  {fmt(before):<9} {fmt(after_loss):<11} {fmt(after_push):<11} "
                  f"{fmt(entry['after_owner']) if 'after_owner' in entry else '-':<11} "
                  + ", ".join(f"{a} {n}" for a, n in sorted(answers.items())))

    print("\nsummary (copies of the current version on the replicas, owner left out)")
    for lost in args.lost:
        group = [r for r in rounds if r["lost"] == lost]
        line = (f"  {lost:>2} lost: after the loss {summary_counts([r['after_loss']['current'] for r in group])}; "
                f"after the holders' republication {summary_counts([r['after_push']['current'] for r in group])}; "
                f"fully restored {sum(1 for r in group if r['after_push']['current'] == r['replicas'])}/{len(group)}")
        if args.owner_returns:
            line += (f"; after the owner's return "
                     f"{summary_counts([r['after_owner']['current'] for r in group])}, fully restored "
                     f"{sum(1 for r in group if r['after_owner']['current'] == r['replicas'])}/{len(group)}")
        print(line)
    GENERATED.mkdir(exist_ok=True)
    out = GENERATED / f"outage-{config['profile']}-{time.strftime('%Y%m%d-%H%M%S')}.json"
    out.write_text(json.dumps({"config": config, "args": vars(args) | {"func": None}, "rounds": rounds},
                              indent=2) + "\n")
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
    up = sub.add_parser("update", help="rotation time, and which replicas hold the new version")
    up.add_argument("--owner", default="node-1")
    up.add_argument("--rounds", type=int, default=20)
    up.add_argument("--rotations", type=int, default=1, help="rotations per round, after the publication")
    up.add_argument("--restart", type=int, default=0,
                    help="replicas holding the current version that crash and restart just before the last rotation")
    up.add_argument("--counters", action="store_true",
                    help="read every node's counters before and after the last rotation (image with counters)")
    up.add_argument("--settle", type=float, default=0.3,
                    help="seconds after the publication, between rotations, and before reading the counters")
    up.add_argument("--wait", type=float, default=0.5,
                    help="seconds after the last rotation before reading what the replicas hold")
    up.add_argument("--liars", type=int, default=0,
                    help="replicas closest to the key that lie in FindHash during the round (image built "
                         "from ADR 0005)")
    up.set_defaults(func=cmd_update)
    ch = sub.add_parser("churn", help="copies of a record over time while nodes crash, with liars")
    ch.add_argument("--owner", default="node-1")
    ch.add_argument("--duration", type=float, default=600, help="seconds of churn")
    ch.add_argument("--rotations", type=int, default=1, help="rotations after the publication, before the churn")
    ch.add_argument("--liars", type=int, default=0, help="replicas closest to the key that lie in FindHash")
    ch.add_argument("--churn-every", type=float, default=10, help="seconds between two crashes")
    ch.add_argument("--churn-among", choices=["replicas", "all"], default="replicas",
                    help="nodes that may crash: the k closest to the key, or every node (never the owner or a liar)")
    ch.add_argument("--republish-every", type=float, default=60,
                    help="seconds between two republications of the current version by the owner")
    ch.add_argument("--sample-every", type=float, default=5, help="seconds between two counts of the copies")
    ch.add_argument("--settle", type=float, default=0.3, help="seconds after the publication and each rotation")
    ch.add_argument("--seed", type=int, default=1, help="seed of the choice of the nodes that crash")
    ch.set_defaults(func=cmd_churn)
    ou = sub.add_parser("outage", help="owner offline, replicas lost at once, then the holders' republication")
    ou.add_argument("--owner", default="node-1")
    ou.add_argument("--lost", type=int, nargs="+", default=[4, 7, 8, 12, 16],
                    help="replicas holding the record that restart empty at once")
    ou.add_argument("--rounds", type=int, default=5, help="rounds per value of --lost")
    ou.add_argument("--rotations", type=int, default=1, help="rotations after the publication")
    ou.add_argument("--owner-returns", action="store_true",
                    help="the owner then comes back and republishes (images built since ADR 0005)")
    ou.add_argument("--settle", type=float, default=0.3, help="seconds after the publication and each rotation")
    ou.add_argument("--wait", type=float, default=1.0, help="seconds after the republications before counting")
    ou.set_defaults(func=cmd_outage)
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
