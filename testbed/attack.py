#!/usr/bin/env python3
"""Attack mode of the testbed: an attacker that reads the traffic of a running
testbed network and sends forged records for the DIDs it sees.

Built on testbed.py: start a network with it first.

    testbed/testbed.py up --nodes 10 --k 3 --profile wan-eu
    testbed/attack.py start                 # race: one forged STORE per UPDATE
    testbed/attack.py race --rounds 20      # crash a replica, rotate, count who fills it
    testbed/attack.py start --mode burst    # many forged STOREs per UPDATE at once
    testbed/attack.py start --mode persist  # forged STOREs to every node, all the time
    testbed/attack.py restart --rounds 20   # crash a replica, no update, see what it holds
    testbed/attack.py logs
    testbed/attack.py stop

See testbed/README.md, section "Attack mode".
"""

import argparse
import concurrent.futures
import json
import re
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True  # no __pycache__ inside the repository
sys.path.insert(0, str(Path(__file__).resolve().parent))
from testbed import (  # noqa: E402
    ATTACKER,
    DHT_PORT,
    GENERATED,
    IMAGE,
    check_node,
    container,
    ctl,
    fail,
    load_config,
    run,
)


def cmd_attacker(args):
    config = load_config()
    if args.action == "start":
        run(["docker", "rm", "-f", ATTACKER], capture=True, check=False)
        # Host network namespace: there it sees every container's traffic. The
        # entrypoint is replaced, so no netem rule touches the host.
        run([
            "docker", "run", "-d", "--name", ATTACKER, "--network", "host", "--cap-add", "NET_RAW",
            "--entrypoint", "/app/testbed_attacker",
            "-e", f"TESTBED_PREFIX={config['subnet']}",
            "-e", f"DHT_PORT={DHT_PORT}",
            "-e", f"ATTACK_MODE={args.mode}",
            "-e", f"ATTACK_DELAY_MS={args.delay}",
            "-e", f"ATTACK_BURST={args.burst}",
            "-e", f"ATTACK_PORTS={args.ports}",
            "-e", f"ATTACK_PERIOD_MS={args.period}",
            "-e", f"ATTACK_DID_TTL_S={args.did_ttl}",
            "-e", f"RUST_LOG={args.log}",
            args.image or config.get("image", IMAGE),
        ], capture=True)
        time.sleep(1)
        print(run(["docker", "logs", ATTACKER], capture=True, check=False).stderr.strip())
    elif args.action == "stop":
        run(["docker", "rm", "-f", ATTACKER], capture=True, check=False)
        print("attacker stopped")
    else:
        run(["docker", "logs", *(["-f"] if args.follow else []), ATTACKER])


def record_key(node, did):
    """Signing key of the record `node` holds for `did`, or None."""
    reply = ctl(node, "storage", check=False)
    for entry in (reply or {}).get("records", []):
        if entry["record"].get("did") == did:
            return entry["record"].get("signing_key")
    return None


def keys_of(nodes, did):
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        return dict(zip(nodes, pool.map(lambda node: record_key(node, did), nodes)))


def wait_answering(node, timeout=20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if ctl(node, "stats", check=False) is not None:
            return True
        time.sleep(0.1)
    return False


def attacker_log_since(since):
    result = run(["docker", "logs", "--since", since, ATTACKER], capture=True, check=False)
    return (result.stdout + result.stderr).splitlines() if result.returncode == 0 else None


def label_for(v1, v2=None):
    def label(key):
        if key is None:
            return "empty"
        if v2 is not None and key == v2:
            return "owner"
        if key == v1:
            return "old" if v2 is not None else "owner"
        return "attacker"
    return label


def attacker_summary(started_at):
    """What the attacker logged since `started_at`, in a few lines."""
    lines = attacker_log_since(started_at)
    if lines is None:
        return
    sent = [float(m.group(1)) for line in lines if (m := re.search(r"sent ([0-9.]+) ms after", line))]
    if sent:
        sent.sort()
        print(f"  attacker: {len(sent)} attacks, sent {sent[len(sent) // 2]:g} ms (median) after seeing the UPDATE")
    answers = {}
    for line in lines:
        if (m := re.search(r"answer (Some\(\w+\)|None)$", line)):
            answers[m.group(1)] = answers.get(m.group(1), 0) + 1
        elif (m := re.search(r"answers ((?:[\w ]+=\d+ ?)+)$", line)):
            for name, value in re.findall(r"([\w ]+?)=(\d+)", m.group(1)):
                answers[name.strip()] = answers.get(name.strip(), 0) + int(value)
    if answers:
        print("  attacker's answers: " + ", ".join(f"{a} {n}" for a, n in sorted(answers.items())))


def cmd_race(args):
    """A replica crashes and comes back empty, then the owner rotates its keys.
    Who fills the empty replica: the owner, or an attacker racing it?"""
    config = load_config()
    check_node(args.owner, config)
    nodes = [f"node-{i}" for i in range(1, config["nodes"] + 1)]
    started_at = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    rounds = []
    print(
        f"race: {args.rounds} rounds, owner {args.owner}, {config['nodes']} nodes, k={config['k']}, "
        f"profile {config['profile']}, image {config.get('image', IMAGE)}"
    )
    print(f"{'round':>5}  {'victim':<8} {'before':<8} {'update':<14} {'after':<11} {'others':<9} forged reads")
    for number in range(1, args.rounds + 1):
        ctl(args.owner, "forget")
        published = ctl(args.owner, "publish")
        did, v1 = published["did"], published["record"]["signing_key"]
        holders = [n for n, key in keys_of([n for n in nodes if n != args.owner], did).items() if key == v1]
        if not holders:
            print(f"{number:>5}  no replica besides the owner: skipped")
            continue
        victim = holders[(number - 1) % len(holders)]
        # A crash: no Leave, and the node comes back with its id and no records.
        run(["docker", "kill", container(victim)], capture=True)
        run(["docker", "start", container(victim)], capture=True)
        if not wait_answering(victim):
            fail(f"{victim} did not come back")
        before = record_key(victim, did)
        update = ctl(args.owner, "update")
        v2 = update["to_key"]
        time.sleep(args.wait)
        after = record_key(victim, did)
        others = [k for n, k in keys_of([n for n in holders if n != victim], did).items()]
        readers = [n for n in nodes if n not in holders and n not in (args.owner, victim)][: args.readers]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            reads = list(pool.map(lambda n: (ctl(n, "get", did, check=False) or {}).get("record"), readers))
        read_keys = [r.get("signing_key") if r else None for r in reads]

        label = label_for(v1, v2)
        entry = {
            "victim": victim,
            "before": label(before),
            "update": update["outcome"],
            "after": label(after),
            "others_owner": sum(1 for k in others if k == v2),
            "others": len(others),
            "forged_reads": sum(1 for k in read_keys if label(k) == "attacker"),
            "reads": len(read_keys),
        }
        rounds.append(entry)
        print(
            f"{number:>5}  {victim:<8} {entry['before']:<8} {entry['update']:<14} {entry['after']:<11} "
            f"{entry['others_owner']}/{entry['others']:<7} {entry['forged_reads']}/{entry['reads']}"
        )

    if not rounds:
        fail("no round ran")
    count = lambda field, value: sum(1 for r in rounds if r[field] == value)
    print("\nsummary")
    print(f"  victim empty before the update: {count('before', 'empty')}/{len(rounds)}")
    for value in ("owner", "attacker", "old", "empty"):
        print(f"  victim after the update holds {value}: {count('after', value)}/{len(rounds)}")
    outcomes = sorted({r["update"] for r in rounds})
    print("  owner's update: " + ", ".join(f"{o} {count('update', o)}" for o in outcomes))
    intact = sum(r["others_owner"] for r in rounds)
    total = sum(r["others"] for r in rounds)
    print(f"  other replicas holding the owner's record: {intact}/{total}")
    forged = sum(r["forged_reads"] for r in rounds)
    reads = sum(r["reads"] for r in rounds)
    print(f"  plain reads returning the forged record: {forged}/{reads}")
    attacker_summary(started_at)
    GENERATED.mkdir(exist_ok=True)
    out = GENERATED / f"race-{config['profile']}-{time.strftime('%Y%m%d-%H%M%S')}.json"
    out.write_text(json.dumps({"config": config, "rounds": rounds}, indent=2) + "\n")
    print(f"  details: {out}")


def cmd_restart(args):
    """A replica crashes and comes back empty; there is no update. What does it
    hold after a while, and how many nodes hold a forged record? Meant for the
    persist attacker, which keeps sending forged records to every node."""
    config = load_config()
    check_node(args.owner, config)
    nodes = [f"node-{i}" for i in range(1, config["nodes"] + 1)]
    started_at = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
    rounds = []
    print(
        f"restart: {args.rounds} rounds, owner {args.owner}, {config['nodes']} nodes, k={config['k']}, "
        f"profile {config['profile']}, image {config.get('image', IMAGE)}"
    )
    print(f"{'round':>5}  {'victim':<8} {'publish':<10} {'after':<9} {'forged copies':<14} forged reads")
    for number in range(1, args.rounds + 1):
        ctl(args.owner, "forget")
        published = ctl(args.owner, "publish")
        did, v1 = published["did"], published["record"]["signing_key"]
        time.sleep(args.settle)
        holders = [n for n, key in keys_of([n for n in nodes if n != args.owner], did).items() if key == v1]
        if not holders:
            print(f"{number:>5}  no replica besides the owner: skipped")
            continue
        victim = holders[(number - 1) % len(holders)]
        if not args.no_crash:
            run(["docker", "kill", container(victim)], capture=True)
            run(["docker", "start", container(victim)], capture=True)
            if not wait_answering(victim):
                fail(f"{victim} did not come back")
        time.sleep(args.wait)
        label = label_for(v1)
        everyone = keys_of([n for n in nodes if n != args.owner], did)
        readers = [n for n in nodes if n not in holders and n not in (args.owner, victim)][: args.readers]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            reads = list(pool.map(lambda n: (ctl(n, "get", did, check=False) or {}).get("record"), readers))
        read_keys = [r.get("signing_key") if r else None for r in reads]
        entry = {
            "victim": victim,
            "publish": published.get("outcome", "?"),
            "after": label(everyone.get(victim)),
            "forged_copies": sum(1 for k in everyone.values() if label(k) == "attacker"),
            "nodes": len(everyone),
            "forged_reads": sum(1 for k in read_keys if label(k) == "attacker"),
            "reads": len(read_keys),
        }
        rounds.append(entry)
        print(
            f"{number:>5}  {victim:<8} {entry['publish']:<10} {entry['after']:<9} "
            f"{entry['forged_copies']}/{entry['nodes']:<12} {entry['forged_reads']}/{entry['reads']}"
        )

    if not rounds:
        fail("no round ran")
    count = lambda field, value: sum(1 for r in rounds if r[field] == value)
    print("\nsummary")
    for value in ("owner", "attacker", "empty"):
        print(f"  restarted replica holds {value}: {count('after', value)}/{len(rounds)}")
    outcomes = sorted({r["publish"] for r in rounds})
    print("  owner's publication: " + ", ".join(f"{o} {count('publish', o)}" for o in outcomes))
    copies = sum(r["forged_copies"] for r in rounds)
    total = sum(r["nodes"] for r in rounds)
    print(f"  nodes holding a forged record: {copies}/{total} (all nodes but the owner, every round)")
    forged = sum(r["forged_reads"] for r in rounds)
    reads = sum(r["reads"] for r in rounds)
    print(f"  plain reads returning the forged record: {forged}/{reads}")
    attacker_summary(started_at)
    GENERATED.mkdir(exist_ok=True)
    out = GENERATED / f"restart-{config['profile']}-{time.strftime('%Y%m%d-%H%M%S')}.json"
    out.write_text(json.dumps({"config": config, "rounds": rounds}, indent=2) + "\n")
    print(f"  details: {out}")



def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    for action, help_text in [
        ("start", "start the attacker in the host network namespace"),
        ("stop", "stop and remove the attacker"),
        ("logs", "attacker logs"),
    ]:
        a = sub.add_parser(action, help=help_text)
        a.set_defaults(func=cmd_attacker, action=action)
        if action == "start":
            a.add_argument("--mode", choices=["race", "burst", "persist"], default="race")
            a.add_argument("--delay", type=int, default=0, help="race, burst: extra delay in ms before forging")
            a.add_argument("--burst", type=int, default=64, help="burst: forged STOREs per UPDATE")
            a.add_argument("--ports", type=int, default=16, help="burst: attacker ports")
            a.add_argument("--period", type=int, default=100, help="persist: ms between rounds of forged STOREs")
            a.add_argument("--did-ttl", type=int, default=20, help="persist: seconds a DID stays a target")
            a.add_argument("--log", default="warn,testbed_attacker=info")
            a.add_argument("--image", help="image to run the attacker from (default: the network's)")
        if action == "logs":
            a.add_argument("-f", "--follow", action="store_true")

    rc = sub.add_parser("race", help="crash a replica, rotate, and see who fills it")
    rc.add_argument("--owner", default="node-1")
    rc.add_argument("--rounds", type=int, default=10)
    rc.add_argument("--wait", type=float, default=1.0, help="seconds to wait after the update")
    rc.add_argument("--readers", type=int, default=3, help="nodes that read the DID after each round")
    rc.set_defaults(func=cmd_race)

    rs = sub.add_parser("restart", help="crash a replica without an update and see what it holds")
    rs.add_argument("--owner", default="node-1")
    rs.add_argument("--rounds", type=int, default=10)
    rs.add_argument("--settle", type=float, default=0.5, help="seconds between publication and crash")
    rs.add_argument("--wait", type=float, default=3.0, help="seconds to wait after the restart")
    rs.add_argument("--readers", type=int, default=3, help="nodes that read the DID after each round")
    rs.add_argument("--no-crash", action="store_true",
                    help="do not crash the replica: only publication under attack, e.g. to compare traffic")
    rs.set_defaults(func=cmd_restart)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
