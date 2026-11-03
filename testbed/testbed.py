#!/usr/bin/env python3
"""Docker testbed for auth-kademlia-rs: N DHT nodes on an emulated network.

Interactive mode: start a network, then drive single nodes.

    testbed/testbed.py up --nodes 10 --k 3 --alpha 3 --profile wan-eu
    testbed/testbed.py ctl node-3 publish
    testbed/testbed.py get node-3 --from node-9
    testbed/testbed.py ctl node-3 update
    testbed/testbed.py logs
    testbed/testbed.py down

Only the Python standard library is used. See testbed/README.md.
"""

import argparse
import concurrent.futures
import json
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
GENERATED = HERE / ".generated"
COMPOSE_FILE = GENERATED / "compose.yaml"
CONFIG_FILE = GENERATED / "config.json"
IMAGE = "auth-kademlia-testbed:latest"
PROJECT = "aktestbed"
DHT_PORT = 4000

# One-way delay added to every container's egress. A request and its reply
# cross two containers, so the round trip is twice this value.
PROFILES = {
    "lan": {
        "delay_ms": 0.0,
        "rtt_ms": None,
        "source": "No delay added: switch hops take microseconds, so the RTT is "
        "the Docker bridge's own, shown by the rtt command.",
    },
    "wan-eu": {
        "delay_ms": 6.8,
        "rtt_ms": 13.6,
        "source": "Verizon IP latency statistics, Europe, September 2026 average.",
    },
    "wan-eu-target": {
        "delay_ms": 15.0,
        "rtt_ms": 30.0,
        "source": "Verizon IP latency statistics, Europe, target (upper bound).",
    },
    "wan-atlantic": {
        "delay_ms": 35.2,
        "rtt_ms": 70.4,
        "source": "Verizon IP latency statistics, Trans-Atlantic, September 2026 average.",
    },
    "wan-atlantic-target": {
        "delay_ms": 45.0,
        "rtt_ms": 90.0,
        "source": "Verizon IP latency statistics, Trans-Atlantic, target (upper bound).",
    },
}


def fail(message):
    print(f"error: {message}", file=sys.stderr)
    sys.exit(1)


def run(args, capture=False, check=True):
    result = subprocess.run(args, capture_output=capture, text=True)
    if check and result.returncode != 0:
        if capture:
            sys.stderr.write(result.stderr)
        fail(f"command failed: {' '.join(args)}")
    return result


def compose(*args, capture=False, check=True):
    if not COMPOSE_FILE.exists():
        fail("no testbed has been generated: run `up` first")
    return run(["docker", "compose", "-p", PROJECT, "-f", str(COMPOSE_FILE), *args], capture, check)


def load_config():
    if not CONFIG_FILE.exists():
        fail("no testbed has been generated: run `up` first")
    return json.loads(CONFIG_FILE.read_text())


def node_ip(prefix, index):
    """node-1 is <prefix>.0.11; 200 nodes per /24, starting at .10."""
    return f"{prefix}.{index // 200}.{index % 200 + 10}"


def container(node):
    return f"tb-{node}"


def check_node(node, config):
    match = re.fullmatch(r"node-(\d+)", node)
    if not match or not 1 <= int(match.group(1)) <= config["nodes"]:
        fail(f"unknown node '{node}': use node-1 .. node-{config['nodes']}")


# ---------------------------------------------------------------------------
# Network generation
# ---------------------------------------------------------------------------


def netem_values(args):
    delay = PROFILES[args.profile]["delay_ms"] if args.delay is None else args.delay
    return delay, args.jitter, args.loss


def generate(args):
    prefix = args.subnet
    delay, jitter, loss = netem_values(args)
    seeds = ",".join(f"{node_ip(prefix, i)}:{DHT_PORT}" for i in range(1, args.seeds + 1))
    lines = [
        f"name: {PROJECT}",
        "networks:",
        "  testbed:",
        "    driver: bridge",
        "    ipam:",
        "      config:",
        f"        - subnet: {prefix}.0.0/16",
        "services:",
    ]
    for i in range(1, args.nodes + 1):
        name = f"node-{i}"
        ip = node_ip(prefix, i)
        lines += [
            f"  {name}:",
            f"    image: {IMAGE}",
            f"    container_name: {container(name)}",
            f"    hostname: {name}",
            "    cap_add: [NET_ADMIN]",
            "    stop_grace_period: 5s",
        ]
        if args.cpus:
            lines.append(f'    cpus: "{args.cpus}"')
        lines += [
            "    environment:",
            f"      NODE_NAME: {name}",
            f'      NODE_IP: "{ip}"',
            f'      NODE_PORT: "{DHT_PORT}"',
            f'      DHT_K: "{args.k}"',
            f'      DHT_ALPHA: "{args.alpha}"',
            f'      SEEDS: "{seeds}"',
            f'      NETEM_DELAY_MS: "{delay:g}"',
            f'      NETEM_JITTER_MS: "{jitter:g}"',
            f'      NETEM_LOSS_PCT: "{loss:g}"',
            f'      RUST_LOG: "{args.log}"',
            "    networks:",
            "      testbed:",
            f"        ipv4_address: {ip}",
        ]
        if i > args.seeds:
            lines.append("    depends_on: [" + ", ".join(f"node-{s}" for s in range(1, args.seeds + 1)) + "]")
    return "\n".join(lines) + "\n"


def ctl(node, *command, check=True):
    result = run(
        ["docker", "exec", container(node), "/app/testbed_node", "ctl", *command],
        capture=True,
        check=False,
    )
    if result.returncode != 0:
        if check:
            sys.stderr.write(result.stderr)
            fail(f"{node} did not answer")
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        if check:
            fail(f"{node} answered something that is not JSON: {result.stdout!r}")
        return None


def all_stats(nodes):
    names = [f"node-{i}" for i in range(1, nodes + 1)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as pool:
        replies = list(pool.map(lambda name: ctl(name, "stats", check=False), names))
    return dict(zip(names, replies))


def running(node):
    result = run(["docker", "inspect", "-f", "{{.State.Running}}", container(node)], capture=True, check=False)
    return result.stdout.strip() == "true"


def wait_ready(nodes, timeout):
    """Wait until every node has at least one live contact."""
    started = time.monotonic()
    needed = 1 if nodes > 1 else 0
    while True:
        stats = all_stats(nodes)
        missing = [n for n, s in stats.items() if s is None or s["live_contacts"] < needed]
        exited = [n for n in missing if stats[n] is None and not running(n)]
        if exited:
            fail(f"{', '.join(exited)} exited: see `testbed/testbed.py logs {exited[0]}`")
        elapsed = time.monotonic() - started
        if not missing:
            live = [s["live_contacts"] for s in stats.values()]
            print(
                f"ready after {elapsed:.0f} s: live contacts per node "
                f"min {min(live)}, avg {sum(live) / len(live):.1f}, max {max(live)}"
            )
            return
        if elapsed > timeout:
            fail(f"not ready after {timeout} s: {', '.join(missing)} still without contacts")
        time.sleep(2)


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------


def cmd_build(_args):
    print(f"building {IMAGE} (the first build compiles the whole crate)")
    run(["docker", "build", "-f", str(HERE / "Dockerfile"), "-t", IMAGE, str(ROOT)])


def cmd_up(args):
    if args.nodes < 1 or not 1 <= args.seeds <= args.nodes:
        fail("need at least one node, and 1 <= seeds <= nodes")
    if args.nodes > 1000:
        fail("at most 1000 nodes")
    if args.k < 1 or args.alpha < 1:
        fail("k and alpha must be at least 1")
    if not args.no_build:
        cmd_build(args)
    GENERATED.mkdir(exist_ok=True)
    COMPOSE_FILE.write_text(generate(args))
    delay, jitter, loss = netem_values(args)
    config = {
        "nodes": args.nodes,
        "k": args.k,
        "alpha": args.alpha,
        "seeds": args.seeds,
        "subnet": args.subnet,
        "profile": args.profile,
        "delay_ms": delay,
        "jitter_ms": jitter,
        "loss_pct": loss,
        "cpus": args.cpus,
    }
    CONFIG_FILE.write_text(json.dumps(config, indent=2) + "\n")
    rtt = "about the bridge RTT" if delay == 0 else f"about {2 * delay:g} ms"
    print(
        f"starting {args.nodes} nodes, k={args.k}, alpha={args.alpha}, {args.seeds} seeds; "
        f"network {args.profile}: one-way delay {delay:g} ms per container (RTT {rtt}), "
        f"jitter {jitter:g} ms, loss {loss:g}% per direction"
    )
    compose("up", "-d", "--remove-orphans", "--force-recreate")
    wait_ready(args.nodes, args.timeout)


def cmd_down(_args):
    compose("down", "--remove-orphans")


def cmd_status(_args):
    config = load_config()
    stats = all_stats(config["nodes"])
    print(
        f"{config['nodes']} nodes, k={config['k']}, alpha={config['alpha']}, "
        f"profile {config['profile']}, loss {config['loss_pct']}%"
    )
    print(f"{'node':<10} {'ip':<16} {'live/contacts':>14} {'records':>8}")
    for i in range(1, config["nodes"] + 1):
        name = f"node-{i}"
        s = stats[name]
        ip = node_ip(config["subnet"], i)
        if s is None:
            print(f"{name:<10} {ip:<16} {'no answer':>14}")
        else:
            print(f"{name:<10} {ip:<16} {s['live_contacts']:>6}/{s['contacts']:<7} {s['records']:>8}")


def cmd_ctl(args):
    config = load_config()
    check_node(args.node, config)
    print(json.dumps(ctl(args.node, *args.command), indent=2))


def cmd_get(args):
    """Read a DID from another node. TARGET is a DID, a UUID or a node name."""
    config = load_config()
    check_node(args.from_node, config)
    target = args.target
    if re.fullmatch(r"node-\d+", target):
        check_node(target, config)
        did = ctl(target, "info").get("did")
        if not did:
            fail(f"{target} has not published a DID yet")
        target = did
    print(json.dumps(ctl(args.from_node, "get", target), indent=2))


def cmd_netem(args):
    config = load_config()
    check_node(args.node, config)
    if args.profile:
        delay = PROFILES[args.profile]["delay_ms"]
    else:
        delay = args.delay if args.delay is not None else config["delay_ms"]
    jitter = args.jitter if args.jitter is not None else config["jitter_ms"]
    loss = args.loss if args.loss is not None else config["loss_pct"]
    base = ["docker", "exec", container(args.node), "tc", "qdisc"]
    if delay == 0 and jitter == 0 and loss == 0:
        run(base + ["del", "dev", "eth0", "root"], capture=True, check=False)
        print(f"{args.node}: no network emulation")
        return
    netem = ["delay", f"{delay:g}ms"]
    if jitter:
        netem += [f"{jitter:g}ms", "distribution", "normal"]
    if loss:
        netem += ["loss", f"{loss:g}%"]
    run(base + ["replace", "dev", "eth0", "root", "netem", *netem])
    print(f"{args.node}: netem {' '.join(netem)}")


def cmd_rtt(args):
    config = load_config()
    check_node(args.source, config)
    check_node(args.destination, config)
    ip = node_ip(config["subnet"], int(args.destination.split("-")[1]))
    result = run(
        ["docker", "exec", container(args.source), "ping", "-c", str(args.count), "-i", "0.2", "-q", ip],
        capture=True,
        check=False,
    )
    print(result.stdout.strip() or result.stderr.strip())


def cmd_docker_action(action):
    def handler(args):
        config = load_config()
        for node in args.nodes:
            check_node(node, config)
        run(["docker", action, *[container(node) for node in args.nodes]])
    return handler


def cmd_logs(args):
    load_config()
    extra = ["-f"] if args.follow else []
    compose("logs", "--no-log-prefix" if args.node else "--timestamps", *extra, *([args.node] if args.node else []))


def cmd_profiles(_args):
    for name, profile in PROFILES.items():
        rtt = "bridge only" if profile["rtt_ms"] is None else f"{profile['rtt_ms']:g} ms"
        print(f"{name:<20} one-way {profile['delay_ms']:>5g} ms   RTT {rtt:<12} {profile['source']}")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("build", help="build the testbed image").set_defaults(func=cmd_build)

    up = sub.add_parser("up", help="generate and start a network")
    up.add_argument("--nodes", type=int, default=10)
    up.add_argument("--k", type=int, default=20, help="Kademlia k (default 20)")
    up.add_argument("--alpha", type=int, default=3, help="Kademlia alpha (default 3)")
    up.add_argument("--seeds", type=int, default=3, help="bootstrap nodes: node-1 .. node-SEEDS")
    up.add_argument("--profile", choices=PROFILES, default="lan")
    up.add_argument("--delay", type=float, help="one-way delay in ms, overrides the profile")
    up.add_argument("--jitter", type=float, default=0.0, help="jitter in ms (default 0)")
    up.add_argument("--loss", type=float, default=0.0, help="loss in %% per direction (default 0)")
    up.add_argument("--cpus", type=str, help="CPU limit per container, e.g. 0.5")
    up.add_argument("--log", default="warn,testbed_node=info", help="RUST_LOG for every node")
    up.add_argument("--subnet", default="10.213", help="first two octets of the /16 (default 10.213)")
    up.add_argument("--timeout", type=int, default=120, help="seconds to wait for contacts")
    up.add_argument("--no-build", action="store_true", help="reuse the existing image")
    up.set_defaults(func=cmd_up)

    sub.add_parser("down", help="stop and remove the network").set_defaults(func=cmd_down)
    sub.add_parser("status", help="contacts and records of every node").set_defaults(func=cmd_status)
    sub.add_parser("profiles", help="network profiles and their sources").set_defaults(func=cmd_profiles)

    c = sub.add_parser("ctl", help="send a command to one node")
    c.add_argument("node")
    c.add_argument("command", nargs="+", help="info | publish | update | discard | get <did> | stats | storage | routing")
    c.set_defaults(func=cmd_ctl)

    g = sub.add_parser("get", help="read a DID from a node")
    g.add_argument("target", help="DID, UUID, or the name of the node that published it")
    g.add_argument("--from", dest="from_node", required=True)
    g.set_defaults(func=cmd_get)

    n = sub.add_parser("netem", help="change the network emulation of one node")
    n.add_argument("node")
    n.add_argument("--profile", choices=PROFILES)
    n.add_argument("--delay", type=float)
    n.add_argument("--jitter", type=float)
    n.add_argument("--loss", type=float)
    n.set_defaults(func=cmd_netem)

    r = sub.add_parser("rtt", help="ping from one node to another")
    r.add_argument("source")
    r.add_argument("destination")
    r.add_argument("--count", type=int, default=10)
    r.set_defaults(func=cmd_rtt)

    for action, help_text in [
        ("pause", "freeze nodes: they stop answering, like a hang"),
        ("unpause", "resume frozen nodes"),
        ("stop", "stop nodes: they send Leave and exit"),
        ("start", "start stopped nodes again, with empty storage"),
    ]:
        p = sub.add_parser(action, help=help_text)
        p.add_argument("nodes", nargs="+")
        p.set_defaults(func=cmd_docker_action(action))

    lg = sub.add_parser("logs", help="node logs")
    lg.add_argument("node", nargs="?")
    lg.add_argument("-f", "--follow", action="store_true")
    lg.set_defaults(func=cmd_logs)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
