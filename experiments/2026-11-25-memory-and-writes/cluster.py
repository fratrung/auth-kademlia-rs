#!/usr/bin/env python3
"""N whole nodes (probe_node), one process each, on loopback. Measures each
node's memory idle and holding records, and the traffic of one round of the
republication: each node in turn republishes the records no other node
renewed since the round started, as `schedule_republish` does once a day.

    cluster.py <probe_node binary> <out dir> <nodes> <k> <alpha> <dids per node> <threads> <base port>
"""
import json
import os
import selectors
import shutil
import statistics
import subprocess
import sys
import time

binary, out = sys.argv[1], sys.argv[2]
N, K, ALPHA, M, THREADS, BASE = (int(x) for x in sys.argv[3:9])
TIMEOUT = 600

shutil.rmtree(out, ignore_errors=True)
os.makedirs(out)
procs = []


def start(i):
    data = os.path.join(out, f"node-{i}")
    p = subprocess.Popen(
        [binary, str(BASE + i), str(BASE), str(K), str(ALPHA), data, str(THREADS)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        text=True, bufsize=1)
    procs.append(p)
    return read(i)


def read(i):
    sel = selectors.DefaultSelector()
    sel.register(procs[i].stdout, selectors.EVENT_READ)
    if not sel.select(TIMEOUT):
        raise TimeoutError(f"node {i} did not answer")
    line = procs[i].stdout.readline()
    if not line:
        raise RuntimeError(f"node {i} exited")
    return json.loads(line)


def ask(i, command):
    procs[i].stdin.write(command + "\n")
    procs[i].stdin.flush()
    return read(i)


def summary(values):
    values = sorted(values)
    return {"min": values[0], "median": statistics.median(values), "max": values[-1]}


def total_sent(stats):
    return sum(b for _, b in (stats["sent"] or {}).values())


def du(path):
    total = 0
    for name in os.listdir(path):
        total += os.stat(os.path.join(path, name)).st_size
    return total


results = {"nodes": N, "k": K, "alpha": ALPHA, "dids_per_node": M, "threads": THREADS}
try:
    for i in range(N):
        start(i)
    for i in range(1, N):
        ask(i, "bootstrap")
    for i in range(1, N):
        ask(i, "bootstrap")
    time.sleep(3)
    idle = [ask(i, "stats") for i in range(N)]

    published = [ask(i, f"publish {M}") for i in range(N)]
    time.sleep(5)
    loaded = [ask(i, "stats") for i in range(N)]

    since = int(time.time() * 1000)
    started = time.time()
    rounds = [ask(i, f"republish_since {since}") for i in range(N)]
    round_s = time.time() - started
    time.sleep(2)
    after = [ask(i, "stats") for i in range(N)]

    by_type = {}
    for before, later in zip(loaded, after):
        for kind, (_, b) in (later["sent"] or {}).items():
            by_type[kind] = by_type.get(kind, 0) + b - (before["sent"] or {}).get(kind, [0, 0])[1]
    per_node = [total_sent(a) - total_sent(b) for b, a in zip(loaded, after)]

    results.update({
        "published_ok": sum(p["published"] for p in published),
        "published_of": sum(p["of"] for p in published),
        "idle_rss_kb": summary([s["rss_kb"] for s in idle]),
        "idle_heap": summary([s["heap"] for s in idle]),
        "idle_routing": summary([s["routing"] for s in idle]),
        "threads": summary([s["threads"] for s in idle]),
        "loaded_records": summary([s["records"] for s in loaded]),
        "loaded_rss_kb": summary([s["rss_kb"] for s in loaded]),
        "loaded_heap": summary([s["heap"] for s in loaded]),
        "loaded_routing": summary([s["routing"] for s in loaded]),
        "hwm_kb_end": summary([s["hwm_kb"] for s in after]),
        "heap_peak_in_round": summary([s["heap_peak"] for s in after]),
        "round_republished": sum(r["republished"] for r in rounds),
        "round_seconds": round(round_s, 1),
        "round_bytes_total": sum(per_node),
        "round_bytes_per_node": summary(per_node),
        "round_bytes_by_type": dict(sorted(by_type.items(), key=lambda kv: -kv[1])),
    })
finally:
    for i, p in enumerate(procs):
        try:
            ask(i, "quit")
        except Exception:
            pass
    for p in procs:
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()

results["data_dir_bytes"] = summary([du(os.path.join(out, f"node-{i}")) for i in range(N)])
with open(os.path.join(out, "results.json"), "w") as f:
    json.dump(results, f, indent=1)
print(json.dumps(results, indent=1))
