"""Summarize an outage run with reads: rounds split by whether the first
publication reached every replica before the loss."""
import json, sys
from collections import defaultdict

def add(acc, t):
    for k in ("current", "older", "other", "none", "error"):
        acc[k] += t.get(k, 0) if t else 0

for path in sys.argv[1:]:
    d = json.load(open(path))
    print(path, d["config"].get("image"))
    groups = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))
    for r in d["rounds"]:
        intact = r["before"]["current"] == r["replicas"]
        key = (r["lost"], "intact" if intact else "poisoned/failed at publication")
        g = groups[key]
        g["rounds"]["n"] += 1
        g["restored"]["n"] += r["after_push"]["current"] == r["replicas"]
        g["forged replicas after push"]["n"] += r["after_push"]["other"]
        add(g["reads off"], r.get("reads_owner_offline"))
        add(g["joiners"], r.get("joiner_reads"))
        if "reads_owner_back" in r:
            add(g["reads back"], r["reads_owner_back"])
            g["after owner"]["n"] += r["after_owner"]["current"] == r["replicas"]
    for (lost, kind), g in sorted(groups.items()):
        fmt = lambda t: f"{t['current']}/{t['older']}/{t['other']}/{t['none']}" + (f" err {t['error']}" if t['error'] else "")
        line = (f"  lost {lost:>2} {kind:<32} rounds {g['rounds']['n']}, restored {g['restored']['n']}, "
                f"forged replicas {g['forged replicas after push']['n']}, reads {fmt(g['reads off'])}, joiners {fmt(g['joiners'])}")
        if "reads back" in g:
            line += f", owner back: restored {g['after owner']['n']}, reads {fmt(g['reads back'])}"
        print(line)
