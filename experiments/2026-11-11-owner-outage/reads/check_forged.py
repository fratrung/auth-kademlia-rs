"""Match the records read as `other` with the forged keys the attacker logged."""
import json, re, sys
from collections import defaultdict

run, log = sys.argv[1], sys.argv[2]
forged = defaultdict(set)
for line in open(log):
    m = re.search(r"persist: learned (\S+) from .* forged key (\w+)", line)
    if m:
        forged[m.group(1)].add(m.group(2))
d = json.load(open(run))
print(run, d["config"]["image"])
totals = defaultdict(int)
for r in d["rounds"]:
    did = r["did"]
    for field in ("reads_owner_offline", "reads_owner_back", "joiner_reads"):
        reads = r.get(field)
        if not reads:
            continue
        for key, count in reads.get("keys", {}).items():
            if key == "None":
                kind = "nothing"
            elif key in r["versions"]:
                kind = "owner's version"
            elif key in forged[did]:
                kind = "attacker's forgery"
            else:
                kind = "UNKNOWN key"
            totals[(field, kind)] += count
for (field, kind), count in sorted(totals.items()):
    print(f"  {field:<20} {kind:<20} {count}")
print("  DIDs learned by the attacker:", sum(1 for r in d["rounds"] if forged[r["did"]]), "of", len(d["rounds"]))
