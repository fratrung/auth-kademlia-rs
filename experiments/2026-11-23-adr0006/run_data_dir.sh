#!/usr/bin/env bash
# The same crashes as A2, L1 and L2, with every node keeping its records on
# disk (`testbed.py up --data-dir`): a replica killed and started again comes
# back with the files it wrote. 127 nodes, k = 20, WAN Europe. Each step
# writes its output to $OUT/<step>.txt, the data of its rounds to
# $OUT/<step>.json, and the host's dropped datagrams to the log.
set -u
# Run from anywhere: the repository root is two levels up from this file.
cd "$(dirname "$0")/../.." || exit 1
OUT=testbed/.generated/adr0006-data-runs
mkdir -p "$OUT"
LOG="$OUT/runner.log"
IMAGE=${IMAGE:-auth-kademlia-testbed:adr0006-data}

drops() {
    python3 -I -c "print(sum(int(line.split()[1], 16) for line in open('/proc/net/softnet_stat')))"
}

step() {
    local name=$1
    shift
    local before after rc details
    before=$(drops)
    echo "=== $(date '+%F %T') $name: $*" | tee -a "$LOG"
    "$@" >"$OUT/$name.txt" 2>&1
    rc=$?
    after=$(drops)
    # measure.py and attack.py name the file of their rounds last.
    details=$(sed -n 's/^ *details: //p' "$OUT/$name.txt" | tail -n 1)
    [ -n "$details" ] && [ -f "$details" ] && cp "$details" "$OUT/$name.json"
    echo "=== $(date '+%F %T') $name: exit $rc, host drops $((after - before))" | tee -a "$LOG"
}

p=data-wan-eu
echo "=== $(date '+%F %T') start on $IMAGE" | tee -a "$LOG"
step "$p-up" testbed/testbed.py up --nodes 127 --k 20 --alpha 3 --profile wan-eu --data-dir --image "$IMAGE" --no-build
# A2: a replica crashes and restarts without an update, with no attacker,
# then with a persistent one.
step "$p-restart-control" testbed/attack.py restart --rounds 20
step "$p-persist-start" testbed/attack.py start --mode persist
step "$p-persist" testbed/attack.py restart --rounds 20
step "$p-persist-stop" testbed/attack.py stop
# E4: a replica restarted just before a rotation.
step "$p-update" testbed/measure.py update --rounds 20 --restart 1
# L1: copies over time while nodes crash.
step "$p-churn" testbed/measure.py churn --duration 600 --liars 0
# L2: the owner offline while replicas crash at once.
step "$p-outage" testbed/measure.py outage --lost 4 8 12 16 20 --rounds 5 --owner-returns
step "$p-down" testbed/testbed.py down
echo "=== $(date '+%F %T') done" | tee -a "$LOG"
