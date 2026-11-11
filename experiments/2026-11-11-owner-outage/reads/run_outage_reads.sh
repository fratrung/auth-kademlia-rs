#!/usr/bin/env bash
# Reads while replicas are lost and the owner is offline, with a persistent
# attacker sending forged versions: 127 nodes in the network and 3 that join
# it at the worst moment of each round; main, then the branch.
set -u
cd "$(dirname "$0")/../../.." || exit 1
OUT=testbed/.generated/outage-reads-runs
mkdir -p "$OUT"
LOG="$OUT/runner.log"
drops() {
    python3 -I -c "print(sum(int(line.split()[1], 16) for line in open('/proc/net/softnet_stat')))"
}
step() {
    local name=$1
    shift
    local before after rc
    before=$(drops)
    echo "=== $(date '+%F %T') $name: $*" | tee -a "$LOG"
    "$@" >"$OUT/$name.txt" 2>&1
    rc=$?
    after=$(drops)
    echo "=== $(date '+%F %T') $name: exit $rc, host drops $((after - before))" | tee -a "$LOG"
}
for case in main:auth-kademlia-testbed:main-424b76f-push branch:auth-kademlia-testbed:adr0005-push; do
    tag=${case%%:*}
    image=${case#*:}
    step "$tag-up" testbed/testbed.py up --nodes 130 --k 20 --alpha 3 --profile wan-eu --image "$image" --no-build
    step "$tag-attacker-start" testbed/attack.py start --mode persist --period 1000 --did-ttl 60
    if [ "$tag" = branch ]; then
        step "$tag-outage-reads" testbed/measure.py outage --lost 8 12 16 20 --rounds 5 --reads --joiners 3 --owner-returns
    else
        step "$tag-outage-reads" testbed/measure.py outage --lost 8 12 16 20 --rounds 5 --reads --joiners 3
    fi
    step "$tag-attacker-log" testbed/attack.py logs
    step "$tag-attacker-stop" testbed/attack.py stop
    step "$tag-down" testbed/testbed.py down
done
echo "=== $(date '+%F %T') done" | tee -a "$LOG"
