#!/usr/bin/env bash
# The owner offline while replicas are lost at once: main, then the branch.
set -u
cd "$(dirname "$0")/../.." || exit 1
OUT=testbed/.generated/outage-runs
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
    step "$tag-up" testbed/testbed.py up --nodes 127 --k 20 --alpha 3 --profile wan-eu --image "$image" --no-build
    if [ "$tag" = branch ]; then
        step "$tag-outage" testbed/measure.py outage --lost 4 7 8 12 16 --rounds 5 --owner-returns
    else
        step "$tag-outage" testbed/measure.py outage --lost 4 7 8 12 16 --rounds 5
    fi
    step "$tag-down" testbed/testbed.py down
done
echo "=== $(date '+%F %T') done" | tee -a "$LOG"
