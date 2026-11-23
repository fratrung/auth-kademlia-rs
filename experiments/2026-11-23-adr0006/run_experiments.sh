#!/usr/bin/env bash
# ADR 0006 experiments on one image, one network at a time: E1 to E4 on four
# network profiles; the attacks, the liars, the spoofed answers and the churn;
# the owner offline while replicas are lost, then the reads in that state
# under a persistent attacker. The ADR 0005 results to compare with are in
# experiments/2026-11-11-*. Each step writes its output to $OUT/<step>.txt,
# the data of its rounds to $OUT/<step>.json, and the host's dropped
# datagrams to the log.
set -u
# Run from anywhere: the repository root is two levels up from this file.
cd "$(dirname "$0")/../.." || exit 1
OUT=testbed/.generated/adr0006-runs
mkdir -p "$OUT"
LOG="$OUT/runner.log"
IMAGE=${IMAGE:-auth-kademlia-testbed:adr0006}
ONLY=${1:-all}   # all, compare, attacks or outage

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

up() { # profile nodes k loss
    testbed/testbed.py up --nodes "$2" --k "$3" --alpha 3 --profile "$1" --loss "$4" --image "$IMAGE" --no-build
}

compare() { # 127 nodes, k = 20, as EXPERIMENTS.md E1 to E4
    for case in lan:0:20 wan-eu:0:20 wan-atlantic:0:20 wan-eu:0.5:40; do
        IFS=: read -r profile loss rounds <<<"$case"
        local name="adr0006-$profile"
        [ "$loss" != 0 ] && name="$name-loss$loss"
        step "$name-up" up "$profile" 127 20 "$loss"
        step "$name-e1" testbed/measure.py publish --rounds "$rounds"
        step "$name-update" testbed/measure.py update --rounds 20 --restart 1
        if [ "$profile" != wan-atlantic ]; then
            step "$name-e2" testbed/measure.py publish --rounds "$rounds" --watchers 0 --counters
        fi
        step "$name-update-counters" testbed/measure.py update --rounds 10 --restart 1 --counters
        step "$name-down" testbed/testbed.py down
    done
}

attacks_small() { # 10 nodes, k = 3, as EXPERIMENTS.md A1 to A3
    for profile in lan wan-eu wan-atlantic; do
        step "k3-$profile-up" up "$profile" 10 3 0
        step "k3-$profile-race-start" testbed/attack.py start --mode race
        step "k3-$profile-race" testbed/attack.py race --rounds 20
        step "k3-$profile-race-stop" testbed/attack.py stop
        if [ "$profile" = wan-eu ]; then
            step "k3-$profile-burst-start" testbed/attack.py start --mode burst
            step "k3-$profile-burst" testbed/attack.py race --rounds 20
            step "k3-$profile-burst-stop" testbed/attack.py stop
            step "k3-$profile-restart-control" testbed/attack.py restart --rounds 20
            step "k3-$profile-persist-start" testbed/attack.py start --mode persist
            step "k3-$profile-persist" testbed/attack.py restart --rounds 20
            step "k3-$profile-persist-stop" testbed/attack.py stop
            step "k3-$profile-successor-start" testbed/attack.py start --mode successor
            step "k3-$profile-successor" testbed/attack.py restart --rounds 20 --no-crash
            step "k3-$profile-successor-stop" testbed/attack.py stop
        fi
        step "k3-$profile-down" testbed/testbed.py down
    done
}

attacks_large() { # 127 nodes, k = 20, WAN Europe, as EXPERIMENTS.md A1 to A5 and L1
    local p=k20-wan-eu
    step "$p-up" up wan-eu 127 20 0
    step "$p-race-start" testbed/attack.py start --mode race
    step "$p-race" testbed/attack.py race --rounds 20
    step "$p-race-stop" testbed/attack.py stop
    step "$p-burst-start" testbed/attack.py start --mode burst
    step "$p-burst" testbed/attack.py race --rounds 20
    step "$p-burst-stop" testbed/attack.py stop
    step "$p-restart-control" testbed/attack.py restart --rounds 20
    step "$p-persist-start" testbed/attack.py start --mode persist
    step "$p-persist" testbed/attack.py restart --rounds 20
    step "$p-persist-stop" testbed/attack.py stop
    step "$p-successor-start" testbed/attack.py start --mode successor
    step "$p-successor" testbed/attack.py restart --rounds 20 --no-crash
    step "$p-successor-stop" testbed/attack.py stop
    # Liars in FindHash: the counts of the ADR 0005 runs (12 and 13 were
    # below and at its quorum), and 18, every replica but the one restarted
    # and the owner.
    for liars in 0 1 12 13 18; do
        step "$p-liars$liars" testbed/measure.py update --rounds 20 --restart 1 --counters --liars "$liars"
    done
    # Spoofed answers: under guessed ids, then the control under observed ids.
    for ids in guessed observed; do
        step "$p-spoof-$ids-start" testbed/attack.py start --mode spoof --spoof-ids "$ids"
        step "$p-spoof-$ids" testbed/measure.py update --rounds 20 --restart 1 --counters
        step "$p-spoof-$ids-stop" testbed/attack.py stop
    done
    # Copies over time with churn: none, one and 13 liars.
    for liars in 0 1 13; do
        step "$p-churn-liars$liars" testbed/measure.py churn --duration 600 --liars "$liars"
    done
    step "$p-down" testbed/testbed.py down
}

outage() { # EXPERIMENTS.md L2 and L3
    local p=outage-wan-eu
    step "$p-up" up wan-eu 127 20 0
    step "$p-outage" testbed/measure.py outage --lost 4 7 8 12 16 --rounds 5 --owner-returns
    step "$p-down" testbed/testbed.py down
    # 3 more nodes stay out of the network and join it at the worst moment
    # of each round.
    p=reads-wan-eu
    step "$p-up" up wan-eu 130 20 0
    step "$p-attacker-start" testbed/attack.py start --mode persist --period 1000 --did-ttl 60
    step "$p-outage-reads" testbed/measure.py outage --lost 8 12 16 20 --rounds 5 --reads --joiners 3 --owner-returns
    step "$p-attacker-log" testbed/attack.py logs
    step "$p-attacker-stop" testbed/attack.py stop
    step "$p-down" testbed/testbed.py down
}

echo "=== $(date '+%F %T') start ($ONLY) on $IMAGE" | tee -a "$LOG"
case "$ONLY" in all | compare) compare ;; esac
case "$ONLY" in all | attacks) attacks_small; attacks_large ;; esac
case "$ONLY" in all | outage) outage ;; esac
echo "=== $(date '+%F %T') done" | tee -a "$LOG"
