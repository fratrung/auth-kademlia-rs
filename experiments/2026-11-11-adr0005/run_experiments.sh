#!/usr/bin/env bash
# ADR 0005 experiments, one network at a time: E1, E2/E3 and the update mode
# on the main image and on the branch image, then the attacks, the liars, the
# spoofed answers and the churn on the branch image. Each step writes its
# output to $OUT/<step>.txt and the host's dropped datagrams to the log.
set -u
# Run from anywhere: the repository root is two levels up from this file.
cd "$(dirname "$0")/../.." || exit 1
OUT=testbed/.generated/adr0005-runs
mkdir -p "$OUT"
LOG="$OUT/runner.log"
MAIN=auth-kademlia-testbed:main-424b76f
BRANCH=auth-kademlia-testbed:adr0005-final
ONLY=${1:-all}   # all, compare (E1/E2/E3/update on both images) or attacks

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

up() { # image profile nodes k loss
    testbed/testbed.py up --nodes "$3" --k "$4" --alpha 3 --profile "$2" --loss "$5" --image "$1" --no-build
}

compare() { # tag image
    local tag=$1 image=$2
    for case in lan:0:20 wan-eu:0:20 wan-atlantic:0:20 wan-eu:0.5:40; do
        IFS=: read -r profile loss rounds <<<"$case"
        local name="$tag-$profile"
        [ "$loss" != 0 ] && name="$name-loss$loss"
        step "$name-up" up "$image" "$profile" 127 20 "$loss"
        step "$name-e1" testbed/measure.py publish --rounds "$rounds"
        step "$name-update" testbed/measure.py update --rounds 20 --restart 1
        if [ "$profile" != wan-atlantic ]; then
            step "$name-e2" testbed/measure.py publish --rounds "$rounds" --watchers 0 --counters
        fi
        step "$name-update-counters" testbed/measure.py update --rounds 10 --restart 1 --counters
        step "$name-down" testbed/testbed.py down
    done
}

attacks_small() { # 10 nodes, k = 3, as EXPERIMENTS.md A1 and A2
    for profile in lan wan-eu wan-atlantic; do
        step "k3-$profile-up" up "$BRANCH" "$profile" 10 3 0
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

attacks_large() { # 127 nodes, k = 20, WAN Europe
    local p=k20-wan-eu
    step "$p-up" up "$BRANCH" wan-eu 127 20 0
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
    # Liars in FindHash: none, one, quorum - 1 and quorum (13 at k = 20).
    for liars in 0 1 12 13; do
        step "$p-liars$liars" testbed/measure.py update --rounds 20 --restart 1 --counters --liars "$liars"
    done
    # Spoofed answers: under guessed ids, then the control under observed ids.
    for ids in guessed observed; do
        step "$p-spoof-$ids-start" testbed/attack.py start --mode spoof --spoof-ids "$ids"
        step "$p-spoof-$ids" testbed/measure.py update --rounds 20 --restart 1 --counters
        step "$p-spoof-$ids-stop" testbed/attack.py stop
    done
    # Copies over time with churn: none, one and quorum liars.
    for liars in 0 1 13; do
        step "$p-churn-liars$liars" testbed/measure.py churn --duration 600 --liars "$liars"
    done
    step "$p-down" testbed/testbed.py down
}

echo "=== $(date '+%F %T') start ($ONLY)" | tee -a "$LOG"
case "$ONLY" in
    all | compare)
        compare main "$MAIN"
        compare branch "$BRANCH"
        ;;
esac
case "$ONLY" in
    all | attacks)
        attacks_small
        attacks_large
        ;;
esac
echo "=== $(date '+%F %T') done" | tee -a "$LOG"
