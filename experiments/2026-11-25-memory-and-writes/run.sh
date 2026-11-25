#!/usr/bin/env bash
# Memory, disk and writes of a node before and after the file of renewals and
# the daily republication (f183e76), and before and after the SHA-256 of the
# custody files (e399e63). No Docker: the probes of this folder are built
# from a copy of the repository at each commit, and the nodes run as
# processes on loopback. One step at a time.
#
#   experiments/2026-11-25-memory-and-writes/run.sh <work dir>
#
# The work directory, outside the repository, holds the copies, the builds
# (about 300 MB each) and the data directories; the results are written next
# to this script. The data directories must be on the disk to measure: the
# writes to the device are those of its file system.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
work=${1:?a work directory outside the repository}
mkdir -p "$work"
work=$(cd "$work" && pwd)
log=$here/runner.log
: > "$log"

BEFORE_CUSTODY=f28c760   # custody files without their SHA-256
BEFORE=e399e63           # custody files with it; renewals rewrite records, hourly
AFTER=f183e76            # the file of renewals, daily republication and flush
JOBS=${JOBS:-8}

step() {
    local name=$1
    shift
    echo "$(date -Is) start $name" >> "$log"
    "$@"
    echo "$(date -Is) end $name" >> "$log"
}

# build <commit> <example> [features]: the example built from the commit,
# copied to $work/<example>-<commit>.
build() {
    local commit=$1 example=$2 features=${3:-}
    local src=$work/src-$commit
    if [ ! -d "$src" ]; then
        mkdir -p "$src"
        git -C "$repo" archive "$commit" | tar -x -C "$src"
    fi
    mkdir -p "$src/examples"
    cp "$here/$example.rs" "$src/examples/"
    (cd "$src" && CARGO_TARGET_DIR="$work/target-$commit" cargo build --release --quiet \
        -j "$JOBS" ${features:+--features "$features"} --example "$example")
    cp "$work/target-$commit/release/examples/$example" "$work/$example-$commit"
}

storage() {
    local commit=$1 records=$2 cycles=$3
    local dir=$work/storage-$commit-$records-$cycles
    rm -rf "$dir"
    "$work/probe_mem-$commit" storage "$dir" "$records" "$cycles" \
        > "$here/storage-$commit-$records-$cycles.txt"
}

custody() {
    local commit=$1
    local dir=$work/custody-$commit
    rm -rf "$dir"
    "$work/probe_mem-$commit" custody "$dir" > "$here/custody-$commit.txt"
}

cluster() {
    local commit=$1 dids=$2
    python3 -I "$here/cluster.py" "$work/probe_node-$commit" "$work/cluster-$commit-$dids" \
        30 20 3 "$dids" 4 17100 > /dev/null
    cp "$work/cluster-$commit-$dids/results.json" "$here/cluster-$commit-dids$dids.json"
}

for commit in $BEFORE_CUSTODY $BEFORE $AFTER; do
    step "build probe_mem $commit" build "$commit" probe_mem
done
for commit in $BEFORE_CUSTODY $BEFORE; do
    step "custody $commit" custody "$commit"
done
for commit in $BEFORE $AFTER; do
    for records in 20 1000; do
        # 24 renewals and flushes a day before, 1 after; both on each code
        # to tell the file of renewals from the daily interval.
        for cycles in 24 1; do
            step "storage $commit $records $cycles" storage "$commit" "$records" "$cycles"
        done
    done
done
for commit in $BEFORE $AFTER; do
    step "build probe_node $commit" build "$commit" probe_node counters
    for dids in 1 10; do
        step "cluster $commit $dids" cluster "$commit" "$dids"
    done
done
