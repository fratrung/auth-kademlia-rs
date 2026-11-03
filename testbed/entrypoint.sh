#!/bin/sh
# Apply the network profile to this container's egress, then start the node.
# A request and its reply cross two containers, so the round trip gets twice
# NETEM_DELAY_MS, and NETEM_LOSS_PCT applies once per direction.
set -eu
IFACE="${NETEM_IFACE:-eth0}"
DELAY="${NETEM_DELAY_MS:-0}"
JITTER="${NETEM_JITTER_MS:-0}"
LOSS="${NETEM_LOSS_PCT:-0}"

# Numeric test, so that "0", "0.0" and "0.00" all mean zero.
nonzero() { awk -v value="$1" 'BEGIN { exit !(value + 0 != 0) }'; }

if nonzero "$DELAY" || nonzero "$JITTER" || nonzero "$LOSS"; then
    set -- delay "${DELAY}ms"
    if nonzero "$JITTER"; then
        set -- "$@" "${JITTER}ms" distribution normal
    fi
    if nonzero "$LOSS"; then
        set -- "$@" loss "${LOSS}%"
    fi
    tc qdisc replace dev "$IFACE" root netem "$@"
    echo "[testbed] netem on $IFACE: $*"
else
    echo "[testbed] no network emulation on $IFACE"
fi
exec /app/testbed_node
