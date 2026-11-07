# Resilience test Docker image.
#
# Builds BOTH resilience_victim and resilience_attacker in a single Rust
# compilation pass, then packages them into two separate runtime images.
#
# The docker-compose.yaml references each stage via `target: node_a` /
# `target: node_b` — no duplicate compilation.
#
# Build context: project root (one level up from this file).
# Usage: docker compose -f resilience/docker-compose.yaml up --build

# ── Stage 1: compile ──────────────────────────────────────────────────────────
FROM rustlang/rust:nightly-bookworm-slim AS builder

WORKDIR /app
COPY . .

# Build both binaries in a single cargo invocation so the compiler cache is
# shared and incremental compilation applies across both targets.
RUN cargo build --release \
        --bin resilience_victim \
        --bin resilience_attacker

# Ensure issuer.bin exists (create an empty placeholder if absent).
# The victim only reads it for STATUS_LIST_KEY ops; normal DID records work
# without it.  The attacker never reads it at all.
RUN test -f issuer.bin || touch issuer.bin

# ── Stage 2: Node A (victim) runtime image ───────────────────────────────────
FROM debian:bookworm-slim AS node_a

WORKDIR /app
COPY --from=builder /app/target/release/resilience_victim ./resilience_victim
COPY --from=builder /app/issuer.bin .

ENTRYPOINT ["./resilience_victim"]

# ── Stage 3: Node B (attacker) runtime image ─────────────────────────────────
FROM debian:bookworm-slim AS node_b

WORKDIR /app
COPY --from=builder /app/target/release/resilience_attacker ./resilience_attacker
COPY --from=builder /app/issuer.bin .

ENTRYPOINT ["./resilience_attacker"]
