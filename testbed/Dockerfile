# syntax=docker/dockerfile:1
# Testbed image: one DHT node per container, with tc for network emulation.
# Built by `testbed/testbed.py build`, with the repository root as context.
FROM rust:1.98.1-bookworm AS builder
WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --features testbed --bin testbed_node --bin testbed_attacker \
    && cp target/release/testbed_node target/release/testbed_attacker /usr/local/bin/

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /usr/local/bin/testbed_node /usr/local/bin/testbed_attacker /app/
COPY testbed/entrypoint.sh /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
