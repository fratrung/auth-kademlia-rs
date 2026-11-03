# syntax=docker/dockerfile:1
# Testbed image: one DHT node per container, with tc for network emulation.
# Built by `testbed/testbed.py build`, with the repository root as context.
FROM rust:1.98.1-bookworm AS builder
WORKDIR /app
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/app/target \
    cargo build --release --bin testbed_node \
    && cp target/release/testbed_node /usr/local/bin/testbed_node

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 iputils-ping \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /usr/local/bin/testbed_node /app/testbed_node
COPY testbed/entrypoint.sh /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
