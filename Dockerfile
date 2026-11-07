FROM rustlang/rust:nightly-bookworm-slim AS builder

WORKDIR /app
COPY . .
RUN cargo build --release --bin dht_node

FROM debian:bookworm-slim

WORKDIR /app
COPY --from=builder /app/target/release/dht_node .
COPY --from=builder /app/issuer.bin .

ENTRYPOINT ["./dht_node"]
