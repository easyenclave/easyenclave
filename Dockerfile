FROM rust:1-bookworm AS builder

WORKDIR /src
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libsqlite3-0 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/ee-cp /usr/local/bin/
COPY --from=builder /src/target/release/ee-agent /usr/local/bin/
COPY --from=builder /src/target/release/ee-aggregator /usr/local/bin/
COPY --from=builder /src/target/release/ee-hostd /usr/local/bin/
COPY --from=builder /src/crates/cp/static /usr/share/easyenclave/static

# Default to running the control plane (with built-in aggregator)
EXPOSE 8080
ENV LISTEN_ADDR=0.0.0.0:8080
ENV BUILTIN_AGGREGATOR=true
ENV RUST_LOG=info

ENTRYPOINT ["ee-cp"]
