FROM rust:1.86-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release -p ee-agent -p ee-cp

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    supervisor \
    curl \
  && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/ee-agent /usr/local/bin/ee-agent
COPY --from=builder /src/target/release/ee-cp /usr/local/bin/ee-cp

RUN mkdir -p /etc/supervisor/conf.d /data/ee-agent
COPY image/supervisord.conf /etc/supervisor/conf.d/supervisord.conf

CMD ["/usr/bin/supervisord", "-n", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
