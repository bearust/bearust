FROM rust:1.84.1-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends clang cmake make perl pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
RUN cargo build --release --locked
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates netcat-openbsd && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 bearust && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin bearust \
    && mkdir -p /run/bearust && chown bearust:bearust /run/bearust
COPY --from=builder /src/target/release/bearust /usr/local/bin/bearust
USER bearust
WORKDIR /run/bearust
ENTRYPOINT ["bearust"]
CMD ["serve", "--config", "/etc/bearust/bearust.toml", "--json-logs"]
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD ["sh", "-c", "test -s /run/bearust/bearust.pid && kill -0 $(cat /run/bearust/bearust.pid) && nc -z 127.0.0.1 8080"]
