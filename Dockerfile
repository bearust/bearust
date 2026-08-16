FROM node:22-bookworm-slim AS frontend-builder
WORKDIR /frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend ./
RUN npm run build

FROM rust:1.97.1-bookworm AS builder
ENV RUSTUP_TOOLCHAIN=1.97.1
RUN apt-get update && apt-get install -y --no-install-recommends clang cmake make perl pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY src ./src
COPY crates ./crates
COPY migrations ./migrations
RUN cargo build --release --locked
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates netcat-openbsd && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 bearust && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin bearust \
    && mkdir -p /run/bearust && chown bearust:bearust /run/bearust
COPY --from=builder /src/target/release/bearust /usr/local/bin/bearust
COPY --from=frontend-builder /frontend/dist /usr/share/bearust/frontend
USER bearust
WORKDIR /run/bearust
ENTRYPOINT ["bearust"]
CMD ["serve", "--config", "/etc/bearust/bearust.toml", "--json-logs"]
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD ["sh", "-c", "test -s /run/bearust/bearust.pid && kill -0 $(cat /run/bearust/bearust.pid) && nc -z 127.0.0.1 8080"]
