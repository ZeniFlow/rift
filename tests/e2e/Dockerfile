# Стенд для e2e: riftd + iroh-relay в одном образе.
FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p riftd && cp target/release/riftd /usr/local/bin/ && \
    cargo install --locked iroh-relay@1.3.0 --features server --root /usr/local

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping netcat-openbsd iproute2 iptables openssl && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/riftd /usr/local/bin/iroh-relay /usr/local/bin/
COPY tests/e2e/node.sh tests/e2e/relay.sh /e2e/
