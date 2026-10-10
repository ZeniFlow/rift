# Стенд для e2e: riftd + iroh-relay в одном образе.
FROM rust:1-slim-bookworm AS build
WORKDIR /src
# Только исходники Rust: правки тестов и документации не пересобирают бинари.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked -p riftd -p rift-trust && cp target/release/riftd target/release/rift-ca /usr/local/bin/ && \
    cargo install --locked iroh-relay@1.3.0 --features server --root /usr/local

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping netcat-openbsd iproute2 iptables openssl busybox && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/bin/riftd /usr/local/bin/rift-ca /usr/local/bin/iroh-relay /usr/local/bin/
COPY tests/e2e/node.sh tests/e2e/relay.sh tests/e2e/names.sh /e2e/
