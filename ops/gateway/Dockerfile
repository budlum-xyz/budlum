# budlum-gateway, multi-stage.
#
# The builder compiles the workspace binary against a pinned Rust toolchain; the
# runtime image carries the binary, a CA bundle and nothing else. The final
# image runs as an unprivileged user and exposes the plain-HTTP port only,
# because the terminator holds the certificate.
#
# The toolchain is taken from the repository's own `rust-toolchain.toml` rather
# than written here, so the image cannot drift from the tree it builds.
FROM rust:1-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --bin budlum-gateway

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 61000 --home-dir /var/lib/budlum-gateway --create-home budlum-gateway
COPY --from=builder /src/target/release/budlum-gateway /usr/local/bin/budlum-gateway
COPY ops/gateway/gateway.toml /etc/budlum-gateway/gateway.toml
RUN mkdir -p /var/lib/budlum-gateway && chown -R budlum-gateway:budlum-gateway /var/lib/budlum-gateway
USER budlum-gateway
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/budlum-gateway", "/etc/budlum-gateway/gateway.toml"]
