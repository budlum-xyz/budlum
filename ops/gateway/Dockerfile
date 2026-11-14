# budlum-gateway, multi-stage.
#
# The builder compiles the workspace binary against a pinned Rust toolchain; the
# runtime image carries the binary, a CA bundle and nothing else. The final
# image runs as an unprivileged user and exposes the plain-HTTP port only,
# because the terminator holds the certificate.
#
# The toolchain is taken from the repository's own `rust-toolchain.toml` rather
# than written here, so the image cannot drift from the tree it builds. Both base
# images are pinned by digest, so a build cannot silently pick up a different
# image under the same tag.
FROM rust:1-bookworm@sha256:ade39a710ef85f3506cffcfec3e8a24ba090badef1dff2fb798f71d878833fea AS builder
WORKDIR /src
COPY . .
RUN cargo build --release --bin budlum-gateway

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 61000 --home-dir /var/lib/budlum-gateway --create-home budlum-gateway
COPY --from=builder /src/target/release/budlum-gateway /usr/local/bin/budlum-gateway
COPY ops/gateway/gateway.toml /etc/budlum-gateway/gateway.toml
RUN mkdir -p /var/lib/budlum-gateway && chown -R budlum-gateway:budlum-gateway /var/lib/budlum-gateway
USER budlum-gateway
EXPOSE 8080
# A TCP connect to the listener. The image carries no curl, and the listener
# answers only a valid `Host`, so a connect is the honest liveness probe.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/8080"]
ENTRYPOINT ["/usr/local/bin/budlum-gateway", "/etc/budlum-gateway/gateway.toml"]
