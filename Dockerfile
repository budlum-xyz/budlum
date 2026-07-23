# ── Budlum Core Production Docker Image ────────────────────
# Multi-stage build: builder → runtime

# ── Stage 1: Builder ────────────────────────────────────────
FROM rust:1.97.1-bookworm@sha256:77fac8b98f9f46062bb680b6d25d5bcaabfc400143952ebc572e924bcbedc3fa AS builder

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    clang \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy the monorepo manifests and sources. BudZero/BudZKVM is vendored as
# source under budzero/ and is built from the same immutable checkout.
COPY Cargo.toml Cargo.lock build.rs ./
COPY src/ ./src/
COPY benches/ ./benches/
COPY proto/ ./proto/
COPY budzero/ ./budzero/

# Build release binary
RUN cargo build --release --locked && \
    cp target/release/budlum-core /usr/local/bin/budlum-core

# ── Stage 2: Runtime ────────────────────────────────────────
FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/budlum-core /usr/local/bin/budlum-core

RUN useradd --create-home --shell /bin/bash budlum

# Multi-node compose mount-point'leri (devnet-multinode-smoke): named volume
# ilk mount'ta imaj dizin sahipliğini devralır — önceden budlum sahipli
# oluşturulmazsa container (USER budlum) storage init'te EACCES alır ve
# restart-loop'a düşer (ilk CI koşusunda yakalanan defo, 2026-07-18).
RUN mkdir -p /home/budlum/data /home/budlum/secrets \
    && chown -R budlum:budlum /home/budlum

USER budlum
WORKDIR /home/budlum

# Expose default ports
#   4001 = P2P (devnet), 8545 = RPC public, 8546 = RPC operator, 9090 = Metrics
EXPOSE 4001 8545 8546 9090

# HEALTHCHECK (Güvenlik Planı §3.7): RPC portunun dinlendiğini doğrular.
# `curl`, bu meşru sağlık-kontrolü kullanımı için runtime imajında tutuldu.
# Konteyner ayakta ama RPC yanıt vermiyorsa unhealthy işaretlenir.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:8545/ || exit 1

ENV RUST_LOG=info

ENTRYPOINT ["budlum-core"]
# Default: devnet (safety — mainnet requires explicit --network mainnet flag).
# See docs/budlum-ci-guvenlik-plani.md §2 (Dockerfile default mode).
CMD ["--network", "devnet", "--port", "4001"]
