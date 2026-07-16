# ── Budlum Core Production Docker Image ────────────────────
# Multi-stage build: builder → runtime

# ── Stage 1: Builder ────────────────────────────────────────
FROM rust:1.97.0-bookworm@sha256:8fa55b2f3ddf97471ab6a767bfa3f37e6bad0986ba823e75fea57e2a2a5c3073 AS builder

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

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/budlum-core /usr/local/bin/budlum-core

RUN useradd --create-home --shell /bin/bash budlum
USER budlum
WORKDIR /home/budlum

# Expose default ports
#   4001 = P2P (devnet), 8545 = RPC public, 8546 = RPC operator, 9090 = Metrics
EXPOSE 4001 8545 8546 9090

ENV RUST_LOG=info

ENTRYPOINT ["budlum-core"]
# Local smoke: scripts/phase3_smoke_rpc.sh (devnet override recommended)
CMD ["--network", "mainnet", "--port", "4001"]
