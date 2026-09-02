# ── Budlum Core Production Docker Image ────────────────────
# Multi-stage build: builder → runtime

# ── Stage 1: Builder ────────────────────────────────────────
# The toolchain MUST be THE SAME as rust-toolchain.toml (channel = "1.97.1") and
# the dtolnay/rust-toolchain pin in CI. It used to be 1.97.1:
# the image was built with a different compiler from CI, which invalidated the
# "reproducible build" claim (codegen and MIR optimisations change between
# releases and the produced binary comes out bit-for-bit different).
#
#
# The digest was verified from the registry: the config blob of this image carries
# RUST_VERSION=1.97.1. A tag name is not evidence -- the previous shape was
# was `rust:1.97.1-bookworm@sha256:77fac8b9...` and the toolchain inside
# and the RUST_VERSION inside that digest really was 1.97.1, even though the comment
# said "verified for 1.94.0". Turning only the tag into 1.97.1 would let the digest
# override it; the two must change together. `check-docker-toolchain-matches-pin.sh`
# verifies on every PR that these two and rust-toolchain.toml point at the same version.
FROM rust:1.97.1-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97 AS builder

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    clang \
    cmake \
    && rm -rf /var/lib/apt/lists/*
# prost-build looks for protoc on PATH; in some images PATH may have
# changed (docker-smoke was giving 'Could not find protoc'). Point at it
# explicitly and verify the installation.
ENV PROTOC=/usr/bin/protoc
RUN test -x "$PROTOC" || (echo "protoc is not at $PROTOC" >&2; exit 1)

WORKDIR /build

# Copy the monorepo manifests and sources. BudZero/BudZKVM is vendored as
# source under budzero/ and is built from the same immutable checkout.
# rust-toolchain.toml is copied too: without it whatever compiler is in the image
# gets used and the pin is silently disabled. Moreover, when the file is present rustup
# stops on a mismatch, so if the base image drifts again the build breaks -- instead of
# producing a bit-for-bit different binary.
COPY Cargo.toml Cargo.lock build.rs rust-toolchain.toml ./
COPY src/ ./src/
COPY benches/ ./benches/
COPY proto/ ./proto/
COPY budzero/ ./budzero/
# The packing between a field element and a 32-byte note hash. It is a path
# dependency of the node, so a build without it does not fall back to
# anything, it fails to resolve, which is how this line came to be missing
# and be noticed the same hour.
COPY crates/note-packing/ ./crates/note-packing/

# Is the compiler really the pinned version: BEFORE the build, inside the image.
# Without this line a binary produced by the wrong compiler would be published
# silently and the "reproducible build" claim would exist only on paper.
#
# NO pipe (hadolint DL4006): had it been written `rustc --version | cut`, rustc's
# exit code would be masked by cut's and the step would pass even if rustc did not run --
# exactly the silent pass this gate wants to prevent. Removing the pipe is a narrower
# fix than adding `set -o pipefail`: `rustc --version` runs on its own first, and if it
# fails the `&&` chain stops there.
RUN pinned="$(sed -n 's/^channel *= *"\(.*\)"/\1/p' rust-toolchain.toml)" && \
    version_line="$(rustc --version)" && \
    actual="${version_line#rustc }" && \
    actual="${actual%% *}" && \
    if [ "$pinned" != "$actual" ]; then \
      echo "HATA: imaj rustc $actual tasiyor, rust-toolchain.toml $pinned pinliyor" >&2; \
      exit 1; \
    fi && \
    echo "toolchain OK: rustc $actual == rust-toolchain.toml $pinned"

# Build release binary
# Pass the PROTOC env explicitly to the build: prost-build resolves protoc
# could not find it, docker-smoke reported 'Could not find protoc'.
RUN PROTOC=/usr/bin/protoc cargo build --release --locked && \
    cp target/release/budlum-core /usr/local/bin/budlum-core

# ── Stage 2: Runtime ────────────────────────────────────────
FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/budlum-core /usr/local/bin/budlum-core

# Hadolint DL3066: non-numeric user-id. The user is created with the deterministic
# UID 1000 and `USER 1000` uses the numeric form, so it resolves on the host side
# (Security Plan section 3: the runtime user is not root).
RUN useradd --create-home --shell /bin/bash --uid 1000 budlum

# Multi-node compose mount points (devnet-multinode-smoke): a named volume
# inherits the image directory ownership on first mount - if it is not created
# owned by budlum beforehand the container (USER 1000) gets EACCES during storage
# init and falls into a restart loop (a defect caught in the first CI run, 2026-07-18).
RUN mkdir -p /home/budlum/data /home/budlum/secrets \
    && chown -R 1000:1000 /home/budlum

USER 1000
WORKDIR /home/budlum

# Expose default ports
#   4001 = P2P (devnet), 8545 = RPC public, 8546 = RPC operator, 9090 = Metrics
EXPOSE 4001 8545 8546 9090

# HEALTHCHECK (Security Plan section 3.7): verifies that the RPC port is listening.
# `curl` is kept in the runtime image for this legitimate health check use.
# If the container is up but the RPC does not answer it is marked unhealthy.
# The JSON form (hadolint DL3025): `curl -f` is already in fail mode - it returns
# exit 1 on a failed connection, which makes the healthcheck's healthy/unhealthy decision.
# F-20: JSON-RPC probe on the public listener the image actually binds
# (8545). Compose's operator listener (8546) is opt-in via
# --rpc-operator-listener; a default `docker run` never opens it, so a
# probe there would mark a live rpc-role node unhealthy. A bare GET of
# / is not a JSON-RPC request.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD ["curl", "-sf", "--max-time", "4", "-H", "Content-Type: application/json", "-d", "{\"jsonrpc\":\"2.0\",\"method\":\"bud_netListening\",\"params\":[],\"id\":1}", "http://127.0.0.1:8545"]

ENV RUST_LOG=info

ENTRYPOINT ["budlum-core"]
# Default: devnet (safety - mainnet requires explicit --network mainnet flag).
# The default run mode of the Dockerfile.
CMD ["--network", "devnet", "--port", "4001"]
