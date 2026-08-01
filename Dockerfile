# ── Budlum Core Production Docker Image ────────────────────
# Multi-stage build: builder → runtime

# ── Stage 1: Builder ────────────────────────────────────────
# Toolchain, rust-toolchain.toml (channel = "1.94.0") ve CI'daki
# dtolnay/rust-toolchain pini ile AYNI olmak zorundadir. Onceden 1.97.1
# kullaniliyordu: imaj CI'dan farkli bir derleyiciyle build ediliyor, bu da
# "tekrarlanabilir build" iddiasini gecersiz kiliyordu (codegen ve MIR
# optimizasyonlari surumler arasi degisir, uretilen binary bit-bit farkli
# olur).
#
# Digest, registry'den dogrulandi: bu imajin config blob'undaki
# RUST_VERSION=1.94.0'dir. Etiket adi kanit degildir -- onceki hali
# `rust:1.97.1-bookworm@sha256:77fac8b9...` idi ve o digest'in icindeki
# RUST_VERSION gercekten 1.97.1'di, yorum "1.94.0 icin dogrulandi" dedigi
# halde. Sadece etiket 1.94.0'a cevrilse digest onu ezerdi; ikisi birlikte
# degismek zorunda. `check-docker-toolchain-matches-pin.sh` bu ikisinin ve
# rust-toolchain.toml'un ayni surumu gosterdigini her PR'da dogrular.
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
# rust-toolchain.toml da kopyalanir: onsuz imaj icindeki derleyici ne ise o
# kullanilir ve pin sessizce devre disi kalir. Ustelik dosya varsa rustup
# uyusmazlikta durur, yani base imaj bir daha kayarsa build patlar -- bit-bit
# farkli bir binary uretmek yerine.
COPY Cargo.toml Cargo.lock build.rs rust-toolchain.toml ./
COPY src/ ./src/
COPY benches/ ./benches/
COPY proto/ ./proto/
COPY budzero/ ./budzero/

# Derleyici gercekten pinli surum mu: build'den ONCE, imaj icinde.
# Bu satir olmasaydi yanlis derleyiciyle uretilmis bir binary sessizce
# yayinlanirdi ve "tekrarlanabilir build" iddiasi kagit uzerinde kalirdi.
#
# Boru YOK (hadolint DL4006): `rustc --version | cut` yazilsaydi rustc'nin
# cikis kodu cut'inkiyle ortulurdu ve rustc calismasa bile adim gecerdi --
# tam olarak bu kapinin engellemek istedigi sessiz gecis. `set -o pipefail`
# eklemek yerine boruyu kaldirmak daha dar bir cozum: `rustc --version`
# once kendi basina calisir, basarisiz olursa `&&` zinciri orada durur.
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
# ilk mount'ta imaj dizin sahipliğini devralır - önceden budlum sahipli
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
# Default: devnet (safety - mainnet requires explicit --network mainnet flag).
# See docs/budlum-ci-guvenlik-plani.md §2 (Dockerfile default mode).
CMD ["--network", "devnet", "--port", "4001"]
