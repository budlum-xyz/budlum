# ── Budlum Core Production Docker Image ────────────────────
# Multi-stage build: builder → runtime

# ── Stage 1: Builder ────────────────────────────────────────
# Toolchain, rust-toolchain.toml (channel = "1.97.0") ve CI'daki
# dtolnay/rust-toolchain pini ile AYNI olmak zorundadir. Onceden 1.97.1
# kullaniliyordu: imaj CI'dan farkli bir derleyiciyle build ediliyor, bu da
# "tekrarlanabilir build" iddiasini gecersiz kiliyordu (codegen ve MIR
# optimizasyonlari surumler arasi degisir, uretilen binary bit-bit farkli
# olur).
#
# Digest, registry'den dogrulandi: bu imajin config blob'undaki
# RUST_VERSION=1.97.0'dir. Etiket adi kanit degildir -- onceki hali
# `rust:1.97.1-bookworm@sha256:77fac8b9...` idi ve o digest'in icindeki
# RUST_VERSION gercekten 1.97.1'di, yorum "1.94.0 icin dogrulandi" dedigi
# halde. Sadece etiket 1.97.0'a cevrilse digest onu ezerdi; ikisi birlikte
# degismek zorunda. `check-docker-toolchain-matches-pin.sh` bu ikisinin ve
# rust-toolchain.toml'un ayni surumu gosterdigini her PR'da dogrular.
FROM rust:1.97.0-bookworm@sha256:8fa55b2f3ddf97471ab6a767bfa3f37e6bad0986ba823e75fea57e2a2a5c3073 AS builder

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    protobuf-compiler \
    clang \
    cmake \
    && rm -rf /var/lib/apt/lists/*
# prost-build protoc'u PATH'ten arar; bazi imajlarda PATH degismis
# olabiliyor (docker-smoke 'Could not find protoc' veriyordu). Acikca
# isaret edelim + kurulumu dogrulayalim.
ENV PROTOC=/usr/bin/protoc
RUN test -x "$PROTOC" || (echo "protoc $PROTOC'da yok" >&2; exit 1)

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
# The packing between a field element and a 32-byte note hash. It is a path
# dependency of the node, so a build without it does not fall back to
# anything, it fails to resolve, which is how this line came to be missing
# and be noticed the same hour.
COPY crates/note-packing/ ./crates/note-packing/

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
# PROTOC env'ini build'e acikca gecir: prost-build protoc'u PATH'ten
# bulamadigi durumlarda docker-smoke 'Could not find protoc' veriyordu.
RUN PROTOC=/usr/bin/protoc cargo build --release --locked && \
    cp target/release/budlum-core /usr/local/bin/budlum-core

# ── Stage 2: Runtime ────────────────────────────────────────
FROM debian:bookworm-slim@sha256:abd67ffcfa541b485a3dff59865ab629aa048a6c613e639d36e7456b0b229241

# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/budlum-core /usr/local/bin/budlum-core

# Hadolint DL3066: non-numeric user-id. Kullanıcı deterministik UID 1000 ile
# oluşturulur ve `USER 1000` numeric form kullanır, böylece host tarafında
# çözümlenebilir (Güvenlik Planı §3: runtime kullanıcısı root değildir).
RUN useradd --create-home --shell /bin/bash --uid 1000 budlum

# Multi-node compose mount-point'leri (devnet-multinode-smoke): named volume
# ilk mount'ta imaj dizin sahipliğini devralır - önceden budlum sahipli
# oluşturulmazsa container (USER 1000) storage init'te EACCES alır ve
# restart-loop'a düşer (ilk CI koşusunda yakalanan defo, 2026-07-18).
RUN mkdir -p /home/budlum/data /home/budlum/secrets \
    && chown -R 1000:1000 /home/budlum

USER 1000
WORKDIR /home/budlum

# Expose default ports
#   4001 = P2P (devnet), 8545 = RPC public, 8546 = RPC operator, 9090 = Metrics
EXPOSE 4001 8545 8546 9090

# HEALTHCHECK (Güvenlik Planı §3.7): RPC portunun dinlendiğini doğrular.
# `curl`, bu meşru sağlık-kontrolü kullanımı için runtime imajında tutuldu.
# Konteyner ayakta ama RPC yanıt vermiyorsa unhealthy işaretlenir.
# JSON form (hadolint DL3025): `curl -f` zaten fail-mode'dur - başarısız
# bağlantıda exit 1 döner, healthcheck'in healthy/unhealthy kararını verir.
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
# Dockerfile varsayilan calisma modu.
CMD ["--network", "devnet", "--port", "4001"]
