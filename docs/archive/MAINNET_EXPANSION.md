# Budlum — : Genişletme (Genesis + Coverage + Fuzz + BudL + Security + Wallet-Core)

> **Yazar:** ARENA1 ( yöneticisi), 2026-07-19.
> **Temel:** main `8ec7059`.
> **İlişki:** `docs/BUDLUM_TASK11.md` (Mainnet Lockdown — V-bulgu kapanışı) tamamlandıktan
> sonra veya paralel olarak yürütülür. , ana zincir kapasitesini genişletir;
>  ise mainnete hazırlik kapanışıdır.
> **Kaynak:** Kullanıcı emri (6  + wallet-core permissionless notu).
> Her  için: kapsam, tasarım, kabul kriterleri, riskler, karar kapıları.

---

## : Genesis Config — 4 Domain Bootstrap + İlk Token Dağılımı

### Kapsam
`config/mainnet-genesis.json` + `src/chain/genesis.rs::mainnet_genesis()` içinde
4 domain tanımı (PoW + PoS + BFT + PoA) + ilk token dağılımı (5 havuz:
Community/Liquidity/Ecosystem/Team/Burn Reserve, toplam 100T $BUD).

### Mevcut durum
- `mainnet-genesis.json`: `ceremony_allocations_plan` placeholder adreslerle
  hazır (5 havuz), ama `allocations` boş (`[]`), `validators` boş (`[]`).
- `mainnet_genesis()` kodu: deterministic placeholder adresler kullanıyor.
- **Domain tanımı YOK** — genesis'te hiç domain register edilmiyor.

### Plan
1. **`GenesisConfig` genişletme:** `domains: Vec<GenesisDomain>` alanı ekle
   (`#[serde(default)]` backward-compat).
2. **4 domain bootstrap:**
   - **PoW** (DomainId=1): `pow-confirmation-depth` adapter, bridge_enabled=true.
   - **PoS** (DomainId=2): `pos-qc-finality` adapter, BLS validator set.
   - **BFT** (DomainId=3): `bft-aggregate-sig` adapter, rotating leader.
   - **PoA** (DomainId=4): `poa-authority-quorum` adapter, KYC'den geçmiş
     authority set (PoA izolasyon kuralı: stake YOK, KYC + admin approve).
3. **Token dağılımı:** 5 havuz adresleri ceremony'de doldurulur; kod'da
   placeholder (deterministic) + `ceremony_allocations_plan` ile uyumlu.
4. **Test:** `test_mainnet_genesis_has_4_domains` + `test_genesis_domains_isolated`.

### Kabul Kriterleri
- [ ] Genesis JSON'da 4 domain tanımı (PoW/PoS/BFT/PoA).
- [ ] PoA domain STAKE İÇERMEZ (permissionless registry'den TAMAMEN AYRI —
  CLAUDE.md §2 PoA izolasyon kuralı).
- [ ] Token dağılımı 100T = 10+10+20+20+40T.
- [ ] Genesis hash deterministic (test_mainnet_genesis_json_matches_code).
- [ ] CI yeşil.

### Riskler
- Domain eklemek genesis hash'i değiştirir → ceremony re-freeze gerekli (MR-6).
- PoA domain'in permissionless registry'ye sızmasını test etmek (izolasyon).

---

## : Coverage — cargo-tarpaulin CI + README Badge

### Kapsam
cargo-tarpaulin'i CI'ya ekle (Coverage job'u llvm-cov'den tarpaulin'e geçiş
veya paralel) + README'ye coverage badge koy.

### Mevcut durum
- Coverage job: `nextest + llvm-cov` () — sürekli flake (sled lock,
  test bug). Tarpaulin bağımlılığı YOK.
- README'de coverage badge YOK.

### Plan
1. **`scripts/check-coverage-tarpaulin.sh`:** tarpaulin çalıştır + ratchet
   (coverage % alt sınır).
2. **CI job `Coverage (tarpaulin)`:** `cargo-tarpaulin --workspace --out xml`
   + ratchet karşılaştırma. llvm-cov job paralel kalır (geçiş dönemi).
3. **README badge:** `[![Coverage](https://img.shields.io/endpoint?url=...)]`
   — tarpaulin XML → badge (codecov-style).
4. **Coverage hedefleri (MR-5):** consensus ≥90%, cross_domain ≥90%, crypto ≥90%.

### Kabul Kriterleri
- [ ] CI'da tarpaulin job çalışıyor.
- [ ] README'de coverage badge.
- [ ] Coverage ratchet (azalmaya RED).

### Riskler
- Tarpaulin llvm-cov'den farklı coverage hesaplar → ratchet sıfırlama.
- Workspace geniş (budzero) → uzun süre (10+ dk).

---

## : Fuzz Altyapısı — Consensus + Relayer + ZK Target'ları

### Kapsam
cargo-fuzz target'ları: consensus state transition, relayer escrow, ZK verifier
giriş noktaları.

### Mevcut durum
- 7 fuzz target var: `block_deserialize`, `consensus_validate`, `evm_mpt_verify`,
  `evm_rlp_decode`, `fuzz_blockchain_serialize`, `snapshot_deserialize`,
  `transaction_deserialize`.
- **Eksik:** consensus state transition (fork/reorg), relayer escrow lifecycle,
  ZK verifier (ProofEnvelope decode + verify).

### Plan
1. **`fuzz/fuzz_targets/consensus_state_transition.rs`:** rastgele block sequence
   → produce/validate → state root deterministik + reorg güvenli.
2. **`fuzz/fuzz_targets/relayer_escrow.rs`:** rastgele relay message sequence
   → escrow lifecycle (lock→mint→burn→unlock) → fund conservation.
3. **`fuzz/fuzz_targets/zk_verifier.rs`:** rastgele ProofEnvelope bytes →
   STARK verify → RED (invalid proof) veya OK, panic YOK.
4. **Fuzz corpus:** mevcut corpus'lara gerçek proof fixture'ları ekle.
5. **Fuzz Nightly:** 24h target'lar CI'da (fuzz-nightly.yml zaten var).

### Kabul Kriterleri
- [ ] 3 yeni fuzz target derleniyor.
- [ ] `cargo +nightly fuzz run <target> -- -max_total_time=60` → 0 crash.
- [ ] Fuzz Nightly workflow'a yeni target'lar eklendi.

### Riskler
- Consensus state transition fuzz'ı karmaşık (PoW/PoS/BFT farklı logic).
- ZK verifier fuzz'ı STARK backend gerektirir (budzero, yavaş).

---

## : BudL Dil Spesifikasyonu — SPEC.md + Struct/Stdlib Compiler Desteği

### Kapsam
BudZKVM içinde `BudL_SPEC.md` yaz (dil grameri + tipler + opcode'lar),
ardından struct + stdlib desteğini compiler'a (`budzero/bud-compiler/`) ekle.

### Mevcut durum
- `bud-compiler/src/`: lexer.rs, parser.rs, ast.rs, sema.rs, codegen.rs.
- `.bud` örnekleri: `contract`, `fn`, `let`, aritmetik, `emit` event'leri.
- **Eksik:** struct tanımı, stdlib (hash, signature, storage), spec dokümanı.

### Plan
1. **`budzero/docs/BudL_SPEC.md`:** Dil spesifikasyonu:
   - Grammar (BNF): contract, fn, let, if/else, while, emit, struct.
   - Types: u64, u128, bool, Address, Hash32, struct.
   - Opcode mapping: BudZKVM ISA'ya derleme.
   - Gas model: her opcode için gas maliyeti.
   - Stdlib: `hash()`, `verify_sig()`, `block_height()`, `caller()`.
2. **Struct desteği (`bud-compiler/src/parser.rs` + `ast.rs`):**
   ```budl
   struct UserData { owner: Address, amount: u64, nonce: u64 }
   ```
3. **Stdlib (`bud-compiler/src/sema.rs` + `codegen.rs`):**
   - `hash(data: Vec<u8>) -> Hash32` → `Hash` opcode.
   - `verify_sig(msg, sig, pk) -> bool` → host-call.
   - `block_height() -> u64` → `Context` opcode (block_height slot).
   - `caller() -> Address` → `Context` opcode (sender slot).
4. **Test:** struct + stdlib kullanan `.bud` kontrat derle + BudZKVM'de çalıştır.

### Kabul Kriterleri
- [ ] `budzero/docs/BudL_SPEC.md` published.
- [ ] Parser struct tanımı destekliyor.
- [ ] Stdlib fonksiyonları codegen'de opcode'lara mapping.
- [ ] Test: struct + stdlib kullanan kontrat derlenip çalışıyor.

### Riskler
- Struct → memory layout (BudZKVM word-addressable, alignment).
- Stdlib host-call interface (ZKVM ↔ host boundary, gas accounting).

---

## : (Düşük Öncelik) SECURITY.md / Bug Bounty Taslağı

### Kapsam
SECURITY.md'yi bug bounty planı ile güncelle: 4 severity tier, 90 gün embargo,
Discord/Telegram triage süreci.

### Mevcut durum
- SECURITY.md mevcut (140 satır) — genel policy + supported versions.
- `docs/BUG_BOUNTY.md` mevcut — 4 seviye ($50k-$100k / $10k-$25k / $2.5k-$5k /
  $500-$1k), 90 gün embargo, immunefi planı.
- **Eksik:** SECURITY.md BUG_BOUNTY.md'ye link + triage süreci (Discord/Telegram).

### Plan
1. **SECURITY.md güncelleme:**
   - Bug bounty 4 tier tablosu (BUG_BOUNTY.md'den referans).
   - Triage: Discord `#security-reports` + Telegram @budlum_security.
   - 90 gün embargo + coordinated disclosure.
   - Safe harbor (good-faith araştırmacı koruması).
   - Out-of-scope (social engineering, third-party CVE).
2. **README badge:** `[![Security](https://img.shields.io/badge/security-report-blue)]`.

### Kabul Kriterleri
- [ ] SECURITY.md'de bounty tier + triage süreci.
- [ ] BUG_BOUNTY.md ile çapraz-referans.

### Riskler
- Düşük (docs işi, CI risk yok).

---

## : Wallet-Core — BIP39+SLIP-0010, UniFFI+WASM Bindings (Permissionless Relayer)

### Kapsam
Kullanıcı tarafı wallet kütüphanesi: BIP39 mnemonic + SLIP-0010 ed25519
key-derivation + UniFFI (Rust→mobile) + wasm-bindgen (Rust→browser) bindings.
**Relayer permissionless** — wallet, relayer stake+yetkilendirme GEREKTIRMEZ
(CLAUDE.md §2: "Herkes relayer olabilir, stake + slashing ile güvenlik").
Wallet imzalar relayer'a GÖNDERIR; relayer'ın kendisi permissionless.

### Mevcut durum
- BIP39/SLIP-0010/HD-wallet bağımlılık YOK.
- UniFFI/wasm-bindgen bağımlılık YOK.
- Ed25519 imzalama: `crypto/primitives.rs::KeyPair` + `sign()` mevcut.
- Wallet modülü/crate'i YOK.

### Plan
1. **Yeni crate: `wallet-core/`** (workspace dışı bağımsız crate, Core'a
   bağımlı DEĞİL — wallet yalnızca imzalama yapar, zincir state'ini tutmaz).
2. **BIP39 mnemonic:** `bip39` crate (entropy → mnemonic → seed).
3. **SLIP-0010 ed25519 key-derivation:** `slip10` algoritması (BIP32 ed25519
   variant — Ed25519 non-hardened derivation desteklemez, sadece hardened).
   - Path: `m/44'/budlum'/0'/0'/0` (BIP44-style, coin type = TBD).
4. **KeyPair entegrasyon:** wallet-core → `crypto::primitives::KeyPair`
   (ed25519-dalek 2.2.0, mevcut bağımlılık).
5. **Transaction signing:** wallet-core, `Transaction::calculate_hash()` +
   `sign()` → signed tx (V29 V4 canonical signing format).
6. **UniFFI binding:** Rust → Kotlin/Swift (`wallet-core/src/lib.rs` +
   `wallet-core/uniffi.toml`). Mobile app'ler wallet-core'u çağırır.
7. **wasm-bindgen binding:** Rust → JavaScript (`wallet-core/src/wasm.rs`).
   Browser (Metamask-style) wallet'lar.

### Güvenlik Kuralı (Permissionless Relayer)

**CLAUDE.md §2 PoW/PoS/BFT:**
> "Herhangi biri relayer olabilir, stake + slashing ile güvenlik. Sabit/
> whitelist'li relayer seti KODLAMA."

Wallet-core **relayer DEĞILDIR.** Wallet imzalar, kullanıcı gönderir, herhangi
bir relayer (stake ile) taşır. Wallet-core'da:
- ❌ Relayer kayıt/stake/whitelist KODU YOK.
- ❌ "Yetkili relayer" listesi KODU YOK.
- ✅ Signed transaction üretimi (kullanıcı → relayer → chain).
- ✅ Message signing (cross-domain, bridge, governance vote).

### Kabul Kriterleri
- [ ] `wallet-core/` crate derleniyor.
- [ ] BIP39 mnemonic generate/restore + SLIP-0010 ed25519 derivation.
- [ ] Transaction sign (V29 V4 format) → chain'de verify.
- [ ] UniFFI binding (Kotlin/Swift header generate).
- [ ] wasm-bindgen binding (JS bundle).
- [ ] **Permissionless relayer kuralı testi:** wallet-core'da relayer
  stake/whitelist kodu YOK (grep kanıtı).

### Riskler
- SLIP-0010 ed25519 hardened-only: non-hardened derivation Ed25519'da
  güvenli değil (RFC 8032 curve structure) → yalnız hardened path.
- UniFFI + wasm-bindgen aynı crate'te conflict → feature flag'lerle çözüm.
- V29 V4 signing formatı wallet-core'a taşınmalı (transaction.rs'den
  extract, wallet-core bağımsız olmalı).

### Karar Kapıları (Kullanıcıya)
1. **Coin type:** BIP44 `m/44'/<coin_type>'/...` — Budlum için hangi SLIP-44
   coin type numarası? (Öneri: 0x425544 = "BUD" ASCII).
2. **Address scheme:** Budlum Address = Ed25519 pubkey SHA-256 hash (32 byte).
   Wallet-core'dan Address üretimi netleşecek mi? (Mevcut: `Address::from(pubkey)`).
3. **Mnemonic word count:** 12 (128-bit entropy) veya 24 (256-bit)?

---

## Öncelik Matrisi

| Sıra |  | Tip | Risk | Mainnet-engeli? |
|---|---|---|---|---|
| 1 | **Genesis Config** (4 domain + token) | kod | 🟡 genesis hash değişimi | 🔴 EVET (MR-6) |
| 2 | **Fuzz Altyapısı** (3 target) | fuzz | 🟡 karmaşık | 🟡 mainnet-prep |
| 3 | **Coverage** (tarpaulin + badge) | CI | 🟢 düşük | 🟡 MR-5 |
| 4 | **BudL SPEC** + struct/stdlib | docs+kod | 🟡 compiler karmaşıklık | ⚪ mainnet sonrası |
| 5 | **SECURITY.md** (bounty taslak) | docs | 🟢 düşük | 🟡 MR-8 |
| 6 | **Wallet-Core** (BIP39+bindings) | kod | 🟡 SLIP-0010 ed25519 | ⚪ mainnet sonrası |

---

## Koordinasyon ( Yöneticisi)

|  | Domain | Sorumlu |
|---|---|---|
| Genesis Config | `src/chain/genesis.rs` | ARENA2 (chain) + ARENA1 review |
| Coverage | `.github/workflows/` | ARENA3 (CI/fuzz domain) |
| Fuzz | `fuzz/fuzz_targets/` | ARENA3 (fuzz domain) |
| BudL SPEC | `budzero/bud-compiler/` | ARENA3 (ZK/compiler) + kullanıcı review |
| SECURITY.md | `SECURITY.md` + `docs/BUG_BOUNTY.md` | ARENA1 (docs) |
| Wallet-Core | yeni `wallet-core/` crate | ARENA1 (cross_domain/crypto) |

---

*Co-authored-by: ARENA1 <arena1@budlum.ai>*
