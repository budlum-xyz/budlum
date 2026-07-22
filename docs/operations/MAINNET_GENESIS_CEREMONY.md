# Mainnet Genesis Ceremony Procedure (Canonical)

**Status:** procedure only — does **not** claim a ceremony has occurred.
**Audience:** release managers, multi-sig holders, node operators.
**Related:** `docs/operations/PRODUCTION_RUNBOOK.md` §8, `config/mainnet-genesis.json`,
plan katmanı: `docs/TASK7_CEREMONY_PLAN.md` (7.1–7.5 görevleri, timeline).

> **2026-07-16 konsolidasyonu (Task 8.9, kullanıcı kararı Q2):** Bu dosya tek
> kanonik ceremony prosedürüdür. `docs/MAINNET_GENESIS_CEREMONY.md`'deki
> (ARENA5, TR) benzersiz içerik — validator key tabloları, treasury havuzları,
> genesis JSON şablonu, ilk-blok kontrolleri, imza tablosu — buraya taşındı;
> o dosya artık TR özet + yönlendirmedir. Bayat bilgi sadece bu dosyada düzeltilir.

---

## 0. Why this exists

`mainnet_genesis()` and `config/mainnet-genesis.json` currently use
**deterministic placeholder addresses** (repeated-byte vectors such as
`0x10…10`, `0x20…20`). Those values are for CI and offline hash checks only.
A real-value Mainnet launch requires a multi-party ceremony that replaces
placeholders, freezes the genesis hash, and publishes seed nodes.

Until the ceremony completes, operators must treat mainnet profile as
**pre-production**.

---

## 1. Roles

| Role | Responsibility |
|------|----------------|
| Ceremony lead | Agenda, room/call, artifact checklist |
| Key holders (N-of-M) | Generate / custody treasury + validator material offline |
| Independent builders (≥2) | Rebuild genesis JSON from the same inputs; compare hashes |
| Witness / notary | Sign the ceremony minutes (git commit + hash list) |
| Operators | Publish bootnode multiaddrs only after hash freeze |

TR katılımcı tanımı (konsolide edilen belgeden): Kullanıcı (key holder /
ceremony master), doğrulama ekibi, validator operatörleri (N-of-M).
Güvenlik kuralları: **air-gap** üretim, **HSM** (BLS/PQ HSM dışına çıkmaz),
tercihan ≥2 bağımsız gözlemci.

---

## 2. Inputs (prepared offline)

1. Final `chain_id` (must remain `1` unless hard-fork planned).
2. Allocation list: `(address, amount)` for treasury / community / liquidity / ecosystem / team (or explicit decision to keep `bud_tokenomics`).
3. Validator set: addresses + BLS PoP + PQ material **via PKCS#11 only** (disk BLS/PQ banned on mainnet).
4. `block_reward`, `base_fee`, `gas_schedule`, `timestamp` (unix ms).
5. Empty or final `bootnodes` / `dns_seeds` lists for `config/mainnet.toml`.

No private keys on networked machines during generation if policy requires air-gap.

### 2.1 Validator key generation (tooling, evidence-backed)

Ed25519 validator anahtarları binary'deki `keygen` alt komutuyla üretilir
(Task 8.9 / Görev 7.1 tooling — bu komut 2026-07-16'da eklendi; öncesinde
dokümanda olup binary'de OLMAYAN bir adımdı):

```bash
# Air-gap makinede, her validator için:
budlum-core keygen --type ed25519 --output validator_N_ed25519.key
# Secret key: 0600 izinle yazılır, stdout'a ASLA basılmaz.
# Public key:  validator_N_ed25519.key.pub (hex) + adres stdout'ta gösterilir.
```

`--type bls|pq` disk üretimi **reddedilir** (exit 1) — BLS/PQ yalnızca HSM
içinde üretilir; bkz. `docs/operations/HSM_VENDOR_NATIVE_GUIDE.md`.
HSM donanımı yoksa BLS/PQ anahtarları üretilmez: mainnet PoA/Ed25519-only
başlar, BLS/PQ post-launch eklenir (M6 bilinçli borcu, §5.1).

| Validator | Ed25519 Pubkey (keygen .pub) | Coğrafi Bölge | BLS Pubkey (HSM) | PQ Pubkey (HSM) | HSM Slot |
|-----------|------------------------------|---------------|------------------|-----------------|----------|
| V1 | `___DOLDUR___` | EU | `___DOLDUR___` | `___DOLDUR___` | `___DOLDUR___` |
| V2 | `___DOLDUR___` | US-East | `___DOLDUR___` | `___DOLDUR___` | `___DOLDUR___` |
| V3 | `___DOLDUR___` | US-West | `___DOLDUR___` | `___DOLDUR___` | `___DOLDUR___` |
| V4 | `___DOLDUR___` | AS-Southeast | `___DOLDUR___` | `___DOLDUR___` | `___DOLDUR___` |

Önkoşul kontrol listesi (tören sabahı): `cargo test --lib`, `cargo clippy -- -D warnings`,
`cargo fmt --check` — hepsi yeşil; M5 raporu ve Task 7 planı okunmuş;
HSM donanım kararı (veya Ed25519-only) verilmiş.

---

## 3. Steps

### 3.1 Draft JSON offline

```bash
# On an air-gapped builder with this exact git commit checked out:
cargo run --release -- genesis build \
  --chain-id 1 \
  --block-reward 25 \
  --base-fee 10 \
  --validators <addr1,addr2,...> \
  --allocations <addr:amount,...> \
  --output ./config/mainnet-genesis.json
```

Or hand-author JSON matching `GenesisConfig` serde layout (see existing
placeholder file). Independent builders must not copy each other's output
files — they recompute from the same public inputs.

Treasury havuzları (konsolide edilen TR belgeden; toplam arz 100 trilyon BUD):

| Havuz | Adres | Miktar (BUD) | Vesting |
|-------|-------|-------------|---------|
| Community | `___DOLDUR___` | 10,000,000,000,000 | Yok |
| Liquidity | `___DOLDUR___` | 10,000,000,000,000 | Yok |
| Ecosystem | `___DOLDUR___` | 20,000,000,000,000 | Yok |
| Team | `___DOLDUR___` | 20,000,000,000,000 | Cliff: 52560 epoch (~1 yıl), Vesting: 210240 epoch (~4 yıl) |
| Burn Reserve | `___DOLDUR___` | 40,000,000,000,000 | Yok (sabit yakım) |

Elle yazım durumunda tam JSON şablonu TR özet belgede
(`docs/MAINNET_GENESIS_CEREMONY.md` §A) korunur; tek gerçek kaynak
`GenesisConfig` serde düzenidir.

### 3.2 Hash freeze

```bash
cargo run --example print_genesis_hash
cargo test --lib chain::genesis::tests::test_mainnet_genesis_json_matches_code
sha256sum config/mainnet-genesis.json
```

Record:

- Genesis block hash
- `state_root`
- `validator_set_hash`
- Git commit SHA of the release tag
- SHA-256 of `config/mainnet-genesis.json`

All independent builders must match bit-for-bit on the three roots/hashes.

**⚠️ Bu hash bir kez yazıldıktan sonra DEĞİŞTİRİLEMEZ** — değişiklik farklı
bir zincir demektir ve tüm allocation'ları geçersiz kılar. Freeze sonrası
`docs/operations/PRODUCTION_RUNBOOK.md` §8.2 tablosuna ve `mainnet.toml`
yorum satırına işlenir. Genesis testlerindeki `validators.is_empty()`
asser'ları (placeholder durumu kodlayan) bu adımda güncellenir — bkz.
**`docs/operations/GENESIS_FLIP_CHECKLIST.md`** (Task 7.4, F1–F5 maddeleri).

### 3.3 Update code constructors (if needed)

If the ceremony abandons the placeholder `mainnet_genesis()` vectors, update:

- `src/chain/genesis.rs` → `mainnet_genesis()`
- `config/mainnet-genesis.json`
- `docs/operations/PRODUCTION_RUNBOOK.md` §8.2 table

Run full CI. Tag release only after green.

### 3.4 Seed / bootnode publication

1. Each sentry/validator publishes a multiaddr (`/ip4/.../tcp/4001/p2p/...`).
2. Ceremony lead fills `p2p.bootnodes` and optional `dns_seeds` in the release
   `mainnet.toml` (or a signed overlay config — never invent peers in docs).
3. Operators verify multiaddrs against the signed minutes before peering.

### 3.5 Minutes template

```
Ceremony date (UTC):
Git tag / commit:
Participants (role + identity):
Genesis block hash:
state_root:
validator_set_hash:
mainnet-genesis.json SHA-256:
Bootnodes (multiaddr list):
Deviations / incidents:
Signatures (N-of-M):
```

| Rol | İsim | İmza | Tarih |
|-----|------|------|-------|
| Ceremony Master / lead | `___DOLDUR___` | `___DOLDUR___` | `___DOLDUR___` |
| Validator V1–V4 Operatörleri | `___DOLDUR___` | `___DOLDUR___` | `___DOLDUR___` |
| Doğrulama (witness) | `___DOLDUR___` | `commit SHA` | `___DOLDUR___` |

Attach minutes as a signed artifact (git-signed tag message or detached
signatures). Do not store private keys in the repository.

### 3.6 First block (T-0) checks

1. Tüm validator node'ları başlatılır: `budlum-core --config config/mainnet.toml --network mainnet`
2. İlk prevote/precommit quorum'u gözlenir; FinalityCert üretilir.
3. İlk blok: `bud_blockNumber` → 1, `bud_finalizedHeight` → 1,
   Prometheus `budlum_blocks_produced_total` → 1.
4. Sağlık: `curl -X POST http://localhost:8545 -d '{"jsonrpc":"2.0","method":"bud_health","params":[],"id":1}'`
   (`bud_health` metodu `src/rpc/api.rs`'de mevcuttur.)

---

## 4. Fail-closed checks already in the binary

- Missing `genesis_file` path → process exit 1.
- Genesis `chain_id` ≠ configured chain id → exit 1.
- DB genesis hash ≠ expected hash on restart → exit 1.
- Mainnet disk BLS/PQ keys → rejected (PKCS#11 required).
- Placeholder path strings containing `devnet`/`testnet`/`placeholder` on
  mainnet → CLI security failure.
- **(Task 8.9 / Q5, 2026-07-16):** Dummy/placeholder marker içeren bootnode
  veya DNS seed (`dummy`, `placeholder`, `203.0.113.`, `.example`) mainnet'te
  dial edilmez → CRITICAL exit 1 (`first_placeholder_peer`,
  `src/core/chain_config.rs`; bağlama noktası `src/main.rs`). Bu guard §3.4
  tamamlanmadan mainnet başlatılamayacağını garanti eder.

---

## 5. Explicit non-goals

- This document does **not** generate production keys.
- This document does **not** mark Mainnet as audited.
- VerifyMerkle / B.U.D. Görev 3 remains Task 4; interim retrieval is documented in
  `docs/BUD_INTERIM.md`.

### 5.1 Documented post-launch debts (bilinçli borçlar)

| # | Borç | Aktivasyon Koşulu |
|---|------|-------------------|
| M5 | VerifyMerkle Z-B gate | 64-depth STARK yeşil → soft-fork PR |
| M6 | HSM vendor-native BLS/PQ | Donanım temin → config aktivasyonu |
| M7 | External audit | Bug bounty launch → firma seçimi |
| M10 | SocialFi/Hub/Marketplace | Küçük PR'larla post-launch |

---

## 6. Seed multiaddr template (fill at ceremony)

Copy into `config/mainnet.toml` only after N-of-M signatures:

```toml
[p2p]
bootnodes = [
  # "/ip4/<A.B.C.D>/tcp/4001/p2p/<PeerId>",
  # "/ip6/<addr>/tcp/4001/p2p/<PeerId>",
]
dns_seeds = [
  # "_dnsaddr.mainnet.seed.example.org",
]
```

Also update `src/core/chain_config.rs` `MAINNET_BOOTNODES` / `MAINNET_DNS_SEEDS`
if the binary built-in list is used without a TOML overlay.

| Slot | Operator | multiaddr | PeerId | Signer |
|------|----------|-----------|--------|--------|
| 1 | | | | |
| 2 | | | | |
| 3 | | | | |

After freeze, recompute genesis hash only if genesis JSON changed; seed-only
updates do **not** change the genesis block hash.


---

## 8. Task 9 Ceremony Readiness (ARENA3, 2026-07-16)

**Status:** `template_ready` — ceremony template prepared, awaiting operator keys.

### Completed:
- ✅ `config/mainnet-genesis.json`: 5 allocations (Treasury, Community, Ecosystem, Team, Burn) + 4 validators
- ✅ `config/mainnet.toml`: ceremony-ready bootstrap peers + DNS seeds
- ✅ `src/core/chain_config.rs`: MAINNET_BOOTNODES + MAINNET_DNS_SEEDS synchronized
- ✅ `ceremony_status = "template_ready"` in both genesis JSON and mainnet.toml
- ✅ VerifyMerkle production gate OPEN (real Proof-of-Storage active)
- ✅ B.U.D. Görev 3: merkle_proof mandatory for all deals

### Operator Checklist (during ceremony):
1. **Generate keypairs** (air-gapped, via PKCS#11 HSM):
   - Ed25519 consensus key
   - BLS12-381 finality key
   - Dilithium5 PQ backup key
2. **Replace validator addresses** in `config/mainnet-genesis.json` with generated pubkeys
3. **Replace bootstrap Peer IDs** in `config/mainnet.toml` and `src/core/chain_config.rs`
4. **Publish DNS TXT records** for `_dnsaddr.bootstrap-N.mainnet.budlum.network`
5. **N-of-M multi-sig**: at least 3 of 5 key holders sign the genesis hash
6. **Flip ceremony_status**: `template_ready` → `frozen` after all signatures collected
7. **Publish genesis hash** in `docs/operations/PRODUCTION_RUNBOOK.md` §8

### Remaining (post-ceremony):
- 🟡 HSM vendor-native BLS/PQ mechanism (hardware-dependent)
- 🟡 External security audit (Task 5)
- 🟡 Mainnet launch announcement

---

## 9. Task 10.5 Augmentation — MPC key-gen, rotation, destruction, timeline (F27)

> **Kaynak:** Task 10.5 çapraz-kesit eksiklik analizi (`docs/TASK10.5_CROSS_CUTTING_GAP_ANALYSIS.md` F27, 🔴 mainnet-blocker).
> **Yazar:** ARENA1 (görev yöneticisi), 2026-07-18.
> Bu bölüm, yukarıdaki §1–§8 prosedürünü **değiştirmez**; onun **eksik
> kalan boyutlarını** (MPC, rotation, destruction, timeline) ekler. MR-6
> (Mainnet Readiness criterion 6: genesis ceremony) kapanışı için gereklidir.

### 9.1 Neden augmentation

§2.1 Ed25519 `keygen` tek-party (her validator kendi makinesinde). Bu consensus
imzaları için yeterli (her validator bağımsız imzalar). Ama **treasury/team
multi-sig** ve **HSM-içi BLS/PQ key-custody** için **N-of-M threshold** modeli
gerekir — tek bir key holder'ın compromize olması treasury drain'e yol açar.
Ayrıca §5'te "ceremony sonrası key rotation" prosedürü YOK: bir validator key'i
sızarsa zincir nasıl rotate eder? Bu bölüm her iki boşluğu kapatır.

### 9.2 Threshold key generation (MPC / DKG) — treasury + HSM BLS/PQ

**Amaç:** Hiçbir single party tüm özel anahtarı görmesin; N-of-M threshold imza.

**Model:** Distributed Key Generation (DKG, Pedersen verisini her party broadcast
eder; hiçbir party full sk'yi öğrenmez). Threshold = `t` of `n` (örn. 3-of-5).

| Anahtar sınıfı | Threshold modeli | Tooling | Not |
|---|---|---|---|
| Treasury/team multi-sig (Ed25519) | FROST-style threshold Ed25519 (t-of-n) | ceremony-time: external audited FROST impl (örn. `frost-core` reference) | §3.1 allocation'daki treasury adresleri threshold pubkey'ine bağlı |
| BLS12-381 finality (PoS/BFT) | DKG inside HSM (vendor-native; M6 debt) | HSM vendor SDK | Henüz HSM yoksa: Ed25519-only başlar, BLS/PQ post-launch (M6) |
| PQ Dilithium5 backup | HSM-içi DKG | HSM vendor SDK | M6'ya bağlı |

**Ceremony akışı (DKG round):**
1. Her party `i` air-gap makinede `(polynomial_share_i, commit_i)` üretir.
2. `commit_i`'ler witness'a notarize edilir (§9.4 destruction evidence ile).
3. Party'ler private channel (ceremony room / mTLS) üzerinden share'lerini exchange eder.
4. Aggregate → threshold pubkey `PK_t` + per-party private share `sk_i`.
5. **Hiçbir party `PK_t`'nin karşılığı olan full sk'yi öğrenmez.**
6. `PK_t` → treasury/team adresi olarak §3.1 allocation'a yazılır.

**Kabul:** Budlum konsensüsü **tek-party validator Ed25519** ile başlayabilir
(M6'ya kadar BLS/PQ yok). Threshold treasury multi-sig **best-effort**: HSM
yoksa ceremony, treasury'i tek-party controlled address ile dondurur ve
bu **bilinçli borç (M6-treasury-threshold)** olarak §5.1'e eklenir.

### 9.3 Emergency key rotation (key-compromise prosedürü)

**Tetikleyiciler:** (a) validator key sızması (kanıt veya şüphe), (b) HSM
hardware failure, (c) ceremony participant offboarding, (d) slashing sonrası
key deprecation.

**Akış (post-launch):**

| Adım | Aksiyon | Sorumlu | SLA |
|---|---|---|---|
| 1 | Compromise şüphesi → incident raporu (`security@budlum.network`) | reporter | T+0 |
| 2 | Triage: kanıt değerlendirme, severity (Critical/High) | security lead | T+24h |
| 3 | **Slashing:** compromize validator'ın equivocation/liveness kanıtı → on-chain slash (CLAUDE.md slashing akışı) | consensus | T+72h |
| 4 | **Key rotation:** yeni validator key üretimi (air-gap), PoP güncellemesi | operator | T+7d |
| 5 | **Validator set update:** governance proposal (`ProposalType::ParameterUpdate` veya slashing-ledger rotate) | governance | T+14d |
| 6 | **Old key deprecation:** eski pubkey blacklist (consensus reject) | consensus | T+30d |
| 7 | **Post-mortem:** incident raporu + timeline + witness imza | ceremony lead | T+45d |

**Mainnet öncesi (ceremony'de) compromise:** key yeniden üretilir, ceremony
restart (T-0'dan önce → genesis JSON rebuild + hash re-freeze). Ceremony
minutes'ta (§3.5) "deviation/incident" alanına yazılır.

**Threshold treasury (§9.2) compromise:** t-of-n threshold → `t`'den az party
compromize olursa treasury güvenli. `t+1` party compromize → acil key-rotate
(yeni DKG round, eski threshold deprecate).

### 9.4 Key destruction evidence (üretim materyalinin imhası)

**Kural:** ceremony'de kullanılan tüm **ephemeral üretim materyali** (DKG
polynomial'ları, intermediate share'ler, RNG seed'leri, `keygen` CLI çıktı
logları) ceremony bitiminde **yok edilir** ve imha **witness tarafından
notarize edilir**.

**Imha checklist (§3.5 minutes'e ek):**

```
Destruction evidence:
- [ ] DKG polynomial'lar (her party): shred + 7-pass overwrite
- [ ] RNG seed material: HSM-içi purge (vendor komutu)
- [ ] keygen CLI intermediate files: rm + disk wipe
- [ ] Air-gap makine RAM: power-cycle (cold boot residue)
- [ ] Ceremony call recording (varsa): encrypted archive + access log
- [ ] Printed materials (private key printouts YASAK, varsa): shredder
Witness destruction signature: ___DOLDUR___ (commit SHA + date)
```

**Kalıcı materyal (imha EDİLMEZ):** final validator pubkey'leri, threshold
treasury pubkey'i, genesis JSON — bunlar public artifacts (git commit).

### 9.5 Ceremony timeline (T-7d → T+1d)

| Görev | Zaman | Aktivite | Çıktı |
|---|---|---|---|
| **T-7d** | 1 hafta önce | Participant onboarding, HSM envanter kontrol, air-gap makine setup, dry-run (testnet genesis) | dry-run hash (testnet), participant list locked |
| **T-3d** | 3 gün önce | Ceremony materials dağıtımı (sealed envelopes / HSM provisioning), witness brief | sealed-material receipt log |
| **T-1d** | 1 gün önce | Final CI green confirmation (`MR-1` 3 consecutive green pushes), git tag candidate | release tag SHA |
| **T-0 ceremony** | tören günü | §2.1 Ed25519 keygen + §9.2 DKG (treasury/BLS) + §3.1 genesis JSON build + §3.2 hash freeze + §3.5 minutes + §9.4 destruction | signed genesis JSON + minutes + destruction evidence |
| **T+1d** | ertesi gün | §3.4 bootnode publication + §3.6 first-block T-0 checks + PRODUCTION_RUNBOOK §8 update + immunefi launch (§BUG_BOUNTY M7) | public genesis hash + live mainnet |

### 9.6 MR-6 kapanış kriterleri (F27)

MR-6 (genesis readiness) kapanması için bu bölümün tüm maddeleri **doldurulmuş**
olmalı:

- [ ] §9.2 threshold model kararı (HSM varsa DKG / yoksa Ed25519-only + M6-treasury-threshold borcu)
- [ ] §9.3 emergency rotation akışı reviewer onayı (security + governance)
- [ ] §9.4 destruction checklist ceremony-day doldurulmuş (___DOLDUR___ alanları)
- [ ] §9.5 timeline T-0 gerçekeşmiş + minutes imzalı
- [ ] GENESIS_FLIP_CHECKLIST F1-F5 ✅ (§3.2 referans)

**Bu doküman hâlâ "procedure only"dir** — ceremony gerçekleşene kadar MR-6 🟡
(template ready) kalır. F27 🔴 → MR-6 kapanışıyla 🟢 → ✅.

---

*Co-authored-by: ARENA1 <arena1@budlum.ai> (F27 augmentation, Task 10.5)*
