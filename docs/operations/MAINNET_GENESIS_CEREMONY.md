# Mainnet Genesis Ceremony Procedure (ADIM3)

**Status:** procedure only — does **not** claim a ceremony has occurred.  
**Audience:** release managers, multi-sig holders, node operators.  
**Related:** `docs/operations/PRODUCTION_RUNBOOK.md` §8, `config/mainnet-genesis.json`.

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

---

## 2. Inputs (prepared offline)

1. Final `chain_id` (must remain `1` unless hard-fork planned).
2. Allocation list: `(address, amount)` for treasury / community / liquidity / ecosystem / team (or explicit decision to keep `bud_tokenomics`).
3. Validator set: addresses + BLS PoP + PQ material **via PKCS#11 only** (disk BLS/PQ banned on mainnet).
4. `block_reward`, `base_fee`, `gas_schedule`, `timestamp` (unix ms).
5. Empty or final `bootnodes` / `dns_seeds` lists for `config/mainnet.toml`.

No private keys on networked machines during generation if policy requires air-gap.

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

### 3.2 Hash freeze

```bash
cargo run --example print_genesis_hash
cargo test --lib chain::genesis::tests::test_mainnet_genesis_json_matches_code
```

Record:

- Genesis block hash
- `state_root`
- `validator_set_hash`
- Git commit SHA of the release tag
- SHA-256 of `config/mainnet-genesis.json`

All independent builders must match bit-for-bit on the three roots/hashes.

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

Attach minutes as a signed artifact (git-signed tag message or detached
signatures). Do not store private keys in the repository.

---

## 4. Fail-closed checks already in the binary

- Missing `genesis_file` path → process exit 1.
- Genesis `chain_id` ≠ configured chain id → exit 1.
- DB genesis hash ≠ expected hash on restart → exit 1.
- Mainnet disk BLS/PQ keys → rejected (PKCS#11 required).
- Placeholder path strings containing `devnet`/`testnet`/`placeholder` on
  mainnet → CLI security failure.

---

## 5. Explicit non-goals

- This document does **not** generate production keys.
- This document does **not** mark Mainnet as audited.
- VerifyMerkle / B.U.D. Faz 3 remains ADIM4; interim retrieval is documented in
  `docs/BUD_INTERIM.md`.


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
