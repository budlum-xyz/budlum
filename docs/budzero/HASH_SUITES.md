# BudZero Commitment Hash Suites & V2 Note Packing (WP-56)

## 1. Registered Hash Suites (`crates/note-packing/src/digest4.rs`)

Every V2 commitment and blinded consent record carries an explicit 1-byte
`HashSuiteId` prefix (`KP-5: commitments_carry_hash_suite`):

| Tag | Variant | Domain / Role |
|---|---|---|
| `0x01` | `PoseidonG12V1` | In-circuit Goldilocks width-12 Poseidon (`Digest4`, 4 canonical limbs) |
| `0x02` | `Sha3_256V1` | Host/chain NIST FIPS 202 SHA3-256 commitments and blinded consent handles |
| `0x03` | `Blake3_256V1` | High-throughput segment and auxiliary manifest commitments |

---

## 2. `Digest4` V2 256-Bit Packing (`KP-2: no_64bit_commitments`)

- V1 privacy notes packed a single Goldilocks element (`64` bits) with 24 zero
  bytes.
- V2 commitments use `Digest4([u64; 4])`: four canonical Goldilocks field limbs
  (`limb < 0xFFFF_FFFF_0000_0001`), serialized in little-endian order into 32
  bytes (`SuiteTaggedCommitment` = `33` bytes with leading suite byte).
- `SuiteTaggedCommitment::from_poseidon_digest4` and `decode` reject single-limb
  64-bit truncated digests (`limbs[0] != 0 && limbs[1..4] == [0, 0, 0]`) as well
  as any non-canonical limb `>= GOLDILOCKS_P`.

---

## 3. Padme Buckets, Blinded Consent, & Shamir Escrow (`crates/wallet-core/src/consent_screen.rs`)

- **Padme Length Hiding (`TSO12`):** `padme_bucket_len` rounds every sealed object
  and key envelope length to an idempotent `O(log log L)` Padme bucket.
- **Blinded Consent (`TSO8`, `TSO9`, `TSO11`):** `ConsentScreenPrompt` displays
  human-readable scope locally while `seal_for_chain` emits only length-prefixed,
  salted `SHA3-256` commitments (`grant_commitment`, `revocation_handle`),
  omitting `issuer`, `grantee`, and `content_id` from chain state. Public
  publication requires `yk6_verified == true`.
- **Shamir `t-of-n` Key Escrow (`TK7`, `TSO10`):** `shamir_split_32` and
  `shamir_reconstruct_32` evaluate and interpolate polynomials over `GF(2^8)`
  (`0x11B`), guaranteeing zero key recovery below `t` shares and exact 32-byte
  recovery from any `t` distinct shares.
