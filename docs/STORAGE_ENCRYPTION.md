# B.U.D. 3.0 Storage Encryption and Sealed Objects

`B.U.D. 3.0` supports both public content-addressed objects and encrypted **sealed
objects** (`src/storage/bud3/seal.rs`, `src/storage/bud3/grants.rs`,
`src/storage/bud3/keys.rs`).

## Cryptographic Construction

1. **Length hiding (`Padme`)**: plaintext object lengths are padded into deterministic
   `Padme` size buckets before segmentation so symbol counts leak bounded bits of size
   information (`src/storage/bud3/seal.rs`).
2. **Per-segment AEAD**: each segment is encrypted under a domain-separated symmetric
   key derived from the object master secret; commitments bind both ciphertext symbols
   (`BOF-1` / RFC 6330 RaptorQ) and the plaintext root.
3. **Hybrid post-quantum key encapsulation (`X-Wing`)**: access grants wrap per-object
   keys to recipient public keys using hybrid `ML-KEM-768 + X25519` (`X-Wing`,
   `src/storage/bud3/grants.rs`).
4. **Blinded consent and Shamir escrow (post-launch staged)**: blinded consent screens
   (`crates/wallet-core/src/consent_screen.rs`) and `YK1..YK11` sealed predicates
   (`src/storage/bud3/predicates.rs`) remain height-gated closed on public testnet `45261`
   until external cryptographic review completes. See also
   [`docs/BUD_CONTENT_ENCRYPTION.md`](BUD_CONTENT_ENCRYPTION.md).
