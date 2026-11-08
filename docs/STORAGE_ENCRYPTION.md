# B.U.D. 3.0 Content Encryption, Unlinkable Grants, and Cryptographic Shredding

This document specifies the B.U.D. 3.0 sealed-object encryption pipeline
(`src/storage/bud3/seal.rs`), post-quantum hybrid key packages (`src/storage/bud3/keys.rs`),
unlinkable view grants (`src/storage/bud3/grants.rs`), and cryptographic erasure
(`src/storage/bud3/delete.rs`).

## 1. Order of Operations and Padme Length Bucketing

1. Plaintext is compressed with the A0 lossless pipeline **before** encryption so
   compression ratios do not leak after sealing and remain effective.
2. Compressed bytes are prefixed with the exact 8-byte little-endian uncompressed/A0
   length and padded to the deterministic Padme bucket length (`padme_padded_len`),
   capping length side-channel leakage to `O(log log L)` bits.
3. The BOF-1 header sets `flags |= FLAG_SEALED` (`bit0`) and writes `content_len = 0`
   on chain and on wire so the true plaintext size never appears in public metadata.

## 2. Keyed Content Identifier and AEAD Binding

- Public content identifier:
  `ContentId = SHA-256("BDLM_BUD3_OBJECT_V1" || u64_le(len) || plaintext)`.
- Sealed content identifier:
  `ContentId = SHA-256("BDLM_BUD3_CID_SEALED_V1" || object_key || u64_le(len) || plaintext)`.
- Per-object key derivation:
  `object_key = HKDF-SHA256(owner_master_key, object_nonce, "BDLM_BUD3_OBJ_KEY_V1")`.
- Payload encryption uses `XChaCha20-Poly1305` with AEAD additional authenticated
  data bound to `("BDLM_BUD3_SEAL_AAD_V1" || sealed_content_id || bof1_flags)`.
  Flipping the sealed flag or substituting another `ContentId` fails authentication.

## 3. X-Wing (`0x647a`) Hybrid Key Packages and Unlinkable Grants

- Every `ObjectKeyPackage { object_key, content_id }` shared with a reader is
  encapsulated to the recipient's hybrid post-quantum `X-Wing` (`ML-KEM-768 + X25519`,
  IANA KEM `0x647a`) public key (`seal_key_package_xwing` / `open_key_package_xwing`).
- On-chain `GrantRow` records (`IssueViewGrant` / `RevokeViewGrant`) store **only**:
  - `grant_tag = SHA-256("BDLM_BUD3_GRANT_V1" || nft_id || grant_nonce)`,
  - `one_time_public_key` (`ML-DSA-65` public key derived solely for this grant),
  - `sealed_key_package` (X-Wing capsule),
  - `expires_at_height` (strictly greater than `current_height`).
- Neither `content_id`, `issuer`, nor `grantee` appears in `GrantRow`.

## 4. Revocation and Cryptographic Erasure (`SocialDelete`)

- Revoking an individual grant (`RevokeViewGrant`) verifies an `ML-DSA-65` signature
  under `one_time_public_key` over `("BDLM_BUD3_GRANT_REVOKE_V1" || grant_tag)` and
  immediately removes the `GrantRow` from state so no node serves its capsule.
- Burning or socially deleting a sealed NFT (`SocialDelete`) atomically verifies and
  shreds every listed active `GrantRow`, decrements the object reference count, and
  records a permanent tombstone once zero references remain.
