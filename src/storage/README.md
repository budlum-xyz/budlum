# Storage (`src/storage`)

B.U.D. 3.0 is the single content-storage architecture of Budlum.

## Current Module Surface

- `bud3/content_id.rs`: `ContentId` — 32-byte digest plus optional byte length (`public` SHA-256 for public content; `sealed` length-prefixed `BDLM_BUD3_CID_SEALED_V1` commitment for encrypted content).
- `bud3/content_ref.rs`: `ContentRef`, `StorageError`, and `register_content`. Direct registration has no content registration door outside a signed block transaction and returns `StorageError::Bud3NotReady` until the object lifecycle lands.
- `bud3/tx.rs`: `StorageTx` — signed storage transaction carrier bound under `BUD3_TX_V1`.

Node-local chain persistence, the account proof trie, and block/witness pruning policies live in `src/persistence/`.
Compression and format codecs live in `crates/bud-codec/`.
