# Budlum Storage Architecture (B.U.D. 3.0)

B.U.D. 3.0 is the unified storage architecture of Budlum. Every validator participates in content custody; there is no separate storage-operator or content-validator role.

## Core Principles

1. **Commitment vs. Object:** On-chain state records a 32-byte commitment and metadata, while validators hold encoded custody shares of the object off-chain. The commitment has a fixed 32-byte width; the stored object itself has variable size proportional to its compressed payload.
2. **Content Identity (`ContentId`):** Public content is identified by its SHA-256 digest and byte length. Sealed content is identified by a domain-separated commitment (`BDLM_BUD3_CID_SEALED_V1`) keyed by a content-derived tag and byte length.
3. **Payload Compression (`crates/bud-codec`):** Format-aware lossless codecs, shared dictionary compression, version deltas, and Codec 10 block-aligned image derivations reduce object bytes before segmentation.
4. **Custody and Verification:** Objects are split into segments and encoded into symbols so validators hold custody shares that are auditable and repairable without re-uploading the whole object.
5. **Transaction Boundary:** Every storage state transition enters through a signed `TransactionType::Storage` transaction in a block. Node-local RPCs never mutate chain storage state directly.
