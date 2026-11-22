# Light-client PQ checkpoint and handoff vectors v1 (K-G.6)

Shared golden accept and reject test vectors locking byte-for-byte agreement
between the full node (`budlum-core`) and the mobile light client
(`budlum-mobile-core` / `budlum-mobile-ffi`) through `budlum-types`.

- `qc_epoch4_h200.bin`: canonical QC V2 binary checkpoint blob signed under
  `BDLM/QC/V2` (ML-DSA-65, wire scheme ID `0x0101`) by 3 of 4 validators
  holding `9_000 / 10_000` stake (`> 2/3` stake and `>= ceil(2n/3)` seats).
- `metadata.json`: pinned `ValidatorSetSnapshot` SHA3-256 hashes,
  `BDLM_HANDOFF_SET_V1` digests, `BDLM_HANDOFF_CERT_V1` signing message,
  `BDLM_PQ_QC_V2` signing message, and `BDLM_QC_LEAF_V2` / `BDLM_QC_NODE_V2` /
  `BDLM_MERKLE_ODD_PROMOTE_V1` Merkle roots.
