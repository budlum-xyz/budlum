# Ethereum sync-committee mainnet vectors

Real mainnet light-client data, encoded as the consensus specifications define
them, for the evidence-format-v4 verifier tests in
`src/tests/ethereum_real_finality.rs`.

| File | Bytes | What it is |
|---|---|---|
| `deneb-p1300-finality-update.ssz` | 2054 | `LightClientFinalityUpdate` (Deneb, 6-sibling finality branch), attested slot 10649980, signature slot 10649981, 511/512 signers |
| `deneb-p1300-committee.ssz` | 24624 | `SyncCommittee` for period 1300 (512 pubkeys + aggregate) |
| `electra-p1500-finality-update.ssz` | 2098 | Electra (7-sibling branch), attested 12288083, signature 12288084, 509/512 |
| `electra-p1500-committee.ssz` | 24624 | Period 1500 committee |
| `fulu-p1915-finality-update.ssz` | 2078 | Fulu, attested 15692773, signature 15692774, 512/512 |
| `fulu-p1915-finality-update-508.ssz` | 2084 | Fulu, attested 15692774, signature 15692775, 508/512 |
| `fulu-p1915-committee.ssz` | 24624 | Period 1915 committee |

Sources: a Lodestar beacon node's native SSZ responses, cross-checked against a
second independent provider's JSON re-encoded byte-for-byte. Committee SSZ
`hash_tree_root`s: period 1300 `ceaf0d8b..ef32d`, period 1500
`15e7917a..97e5444`, period 1915 `e74fea87..ffa659`. Genesis validators root
(mainnet) `4b363db9..1bfe95`. Fork versions: Deneb `0x04000000` (epoch 269568),
Electra `0x05000000` (epoch 364032), Fulu `0x06000000` (epoch 411392).

Each update's aggregate signature verifies against its committee with the real
`compute_signing_root` under an independent reimplementation of the consensus
rules; the Rust tests here are known-answer tests against that measurement.
