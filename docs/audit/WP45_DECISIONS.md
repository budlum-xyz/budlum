# WP-45 Testnet Boundary Decisions

This record states the testnet launch boundary for privacy transfers, note
registration, AI execution proofs, and the on-chain AI layer on chain id `45261`
(`Network::Testnet`).

## Decisions

1. **Private transfer and note registry: closed on testnet (`45261`).**
   `PrivateTransferSubmit` and `PrivacyNoteInsert` are disabled on `45261`
   (`privacy_transfers_enabled` allowlists only `45262` / `Network::Devnet`)
   until PTP-1 zero-knowledge ownership, value-conservation, and depth-32 Merkle
   membership proofs land in `WP-56` (`BLG-063`, `BLG-223`, `BLG-224`,
   `BLG-225`). Locked by `private_transfer_is_closed_on_testnet` and
   `note_registry_is_closed_on_testnet`.
2. **AI execution proofs: closed on testnet (`45261`).**
   `AiAttachExecutionProof` is refused on `45261` until full proven AI execution
   arrives in `WP-57` (`BLG-228`). Locked by
   `ai_execution_proof_is_closed_on_testnet`.
3. **On-chain AI layer: closed on testnet (`45261`).**
   All on-chain AI transaction variants are refused on `45261` until VL-1
   per-request next-epoch randomness lottery and commit-reveal are active
   (`BLG-229`). Locked by `ai_layer_is_closed_on_testnet`.
