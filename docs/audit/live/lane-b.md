# Storage and privacy live audit (WP-02, partial)

This is a partial audit of commit `20140e87061efc9d8d4076e04305c1318705e348`,
not a completion record for WP-02. The remaining findings, storage inventory,
reproduction tests and CI evidence still need to be supplied.

| Finding | Live observation | Evidence | Closing package | Severity |
|---|---|---|---|---|
| BLG-063 | The testnet privacy boundary is open. The rest of this finding has not been revalidated. | `src/execution/executor.rs`: `privacy_transfers_enabled` explicitly allows `Network::Testnet`; both `PrivacyNoteInsert` and `PrivateTransferSubmit` call it. `privacy_transfers_stay_off_for_an_unclaimed_chain_id` currently asserts that testnet is enabled. | WP-45 | Critical |

The execution allowlist and the admission and precheck boundaries also differ:
`AccountState::validate_transaction_with_context` rejects these transaction
kinds only for mainnet, and `Blockchain::tx_precheck` does the same for the
node's chain ID. Thus an unknown chain ID can pass those individual checks even
though execution refuses it. The checks must be reconciled when the testnet
boundary is closed; precheck must not promise acceptance where execution refuses.

No red reproduction output or CI run is available for this audit. The existing
assertion is source evidence, not a substitute for the required reproduction.
No finding is marked closed here.
