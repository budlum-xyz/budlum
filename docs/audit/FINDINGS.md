# Findings Ledger (İP-04)
## English Equivalent of Section 14
## Format: ID | Importance | Area | English Title | Live Status | Test Name | Closing Package | Importance Suggestion

| ID | Importance | Area | English Title | Live Status | Test Name | Closing Package | Importance Suggestion |
|----|------------|------|---------------|-------------|-----------|-----------------|-----------------------|
| BLG-001 | Critical | consensus | PoS leader selection skips empty height and locks production | Verified (Red test output) | audit_repro_a_blg_001 | İP-12 | Critical |
| BLG-002 | High | tokenomics | Distributed testnet profile ceremony, peer source and tokenomics not ready for opening | Open | audit_repro_a_blg_002 | İP-16 | High |
| BLG-003 | High | tokenomics | Genesis supply verification does not check total 100M limit with additional allocations and bootstrap stake | Verified (Red test output) | audit_repro_a_blg_003 | İP-16 | High |
| BLG-004 | Medium | cryptography | Rewriting key file does not narrow existing wide permissions | Verified (Red test output) | audit_repro_a_blg_004 | İP-61 | Medium |
| BLG-005 | Medium | build/CI | Default secret/data directories are not excluded by Git | Pre-corrected (Green) | audit_lane_a_blg_005 | İP-16 | Medium |
| BLG-006 | Medium | tokenomics | Validation reward pool epoch dependency | Pre-corrected (Green) | audit_lane_a_blg_006 | İP-16 | Medium |
| BLG-007 | Medium | network/P2P | UTF-8 byte slicing panic drops node without identity-verified P2P Prevote/Precommit/FinalityCert messages | Verified (Red test output) | audit_repro_a_blg_007 | İP-17 | Medium |
| BLG-008 | Medium | RPC | Testnet open RPC acceptance condition does not match current profile requiring key for all calls | Open verified | audit_repro_a_blg_008 | İP-16 | Medium |
| BLG-009 | Medium | cryptography | Main PQ API mandatory registered FIPS context and open schema identifier condition not met | Verified (Red test output) | audit_repro_a_blg_009 | İP-61 | Medium |
| BLG-010 | Medium | cryptography | PKCS#11 key label (key_label) applies after founder binds single key without label | Verified (Red test output) | audit_repro_a_blg_010 | İP-61 | Medium |
| BLG-011 | Medium | RPC/operation | Distributed ops/budlum-core.service unit does not provide RPC credential read by runtime and opens LimitCORE=infinity | Verified (Red test output) | audit_repro_a_blg_011 | İP-41 | Medium |
| BLG-012 | Medium | build/CI | Global coverage latch (coverage.rs) reads percentage of first file instead of total and passes NaN base | Verified (Red test output) | audit_repro_d_blg_012 | İP-42 | Medium |
| BLG-013 | Medium | build/CI | Documented prepush helper always runs intentionally overridden --all-features composition | Verified (Red test output) | audit_repro_d_blg_013 | İP-42 | Medium |
| BLG-014 | Medium | storage | Backup drill (backup_drill.rs) --check-db exit code ignored and substring match accepted as success | Verified (Red test output) | audit_repro_d_blg_014 | İP-42 | Medium |
| BLG-015 | Medium | build/CI | Three standalone Rust packages unit tests not run by root cargo test --workspace | Verified (Red test output) | audit_repro_d_blg_015 | İP-42 | Medium |
| BLG-016 | High | build/CI/supply chain | Fresh RustSec scan finds patchable security notices in 6 of 11 tracked Cargo.lock files | Verified (Red test output) | audit_repro_d_blg_016 | İP-42 | High |
| BLG-017 | Critical | network/P2P | Identity-unverified P2P Prevote/Precommit/FinalityCert messages UTF-8 byte slicing panic drops node | Verified (Red test output) | audit_repro_a_blg_017 | İP-15 | Critical |
| BLG-018 | Critical | consensus | Hybrid finality (finalized_height) cannot progress due to four independent disconnections in live network | Verified (Red test output) | audit_repro_a_blg_018 | İP-12 | Critical |
| BLG-019 | Critical | state transition | TransactionType::StateUpdate allows arbitrary nonce writing to every account without authority and commitment bond | Pre-corrected (Green) | audit_lane_a_blg_019 | İP-17 | Critical |
| BLG-020 | Critical | consensus/state transition | collect_block_transactions pre-retention temp_state mutation and missing nonce/signature check in Executor combine to produce permanent consensus chain split with two mempool operations | Pre-corrected (Green) | audit_lane_a_blg_020 | İP-17 | Critical |
| ... (remaining BLG-021 to BLG-267 and archive families) ... | | | | | | | |

## Notes
- Analysis base: `budlum-testnet-quantum.zip` (2026-11-02)
- Directive Section 0.4.4: Each finding re-verified by İP-01 to İP-04.
- ASD-STE100: Short sentences. Single meaning. Active voice. Present tense.
- Commit SHA and CI run number will be added when PR merges (Directive 15.5 item 8).
