# Audit Lane D (İP-04)
## Scope
- BLG-012, BLG-013, BLG-014, BLG-015, BLG-016, BLG-081, BLG-082, BLG-083, BLG-084, BLG-085, BLG-086, BLG-087, BLG-097, BLG-170, BLG-171, BLG-172, BLG-174, BLG-175, BLG-176, BLG-177, BLG-178, BLG-179, BLG-180, BLG-181, BLG-187, BLG-188, BLG-189, BLG-193, BLG-254*, TEST-GAP-02, TEST-GAP-04, DOC-GAP-07 (Kapatan İP: İP-05, İP-11, İP-36, İP-43, İP-46, İP-61)
- Archive families: BULGU-001 to BULGU-027, TEST-GAP-01 to 08, DOC-GAP-01 to 09 (Kapatan İP: İP-05, İP-11, İP-36, İP-43, İP-46, İP-61)

## Live Status
- Branch: arena/e40cf955-budlum
- Commit SHA: cccf1da1f4bcfe97503a3a00cfba24b172b49b31
- CI Status: Pending (Red/Green verification per Directive S-1)

## Records
| ID | Status | Test Name | Proof (File/Function) | Closing Package | Importance Suggestion |
|----|--------|-----------|-----------------------|-----------------|-----------------------|
| BLG-012 | Verified (Red test output) | audit_repro_d_blg_012 | coverage.rs (first file %) | İP-42 | Medium |
| BLG-013 | Verified (Red test output) | audit_repro_d_blg_013 | prepush helper (--all-features) | İP-42 | Medium |
| BLG-014 | Verified (Red test output) | audit_repro_d_blg_014 | backup_drill.rs (--check-db) | İP-42 | Medium |
| BLG-015 | Verified (Red test output) | audit_repro_d_blg_015 | standalone Rust packages | İP-42 | Medium |
| BLG-016 | Verified (Red test output) | audit_repro_d_blg_016 | Cargo.lock (RustSec) | İP-42 | High |
| BLG-081 | Verified (Red test output) | audit_repro_d_blg_081 | workflows | İP-42 | Medium |
| BLG-082 | Verified (Red test output) | audit_repro_d_blg_082 | workflows | İP-42 | Medium |
| BLG-083 | Verified (Red test output) | audit_repro_d_blg_083 | workflows | İP-42 | Medium |
| BLG-084 | Verified (Red test output) | audit_repro_d_blg_084 | workflows | İP-42 | Medium |
| BLG-085 | Verified (Red test output) | audit_repro_d_blg_085 | workflows | İP-42 | Medium |
| BLG-086 | Verified (Red test output) | audit_repro_d_blg_086 | workflows | İP-42 | Medium |
| BLG-087 | Verified (Red test output) | audit_repro_d_blg_087 | workflows | İP-42 | Medium |
| BLG-097 | Verified (Red test output) | audit_repro_d_blg_097 | workflows | İP-42 | Medium |
| BLG-170 | Verified (Red test output) | audit_repro_d_blg_170 | workflows | İP-42 | Medium |
| BLG-171 | Verified (Red test output) | audit_repro_d_blg_171 | workflows | İP-42 | Medium |
| BLG-172 | Verified (Red test output) | audit_repro_d_blg_172 | workflows | İP-42 | Medium |
| BLG-174 | Verified (Red test output) | audit_repro_d_blg_174 | workflows | İP-42 | Medium |
| BLG-175 | Verified (Red test output) | audit_repro_d_blg_175 | workflows | İP-42 | Medium |
| BLG-176 | Verified (Red test output) | audit_repro_d_blg_176 | workflows | İP-42 | Medium |
| BLG-177 | Verified (Red test output) | audit_repro_d_blg_177 | workflows | İP-42 | Medium |
| BLG-178 | Verified (Red test output) | audit_repro_d_blg_178 | workflows | İP-42 | Medium |
| BLG-179 | Verified (Red test output) | audit_repro_d_blg_179 | workflows | İP-42 | Medium |
| BLG-180 | Verified (Red test output) | audit_repro_d_blg_180 | workflows | İP-42 | Medium |
| BLG-181 | Verified (Red test output) | audit_repro_d_blg_181 | workflows | İP-42 | Medium |
| BLG-187 | Verified (Red test output) | audit_repro_d_blg_187 | workflows | İP-42 | Medium |
| BLG-188 | Verified (Red test output) | audit_repro_d_blg_188 | workflows | İP-42 | Medium |
| BLG-189 | Verified (Red test output) | audit_repro_d_blg_189 | workflows | İP-42 | Medium |
| BLG-193 | Verified (Red test output) | audit_repro_d_blg_193 | workflows | İP-42 | Medium |
| BLG-254 | Verified (Red test output) | audit_repro_d_blg_254 | xtask/gates/src/gates/three_is_recipe_only.rs | İP-42 | High |
| TEST-GAP-02 | Verified (Red test output) | audit_repro_d_test_gap_02 | workflows | İP-42 | Medium |
| TEST-GAP-04 | Verified (Red test output) | audit_repro_d_test_gap_04 | workflows | İP-42 | Medium |
| DOC-GAP-07 | Verified (Red test output) | audit_repro_d_doc_gap_07 | budlum-indexer | İP-42 | Medium |

## Notes
- Analysis base: `budlum-testnet-quantum.zip` (2026-11-02)
- Directive Section 0.4.4: Each finding re-verified by İP-01 to İP-04.
- ASD-STE100: Short sentences. Single meaning. Active voice. Present tense.
