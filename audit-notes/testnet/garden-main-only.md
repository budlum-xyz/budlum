# Garden main-only dependency stop report and storage integration design

## Conflicting requirements

1. Garden directive section 0.3 permits only existing components already merged to `main`.
2. Garden directive sections 4.6 and 4.7 require B.U.D. 3.0 as the sole storage path, canonical upload/view processing and Garden-local placement. A temporary raw-content implementation does not satisfy them.

This stops only the dependency-bound storage replacement. It does not stop the audit, invite/parser tests, resource-bound reviews or independent transport fixes. No approval request or protection bypass is used.

## Checked revisions and evidence

- Main source: `1bd93561`, live-fetched before this report.
- Garden source under validation: `3467a0bababb7648c75631173228d460da935485` plus the separately recorded invite-test-only patch. The patch does not modify storage.
- `git cat-file -e origin/main:src/storage/bud3/mod.rs`, `pipeline.rs` and `content_id.rs` fail because these paths are absent on main. The same paths exist on Garden through unmerged upstream work.
- Main does contain `src/storage/three_pipe.rs`. Its one-shot Three/QR facade is not interchangeable with the canonical B.U.D. 3.0 BOF-1 pipeline.
- Garden's `src/garden/storage.rs:9-12` explicitly describes a temporary single-chunk seam. `put` at lines 128-177 writes original bytes under the legacy `ContentId::of` hash; `get` reads those bytes back. [B-0050 / BLG-269](../findings/garden-storage.md) records the functional gap.
- The existing `DomainStatus`, `PoAFinalityAdapter`, `poa_commit_signing_message`, `poa_authority_set_hash` and legacy content-id primitive exist on main. This is a per-component dependency check, not an assertion that every Garden dependency is missing.
- `src/network/bounded_bincode.rs`, used by the upper-stack B-0042 repair, is also absent on main. Do not silently import that unmerged dependency into a Garden change. The current absence of B-0041/B-0042 fixes from Garden is tracked separately in the network findings.

## Resolution

Preserve the existing isolated PoA network for verification. Do not claim full Garden acceptance. Let the prerequisite PR chain satisfy CI, security review and branch protection and merge to main first. Refresh the main SHA and inspect the canonical APIs again. Do not merge Garden to main during the freeze, and do not force-push the existing stack.

## Integration design after the prerequisite lands

1. Replace only the inside of the Garden storage seam and add required Garden record fields. Keep externally shared paths additive and leave public-chain consensus unchanged.
2. Reuse canonical public content ids, BOF-1 object construction, segmenting, RFC 6330 symbols, symbol commitments and the existing upload/view gates. Do not implement a second encoder or id algorithm.
3. Adapt placement to the Garden genesis and current equal-class validator set. The policy has no stake, validation classes, storage charges, rewards or minting. Its lifetime ends with the Garden. Re-evaluate redundancy when non-host validators leave without changing the canonical encoding.
4. Each validator can accept an upload. Treat the upload as local service work until a signed Garden transaction records the canonical id and commitment. Apply persistent state changes only through blocks.
5. Store assigned verified symbols with bounded per-object and per-node disk charges. Bound upload sessions, frame bytes, decoded allocation and background writers. Keep cancellation and error cleanup explicit.
6. Serve and reconstruct from independently checked symbols, not from retained original content. Preserve the query path from transaction to block and voters.
7. Retire only through verified Garden state. Wipe custody shares, temporary uploads, decoded buffers, metadata and Garden chain material on each participant. Test restart after final leave and prove a new Garden cannot resolve retired ids.

## Verification required before closure

- A negative regression that fails while the raw-file store bypasses the canonical path.
- Canonical id equality between an ordinary B.U.D. 3.0 upload and a Garden upload of the same public bytes.
- BOF-1/commitment and symbol-proof validation, malformed-share rejection and successful reconstruction without retaining complete source content.
- Five-or-more-validator real-process scenario, non-host crash, shrinking placement, host freeze/read/return, final deletion on all nodes and next-Garden isolation.
- Numeric-IP-only operation, NAT/relay path, chain-id isolation, bounded memory/disk work and replay rejection.
- `fmt`, `clippy -D warnings`, all applicable tests and gates, and independent review where required.
- Exact fixing SHA, green CI run id and run number, and every acceptance-step test name. Queued, skipped, cancelled or unrelated runs are not closure evidence.
