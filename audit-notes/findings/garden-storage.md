# B-0050 / BLG-269: Garden bypasses B.U.D. 3.0 and persists complete raw content under a legacy id

- Location: `src/garden/storage.rs:3-12,17-18,128-177,232-274`, `src/garden/types.rs` publication and placement structures, and their production callers in `src/garden/node.rs`, at Garden source revision `3467a0bababb7648c75631173228d460da935485`.
- Severity: high, functional correctness and directive compliance. No remote exploit is claimed by this finding.
- Binding requirement: Garden directive sections 4.6 and 4.7 require the existing B.U.D. 3.0 upload/view path, Garden-local placement, and content reconstructed by the receiving validator. Section 0.3 permits only dependencies already merged to `main`. The base specification sections 6.1, 6.2 and 6.4 require BOF-1 objects, RFC 6330 symbols, canonical content ids and the upload gates, rather than a second raw-content store.
- Faulty lines:

  ```rust
  use crate::storage::content_id::ContentId;
  ```

  ```rust
  let content_id = ContentId::of(bytes).0;
  let mut file = fs::File::create(&tmp)?;
  file.write_all(bytes)?;
  file.sync_all()?;
  fs::rename(&tmp, &path)?;
  ```

  The module's own opening comment describes the implementation as a temporary single-chunk seam pending the B.U.D. 3.0 object layer.
- What is wrong: `GardenContentStore` writes the full original publication to a file, or clones it into an in-memory map. Retrieval reads the same file and verifies the old domain-separated hash. The production path does not call `storage::bud3::pipeline`, produce BOF-1 records, place fountain symbols, run the two-path gates, or reconstruct from custody shares.
- Identifier mismatch: legacy `storage::content_id::ContentId::of` computes the domain-separated `BDLM_CONTENT_V1` hash. `storage::bud3::content_id::ContentId::public` records ordinary SHA-256, length and kind. A matching hash between two Garden nodes proves their mutual agreement, not conformance to the canonical B.U.D. 3.0 id.
- Impact: the current image scenario can pass while the required storage architecture is absent. Full-object replica retention and Garden-only ids are not the required symbol placement and shared content identity. Repair, shrinking-network placement and deletion need validation on the actual B.U.D. 3.0 storage path; current raw-file tests do not establish those properties.
- Source reproduction: inspect `GardenContentStore::put`, `write_object_file_blocking` and `get`, then follow their calls from `node.rs`. `git grep -n 'bud3' 3467a0ba -- src/garden` does not reveal an implemented B.U.D. 3.0 upload/view path. The passing `garden_step_04_image_resolves_on_another_node_with_equal_content_id` checks equality between Garden nodes but not canonical encoding, symbols or canonical content identity.
- Dependency evidence: `origin/main` is `1bd93561` at the checked snapshot. `src/storage/bud3/mod.rs`, `pipeline.rs` and `content_id.rs` are absent there; they are present on `garden` through unmerged upstream work. The older `three_pipe` facade exists on main but is not the new canonical BOF-1/RFC 6330 pipeline. Its existence is not proof the required dependency has merged.
- Repair sequence:
  1. Keep this finding open and the storage acceptance items unchecked. Do not rename the raw-file seam to claim conformance.
  2. Wait for the canonical storage dependency to merge to main under all required checks. Re-read its live API and revision; do not pin or pull unmerged dependency code into main.
  3. Replace the seam with the existing B.U.D. 3.0 upload and view services. Supply a Garden placement policy without class, stake, fees, rewards or BUD issuance. Keep Garden identity and lifetime isolated from the public testnet.
  4. Carry the canonical content id and object commitment in the Garden publication record. Persist only assigned verified symbols. Preserve bounded upload, decode and disk work.
  5. Reconstruct on another validator from sufficient verified symbols, compare the full canonical id with the ordinary storage API, and prove no full raw content or QR-video artifact remains on any holder.
  6. Repeat sudden non-host departure, host freeze/return, final retirement, restart, all-store deletion and next-Garden isolation through real node processes.
  7. Record the fixing SHA and successful CI run before closing.
- Status: open. Implementation of the dependency-bound replacement is stopped by the main-only rule. Independent Garden tests and audit continue. See the [main-only stop report](../testnet/garden-main-only.md).
