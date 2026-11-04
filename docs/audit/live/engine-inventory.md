# Execution engine inventory (WP-03, directive section 8.2)

Analysis time: 2026-11-04. Sources: crates.io API (`https://crates.io/api/v1/crates/<name>`), GitHub API for each upstream repository (`gh api repos/<owner>/<repo>/...`: license file, workspace `Cargo.toml`, latest release). Nothing in this table comes from memory. Where a value could not be verified it says so.

Directive section 8.2 catalog rows under check: `0x01` EVM, `0x02` WASM, `0x03` SVM, `0x04` Move (Aptos dialect).

## Result table

| Engine | Catalog env | Latest stable at analysis time | Pre-release seen | License (crate metadata) | License file in upstream repo | Min Rust (`rust-version`) | cargo-deny pre-check (root policy `.quality/deny.toml`, `licenses` + `sources`) |
|---|---|---|---|---|---|---|---|
| `revm` | `0x01` EVM | `43.0.3` (published 2026-09-24, not yanked) | none | `MIT` | `LICENSE` (MIT; GitHub detects `MIT`) in `bluealloy/revm` (latest release tag `v120` is the workspace tag, crate version is 43.0.3) | 1.91.0 | PASS. No rejected crate on the revm branch of the graph. |
| `wasmi` | `0x02` WASM | `2.0.0` (published 2026-09-01, not yanked) | none | `MIT/Apache-2.0` | `LICENSE-MIT` and `LICENSE-APACHE` in `wasmi-labs/wasmi` | 1.86 | PASS. |
| `solana-svm` | `0x03` SVM | `4.4.0` (published 2026-10-28, not yanked; agave tag `v4.4.0`) | `4.5.0-alpha.4` | `Apache-2.0` | `LICENSE` in `anza-xyz/agave` (Apache-2.0) | **1.98.1** | FAIL under the current allow list. Two crates, `enum-iterator 2.3.0` and `enum-iterator-derive 1.5.0` (pulled by `solana-svm-timings`), are `0BSD`, which is not in `allow`. 0BSD is OSI-approved and permissive. Fix is a justified allow-list addition (WP-42), not a blocker. |
| `solana-sbpf` | `0x03` SVM | `0.27.0` (published 2026-11-03, not yanked) | none | `Apache-2.0` | `LICENSE-APACHE` and `LICENSE-MIT` in `anza-xyz/sbpf` (crate metadata names Apache-2.0 only) | none declared | PASS. Note: the `solana-svm 4.4.0` graph also pulls `solana-sbpf 0.24.0`, so two versions coexist unless the pin is aligned. |
| `aptos-vm` | `0x04` Move (Aptos dialect) | **No stable release exists.** crates.io has only a `0.0.0` placeholder (2022). In-tree version is `0.1.0` (`aptos-move/aptos-vm/Cargo.toml`), `publish = false`. Latest upstream release tag: `aptos-node-v1.49.8` (2026-11-04). `main` commit `7a89e8311c5097c20b3ce2a4c7ef8557ae8e722f`. | n/a | `LicenseRef-Aptos` (workspace `license-file = "LICENSE"`) | `LICENSE` in `aptos-labs/aptos-core` titled "Innovation-Enabling Source Code License" (GitHub: `NOASSERTION`) | 1.95 (edition 2024) | NOT RUN. The crate is not on crates.io and building a git dependency on the whole aptos-core workspace was out of scope. By inspection `LicenseRef-Aptos` is not on any allow list and would be rejected. |

## Finding from the inventory (new, see `lane-c.md`)

Directive section 8.2 lists `aptos-vm` as `Apache-2.0`. That is wrong for the current upstream. The aptos-core `LICENSE` grants only "non-production and non-commercial use" and forbids using the work "for the purpose of creating, publishing, deploying, launching or offering any blockchain or protocols (whether in mainnet, testnet, devnet, beta or alpha versions) outside of personal, non-production and non-commercial environments". Apache-2.0 applies only after a per-version Change Date, 4 years after the code was publicly uploaded. An "Additional Use Grant" is limited to applications built exclusively on the Aptos protocol and excludes "Competing Use" (any use related to developing a layer 1 or layer 2 blockchain, or built on a protocol other than Aptos). A Budlum testnet embedding `aptos-vm` is outside this grant. Consequence for the plan: catalog row `0x04` and WP-32 cannot ship against current aptos-core. Options are (a) use only code whose Change Date has passed (more than 4 years old, which is far behind the Aptos framework), (b) obtain a commercial license from the Aptos Foundation, (c) run Move through a differently licensed Move VM line (not verified here; needs its own license check), or (d) mark `0x04` closed on testnet with a `move_aptos_env_is_closed_on_testnet` test. This is recorded as BLG-332 in `lane-c.md`.

Second inventory observation: `solana-svm 4.4.0` declares `rust-version = 1.98.1`, but `rust-toolchain.toml` pins `1.97.1`. Adding it requires a toolchain bump together with the Agave pin (BLG-333).

## What could not be verified

- `aptos-vm` cargo-deny result (not run, see above).
- Whether `revm`, `wasmi`, `solana-svm` and `solana-sbpf` pass `cargo-deny check advisories` and `bans` (only `licenses` and `sources` were run, no advisory database used).
- `cargo-vet` and `cargo-geiger` results (S-5): not run.
- The directive's claim of `revm =43.x`: 43.0.3 is indeed the latest 43.x stable on crates.io today.

## How the cargo-deny pre-check was run

`cargo-deny` 0.20.2 was not installed. The official Linux musl release binary was downloaded from the EmbarkStudios release page, its SHA-256 matched the published `.sha256` file, and it was run from a scratch directory outside the repository. A scratch crate depending on `revm =43.0.3`, `wasmi =2.0.0`, `solana-svm =4.4.0`, `solana-sbpf =0.27.0` (494 packages in the resolved graph) was checked with a copy of the repository's `.quality/deny.toml`. Command: `cargo-deny --manifest-path Cargo.toml check licenses sources`. Output: `licenses FAILED, sources ok`, the only rejections being the two `0BSD` crates above.
