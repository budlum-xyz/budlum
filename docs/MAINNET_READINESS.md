# Mainnet readiness

What must be true before a Budlum mainnet genesis is cut, and what is true
today. This page records state; it does not take decisions.

Status values: `done` (evidence recorded and linked), `code` (implemented,
no CI or rehearsal evidence yet), `open` (work remains), `decision` (waits for
the owner).

Owner values: `owner` (the product owner), `agent` (implemented in this
repository), `external` (a third party has to deliver it).

## 1. Release gates

| Gate | Evidence | Owner | Status |
|---|---|---|---|
| CI green on the release commit, every required job | the run number in the release notes | agent | open |
| Three consecutive green nightly testnet rehearsals (`testnet-rehearsal.yml`) | the three run numbers and their reports | agent | open |
| No open critical or high severity finding from an independent review | the review report | external | open |
| Every module wired, rooted in the state root and covered by a rehearsal scenario | `docs/TESTNET.md` and the rehearsal report | agent | open |
| Reproducible build and reproducible genesis | the `Genesis Reproducibility` and cross-platform digest runs | agent | code |
| Release artefact signed and verifiable | `xtask/release` output and `RELEASE_PUBKEY.hex` | agent | code |

## 2. Security review

| Item | Evidence | Owner | Status |
|---|---|---|---|
| Independent audit of consensus, settlement and cryptography | audit report with a closure statement per finding | external | open |
| Bug bounty programme | programme page with scope and payout table | owner | decision |
| Long-running fuzz campaign (the nightly fuzz workflow, 30 consecutive green nights) | the run numbers | agent | open |
| Static and supply-chain analysis on every release commit (OSV, Grype, `cargo-deny`, `cargo-vet`, provenance) | the CI job names on the release commit | agent | code |
| Secret scanning across full history | the `Secret Scan` job on the release commit | agent | code |

## 3. Keys and cryptography

| Item | Evidence | Owner | Status |
|---|---|---|---|
| HSM vendor support for BLS, ML-DSA and the VRF in hardware, per vendor | vendor statements and a `pkcs11-pq` run against real hardware | external | open |
| PQ anchor production mode approved (the anchor currently runs in its non-production mode) | an owner decision recorded in this file | owner | decision |
| `VerifyMerkle` production gate opened, after the external opcode audit | the audit report and the gate change | external | decision |
| Wallet and validator key ceremony documented and rehearsed (generate, back up, restore) | `docs/OPERATIONS.md` plus a restore drill run | agent | code |
| `bincode` 1.x migration decided (it is the consensus encoding and is built into every block) | a written decision, with the activation-height plan if it changes | owner | decision |
| V4 (Ed25519) transaction retirement scheduled <!-- claim:S-I0 --> | the quantum workstream's decision, activation height and migration window | owner | decision |

## 4. Genesis and operations

| Item | Evidence | Owner | Status |
|---|---|---|---|
| Mainnet genesis ceremony with independent operators | ceremony records, the genesis hash and the reproduction check | owner | open |
| Bootnodes and DNS seeds published | addresses in `config/mainnet.toml` and `docs/TESTNET.md` form | owner | open |
| Tokenomics destination addresses fixed (five destinations, fixed supply) | `docs/SETTLEMENT.md` and the genesis document | owner | open |
| Economic parameter values set for mainnet (fee profile, stake floors, unbonding, commission caps, reward schedule) | the mainnet profile in `config/mainnet.toml` | owner | decision |
| Storage format gaps 1-3 closed (each changes the on-disk and on-wire format) | the change plus its migration note | agent | open |
| Consensus upgrade and activation-height scheme documented | a section in this file or `docs/ARCHITECTURE.md` | agent | open |
| Relayer trust model documented | `docs/GRAFT.md` and `docs/SETTLEMENT.md` | agent | code |
| On-chain governance scope documented (what a `Vote` can and cannot change) | `src/core/constitution.rs` plus a document section | agent | code |
| Incident response runbook | `docs/OPERATIONS.md` | agent | code |
| Operating cost measured per validator profile (server and personal device) | the measurement tables written by `budlum-tools resource-sample` | agent | open |

## 5. Licence and provenance

| Item | Evidence | Owner | Status |
|---|---|---|---|
| Dependency licence scan (ScanCode or FOSSA) | the scan report | external | open |
| Every dependency publisher reviewed | the `cargo-supply-chain` and `cargo-vet` runs | agent | code |
| Release provenance attestation | the `provenance` workflow run on the release commit | agent | code |

## 6. What "done" means for this page

A row moves to `done` only with a link or an identifier a reader can check: a
CI run number, a test name, a ceremony hash or an owner decision recorded
here. A row without that evidence is `open`, however much code exists behind
it.
