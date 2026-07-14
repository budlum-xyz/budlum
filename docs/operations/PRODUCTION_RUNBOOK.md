# Production node / enterprise PoA runbook (Tur 13.5)

This runbook covers the shared Budlum binary for end-user RPC, developer and
enterprise PoA deployments. It does **not** claim audited-mainnet readiness.

## 1. Release gate

From one immutable checkout:

```bash
cargo fmt --all -- --check
cargo clippy --lib --tests -- -D warnings
cargo test --lib
cargo test --manifest-path budzero/Cargo.toml --workspace
cargo build --release --locked
```

Record the Git commit, Rust version, genesis hash and BudZero proof format.
BudZero is now in-tree, so there is no sibling commit pin to forget.

## 2. Network and process isolation

- Validator/PoA authority: no public RPC; P2P through sentries where possible.
- Public RPC: separate host or container, API-key auth, explicit allowlist/CORS,
  per-IP quota and connection/body limits.
- Operator RPC: localhost only. Admin methods such as domain/asset registration,
  direct legacy bond helpers and global-header sealing reject the public mode.
- Metrics: bind to the monitoring network, not the Internet.
- Keep mDNS disabled outside devnet.

The per-IP quota map has a hard 10,000-client ceiling and evicts expired windows
before admitting another source, preventing quota accounting from becoming a
memory-DoS primitive.

## 3. Enterprise PoA authority set

1. Freeze the authority list and genesis/config hashes in a signed change
   record.
2. Keep PoA membership in its dedicated KYC/admin registry. Never add PoA
   approval gates to permissionless PoW/PoS/BFT roles.
3. Require real Ed25519 authority signatures over
   `BUDLUM_POA_COMMIT_V1 || domain || height || block_hash`.
4. Rehearse one authority removal, one key rotation and quorum loss before
   production.
5. Alert on authority-set hash changes, rejected quorum certificates, finality
   lag and frozen domains.

## 4. HSM and PIN handling

Mainnet-shaped validators must use `validator.signer.backend = "pkcs11"`.
Provide the module path, slot and **name of** the PIN environment variable in a
private deployment overlay. Inject the PIN through the service manager or a
secret store; never place its value in Git, CLI arguments, logs or shell
history.

Current limitation: PKCS#11 covers the consensus Ed25519 signer. Disk-backed
`ValidatorKeys` also contain BLS and Dilithium secrets, so the process rejects
such files on mainnet until Tur 13.9 delivers/assesses BLS/PQ HSM paths. This is
a fail-closed limitation, not a completed HSM claim.

## 5. PoW bridge policy

PoW bridge mint is allowed only when the registered domain uses
`pow-header-chain-v1` with immutable `pow_parameters`. The submitted proof must
contain a bounded contiguous chain whose header hashes, parent links, roots,
heights, difficulty and cumulative work are recomputed. The target commitment
must also be on the applied contiguous domain chain.

The legacy `pow-confirmation-depth` proof remains decodable for historical
settlement but can never authorize mint.

## 6. Monitoring and incident triggers

Prometheus now observes block propagation, consensus round, storage read/write,
settlement commitments and sealed headers. Page on:

- finality lag above the deployment SLO;
- repeated invalid PoW header chains or PoA quorum failures;
- frozen domain count > 0;
- backup failure or missed restore drill;
- storage p95/p99 regression;
- RPC 429 surge, tracked-client saturation, or operator-listener exposure.

For a suspected bridge/finality incident: disable the affected domain's bridge,
preserve DB/log evidence, stop operator mutations, identify the last finalized
global header, and restore only from a tested backup. Do not manually edit sled
keys.
