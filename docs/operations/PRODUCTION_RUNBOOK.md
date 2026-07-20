# Production node / enterprise PoA runbook (Phase 0.37)

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

Phase 2 §1.1 policy/tooling: mainnet validators still require PKCS#11 and reject
disk-backed `ValidatorKeys`. The BLS/PQ `hsm_mock` backend exists for dev/test
coverage only and is not a production secret-storage path. See
`docs/operations/HSM_BLS_PQ_POLICY.md`.

Current limitation: BLS/PQ support is sufficient for developer integration tests,
not a claim that every vendor HSM offers native non-extractable BLS/Dilithium
mechanisms. Hardware-native vendor integrations remain a separate audit item.

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

---

## 8. Mainnet genesis and seed inventory (Phase 3 section 3.1 / 3.3)

Ceremony procedure (roles, offline build, hash freeze, minutes): `docs/operations/MAINNET_GENESIS_CEREMONY.md`.

> **Status:** pre-ceremony placeholders. Repeated-byte addresses (`0x10..` /
> `0x20..`) are deterministic test vectors, **not** production treasury or
> validator keys. Replace them in a signed Mainnet release ceremony before
> real-value launch. This section does **not** claim audited mainnet readiness.

### 8.1 Canonical files

| Network | Config | Genesis JSON | Code constructor |
|---------|--------|--------------|------------------|
| Mainnet | `config/mainnet.toml` | `config/mainnet-genesis.json` | `mainnet_genesis()` |
| Testnet | `config/testnet.toml` | `config/testnet-genesis.json` | `testnet_genesis()` |
| Devnet | `config/devnet.toml` | `config/devnet-genesis.json` | `devnet_genesis()` |

Node startup loads `network.genesis_file` from the TOML profile. Missing or
mismatched files fail closed (`exit 1`). JSON must match the in-code constructor
hash (enforced by `test_mainnet_genesis_json_matches_code` and siblings).

### 8.2 Mainnet genesis hash (computed from HEAD builders)

| Field | Value |
|-------|-------|
| `chain_id` | `1` |
| `timestamp` (ms) | `1735689600000` (TBD at ceremony; ARENA1 mainnet_genesis) |
| `block_reward` | `25` |
| Design | Permissionless validators (empty set) + full  tokenomics (100M) |
| Genesis block hash | `fd5f7cb272e01333517d9f85b7e1052b89489a80dd497b2655c3dea99d53add4` |
| `state_root` | `03658f40bcddc8d3ee5bf0c3208a00d7b10fb6a4f7a17ccd755906c958fbe3ce` |
| `validator_set_hash` | `a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a` |

Recompute after any genesis field change:

```bash
cargo run --example print_genesis_hash
cargo test --lib chain::genesis::tests::test_mainnet_genesis_json_matches_code
```

| Network | Design | Permissionless validators (empty set) + full  tokenomics (100M) |
| Genesis block hash |
|---------|-------------------|
| Mainnet | `fd5f7cb272e01333517d9f85b7e1052b89489a80dd497b2655c3dea99d53add4` |
| Testnet | `b2e2135d77f963d5d58b58b86059a6299fd5c76ec8fef2a0de7385cc39a1b8c4` |
| Devnet | `841deadf6bf3f5b41cdc973fd8c8f0d012af9ecff752b3e394a1d04addd0bf6c` |

### 8.3 Seed / bootnode list

`config/mainnet.toml` ships with empty `bootnodes` and `dns_seeds`. Populate
only during the signed Mainnet release ceremony. Until then use local overrides
or explicit bootstrap flags. Solo validators may start with empty discovery.

| Role | multiaddr / DNS | Notes |
|------|-----------------|-------|
| _(empty until ceremony)_ | — | — |

### 8.4 Operator checklist (mainnet profile)

1. Verify `config/mainnet-genesis.json` and genesis block hash match section 8.2.
2. Set PKCS#11 signer (`validator.signer.backend = "pkcs11"`); disk BLS/PQ keys fail closed.
3. Point storage data_dir / secrets paths at durable volumes.
4. Fill p2p bootnodes / dns_seeds from the ceremony table.
5. Keep public RPC auth + per-IP quota on; operator RPC on localhost only.
6. Record release Git commit, Rust version, genesis hash, BudZero proof format.
