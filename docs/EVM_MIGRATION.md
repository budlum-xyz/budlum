# EVM Migration Kit (`WP-34`, Directive Section 8.12)

The EVM Migration Kit imports deployed contracts from Ethereum Mainnet (`1`) or
Sepolia (`11155111`) into Budlum's EVM Execution Environment at their **exact
20-byte contract address**, with cryptographically verified bytecode and storage
slots, **without migrating source-chain ETH balance** (`8.12.2` item 7).

## 1. Security Model and Authority Rules

1. **Deployment authority (`8.12.2` item 2):**
   - **Direct `CREATE` (`to = nil`):** The caller verifies an MPT transaction
     proof against `transactionsRoot` and a status-1 receipt proof against
     `receiptsRoot`. The recovered sender is the deployment authority and the
     contract address must equal `CREATE(deployer, nonce)`.
   - **Factory creation (`CREATE` or `CREATE2`):** When a contract was created
     through a factory, the caller supplies `FactoryCreationEvidence` proving
     the factory's own deployment transaction + receipt and the deterministic
     `CREATE(factory, factory_nonce)` or `CREATE2(factory, salt, keccak256(init))`
     derivation. Authority belongs to the factory deployer, never an arbitrary
     transaction caller.
2. **EIP-712 `MigrationAuthorization`:**
   - Domain: `name = "Budlum Migration"`, `version = "1"`, `chainId = budlumChainId`,
     `verifyingContract = contract`.
   - Struct: `MigrationAuthorization(address contract,uint256 budlumChainId,uint256 sourceBlock)`.
   - Must recover to the proven deployment authority (`uel_migration_requires_deployer_authorization`).
3. **Finalized account and storage MPT proofs (`8.12.2` items 3-5):**
   - `account_proof::verify_account` verifies `[nonce, balance, storageRoot, codeHash]`
     against the finalized source `stateRoot` (preserving full 256-bit source
     wei balances so whale contracts never fail decoding).
   - `MigrationTx::ImportEvmStorageChunk` proves up to `4,096` slots per chunk
     atomically (`G-4`: if any slot proof fails, zero slots or fee counters are
     mutated).
   - `MigrationTx::FinalizeEvmImport` recomputes the full Ethereum storage MPT
     root from the staged non-zero slots (`storage_root::compute_storage_root`)
     and refuses unless it matches the proven `storageRoot` byte-for-byte
     (`migration_preserves_address_code_and_storage_root`).
4. **Target occupation & zero-ETH rule (`8.12.2` items 6-7):**
   - Refuses if the 20-byte address is already occupied in `ee/evm/account`,
     collides with a registered native alias or `0x...B001` precompile, has a
     pending import, or already holds native BUD balance (`migration_refuses_occupied_address`).
   - Source-chain ETH is **not** minted or bridged; the installed contract starts
     with `0` BUD balance and records `imported_from: { domain, block, address }`
     queryable via `bud_getImportedContract`.
5. **Fee settlement (`8.12.2` item 8):**
   - Verification BGU (`proof_nodes`, `code_bytes`, `storage_slots`) plus storage
     byte deposit is charged in `attoBUD` from the migrator to `reward_pool_account()`
     before any namespace write commits (`G-3` supply conservation, `G-4` refusal
     atomicity).

## 2. `bud-migrate` CLI

`src/bin/bud-migrate.rs` provides offline bundle verification, EIP-712 digest
computation, and static bytecode dependency scanning:

```bash
# 1. Compute the EIP-712 signing digest for the contract deployer:
bud-migrate digest --contract 0xa3183498b579bd228aa2b62101c40cc1da978f24 \
  --chain-id 45261 --source-block 19000000

# 2. Scan runtime bytecode for PUSH20 hardcoded addresses and external CALLs:
bud-migrate analyze --code-file ./token.runtime.hex --json

# 3. Verify an offline migration bundle end-to-end (authority + MPT + fee quote):
bud-migrate verify ./sepolia-erc20-bundle.json
```

## 3. On-Chain Installation Flow (`ExecutionCoordinator::apply_evm_migration`)

1. Submit `MigrationTx::BeginEvmImport(Box<MigrationRequest>)` -> stages
   `MigrationPlan` in `ExecutionState::pending_evm_migrations`.
2. Submit zero or more `MigrationTx::ImportEvmStorageChunk(ImportEvmStorageChunk)`
   transactions -> proves and stages all populated storage slots.
3. Submit `MigrationTx::FinalizeEvmImport { contract }` -> verifies complete
   `storageRoot`, settles fee from migrator, writes `ee/evm/code`,
   `ee/evm/account` (with `imported_from`), and `ee/evm/storage`, and clears the
   pending plan. Immediately callable via `EvmEe` and visible on `eth_getCode`,
   `eth_getStorageAt`, and `bud_getImportedContract`.
