# Migration Guide

## Clean Testnet Genesis Policy

Public testnet (`chain_id = 45261`, network `BDLT`) launches from a clean genesis.
Legacy storage formats prior to `B.U.D. 3.0` are removed from the codebase and do not
migrate state across genesis restarts.

## Migrating EVM Contracts and Applications (`bud-migrate`)

Existing Solidity and Vyper contracts deploy unchanged onto Budlum's EVM execution
environment (`EeId::EVM`, `revm` Osaka interpreter) via standard Foundry (`forge`),
Hardhat, `viem`, or `ethers` workflows against the Ethereum compatibility JSON-RPC
listener (`127.0.0.1:18547`).

For deterministic offline verification of bytecode compatibility, constructor ABI
arguments, and `0xB001` Universal Call cross-environment bindings before broadcast,
use the `bud-migrate` CLI (`src/bin/bud-migrate.rs`) and see
[`docs/EVM_MIGRATION.md`](EVM_MIGRATION.md).
