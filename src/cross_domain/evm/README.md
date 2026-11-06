# The EVM ChainAdapter (module README): closing F10 H4

**Under the module separation rule, this is the EVM adapter's own README.** The
root `README.md` is only a dashboard; the maturity and risk warnings live here.

## Status

- **Maturity:** F10.1 and F10.2 shipped, closing the H4 spoofed-authorization
  finding. F10.3, the sync committee light client, is implemented and reachable
  from the production verification path; see the warnings below for what it does
  and does not cover.
- **Where the code is:** `src/cross_domain/evm/`, holding `rlp.rs` (an in-tree
  RLP codec), `mpt.rs` (a Merkle-Patricia trie verifier), `receipt.rs` (Ethereum
  receipt decoding), `header.rs` (the header chain and N-confirmation finality),
  `sync_committee.rs` (the Altair sync committee light client), `verify.rs` (the
  `verify_evm_receipt` orchestrator), `adapter.rs` (the `EvmChainAdapter`
  implementation) and `bud_to_eth.rs` (the Budlum side of the F10.5 direction).
- **Test count:** 90 `#[test]` functions, made up of RLP 19, MPT 17, receipt 10,
  header 7, verify 12, sync committee 9, adapter 12 and bud-to-eth 4.
- **Wired to:** `src/cross_domain/chain_adapter.rs`, which holds the
  `ChainAdapter` trait, the `AdapterRegistry` and the `StubAdapter`. The
  `EvmChainAdapter` implementation is F10.2, verifying the receipt proof on
  chain.

## Design decisions

1. The relayer-produces trust model.
2. A PoS sync committee with N-confirmation as the fallback.
3. In-tree RLP and MPT; NO alloy and NO ethers.
4. Both directions, Ethereum to Bud and Bud to Ethereum.

## Maturity warnings

- **N-confirmation finality.** `verify_chain` works over a k-deep canonical
  chain, which leaves a reorg window. A proof carrying no sync committee
  attestation still finalises on confirmations alone, and confirmations are a
  bet that no reorg goes that deep rather than evidence that none can.
- **The sync committee attestation is optional in the proof.** When a proof
  carries one, `verify_evm_receipt` checks it and refuses participation below
  the threshold of 342 out of 512. When a proof carries none, nothing about PoS
  finality is claimed or checked. A caller that needs proof of stake finality
  must therefore require the attestation itself; the verifier cannot infer the
  requirement from a proof that omits it.
- **`EvmChainAdapter::generate`, `submit` and `wait` are off-chain stubs.** The
  production relayer binary, F10.4, comes after mainnet.
  `verify_receipt_proof` is on chain and deterministic.
- **The Bud to Ethereum direction, F10.5, is only half here.** `bud_to_eth.rs`
  builds the Budlum-side payload; the smart contract on Ethereum that verifies
  Budlum finality, a Solidity light client, is a large separate piece of work
  under its own RFC.

## Security invariants (F10.1 and F10.2)

- **Deterministic and network-free.** No function connects to an Ethereum RPC.
  The relayer produces the proof and it is verified inside Budlum consensus,
  which is Q1, relayer-produces.
- **In-tree cryptography.** RLP and MPT are minimal implementations following
  the Yellow Paper, appendices B and D, with NO new dependency; `sha3::Keccak256`
  is reused. There are known-answer vectors and a negative matrix.
- **A garbage proof does not panic.** For DoS safety, random bytes give an `Err`
  and NO panic.
- **Canonical form is checked.** On RLP decoding, a leading zero, a non-minimal
  length, trailing bytes or truncation are all REFUSED, which closes the surface
  for inventing a proof.

## How H4 was closed

H4 in `SECURITY_AUDIT_HACKER`, rated critical: "a UniversalRelay transaction
only emits a log, with no cryptographic binding to the target chain's format,
which allows spoofed authorization". F10.1 and F10.2 closed it: Budlum verifies
Ethereum deposits cryptographically, with its own MPT and header chain, so the
relayer cannot invent a proof.

## What comes next

F10.4, the relayer binary, after mainnet, and F10.5's Ethereum side, the
Solidity light client, under a separate RFC. The fuzz targets `evm_rlp_decode`
and `evm_mpt_verify` shipped with this work.
