# Light client

`src/light_client/mod.rs` verifies the chain without downloading or replaying
transaction bodies. This page records what it trusts, what it verifies and what
it does not do yet.

## Trust anchor

A light client bootstraps from one commitment: a checkpoint height, the block
hash at that height, and the hash of the validator set that finalized it. It
advances that anchor by verifying finality certificates against the same set.
A certificate whose `set_hash` differs from the trusted one is rejected, not
followed: a validator set change needs a new anchor out of band.

## What it verifies

| Kind | Entry point | What it proves |
| --- | --- | --- |
| BLS aggregate finality certificate | `LightClient::verify_checkpoint` | A stake weighted quorum of the trusted set finalized the checkpoint. |
| Post quantum quorum blob | `LightClient::verify_pq_checkpoint` | The same attestation layer a full node imports, in the `QcBlob` form. |

`LightClient::sync_plan` returns the wire requests a transport must issue (the
`GetHeaders` locator and the per checkpoint QC fetch). The verification is
transport agnostic on purpose: the `budlum-light` binary drives the plan over a
chain export, and the mobile app drives the same plan over its own transport.

## What it does not do

- It does not follow a validator set change. That needs a new anchor.
- It does not verify execution. A light client proves that a block is final; it
  does not prove what the block computed.
- The mobile shell that carries this verifier is not in the tree yet. The
  Android validator application and its light client duties are described in
  [MOBILE_VALIDATOR.md](MOBILE_VALIDATOR.md), which also records that the
  application is missing.

## Status

The module is in the tree with the two verification paths and the sync plan.
No test run is recorded on this page; the launch gate rows that depend on the
light client are in `docs/audit/TLG_REPORT.md`.
