# Rehearsal network (WP-46, 1/N scaffolding)

Directive 1.3, 12.5, 17 and 18. The rehearsal proves the testnet launch on a
throwaway network before the real ceremony.

## Topology (card item 2)

- At least 8 Full validators, in at least 3 cloud regions and at least 2
  providers (target: at least 4 distinct operators).
- At least 4 relay nodes (`[relay]` section of directive 7.11.2).
- At least 2 upload gateways.
- Faucet, explorer, and all RPC gateways (Ethereum JSON-RPC, Solana JSON-RPC,
  Aptos REST, Cosmos subset).
- Mobile participation: at least 20 real Android phones (Budlum team and
  volunteers) and at least 1000 simulated Mobile validators running the mobile
  core headless on servers.
- Duration: at least 72 hours uninterrupted, then drills T-1..T-7.

## Procedure

1. Ceremony rehearsal: `ops/rehearsal/genesis_rehearsal.sh <dir-with-public-registrations>`
   writes the rehearsal genesis, records its SHA-256 digest under
   `docs/rehearsal/` and refuses fewer than 8 Full validators.
2. Bring the network up from `config/rehearsal-genesis.json`.
3. Run the 72-hour soak, then the drills in `ops/rehearsal/drills/`.
4. Every drill writes its evidence (metric output, node log summary,
   timeline) under `docs/rehearsal/`.
5. Measurements land in `docs/rehearsal/RESULTS.md`; README and docs numbers
   come from that file only (directive 0.5).

## Drills (pass criteria in each script)

| Drill | Pass criterion |
|---|---|
| T-1 all Mobile validators stop at once | Finality delay unchanged; no object lost; reads continue from Full class |
| T-2 10% of Full validators stop at once | Finality delayed by at most 2 checkpoint intervals; seats hand over within 3 checkpoints |
| T-3 >1/3 of active seats halted for 50 blocks | `budlum_finality_stalled` alert fires; finality resumes when seats return |
| T-4 Mobile validators return | `ResumeValidator` effective after one epoch; repair completes |
| T-5 load: >= 100 GiB total, 10 000 small objects, concurrent views | Upload/view succeed; results recorded |
| T-6 tooling: Foundry, Hardhat, viem, CosmJS, Anchor, aptos CLI; one EVM contract calls a CW20 transfer in the same transaction | All scenarios pass; the cross-env call is atomic |
| T-7 general RPC load test | Rate limit and 429 ratio measured and recorded |
