# Decisions ledger (testnet directive)

Three lists: decisions waiting for Ayaz, the testnet defaults applied while
they wait, and what this work needs from Ayaz to proceed. Nothing here is
decided by the agent; a testnet default is applied only where the directive
gives one, and it is marked `TESTNET-DEFAULT` in code.

## Waiting for a decision

| ID | Topic | Context | Options | Blocking |
|---|---|---|---|---|
| D-01 | Pull request base and CI | `ci.yml` runs on pull requests to `main` and `fix/architecture-tip-adlari` only (N-09). The directive's base rule stacks pull requests on `consensus-of-consensuses` while PR #97 is open, and those get no CI. This session can only push to `lubothebook/budlum` branch `ccr-d9229a3f-lgzpy9`; `budlum-xyz/budlum` is not reachable from it. | (a) add the stacking base to the `pull_request` branch list; (b) target `main` only after #97 merges; (c) Ayaz opens the upstream pull request from the fork branch. | K2 evidence (CI run numbers) for every work package. |
| D-02 | Mainnet `min_stake` | B-14: mainnet is `1_000_000` atoms (1 BUD). | Ayaz gives the mainnet value; testnet uses E-01 (1000 BUD). | Mainnet genesis. |
| D-03 | Mainnet protocol fee rates and fixed floor | B-18: all rates default to 0. A dollar-denominated floor needs a price source. | Price source choice; mainnet ppm values. | Mainnet genesis. |
| D-04 | Mainnet reward pool | E-02 testnet default is the existing schedule (10M BUD over 100000 epochs). | Confirm or change for mainnet. | Mainnet genesis. |
| D-05 | Global header activation on mainnet | WP-2 changes the block commitment format. Testnet starts from a new genesis; mainnet needs an activation height scheme (WP-13). | Height-gated activation versus genesis-only. | Mainnet upgrade plan. |
| D-06 | ML-DSA encoding on Ethereum | EIP-8051 and EIP-8355 are drafts with overlapping addresses (WP-11 item 7). | One encoding decision, written once. | Ethereum-side verifier. |
| D-07 | Mainnet HSM VRF | B-13: no PKCS#11 VRF backend; mainnet PoS validators exit at startup. | (a) a vendor HSM with native VRF over the chain's curve; (b) VRF in a separate signing process with the key sealed by the HSM and only the output signed by PKCS#11; (c) a threshold VRF across the validator's own devices; (d) keep VRF keys on disk for mainnet v1 with a documented exception. Each option is described in detail when WP-3 item 11 lands. | Mainnet PoS. |
| D-08 | `MaxEmergencyHaltEpochs` | N-06: a constitution parameter for a halt hook that K10 forbids and that does not exist. | Remove (constitution root change, new genesis) or keep inert with a test that no halt path exists. | Nothing on testnet. |
| D-09 | Lubot-origin AI operator surface | L-01: `AI_OPERATOR` (RoleId 8), `AiOperatorBond`, `AiOperatorUnbond`, `AiOperatorWithdraw`, the operator-submitted `AiInferenceResult` path and the 80/10/5/5 split come from Lubot's retired design (verified in `b7d4b86`). | Keep, retire, or move to the Lubot repository. Not changed by this directive. | Nothing on testnet. |
| D-10 | AI verifier whitelist mode | N-11: a governance proposal can make the AI verifier role permissioned. | Remove the mode, or bind it to the no-whitelist guardrail. | Nothing on testnet while governance is off. |
| D-11 | Graft claim expiry | E-08: unclaimed application share accrues in the mirror account with no time limit. | A limit, or none. | Nothing on testnet. |
| D-12 | Shared security on mainnet | E-06 and WP-10 item 7: the `shared_security` flag. | Mainnet on or off. | Mainnet genesis. |

## Testnet defaults applied (directive section 10.2)

Each value is written in code with the `TESTNET-DEFAULT` tag when it lands.
Until then the row says `not applied`.

| ID | Parameter | Testnet default | Status |
|---|---|---|---|
| E-01 | Validator `min_stake` | 1000 BUD, written as `bud(1_000)` | not applied |
| E-02 | Reward pool | on; 10M BUD over 100000 epochs | not applied |
| E-03 | Protocol fees | transfer 200 ppm, swap 400 ppm, bridge 800 ppm; fixed floor as a constant atom value | not applied |
| E-04 | `app_fee_share_ppm` | 400000 (40 percent to the application, 60 percent on the existing path) | not applied |
| E-05 | Delegation | minimum self bond = `min_stake`; maximum commission 20 percent; maximum change 1 percentage point per epoch; unbonding 100 epochs | not applied |
| E-06 | Shared security | `max_restaked_share_ppm` = 300000; a fixed `f(eth_units)` ratio; minimum BUD bond 0 | not applied |
| E-07 | Faucet | 100 BUD per request; 24 hour cooldown per address and per IP; daily cap 100000 BUD | not applied |
| E-08 | Graft | small fixed registration fee; default intent deadline 600 blocks; solver fee cap set by the user; no expiry on unclaimed share | not applied |

## What this work needs from Ayaz (directive section 10.3)

Everything that can be prepared without these is prepared; each item is
used when it arrives.

| Item | Used by |
|---|---|
| Servers and operators for at least four independent validators | WP-3, WP-12 |
| Testnet domain name and DNS TXT records (`_dnsaddr`) | WP-4 items 4 and 9 |
| Sepolia deployment key and test ETH | WP-8, WP-10, WP-11 |
| An EigenLayer Sepolia test operator | WP-10 |
| Custody of the faucet key | WP-4 item 5 |
| GitHub secrets for the nightly Sepolia job | WP-8 item 7, WP-11 |
| Access to `budlum-xyz/budlum` for this session, or an upstream pull request opened from `lubothebook/budlum` | D-01 |
