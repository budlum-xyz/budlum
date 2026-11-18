# B-0049 / BLG-268: the short-chain invite regression passes a valid input to a rejection assertion

- Location: `src/garden/invite.rs:347-354` on Garden source revision `3467a0bababb7648c75631173228d460da935485`. `src/garden/types.rs:34,73-75` fixes every Garden chain id's high bits to `0x4741`.
- Severity: medium, verification and CI availability. This is not evidence that the production parser accepts a short id.
- Faulty lines:

  ```rust
  &format!("chain={:016x}", g.chain_id),
  &format!("chain={:x}", g.chain_id),
  ```

  ```rust
  assert!(GardenInvite::parse(&short_chain).is_err());
  ```

- What is wrong: the replacement is identical to the original. A Garden id with the fixed nonzero prefix already needs all 16 hexadecimal digits. Removing a minimum-width formatting directive cannot shorten it. The test sends a valid canonical invite to a rejection assertion.
- Why it matters: the Garden library test job fails even though the parser enforces exact length and lowercase input. This blocks verification of the PR and can encourage an incorrect weakening of admission checks. The malformed-length coverage is also absent because the alleged malformed value is valid.
- Reproduction environment: Debian GNU/Linux 13.7, x86-64. Command: `CARGO_INCREMENTAL=0 CARGO_PROFILE_DEV_DEBUG=0 cargo test --lib garden::`.
- Observed result: exit 101; 117 passed, 1 failed, 0 ignored. Failure: `garden::invite::tests::garden_invite_refuses_non_canonical_hex_and_duplicate_peers`, assertion at `src/garden/invite.rs:354`. The same source passed the 18 real-process scenario tests and the separate real-NAT test; integration success did not establish library-suite success.
- Repair: mutate the encoded value itself, not numeric display padding. Retain a valid positive round trip. For chain, genesis and token, exercise empty, one-character-short, one-character-long, signed, nonhex and uppercase values. Assert that every mutation changes the invite and that the parser returns the field-specific canonical-format error. Keep duplicate-peer rejection and production parsing unchanged.
- Related live work: `df970fc98402e0d025b7832ebada47581f8174f6` on `budlum-stack` contains a one-line fix using `g.chain_id >> 4`. That commit is not on `garden` and is not evidence that PR #164 is fixed. Avoid rewriting or force-pushing either branch.
- Current status: open pending CI. Local fixing commit `c1e9dfda1e7d4c87041b7272c0e7216c3cf9fe94` has exact message `garden` with body `26`; it is not yet pushed at this snapshot. The focused regression passes and all 118 Garden library tests pass, with no ignored tests. The same commit's real-node scenario rerun passes 18/18 in 121.82 seconds, and the real-NAT test passes 1/1 in 7.92 seconds. All stage exits are 0. Later final local source `2574882a`, also carrying the independent network fixes, passes 121/121 Garden library tests and the 18 scenarios on both Debian and Ubuntu userland; its Debian real-NAT test passes too. The source digest matches the committed invite file, and the production parser is not modified. A successful final-commit CI run is still required.
- Local evidence: `/home/user/validation/garden/3467a0ba/library.log` and `integration.log` retain the original results. `/home/user/validation/garden/invite-regression/` retains the proposed patch, source digest and subsequent test outputs. These local artifacts are not CI evidence.
