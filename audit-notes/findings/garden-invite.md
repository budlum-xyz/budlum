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
- CI evidence for the diagnosis: job `134729279818` (`Budlum Core library test`) on `3467a0ba` completed 2026-11-18T13:11:35Z with `test result: FAILED. 6035 passed; 1 failed; 3 ignored` and `panicked at src/garden/invite.rs:354:9: assertion failed: GardenInvite::parse(&short_chain).is_err()`. Job `134729280004` (`Coverage (nextest + llvm-cov, ratchet)`) failed on the same test at 13:27:08Z; the coverage job runs the same suite and aborts on the first failure, so both red checks on that revision are one defect, not two.
- Second attempt on `garden`, `3bc477a0 fix(garden): make non-canonical short_chain invite test deterministic`, is also a no-op. It renders `g.chain_id >> 4`, which is 16 hexadecimal digits rather than 15, because only the low 48 bits of a Garden id are variable and the `0x4741` prefix survives the shift at the top of the word. `replacen` again finds nothing shorter to write, so the line is unchanged. Any fix built by shifting or masking the id has to be checked for width before it is trusted.
- Current status: fixed on `garden` in `48a04fab` and awaiting CI. The test now drops the id's always-zero leading digit to build a real 15-character field, and asserts `assert_ne!` between the canonical and mutated lines before the rejection assertion, so a mutation that changes nothing fails loudly instead of silently inverting the test. Measured locally on this host: with the old text the test fails at `src/garden/invite.rs:355` with exactly the CI assertion; with the fix all six `garden::invite` tests pass, `cargo fmt --all -- --check` is clean, and `cargo test --lib garden::invite --no-run` exits 0. PR #164 has not yet been re-run against this commit.
- Wider repair still outstanding: the note's scope for full field coverage (empty, one-short, one-long, signed, nonhex, uppercase for chain, genesis and token, each asserting a field-specific canonical-format error) is larger than a one-line unblock. Only `chain` short, `chain` signed and `token` uppercase are covered today. The parser's length and lowercase checks for `genesis`, and the `+`-signed and nonhex cases for `genesis`, remain unexercised.

- Local evidence: `/home/user/validation/garden/3467a0ba/library.log` and `integration.log` retain the original results. `/home/user/validation/garden/invite-regression/` retains the proposed patch, source digest and subsequent test outputs. These local artifacts are not CI evidence.
