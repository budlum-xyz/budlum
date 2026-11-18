# B-0052 / BLG-270: host-approval admission grants the host extra authority

- Location: `src/garden/types.rs:153-159,182-185`, `src/garden/service.rs:51-53,75-81`, `src/garden/state.rs:643-654,668-681`, and the production operator RPC route exercised by `tests/garden/garden_scenario.rs:1194-1321`. Inspected final local source: `2574882aa35d4f3787e53aa1911af7b20df6b760`; the same paths and behavior exist on fetched remote Garden `3467a0bababb7648c75631173228d460da935485`.
- Severity: medium, authorization-policy and decentralization requirement violation. It is not an authentication bypass: the implementation deliberately reserves an extra power for the host.
- Requirement: Garden directive section 3.3 says the host has no authority beyond being the first validator. Every participant is a validator, and invitation is the specified admission mechanism. Section 4.4 excludes validator classes.
- Faulty lines:

  ```rust
  "host_approval" => Ok(Self::HostApproval),
  ```

  ```rust
  GardenAdmission::HostApproval => {
      // ...
      GardenValidatorStatus::Waiting
  }
  ```

  ```rust
  if sender != host {
      return Err("only the host admits a key that waits".into());
  }
  ```

- What happens: the founder may choose `admission: "host_approval"` through the normal create API. A valid invite then only permits a waiting record, without a vote or publication rights. A host-signed `GardenTxKind::Admit` transaction decides whether that participant becomes a validator or is turned away. Other validators cannot make that decision. The decision is applied through a block, but block inclusion does not remove the host-only authority.
- Actual reproduction: on Debian 13.7 and configured-DNS Ubuntu Base 24.04.5 userland, final-source `cargo test --test garden_scenario -- --test-threads=1` (or the copied scenario executable) passes `garden_host_approval_admits_only_whom_the_host_accepts`. The test creates an ordinary production Garden with the option, joins two real node processes using the invite, observes both as `Waiting` and only the host as active, observes an ordinary participant's `bud_gardenAdmit` refusal, and then has the host accept one key and reject the other. This passing test proves the prohibited authority is reachable; it is not acceptance evidence for section 3.3. The respective full scenario runs pass 18/18 in 120.92 and 121.12 seconds. The Ubuntu executable is Debian-built and shares the host kernel; no Ubuntu-native build is claimed.
- Impact: a participant may hold a valid shared invite but be censored by one actor, and participants have unequal admission authority. The default `direct` mode does not erase the additional reachable mode. Existing positive tests enforce the conflicting behavior and therefore cannot be treated as proof of compliance.
- Repair plan: remove host-only admission from the supported Garden policy without weakening invite signatures, capacity/rate limits or block-only state changes. Reject a host-approval founding configuration and a received host-authoritative genesis at the common validated boundary, or remove the unsupported mode comprehensively. Treat its wire discriminants explicitly so an old or forged value cannot silently change meaning. Refuse host-only admission transactions for every key. Update the affected library and real-process tests to assert equal admission authority, including valid-invite joins while the host does nothing, host/non-host attempts to exercise extra powers, old mode/genesis rejection, capacity limits and ordinary lifecycle preservation. Coordinate any required shared gate or RPC documentation changes under the additive-path rule rather than deleting checks to obtain a pass.
- Evidence: `/home/user/validation/garden/final-network/garden-scenario.log`, `/home/user/validation/os/ubuntu-24.04/scenario-after-configured-dns.log`, with source/executable digests in the adjacent provenance files. Source paths above are read directly before writing this record.
- Status: open. No policy fix is applied in the current source. Passing tests for the old host-approval behavior must not be relabeled as a fix, and no final-SHA green CI or independent approval exists.
