---
name: budlum-development
description: Use this skill for ANY work on budlum-xyz/budlum (the permissionless multi-consensus Rust L1) — writing or reviewing an Arena.ai round instruction, reviewing Arena's returned patches, debugging a CI/build/consensus/tokenomics failure, running parallel ARENA1/ARENA2/ARENA3 sessions, managing git worktrees/branches for a round, doing a security or architecture audit, or deciding whether to merge a PR. Covers the full round lifecycle (spec → plan → Arena execution → verification → review → finish), a full ADIM instruction template with a worked example, a detailed never-trust-the-summary review protocol, a 4-phase debugging protocol with named sub-techniques, parallel-agent dispatch mechanics, git worktree commands, an L1-specific security checklist with concrete Rust patterns, token-cost discipline, and an institutional-memory practice for carrying lessons across rounds. Trigger this even for "just write the next ADIM," "check if Arena's report is accurate," or "why did CI fail again."
---

# Budlum Development Skill

Self-contained methodology for directing development of **Budlum** (permissionless multi-consensus L1, Rust, hybrid PoW/PoS/BFT + isolated PoA domain) through the Arena.ai iterative-round workflow. This file consolidates and reworks practices distilled from five external references — an agentic-skills/software-methodology framework, a token-compression tool, a code-intelligence MCP server, a set of LLM-coding-pitfall principles, and a secure-coding skill — into Budlum's own vocabulary (ADIM, Turn, ARENA1/2/3, `budlum-main`, `budlum-xyz/budlumdevnet`). You should not need to consult those five originals again; everything actionable from them is reworked below with Budlum-specific detail, worked examples, and exact commands.

---

## 1. Core Engineering Principles

Four principles govern every instruction you write and every patch you review. They exist because LLM implementers — Arena's randomly-assigned model very much included — fail in these specific, predictable ways: silently picking an interpretation instead of flagging ambiguity, over-building, editing things nobody asked them to touch, and reporting success without having verified it. Every other section of this skill is really just these four principles made concrete for a Rust L1 codebase.

### 1.1 Think before instructing — surface assumptions, don't bury them

Before an ADIM goes out, write down every place the requirement is ambiguous and resolve it explicitly in the instruction text — don't leave it for Arena to guess, because it will guess silently and you won't find out until review. If a design choice is uncertain or economically significant, it goes to the user as an explicit option, never auto-decided.

*Example, bad:* "Implement the vesting schedule for team allocations."
*Example, good:* "Implement `VestingSchedule` with linear unlock over 24 months starting at genesis, cliff at month 6 (0% before cliff). If early transfer is attempted before full unlock, reject with `VestingError::LockedUntil(unlock_height)`. This is the base-`$BUD` schedule — do NOT apply the PoSV 2:1 Burn-Synchronized vesting variant here; that's a separate opt-in consensus module, out of scope for this ADIM."

The second version is longer, but it closes off every silent-assumption path the first version leaves open — cliff behavior, error type, and (critically, given Budlum's history) which tokenomics variant applies.

### 1.2 Simplicity first — minimum code that satisfies the spec

Ask for the smallest change that fully implements the requirement. No speculative generics, no config flags nobody requested, no trait abstraction for a type that will only ever have one implementation, no defensive branches for scenarios the spec never described. If Arena returns a 600-line patch for something that should have been 150, that is itself a review finding — flag it in the review notes even if the logic is otherwise correct, because unrequested surface area is unrequested attack surface and unrequested maintenance burden.

Concrete Rust smells to flag: a new trait with exactly one impl and no plan for a second; a `Config` struct with fields nothing reads; a generic `<T: SomeBound>` where only one concrete `T` will ever be passed; a builder pattern for a struct with three fields.

### 1.3 Surgical changes — the diff should trace to the ADIM, line for line

Every changed line in a returned patch should map to something the instruction actually asked for. Reformatting an untouched function, "cleaning up" adjacent code, reordering imports outside the touched file, or silently renaming a public function nobody asked to rename — all of these are reject-and-resubmit triggers, even when the core change is otherwise correct, because they hide the actual diff inside noise and make the next review harder.

The one exception: code that becomes genuinely orphaned *because of this ADIM* (an import, a helper function, a match arm that's now unreachable) should be removed as part of the same change. Pre-existing dead code that isn't in scope gets a one-line note in the review ("noticed unused `legacy_hash()` in `crypto/mod.rs`, out of scope, flagging for a future ADIM") — never deleted opportunistically.

### 1.4 Goal-driven execution — give Arena verifiable success criteria, not vague asks

Don't write "add validation" — write "add a test for negative `amount` in `transfer()` producing `Err(TxError::NegativeAmount)`, then make it pass." Don't write "fix the bug" — write "write a failing test that reproduces the double-burn on restart (restart the node mid-epoch with a pending burn, assert the burn counter is applied exactly once), then make it pass without breaking `test_burn_schedule_flat_rate`." Strong, testable success criteria let Arena iterate on its own and let you verify mechanically; weak criteria ("make tokenomics correct") produce guesswork on Arena's side and a full manual audit on yours — which is strictly more expensive than writing the precise criterion up front.

---

## 2. The Round Lifecycle

Every Turn/ADIM should visibly pass through these phases. Skipping one is exactly how integration gaps like Turn 8's `genesis_allocations()` wiring miss got through undetected until a dedicated audit caught it.

```
Spec/Design → Plan (ADIM breakdown) → Arena executes → Verify (you, not Arena) → Review → Merge / Next round
```

### 2.1 Spec / Design

Before writing instructions, resolve explicitly:
- **What subsystem, and is it really one unit of work?** If a request spans storage persistence *and* RPC exposure *and* tokenomics accounting, that is 2-3 separate ADIM sequences, not one. Bundling independent subsystems into a single ADIM is the single most common cause of a review missing something — the reviewer's attention is split across domains that don't share a mental model.
- **What already exists that this must integrate with.** Check `budlum-main` for prior art before assuming greenfield; a large fraction of Budlum's past integration gaps were "the new code duplicates or ignores something that already existed" rather than the new code being wrong in isolation.
- **What must be carried forward from prior turns**, stated explicitly in the instruction so Arena doesn't re-flag it as a discrepancy or, worse, "fix" it. The standing example: PoSV's declining/compounding annual burn schedule (100M→90M→81M…) and its 2:1 Burn-Synchronized team vesting are specific to the opt-in PoSV consensus module — they are NOT part of base `$BUD` tokenomics, and the flat-rate burn model is correct for the base layer. Any ADIM touching burn or vesting logic should state this distinction inline, every time, rather than assuming it's remembered.

### 2.2 Plan (ADIM breakdown)

Break the spec into ADIM units small enough that each is independently verifiable — roughly 2-5 minutes of focused implementation work each, not "implement the storage subsystem." For each ADIM, before finalizing the instruction:
- Map the exact file paths that will be created or modified. Decomposition decisions get locked in here — decide now which file owns which responsibility, don't leave it to Arena to decide module boundaries mid-implementation.
- Give each file one clear responsibility. If an ADIM's file list has a file doing two unrelated things, split the ADIM.
- Name the exact test(s) that must exist and pass — never "add appropriate tests." If you can't name the test yet, you don't understand the requirement well enough to hand it off.

Reject any ADIM draft containing placeholders — "TBD," "add appropriate error handling," "wire this up properly," "handle edge cases as needed." These are plan failures. A plan with a placeholder in it is not 90% done, it's an ADIM that will produce exactly the kind of silent gap Section 5 is designed to catch — better to not create the gap than to catch it later.

### 2.3 Arena Executes

No changes to this phase — Arena works, you wait. The only leverage you have here was already spent in 2.1/2.2: don't plan to clarify mid-round, because Arena can't ask follow-up questions the way a human collaborator would, and a mid-round clarification usually means the whole ADIM needs to be redone from the ambiguous point forward.

### 2.4 Verify — before you even open the review

**CI is the sole arbiter of push approval — not local verification, not Arena's self-report.** Before reading Arena's summary at all:
1. Pull the actual diff/patch files onto disk.
2. Confirm every test Arena claims to have added actually exists in the diff, and actually exercises the stated behavior — not merely present and trivially green (see Section 5 for how "trivially green" tests slip through).
3. Grep for integration wiring: a new function that's never called outside its own test, a config field that's never read, a struct that's declared but never persisted. This exact pattern produced all three of Turn 8's gaps — `genesis_allocations()` never wired into `GenesisConfig`/`build_state()`, `process_timed_burn()` never triggered during epoch transitions, and `VestingSchedule` lacking early-transfer enforcement. All three compiled, all three had adjacent tests, and all three did nothing at runtime.

### 2.5 Review

Apply Section 1's four principles as a literal checklist against the real diff — see Section 5 for the full protocol and a worked example.

### 2.6 Merge / Next Round

On acceptance: report test counts **per file**, never as one combined total — a single aggregate number hides which file's coverage is thin, and thin coverage in consensus or tokenomics code is a materially different risk than thin coverage in CLI formatting code. Write the next round's instruction with every carry-forward distinction made explicit per 2.1 — don't rely on Arena (or a future reviewer) remembering context from a prior round's conversation, since Arena sessions don't share memory across rounds and a human reviewer six turns later won't either.

---

## 3. Writing ADIM Instructions

### 3.1 Template

```
ADIM <n>: <one-line goal>

Context: <what exists now, what this must integrate with, any carried-forward
distinctions from prior turns that must NOT be re-flagged as discrepancies>

Scope: <exact files to create/modify — nothing else>

Task:
1. <step> → verify: <exact test name or command>
2. <step> → verify: <exact test name or command>
3. <step> → verify: <exact test name or command>

Non-goals: <explicitly out of scope, so Arena doesn't "helpfully" expand>

Decision points requiring approval before proceeding (if any):
<economically significant or genuinely uncertain choices — present as
options, do not auto-select>

Done when: <the precise, checkable condition>
```

### 3.2 Worked example

```
ADIM 14.6: Persist LivenessTracker state across restart

Context: LivenessTracker currently tracks validator liveness in-memory only
(src/consensus/liveness.rs). PermissionlessRegistry (src/consensus/registry.rs)
already persists via the StorageRegistry impl from Turn 14.5 — follow the same
manifest.rs pattern for consistency rather than inventing a second persistence
mechanism. Tokenomics burn counters (src/tokenomics/burn.rs) must be restored
in the SAME atomic transaction as LivenessTracker state if both changed in
this epoch — restoring them independently risks a double-burn on restart,
which is a mandatory test requirement, not a nice-to-have.

Scope:
- src/consensus/liveness.rs (add persistence hooks)
- src/storage/manifest.rs (register new liveness section)
- tests/liveness_persistence.rs (new file)

Task:
1. Add `LivenessTracker::to_bytes()` / `from_bytes()` using the same encoding
   as `PermissionlessRegistry` (bincode, versioned header)
   → verify: test_liveness_roundtrip_encoding
2. Wire persistence into the existing StorageRegistry commit path in
   manifest.rs, in the same transaction as burn-counter persistence
   → verify: test_liveness_and_burn_commit_atomically
3. Add restart simulation: persist mid-epoch, restart, assert liveness state
   AND burn counters match pre-restart values exactly (not just liveness)
   → verify: test_restart_no_double_burn_with_liveness

Non-goals: Do not modify PermissionlessRegistry's own persistence format.
Do not add configurability for the encoding scheme — bincode only, matching
existing convention.

Decision points: none — this follows an established pattern, no new design
decisions required.

Done when: `cargo test -p consensus liveness` passes (3 new tests), and
`cargo test -p tokenomics` still passes unchanged (no regression in existing
burn tests), under the pinned rust-toolchain 1.94.0.
```

Notice what this worked example does that a vaguer instruction wouldn't: it names the exact double-burn risk before Arena can rediscover it the hard way, it points at an existing pattern to copy instead of leaving module-boundary decisions open, and its "done when" is a command you can literally run rather than a description you have to interpret.

---

## 4. Test-Driven Verification Steps

Every "verify:" line in an ADIM should follow red-green discipline, because a test written *after* the implementation tends to test what the code does rather than what it should do:

1. The instruction should imply the test is written to fail first (against the pre-ADIM code), confirming it actually exercises the new behavior.
2. Only then does the implementation make it pass.
3. If Arena's returned patch shows a test and implementation landing in the same commit with no evidence the test was ever run against pre-change code, treat that as a review flag, not an automatic pass — a test that has never been observed to fail is unproven, regardless of whether it's green now.

For refactor-only ADIMs (no behavior change intended), the standing requirement is: existing tests must pass unchanged both before and after, with zero test modifications — if a "pure refactor" ADIM's diff touches test files, that's a signal the refactor wasn't actually behavior-preserving, and it needs to be reviewed as a behavior change, not rubber-stamped as a refactor.

---

## 5. Reviewing Arena's Output — Never Trust the Summary

This is the highest-leverage habit in the whole workflow, because Arena's self-report and Arena's actual patch are two different artifacts, produced by two different processes, and only one of them is ground truth.

### 5.1 Protocol, in order

1. **Read the actual code and patch files.** Not the Arena summary. The summary is a hypothesis about what the patch does; the diff is the fact. Never let the summary set your expectations before you've looked — anchor on the diff first, then check the summary against it, not the other way around.
2. **Re-derive a checklist from the original ADIM** — don't reuse Arena's checklist, since a self-generated checklist inherits the same blind spots as the self-report. Verify each ADIM task item against the diff independently.
3. **Check every "wired in" claim by finding the actual call site.** Search for real invocations: is the new function called anywhere outside its own tests? Is the new config field read anywhere at runtime? Is the new state field persisted *and* restored on the same path other related state uses? This single check would have caught all three Turn 8 gaps and the `verify_pop()` finding (a correctly-implemented BLS proof-of-possession check with zero non-test callers — meaning proof-of-possession isn't actually enforced anywhere in the live path, despite the function existing and being "correct").
4. **Check test-to-claim correspondence, not just test-to-file correspondence.** A test file existing is not the same as the test covering the claimed behavior — open the test and read the assertions. A test named `test_double_burn_restart` that only asserts the node doesn't panic on restart, without checking the actual burn counter value, is a false sense of coverage.
5. **Report test counts per file**, and flag any file where coverage looks thin relative to its risk class. Consensus, tokenomics, and network-input-handling code need denser coverage than CLI formatting or logging code — a review that treats all files as equally covered by "N tests added" is missing the risk-weighting that matters.
6. **If 3+ review rounds keep finding new gaps in the same subsystem**, stop patching symptom-by-symptom and raise explicitly with the user whether the underlying design needs to change. This is an architecture conversation, not another ADIM — see Phase 4.5 in Section 6.

### 5.2 Rationalizations to reject when they show up in your own reasoning

These are the exact failure modes that let bugs through the review step itself — not Arena's failures, yours:
- *"Tests pass, so the phase is complete"* → re-check what the tests actually assert, not that they're green.
- *"Arena said it wired this up"* → find the call site yourself; a claim is not a citation.
- *"This is probably fine, it's a small change"* → small changes are exactly where undisclosed scope creep and drive-by edits hide, because they don't get the scrutiny a large change does.
- *"CI passed last round, this round should be similar"* → CI logs may be inaccessible (Azure blob TLS/SSL blocked from sandbox has already forced manual git-history reconstruction once); passing CI on a *different* commit proves nothing about this one.
- *"The diff is huge, I'll skim it"* → a huge diff for a supposedly-narrow ADIM is itself the finding (see Section 1.2); skimming it is how the actual finding gets missed.

### 5.3 Review report shape

Keep the output structured so gaps are visible at a glance rather than buried in prose:

```
ADIM <n> Review

Tasks verified:
1. <task> — PASS/GAP: <evidence — file:line, or "no call site found">
2. <task> — PASS/GAP: <evidence>

Test counts:
  src/consensus/liveness.rs: 3 new tests
  src/storage/manifest.rs: 1 new test
  tests/liveness_persistence.rs: 2 new tests

Surgical-change check: <clean / N unrelated lines touched, listed>
Security checklist items re-triggered by this diff: <list from Section 10, or "none">

Verdict: ACCEPT / ACCEPT WITH FOLLOW-UP ADIM / REJECT — <one-line reason>
```

---

## 6. Systematic Debugging Protocol

Apply this whenever a CI failure, compile error, or unexpected consensus/tokenomics behavior shows up. Do not propose a fix before Phase 1 is complete — this is a hard gate. Violating the letter of this process (skipping ahead because "it's probably X") is violating the spirit of it just as much as skipping it outright.

### Phase 1 — Root Cause Investigation (mandatory before any fix)

- Read the full error/stack trace, not just the first line — errors often contain the exact solution if read completely. Note exact file paths and line numbers.
- Reproduce reliably. Identify exact steps to trigger the issue every time. If it isn't reproducible on demand, gather more data (logs, a minimal repro case) rather than guessing at a fix — a fix for a bug you can't reproduce is a fix you can't verify.
- Check recent changes: `git diff`/recent commits/dependency or toolchain-version changes. Budlum has a known, recurring failure class here: rustfmt/clippy drift against the **pinned `rust-toolchain 1.94.0`**. Code that is correct by hand can still fail CI formatting checks after several merge rounds if the local toolchain has drifted. Always run `cargo +1.94.0 fmt` and `cargo +1.94.0 clippy --all-targets` locally against the *pinned* toolchain before assuming a formatting fix is correct — don't guess formatting by hand, and never work around this with a permissive `rustfmt.toml`, since that weakens the CI ratchet rather than fixing the actual drift.
- For multi-component failures (something breaking between, say, the network layer and the consensus layer), trace data at each component boundary: log what enters, log what exits, verify environment/config propagation, check state at each layer. Run once to gather evidence showing *where* it breaks, then analyze that evidence to identify the failing component, then investigate that specific component — don't shotgun-debug across every component simultaneously.

### Phase 2 — Pattern Analysis

Once you know where it breaks, determine why. Is this a known class of bug for this codebase — an `unwrap()`/`expect()` on unchecked input in storage/execution/mempool code, an integer overflow in tokenomics math, a race condition in async network handling, a double-application of a state transition on restart? Check whether the same pattern exists elsewhere before fixing only the one instance you found.

### Phase 3 — Hypothesis Testing

Form a specific, falsifiable hypothesis. Write a test that would fail under the hypothesis and pass once the fix is correct — *before* writing the fix itself. If you can't state a test that would distinguish "hypothesis correct" from "hypothesis wrong," the hypothesis isn't specific enough yet.

### Phase 4 — Implementation

Fix the root cause, not the symptom. The fix must ship with the Phase 3 test. If the fix requires touching more than the files implicated by Phase 1's evidence, that's a signal to re-check the hypothesis, not a reason to expand scope quietly.

### Phase 4.5 — Architecture check

If 3+ fix attempts on the same issue have failed, that is not "try again with a different fix" — it's a signal the underlying architecture may be wrong. This is NOT a failed hypothesis to iterate past; it's a wrong-architecture signal. Stop and raise it explicitly with the user before attempting a fourth patch.

### Named sub-techniques

- **Root-cause tracing:** trace a bug backward through the call stack from where it manifests to where it originates — the manifesting location and the causing location are frequently different files, and fixing the manifesting location alone just moves the symptom.
- **Defense in depth:** once the root cause is found and fixed, add validation at the layer(s) above it too — not as a substitute for the root-cause fix, but so a similar-but-not-identical bug can't recreate the same failure through a slightly different path.
- **Condition-based waiting:** when a race condition surfaces as a flaky test, the fix is event-based waiting (poll for the actual condition), never an arbitrary `sleep`/timeout increase. Increasing a timeout is a Phase-1-violation red flag, not a fix — it hides the race without resolving it.

### Red flags that mean "STOP, return to Phase 1"

About to patch a symptom without understanding why it happens; increasing a timeout instead of finding a race; adding a special case instead of fixing the general logic; 90% confident but haven't actually reproduced it. All of these mean stop, don't ship the fix, go back to Phase 1.

**On speed:** systematic debugging is faster than guess-and-check thrashing over the life of an issue, even though a single well-investigated fix can feel slower than an immediate guess — the guess-and-check path's apparent speed is an illusion once you count the review round it takes to discover the guess was wrong.

---

## 7. Parallel Agent Coordination (ARENA1 / ARENA2 / ARENA3)

**Core rule: dispatch one agent per independent problem domain, and only when the domains are genuinely independent.** If two potential parallel streams would touch the same files or the same shared state (e.g. both touching `GenesisConfig`, or both modifying `manifest.rs`), they are not independent — sequence them instead. A merge conflict between two Arena streams is not just an inconvenience; it's a silent risk that one stream's fix quietly reverts or shadows the other's.

### 7.1 Before splitting work

Confirm via `ARENA_AI.md` / `STATUS.md` / `STATUS_ONLINE.md` that each stream's file scope doesn't overlap another active stream's declared scope. If two ADIMs both list a file in their Scope section, that's the signal to sequence rather than parallelize — resolve this before dispatch, not after both streams report done.

### 7.2 Dispatch

Give each stream a fully self-contained ADIM (Section 3 template). A parallel stream has no access to another stream's conversation context and can't ask a clarifying question mid-flight the way a human collaborator would — nothing can be implied, everything actionable must be explicit in that stream's own instruction, including any Section 1.1-style carried-forward context.

### 7.3 Aggregation

Each stream reports back independently. Do not let one stream's "done" status imply another's readiness — apply the full Section 5 review protocol per stream before considering the combined result mergeable. Then, specifically because the streams were parallel, re-check for interaction effects the individual reviews couldn't have caught: did ARENA1's change to a shared type's default value silently change behavior ARENA2's code depends on?

### 7.4 Standing constraint

`budlum-xyz/budlumdevnet` is reference-only across every stream — no stream ever modifies it, regardless of what any instruction implies or what would be "more consistent." If an ADIM ever seems to ask for a `budlumdevnet` change, that's a drafting error to fix before dispatch, not an instruction to follow.

---

## 8. Workspace Isolation

Each active round/stream works in its own isolated branch or worktree so a mid-flight ARENA2 change can't clobber ARENA1's uncommitted state.

```
# before starting a stream: confirm a clean baseline on the fork point
git status                       # must be clean
git worktree add ../budlum-arena2 -b arena2/adim-14-6 main

# work happens inside ../budlum-arena2 in isolation

# on completion, from the main worktree:
git -C ../budlum-arena2 log --oneline -5     # sanity-check what actually landed
git worktree remove ../budlum-arena2         # only after merge/push is confirmed
```

Only clean up a workspace that this workflow created — never remove or repurpose a worktree/branch that predates the current round, and always `cd` back to the repo root before `git worktree remove` (removing from inside the worktree being removed is a common source of silently-failed cleanup).

Given Codespaces is disabled at the org level (a known, recurring delivery blocker for browser-based push from limited devices), plan each round's push path around whatever's actually available on the device in use that day — don't default to assuming Codespaces access will be there.

---

## 9. Finishing a Round or Branch

When a round's work is verified and ready, the options are, in order of preference:
1. **Merge directly** (if this stream owns the target branch outright and CI is green on the exact commit).
2. **Open a PR** (if review by another party, or a merge queue, is required) — use whatever the forge's own tooling provides (CLI or the URL printed on push), not a specific blessed tool.
3. **Keep the branch** (if the work is verified but intentionally not ready to merge yet — e.g. waiting on a decision point from Section 3's template).
4. **Discard** — only on explicit request, and only with an explicit typed confirmation from the user before deleting anything; this is the one irreversible option and should never be inferred from context.

Never treat "task finished" or "push approved" as a stopping point on its own — for the ADIM-based workflow, finishing one ADIM is the trigger to move to the next ADIM automatically, not a natural pause, unless a genuine decision point (Section 3) requires the user first.

---

## 10. Security Review Checklist for an L1 Blockchain

Generic secure-coding checklists are written for web apps (XSS/CSRF/session cookies) and mostly don't transfer to a P2P consensus system. Adapt the underlying discipline instead — defense in depth, fail closed by default, least privilege, never trust externally-supplied input, checklist-driven review by category — to these blockchain-specific categories:

### 10.1 P2P / network input handling
Every deserialization path for peer-supplied data must have an explicit size/length bound checked *before* any allocation proportional to that length happens. This is exactly the class of bug the prior audit found in `network/node.rs`'s SnapshotChunk handling: unbounded memory allocation driven by unauthenticated remote input — a DoS vector requiring no privilege at all. Concretely: any `Vec::with_capacity(n)`, `vec![0u8; n]`, or buffer pre-allocation where `n` comes from a peer message must have `n` checked against a hard maximum *first*. Malformed or oversized messages must fail closed (drop the connection / reject the message) rather than partially process. Re-check this category on every diff touching `network/`, `p2p/`, or any wire-format deserialization, since a refactor can reintroduce a structurally identical unbounded-allocation path even after the original instance is fixed.

### 10.2 Consensus safety invariants
For hybrid PoW/PoS/BFT plus the isolated PoA domain: verify state transitions can't be forged or replayed across the domain boundary — a message or state transition valid in the PoA domain must not be independently valid in the permissionless domain just because the underlying struct is shared. Confirm `LivenessTracker` and `PermissionlessRegistry` persist and restore state atomically, in the same transaction as any tokenomics counters affected in the same epoch — partial restore of related counters (one restored, the related one not) is a correctness bug, not a style issue, and it's exactly the shape of the double-burn risk flagged as a mandatory test requirement.

### 10.3 Economic / tokenomics invariants
Burn, mint, and vesting logic must be checked for: (a) double-application on restart, (b) integer overflow/underflow in supply math — prefer `checked_add`/`checked_sub`/`saturating_*` over raw arithmetic on any balance, supply, or burn-counter type, and treat a raw `+`/`-` on these types as a review flag by default. Any consensus-specific tokenomics variant (PoSV's declining-burn schedule and 2:1 Burn-Synchronized vesting) must stay clearly scoped to its own module so it can't leak into, or be confused with, base-layer `$BUD` tokenomics — see Section 2.1's standing carry-forward note.

### 10.4 Key management / signatures
An implemented-but-uncalled verification function is a real finding, not a false positive. The standing example: `verify_pop()` (BLS proof-of-possession) is correctly implemented but has zero non-test callers — meaning proof-of-possession isn't actually enforced anywhere in the live validator-registration path, despite the function existing and being correct in isolation. Grep for actual call sites on every signature-verification function, every round, not just when it's first introduced — a later refactor can silently drop the call site while leaving the function itself untouched and "working."

### 10.5 RPC / API surface
Every RPC method needs authentication and rate-limiting depth explicitly checked, not assumed from framework defaults. This category was explicitly deferred in the last audit — treat it as still-open until specifically verified, not cleared. When reviewing any new or changed RPC method: confirm what auth check runs before the handler body, and confirm there's a rate limit that would actually trigger under a realistic abuse pattern (not just a limit that exists in config but is never read — see 10.6 for the general pattern).

### 10.6 Storage / state persistence
Every `unwrap()`/`expect()` in storage, execution, and mempool code is a potential panic-on-attacker-input path. This was explicitly deferred, not cleared, in the last full audit — don't assume a passing test suite covers it, since tests exercise expected inputs by construction and this category is specifically about unexpected ones. When reviewing a diff that adds a new `unwrap()`/`expect()` in these three modules, ask explicitly: can this value ever come from network or user input? If yes, it needs a `Result`-returning path with an explicit error variant instead.

### 10.7 Build & supply chain
`Cargo.lock` CVE scanning is a standing to-do, not a one-time check — re-run it whenever dependencies change, not just after a fresh audit request. A blocking build failure like the 23-compile-error `AccountState` struct refactor regression must be caught locally (`cargo build --all-targets` against the pinned toolchain) before it reaches CI, not discovered there — a compile failure discovered in CI on a multi-ADIM round is expensive to isolate after the fact.

### 10.8 HSM / PKCS#11 module
Anything touching the PKCS#11 HSM integration module needs its own dedicated review pass — this was explicitly out of scope for the general audit and must never be assumed covered by it. Treat any diff touching this module as requiring the full Section 5 protocol plus a specific check that key material never crosses into non-HSM code paths, even transiently.

### 10.9 Standing rule across all categories
Treat every item above as "open until specifically re-verified this round," never "checked once, done forever." Code changes elsewhere can silently reintroduce a closed finding — a refactor of the network layer months after the SnapshotChunk fix can add a new, structurally identical unbounded-allocation path without anyone thinking of it as "the same bug."

---

## 11. Token & Cost Efficiency Practices

Arena rounds and review cycles are token-expensive by nature (no spending limit is set for Arena agents, but thoroughness over speed doesn't mean waste). Two structural habits reduce cost without reducing rigor:

1. **Prefer structural/targeted code lookups over full-file dumps when investigating the Rust codebase.** When the question is "where is X called," "what implements trait Y," or "what's the call graph around Z," a targeted structural query is far cheaper than grepping or reading whole files one at a time — the gap compounds fast on a large multi-crate Rust workspace, where a single "where is this used" question can otherwise mean reading dozens of files. If a code-intelligence/indexing tool is available in the environment, prefer it for structural questions; fall back to direct file reads only when you actually need to read implementation logic, not just locate it.
2. **Compress verbose tool output before it enters the review context.** CI logs, full multi-file patch diffs, and Arena's raw session transcripts are usually far longer than the signal they contain. Extract only the relevant sections — the failing test's actual output, the specific hunks touching in-scope files — before reasoning over them at length. This matters especially given the recurring CI-log-access problem (Azure blob TLS/SSL blocked from sandbox has already forced manual git-history reconstruction once); don't compound an already-expensive manual-reconstruction situation by re-reading the same verbose material multiple times across a single review.

Neither habit should ever mean skipping a Section 5 verification step to save tokens — the goal is cheaper *inputs* to the same rigor, never less rigor for a lower token count.

---

## 12. Institutional Memory Across Rounds

Budlum's own handover reports (e.g. `docs/DEVIR_RAPORU.md` from Turn 14.9) already do this instinctively — formalize it as a standing practice rather than an occasional one:

- When a round surfaces a root cause that could recur (the rustfmt/clippy toolchain-drift pattern; a CI-log-access blocker; a "code exists but is never called" gap), write it down in a persistent lessons file, not just in that round's own instruction or review notes — a lesson that only lives in one Turn's conversation is a lesson the next round has to rediscover from scratch.
- When a multi-round handover happens (a stalled merge, a blocked delivery path, a carried-forward tokenomics distinction), the handover doc should state not just *what* is unresolved but *why the previous attempt didn't land* — Turn 14.9's finding that Turn 14.5's storage implementation never made it into the merged PR after 7+ rounds was a toolchain-drift problem, not a code-quality problem, and stating that explicitly is what let the next instruction target the actual cause (run `cargo fmt`/`clippy` locally against the pinned toolchain) instead of re-attempting the same merge blindly.
- Prefer updating one standing lessons/handover document over scattering the same insight across many individual ADIM instructions — the next person (or next Arena round) writing an ADIM should be able to find "known recurring failure modes" in one place rather than needing to have read every prior Turn's transcript.

---

## 13. Quick Reference Checklists

**Before sending an ADIM:**
- [ ] Scope is one coherent unit of work, not several subsystems bundled together
- [ ] Every task has an explicit, checkable "verify:" condition — no vague asks
- [ ] Carried-forward context/distinctions from prior turns are stated explicitly (Section 2.1)
- [ ] Uncertain or economically significant decisions are presented as options, not auto-decided
- [ ] No placeholders ("TBD," "add appropriate X," "handle edge cases as needed")
- [ ] File scope doesn't overlap any other currently-active parallel stream (Section 7.1)

**Before accepting Arena's output:**
- [ ] Read the actual diff/patch — not the summary
- [ ] Re-derived checklist from the original ADIM, checked independently
- [ ] Every "wired in" claim has a confirmed call site (grep, don't trust)
- [ ] New/changed state persists and restores atomically with related state — no double-counting
- [ ] Test assertions actually check the claimed behavior, not just that the test file exists
- [ ] Test counts reported per file, risk-weighted (consensus/tokenomics/network-input > everything else)
- [ ] Ran `cargo fmt`/`cargo clippy` against the pinned `rust-toolchain 1.94.0` — not hand-guessed formatting
- [ ] Section 10 security items re-checked for anything this diff touches
- [ ] CI is green on this exact commit — not inferred from a prior round's green CI

**Before merging / finishing a branch:**
- [ ] All of the above are checked
- [ ] Merge/PR/keep/discard decision matches Section 9 — discard only with explicit typed confirmation
- [ ] Any recurring-failure-mode lesson from this round is written into the standing lessons/handover doc (Section 12), not left only in this round's own notes

If any box is unchecked, the round is not done — regardless of what Arena's report says.


---

## Ortam ve Araclar (2026-07-31 guncel)

Bu bolum eski "ARENA1/ARENA2/ARENA3 worktree" kurulumunun yerini alir. O model
yerel klon + paralel oturum varsayiyordu; artik calisma **GitHub API uzerinden**
yurutuluyor ve workspace minimumda tutuluyor.

### Calisma modeli

| Eski | Simdi |
| :--- | :--- |
| `git clone` + worktree | GitHub Contents/Git Data API |
| yerel `cargo test` | CI job log'undan `test result:` okumak |
| yerel branch | `POST /git/refs` ile dogrudan branch |
| yerel commit | `git/blobs` -> `git/trees` -> `git/commits` -> `PATCH ref` |

Sebep: `.git`, cargo/rustup, `/tmp` her turda sifirlaniyor. Yerel derleme 5-10
dk, CI zaten ayni isi yapiyor. Workspace 201M -> 78M dustu.

**Yerel klon yalniz tarama icin:** `tarball/main` indir, `src/` uzerinde grep
yap, isin bitince sil. Derleme yok.

### Kurulu araclar

**Spec Kit** (`specify`, v0.15.0) — `pip3 install --user specify-cli==0.15.0`.
PATH `.profile` icinde. 10 skill `.claude/skills/` altinda: constitution,
specify, plan, tasks, implement, analyze, checklist, clarify, converge,
taskstoissues.

Bulgu avinda en kullanisli olan `speckit-constitution`: repoda fiilen isleyen
kurallari, her birini **zorlayan mekanizmayla** eslestirerek yaziya dokuyor.
Prosedurun degerli kismi dogrulama adimi — her sayiyi, onu ureten kapinin kendi
komutuyla uretmeyi zorunlu kiliyor (bkz. H5).

**codebase-memory-mcp** (v0.9.0) — `pip3 install --user codebase-memory-mcp`.
**Bu ortamda calismiyor:** indeksleyici 1.9 GB RAM'de (496 MB butce) her
denemede `exit_nonzero` ile cokuyor, 941 KB'lik alt dizinde bile. Arac hatasi
degil, ortam kisiti. Yerine hedefli `grep` taramalari kullaniliyor; grafik
sorgusu gerektiginde GitHub code search API isi goruyor.

### Zorunlu taramalar (H1/H2/H6 dersleri)

Bunlar hack haberine bagli degil, her turda calisir:

1. **Para akan her yerde taban var mi** — `fn .*(fee|reward|burn|payout|share|cut)`
   ve tamsayi bolmesi. Tabansiz yuzde, kucuk miktarlarda sifira yuvarlanir.
2. **Sabit kodlanmis ekonomik oran** — yonetisimle degistirilemeyen her oran.
3. **Ayni sabitin kopyalari** — ve **birden fazla yazimla**: `saturating_mul` /
   `checked_mul` / `wrapping_mul` / duz `*`; bolen tarafinda `/ 100` /
   `/ FIXED_POINT_SCALE` / `/ PPM_DENOMINATOR`. Tek yazimla arama 5 kopyanin
   3'unu bulur (H6).

### 4 paralel blok

Bagimsiz her is ayni `bash` blogunda gider: CI durum sorgusu, kod taramasi,
skill calistirma, web arastirmasi. Hicbiri digerini beklemiyor. Bunu birakmak
H7'de kayitli.
