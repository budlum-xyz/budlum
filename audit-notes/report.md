# Budlum audit report — 2026-11-16

## Scope and method

Live GitHub state 2026-11-16, repo budlum-xyz/budlum, identity lubosruler.
Directives read: THE_BUDLUM_DIREKTIF (6044 lines), BUDLUM_DENETIM_DIREKTIFI, BNS_DIREKTIF, garden_direktifi, PLAN (1063-file checklist).
Method: Strix imitation — attack surface, end-to-end code path trace, test/prove each claim. Skills installed (see below) are the working method, not a substitute for CI.

## What was done in this pass

1. `.netrc` — user's txt token converted to netrc format without exposing content in chat, mode 0600, at `~/.netrc` (excluded from workspace snapshots by design; git credential helper reads it). Git identity set to Lubo's Ruler <ayazkussann@gmail.com> (primary email from GitHub API).
2. Repo cloned, all branches fetched. Rust 1.97.1 installed (rust-toolchain.toml pin), protoc installed via apt (CI uses 29.3 from GitHub; apt 3.21.12 worked for uel-abi build in this pass — version drift noted).
3. Skills cloned to `budlum-work/skills/`: mattpocock/skills, obra/superpowers, affaan-m/ECC, usestrix/strix. See `skills-install.md` for per-repo install notes. ECC is 105 MB; kept shallow clone.
4. Live PR/CI/Strix inventory — see `strix-ledger.md`. 3 open PRs in a stack: #126 testnet->main, #164 garden->testnet, #183 budlum-stack->garden.
5. PR #183 conflict diagnosed and resolved locally in a merge worktree (`/tmp/budlum-merge-test`, merge of origin/garden into origin/budlum-stack): 4 conflict files, semantic merge combining both sides (see `findings/pr183-conflict.md`). `cargo fmt --check` clean on merged tree. Full `cargo check --lib` for budlum-core OOM-killed (SIGKILL) in this 1.9 GB / 2-core sandbox — see Local verification. Merge commit not yet pushed in this pass; push is next step after low-memory check completes or CI is used as validator.
6. Testnet Rehearsal failure root-caused (AppBinding, step 9) — see `findings/appbinding-rehearsal.md`. No fix pushed yet; options recorded, PoW-gate weakening explicitly not recommended.

## Testnet readiness verdict

**NOT READY.** Do not claim testnet ready.

Blockers:
- PR #126: Strix failure (required check), 5 unresolved Strix threads, Testnet Rehearsal real failure (AppBinding step 9), CI queued/in_progress saturation.
- PR #164: 20 unresolved Strix threads, CI queued.
- PR #183: merge conflict (dirty), 86 cancelled checks (no CI signal), 4 unresolved threads.
- Strix billing limit (50 reviews) blocks new Strix reviews and therefore `main` merge (required check).
- Local full-core build/test impossible in this sandbox (OOM) — CI is the only validator for budlum-core; small crates verified locally (see below).

## Local verification (this sandbox, Debian 13 x86_64, 1.9 GB RAM, 2 cores)

- `cargo fmt --all -- --check` on merged PR #183 tree: clean.
- `cargo check -p budlum-types -p budlum-note-packing`: pass (1.25s, cached deps).
- `cargo check --lib` (budlum-core, 470k lines): rustc SIGKILL (OOM) after ~10 min with CARGO_BUILD_JOBS=2, debuginfo=2. Retry with debuginfo=0, codegen-units=16, jobs=1 in progress at time of writing — see `findings/local-build.md` for alternatives researched (CI runners, sccache, split-crate, cross, docker/podman — none available locally except CI).
- No multi-OS test run in this pass. PLAN lists 11 OS targets; only Debian 13 x86_64 is available here. macOS/Windows/Android/iOS/Miri/Fuzz/Docker scenarios are CI-only; see `testnet/index.md`.

## Skills installation

See `skills-install.md`. All four repos cloned shallow; no plugin marketplace install (Claude Code/Codex/Copilot CLIs not present in sandbox). Skills are read as working principles: mattpocock (small composable engineering skills), superpowers (TDD, spec->plan->subagent workflow), ECC (agent harness, commands/agents), Strix (pentest method + CLI via uv/pip — not installed as binary in this pass, method imitated manually).

## Next steps (in order)

1. Finish low-memory cargo check for merged PR #183; if it passes, commit merge on `budlum-stack` and push (identity lubosruler), then rerun cancelled CI jobs. If it OOMs again, push anyway and let CI validate — directive says CI is sole validator, local OOM is not a code failure.
2. Fix PR #183 unresolved findings (repair share MEDIUM, duty-lane LOW, CodeRabbit mobile store) on `budlum-stack`, with tests that fail before / pass after.
3. Decide + implement AppBinding rehearsal fix on `testnet` (PR #126): enable on Testnet + non-PoW domain CLI, or skip scenario with proof. Do not weaken PoW anchor gate.
4. Fix PR #126 unresolved (identity_profile Verified, NFT squat, view receipts cap) and PR #164 Garden net.rs findings, each on its PR branch, each with test.
5. Upgrade Strix billing or accept that `main` merge is blocked; request Strix re-review after fixes.
6. Run full test matrix via CI (fmt, clippy -D warnings, test, CodeQL, Zizmor, Gitleaks, cargo-audit/deny, Semgrep) and Testnet Rehearsal until green. Only then claim testnet ready with commit SHA + CI run numbers.

## Rules observed

No new `#[allow]`, no `#[ignore]`, no force-push, no history rewrite, no branch-protection bypass. No finding closed by comment. Token never committed, never printed in report.
