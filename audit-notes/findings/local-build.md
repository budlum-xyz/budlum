# Local build/test feasibility in this sandbox (2026-11-16)

Environment: Debian 13 x86_64, 1.9 GB RAM, 2 cores, no swap, sudo available, network available.
Toolchain: Rust 1.97.1 (rust-toolchain.toml pin) via rustup, protoc 3.21.12 via apt (CI uses 29.3 from GitHub releases — version drift risk noted, uel-abi built OK).

## What works locally
- `cargo fmt --all -- --check`: works, fast.
- `cargo check -p budlum-types -p budlum-note-packing`: works (small crates, cached deps).
- `cargo check -p budlum-uel-abi` etc.: works once protoc present.
- Python, git, curl, GitHub API: works.

## What does not work locally (OOM)
- `cargo check --lib` for budlum-core (single crate, ~470k lines, 842 .rs files in snapshot): rustc SIGKILL (signal 9, OOM) after ~10 min, CARGO_BUILD_JOBS=2, debuginfo=2. Retry with RUSTFLAGS="-C debuginfo=0 -C codegen-units=16", jobs=1: in progress / still OOM-prone. Root cause: single huge crate, rustc memory >1.9 GB, no swap.
- Full `cargo test --all-features`: impossible locally for same reason + time (CI test suite is thousands of tests, 5711 lib tests per README badge at 00c8918f).
- Docker / docker-compose rehearsal: docker not installed, no daemon. Could install via apt (docker.io) + sudo, but 1.9 GB RAM cannot run 4 validators + RPC + faucet + prometheus stack (CI rehearsal builds images, runs 4 validators).
- macOS / Windows / Android / iOS targets: no cross toolchain, no emulator. `rustup target add` possible for check-only (cargo check --target), but linking/running impossible. CI covers via macos-latest, windows-latest, mobile jobs.
- Miri, Fuzz (cargo-fuzz/libFuzzer), Kani, TSan/ASan: nightly toolchain + long runtime, CI-only in practice. Could install nightly via rustup, but runtime/memory prohibitive locally.
- Garden NAT simulation, multi-node E2E: needs network namespaces, iptables, multiple processes — CI garden-nat-nightly does this on GitHub runners.

## Ways to run "impossible" tests (researched, per directive 4)
1. CI as validator (already the directive's rule): push to PR branch, GitHub Actions runners (ubuntu-24.04, macos, windows, arm) have more RAM/cores. This is the intended path; local OOM is not a code failure.
2. Split-crate checks: `cargo check -p <small crate>` for budlum-types, note-packing, bpqs, bud-codec, uel-abi, wallet-core, bud (standalone). Each is feasible. Core crate is the monolith problem.
3. Low-memory rustc: RUSTFLAGS="-C debuginfo=0 -C codegen-units=256 -C incremental=false", CARGO_BUILD_JOBS=1, `cargo check --lib` with `RUST_MIN_STACK`? Still likely OOM for budlum-core; try `cargo check --lib` on a larger sandbox / CI-like runner if available. sccache does not reduce peak rustc memory.
4. Remote execution: GitHub Actions `workflow_dispatch`, `act` (nektos/act) locally still needs docker. `cargo` via `ssh` to larger machine — not available in this sandbox.
5. Docker via apt: `sudo apt install docker.io` then `docker compose` rehearsal — RAM still insufficient for 4 validators (each budlum node is the same huge binary). Could run single-node native rehearsal (`Testnet Native E2E` job builds binary then runs locally in CI) — locally, building the binary is the OOM step.
6. Cross check-only: `rustup target add aarch64-unknown-linux-gnu x86_64-pc-windows-msvc` etc., `cargo check --target ...` — feasible for check, not for run. Useful for cross-platform compile errors.
7. Nextest / llvm-cov: same memory problem as cargo test for core; small crates feasible.

Conclusion: local full-core test is not feasible in 1.9 GB sandbox. Do not block PRs on local OOM; use CI. Document OOM as environment limit, not code defect. For future passes, request larger sandbox (8 GB+) or rely on CI + small-crate local checks + fmt/clippy on small crates.
