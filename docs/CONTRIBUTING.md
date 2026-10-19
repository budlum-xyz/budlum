# Contributing to Budlum Core

Thanks for helping improve Budlum Core.

Budlum is an experimental Rust Layer-1 blockchain core focused on modular consensus, deterministic execution, ZKVM-native contracts, privacy research, and future AI-assisted execution tooling. Contributions are welcome, especially from builders who enjoy protocol internals and clean systems code.

If you find the project useful, please also consider starring and forking the repo. It helps the project reach more protocol researchers and chain builders.

---

## Ways to Contribute

- Fix bugs in consensus, networking, storage, mempool, execution, or RPC code
- Improve tests, benchmarks, or chaos scenarios
- Add documentation for architecture and protocol behavior
- Review cryptography, finality, privacy, and VM design ideas
- Propose privacy-layer or private-VM experiments
- Improve developer experience and node operator tooling
- Open design discussions before large protocol changes

---

## Project Constitution

The rules this repository enforces live in the code that enforces them:
`src/core/constitution.rs` and its test suite `src/tests/constitution_engine.rs`.

Read it before a first change to consensus, tokenomics or a CI gate. It is
descriptive, not aspirational, every claim in it names a script, a baseline or
a commit you can check. Where it and the code disagree, the code is the fact.

## Before You Start

1. Check existing issues and discussions.
2. Open an issue for large changes before writing a big patch.
3. Keep pull requests focused.
4. Prefer small, reviewable changes over one large rewrite.
5. Do not include secrets, private keys, validator credentials, or real production configs.

For security-sensitive findings, do not open a public issue. See [`SECURITY.md`](SECURITY.md).

---

## Development Setup

### Requirements

- Rust `1.97.1` (pinned in `rust-toolchain.toml`; `rustup` picks it up)
- `protoc`
- Optional: Nix, if you use the provided development shell

### Build

```bash
cargo build
```

### Run Tests

```bash
cargo test
```

With Nix:

```bash
nix develop --command cargo test
```

### Format and Lint

Use the commands CI uses, not the shorter forms: `cargo fmt --all` walks every
workspace member while a bare `cargo fmt` does not, and a failing check skips every
step after it in that job - so one missed file silences the whole job's verdicts.

The rule is not about `Format`, it is about *order*: a red step must never stand
between a reader and another step's answer. Measured on 2026-09-11 - moving `Format`
last made `budlum`'s `Test` step run and report, which is the point of the job, and
the same job then showed the rule is not finished once: `Clippy` also fails, also
sits ahead of `Test`, and re-masked it. So in the `budlum` job the lint steps come
after the build/test/doc verdicts, and `Format` after them; in `budzero` and `budscan`
`Format` is still last. Keep both orders when editing any job: verdicts first, then
analysis, then style, whatever is red today.

```bash
cargo fmt --all -- --check                      # CI: Format
cargo clippy --all-targets -- -D warnings       # CI: Clippy
cargo test --lib --verbose                      # CI: Test (root lib tests)
```

The pedantic/nursery surface is a ratchet, not a wall: it is measured by
`ops/scripts/clippy-extra-report.py` against `.github/clippy-extra-baseline.txt` and
only refuses growth.

A workflow edit cannot be tried locally, so it is checked two other ways. Step bodies
are extracted and executed (see the third rule below), and the reachability of every step
is computed by `python3 ops/scripts/check-step-reachability.py`: it reports a guard that
references a `steps.<id>` no step declares, or declares later, and
`--fail 'budlum:Test'` prints which steps still run when that step is red. Run it after
touching any job's `if:` lines - a mistyped id skips every step behind it and leaves the
job looking green.

### The gates workspace, and what CI's red can actually mean

`xtask/gates` is a separate cargo workspace, so no root `--workspace` command
touches it: `cargo build --release --manifest-path xtask/gates/Cargo.toml` is the
compile, and `cargo clippy --release --manifest-path
xtask/gates/Cargo.toml --all-targets` is a gate: it was staged as a count-only monitoring step,
measured `0` headline lines in the run for `aaf491e`, and only then made to
refuse. Staging a measurement before enforcing it is the pattern to copy when a
gate would otherwise land on pre-existing debt - and note what made enforcement
safe: the step could only be allowed to fail the job once every other step in the
job carried a guard, so its redness stops hiding anything. The `gates` job builds the binary as its first cargo step precisely
because `cargo run --manifest-path ...` on a step named "so-and-so canary" turns a
build failure into a supposed gate finding: measured on 2026-09-10, two
`error[E0308]` in one gate file red six jobs' canaries at once, while a fully green
root clippy step in the same job proved nothing about it.

The `gates` job does not stop at ordering: every gate step carries
`if: always() && steps.build.outcome == 'success'` and pipes its output into a shared
log, and a final `Tally` step greps that log and annotates one line per `FAIL [gate]`
headline. So one red gate no longer hides the other thirty-five, and a job that is red
with no Tally entry means the failure was a toolchain step, not a gate. The
`if:` expressions cannot be checked locally - only the runner and `Repo Lint`'s
actionlint judge them, and actionlint is currently not installed on the runner - so a
step id there is a real hazard: a typo skips every gate and looks green.

Three rules that fall out of that, and are enforced by the job rather than by taste:

- A canary fails for exactly one reason. `cargo run` exits 1 on a gate finding and
  101 when cargo itself fails; those are different sentences and must not share a
  step name.
- Every step whose verdict would otherwise live only on a log host has an
  `if: failure()` surface that turns the tool's own output into annotations
  (`Build surface`, `Format diff surface`, `Canary surface`). A surface exits 0:
  reporting a failure is not a second failure.
- Do not verify a workflow step with `bash -n`. Extract its body from the YAML and
  execute it against a stub binary. That is how `^panicked` was caught missing the
  line a real panic prints, and how a backtick inside a double-quoted `printf`
  format (a live command substitution) was caught before it shipped.

Baselines in this repository are measured records, not configuration: `.github/
dead-pub-api-baseline.txt`, `.github/unwired-guards-baseline.txt` and
`.github/clippy-extra-baseline.txt` are only re-derived from a tree you have
actually built, because re-deriving them from an unverifiable one is how a gate
starts certifying a fiction.

### The mirrored lubot series

`repo-lubot/` ships lubot work as an applicable patch series against
`ayazkussan/lubot` `main`. Its generator ships with it:

```bash
SERIES_DIR=repo-lubot/patches LUBOT_REPO=<clone at the base> \
  python3 repo-lubot/tools/rebuild_series.py    # replays, repairs, self-checks
python3 repo-lubot/tools/rebuild_series.py --table   # regenerates README's table
```

Acceptance is `git am -3` of the files as committed, in a clean clone of the base
commit - not a per-file `patch --dry-run` "clean", which skips hunks it believes are
already applied and exits 0 while doing so.

---

## Pull Request Guidelines

Good pull requests usually include:

- A clear description of the problem and the fix
- Tests for behavioral changes
- Documentation updates when public behavior changes
- Notes about consensus, storage, networking, or replay implications
- A short explanation of any tradeoffs

Avoid:

- Unrelated refactors mixed into feature work
- Formatting-only changes across unrelated files
- Changing protocol behavior without tests or explanation
- Adding dependencies unless they are clearly justified
- Introducing non-deterministic behavior into consensus or execution paths

---

## Consensus and Execution Changes

Changes in these areas need extra care:

- `src/consensus/`
- `src/execution/`
- `src/chain/`
- `src/core/transaction.rs`
- `src/core/block.rs`
- `src/storage/`
- `src/network/protocol.rs`
- `proto/budlum/network/protocol.proto`

Before changing protocol-critical logic, consider:

- Does replay produce the same result?
- Does reorg recovery stay deterministic?
- Does this change block, transaction, or state-root compatibility?
- Does the change require a schema or protocol version bump?
- Can malformed input trigger panic, resource exhaustion, or invalid state?
- Are tests covering both valid and invalid paths?

---

## Privacy and AI Roadmap Contributions

Budlum welcomes research-oriented proposals for:

- Shielded transaction designs
- Selective disclosure
- Private/custom VM execution
- Zero-knowledge proof integration
- Privacy-aware mempool behavior
- AI-assisted transaction simulation
- AI-assisted monitoring and anomaly detection
- Operator backend and analytics services

These features should remain optional and must not compromise deterministic consensus behavior.

---

## Commit Style

Use concise, descriptive commit messages.

Examples:

```text
fix: reject malformed contract bytecode
test: add mempool nonce queue regression case
docs: explain snapshot sync flow
feat: add devnet validator config option
```

---

## Community Expectations

Be direct, respectful, and technical. Strong disagreement is fine; personal attacks are not.

Assume contributors are here to make the protocol better. Ask questions, explain tradeoffs, and keep discussions grounded in code, tests, and reproducible behavior.

---

## License

By contributing to Budlum Core, you agree that your contributions are licensed under the same terms as the repository, the PolyForm Shield License 1.0.0 (`LICENSE.md`). There is no separate contributor agreement.
