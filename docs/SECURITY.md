# Security Policy

Budlum Core is experimental Layer-1 blockchain infrastructure. Security reports are taken seriously, especially issues affecting consensus safety, deterministic execution, networking, storage integrity, cryptography, privacy, or validator operation.

Please do not disclose serious vulnerabilities publicly until they have been reviewed and patched.

---

## Supported Versions

Budlum Core is currently pre-release research software.

| Version | Supported |
| :--- | :--- |
| `main` branch | Best-effort security review |
| Tagged releases | Best-effort, when available |
| Old commits/forks | Not actively supported |

Until stable releases exist, security fixes are expected to land on `main`.

---

## Reporting a Vulnerability

If you believe you found a vulnerability, please report it privately.

Preferred process:

1. Open a private security advisory on GitHub if available.
2. If private advisories are not available, contact the project maintainer directly.
3. Include enough detail to reproduce the issue.
4. Do not publish exploit code or public issue details before coordination.

Useful report details:

- Affected commit, branch, or release
- Impacted component, such as consensus, execution, networking, storage, RPC, mempool, or crypto
- Reproduction steps
- Minimal proof of concept, if safe to share privately
- Expected behavior vs actual behavior
- Suggested fix, if you have one

---

## Scope

High-priority areas include:

- Consensus safety failures
- Block validation bypasses
- Transaction signature or chain ID replay issues
- Deterministic execution failures
- Reorg or restart replay divergence
- State-root corruption
- Storage integrity failures
- Snapshot sync validation failures
- Mempool spam or resource exhaustion attacks
- P2P protocol denial-of-service vectors
- Peer reputation bypasses
- JSON-RPC input validation issues
- Cryptographic misuse or weak domain separation
- ZKVM proof verification bypasses
- Private VM or privacy-layer leakage, when those features land
- Validator key handling risks

Out of scope:

- Social engineering
- Physical attacks
- Vulnerabilities only affecting a heavily modified fork
- Reports without a plausible security impact
- Dependency CVEs that are not reachable from Budlum behavior
- Denial-of-service claims that require unrealistic local machine access

---



---

## Recognition Program

Budlum does not operate a monetary bug bounty. In its place, researchers who
report critical vulnerabilities that are confirmed and fixed receive a
lifetime, non-transferable domain name of their choice under the Budlum
namespace, free of charge, for as long as the project remains active.

### Criteria

1. **Confirmed and fixed.** The report must be accepted by the maintainers and
   the fix must land on `main`.
2. **Critical impact.** The vulnerability must affect consensus safety, fund
   custody, data integrity, or the confidentiality of user data in a way that a
   node operator cannot reasonably mitigate. High-severity issues in the
   areas listed under Scope qualify.
3. **Private disclosure.** The report must follow the private reporting
   process above; public disclosure before coordination disqualifies the
   report.

### Grant mechanics

- The domain is selected by the researcher from the available Budlum
  subdomains and is granted at the sole discretion of the maintainers,
  in coordination with the researcher, and subject to applicable law.
- The grant is recognition, not compensation. Budlum is pre-launch research
  software and makes no promise of financial reward; the program exists to
  honor the work that makes the network safer without turning vulnerability
  discovery into a commercial market.
- Multiple valid reports for the same issue are honored in submission order.
  Substantially different attack surfaces on the same root cause may be
  treated as separate issues at the maintainers' discretion.

## Operator deployment notes

Two assumptions the node makes about its environment. Both hold on an ordinary
host and can be broken by how you deploy it.

**The operator RPC trusts loopback.** `--rpc-operator-listener` refuses to bind
to anything other than a loopback address, and the node will not start if you
try. It carries no authentication of its own, because reaching `127.0.0.1` is
treated as proof of local access.

That assumption breaks wherever the loopback interface is shared. The case to
watch is a Kubernetes pod: every container in a pod shares a network namespace,
so a sidecar, a log shipper, a service mesh proxy, anything pulled in by a
mutating webhook, can reach the operator RPC as if it were the node itself.
The same applies to `docker run --network=container:...` and to any process
running directly on the host.

If the node shares a namespace with workloads you would not hand admin access
to, do not rely on the loopback bind alone. Run the node in its own pod, or
place the operator listener behind an authenticated proxy.

**The default compose file is authenticated; the CI overlay is not.**
`ops/docker-compose.yml` keeps `BUDLUM_RPC_AUTH_REQUIRED=1` and does not publish
the public RPC port. The smoke harness needs an open listener, so those
settings live in `ops/docker-compose.ci.yml` and have to be requested explicitly:

```bash
docker compose -f ops/docker-compose.yml -f ops/docker-compose.ci.yml up -d
```

Never use that overlay on a host with a routable address. It disables RPC
authentication and empties the IP allow-list.

## Security Expectations for Contributors

When changing protocol-sensitive code:

- Avoid panics on untrusted input
- Validate payload sizes and encoded fields
- Keep consensus and execution deterministic
- Treat network messages as hostile
- Keep replay and reorg behavior reproducible
- Avoid leaking secrets in logs
- Do not commit private keys, validator credentials, seeds, or production configs
- Add tests for invalid and adversarial cases

Sensitive paths include:

- `src/consensus/`
- `src/execution/`
- `src/chain/`
- `src/core/`
- `src/network/`
- `src/mempool/`
- `src/storage/`
- `src/rpc/`
- `proto/protocol.proto`

---

## Automated Analysis: What Runs, and What Does Not

Every gate below runs in CI on each pull request and carries a canary that
plants a violation and fails if the gate accepts it. A gate that cannot fail
is not evidence, so the canary is part of the gate rather than an extra.

| Tool | Property | Status |
| :--- | :--- | :--- |
| `cargo clippy -D warnings` | lint-clean on lib and tests | gate |
| clippy `pedantic` + `nursery` | ratchet, count may not increase | gate |
| Miri | undefined behaviour in crypto and BudZero | gate |
| `cargo fuzz` | 9 of 11 targets, 60s each per PR; the two EVM targets are nightly/manual | gate |
| CodeQL, Semgrep | static analysis | gate |
| `cargo audit`, `cargo deny`, OSV, Grype | advisories, licences, supply chain | gate |
| `cargo geiger` | first-party `unsafe` must stay at zero, backing `#![forbid(unsafe_code)]` | gate |
| `cargo machete`, `cargo shear` | unused dependencies | gate |
| `cargo-semver-checks` | public API breakage | gate |
| `taplo` | TOML formatting of supply-chain policy files | gate |
| `cargo bloat` | binary size | report, not a gate, no calibrated threshold yet |
| Kani | bond arithmetic, QC Merkle paths, PQ signature length classification, finality bitmap accounting | gate |

**Kani is integrated for bond arithmetic.** An earlier `scripts/check-kani.sh`
printed a stub message and pointed at a `src/crypto/kani.rs` that was not in the
tree; no workflow ran it, and there were no `#[kani::proof]` harnesses anywhere.
It was removed rather than left to imply coverage that did not exist.

The replacement is real. `kani/` carries five harnesses over the slash penalty
computation, and `.github/workflows/extra-tooling.yml` runs them on every pull
request against a pinned Kani. What is proved: a penalty never exceeds the bond
it is taken from; `remaining + penalty == stake` exactly, so the
`saturating_sub` in `slash_role_only` is not masking an underflow; the 0% and
100% ratios are exact; and the penalty is monotonic in the ratio, so raising a
slash ratio through governance can never reduce the actual penalty. A fifth
harness drops the `ratio <= FIXED_POINT_SCALE` precondition and asserts the
bound would break without it, which records `RegistryParams::validate` as
load-bearing rather than incidental, the other four *assume* that bound, and an
assumption is not a check.

`kani::any()` is every value of the type, so these cover the whole input space
rather than sampled points. The existing proptests are kept alongside them.

The harnesses live in a standalone `kani/` package, in the same way `fuzz/`
does. Kani ships a pinned nightly, 0.67.0, the newest published release,
bundles rustc 1.93.0-nightly, while `budlum-core` declares
`rust-version = "1.97.1"`, so cargo refuses to build the root crate before any
harness runs. The upstream toolchain bump is merged but unreleased
(model-checking/kani#4645). Lowering the MSRV to suit a verification tool would
weaken a promise made to operators in order to make a check pass, so the package
stands alone and mirrors the one expression under proof.
`bond_arithmetic_matches_the_kani_mirror` in the ordinary test suite fails if
the mirror and `slash_role_only` ever diverge.

The gate checks the proofs pass *and* that the number of harnesses Kani ran
matches the number declared in the source, because a proof that silently stops
being compiled would otherwise leave the gate green with nothing behind it,
the exact way the deleted script was hollow.

Signature verification and Merkle paths were listed here as open work: both
reach into third-party crypto crates (SHA3-256, the BLS and PQ backends) that
model checking would have to unroll. They now carry harnesses written against
extracted, bounded logic first, which is exactly the path the previous text
prescribed:

* Merkle paths: `consensus::merkle_tree` is the pure tree shape (sibling
  selection, layer growth, root extraction, the proof walk), SHA3-bound in
  production and model-checked in `kani/` on a fixed-array bounded model with
  a deliberately non-commutative abstract combine. The harnesses prove the
  sibling index stays in bounds, every parent layer is strictly smaller,
  every non-empty tree terminates with a single root, and every leaf's proof
  path rebuilds the root. `qc_merkle_matches_the_kani_mirror` pins the bounded
  model to the production tree.
* Signature verification: the bounded logic around PQ attestations is the
  length-admissibility check (`crypto::primitives::classify_pq_signature_len`).
  The harnesses prove classification is total and round-trips, acceptability
  never disagrees with classification, and the three accepted signature
  lengths are pairwise distinct. `pq_signature_classification_matches_the_
  kani_mirror` pins the constants. The finality bitmap accounting
  (`bitmap_cannot_vote_more_stake_than_the_set_holds`) proves a certificate
  can never vote more stake than its set holds.

The raw signature arithmetic itself still lives behind the third-party crates;
what is proved is the logic a verifier runs around it before that arithmetic
is reached.

---

## Coordinated Disclosure

The expected disclosure flow:

1. Reporter privately submits the issue.
2. Maintainers acknowledge and triage.
3. A fix is prepared and tested.
4. A patch is released or merged.
5. Public disclosure happens after users have had reasonable time to update.

For critical vulnerabilities, public details may be delayed until a safe patch path exists.

---

## Bug Bounty

Budlum Core will run a bug bounty programme from the mainnet v1 launch onwards.

| Severity | Reward (USD) |
|--------|------------|
| Critical (consensus bypass, key extraction, bridge drain) | $50,000 to $100,000 |
| High (DoS, RPC bypass, P2P eclipse) | $10,000 to $25,000 |
| Medium (rate limit bypass, info leak) | $2,500 to $5,000 |
| Low (best practice, docs) | $500 to $1,000 |

**Reporting:** `security@budlum.network` or a GitHub private security advisory.
**Triage:** a first response within 72 hours. Coordinated disclosure: 90 days.

> The programme is not active yet: it opens through Immunefi together with the mainnet launch.

### Triage Channels

- **Discord:** `#security-reports` (visible only to the reporter and the security lead)
- **Telegram:** `@budlum_security` (alternative, a PGP key is requested)
- **GitHub:** a private security advisory (recommended: audit trail)

### Safe Harbor (Good Faith Researcher Protection)

Researchers who meet the conditions below are treated as acting in good faith:

1. Only **test accounts** are used; third party funds and data are not touched.
2. On mainnet, proof-only testing that **puts no funds or data at risk** (read-only).
3. A finding is reported to `security@budlum.network` before it is shared.
4. The 90 day coordinated disclosure window is respected.

**Out of scope:** social engineering, third party infrastructure (RPC/HSM vendors),
draining real funds on mainnet, leaking user data.

---

## Disclaimer

Budlum Core is experimental software. Do not use it to secure real funds, production validator keys, or sensitive private data without an independent security review.
