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
`docker-compose.yml` keeps `BUDLUM_RPC_AUTH_REQUIRED=1` and does not publish
the public RPC port. The smoke harness needs an open listener, so those
settings live in `docker-compose.ci.yml` and have to be requested explicitly:

```bash
docker compose -f docker-compose.yml -f docker-compose.ci.yml up -d
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
| Kani | bond arithmetic: a slash never exceeds its bond | gate |

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
`rust-version = "1.94.0"`, so cargo refuses to build the root crate before any
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

Signature verification and Merkle paths remain open work: both reach into
third-party crypto crates that model checking would have to unroll, so they need
harnesses written against extracted, bounded logic first.

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

Budlum Core, mainnet v1 lansmanından itibaren bir bug bounty programı yürütecektir.

| Seviye | Ödül (USD) |
|--------|------------|
| Kritik (consensus bypass, key extraction, bridge drain) | $50,000 to $100,000 |
| Yüksek (DoS, RPC bypass, P2P eclipse) | $10,000 to $25,000 |
| Orta (rate limit bypass, info leak) | $2,500 to $5,000 |
| Düşük (best practice, docs) | $500 to $1,000 |

**Raporlama:** `security@budlum.network` veya GitHub private security advisory.
**Triage:** 72 saat içinde ilk yanıt. Coordinated disclosure: 90 gün.

> Program henüz aktif değil: mainnet lansmanıyla birlikte Immunefi üzerinden açılacaktır.

### Triage Kanalları

- **Discord:** `#security-reports` (yalnızca reporter + security lead görür)
- **Telegram:** `@budlum_security` (alternatif, PGP key talep edilir)
- **GitHub:** Private security advisory (önerilen: audit trail)

### Safe Harbor (İyi Niyetli Araştırmacı Koruması)

Aşağıdaki koşulları sağlayan araştırmacılar iyi niyetli kabul edilir:

1. Yalnızca **test hesapları** kullanılır; üçüncü parti fon/veriye dokunulmaz.
2. Mainnet'te **fon/veri riske atmayan** salt-kanıt test (read-only).
3. Bulgu paylaşılmadan önce `security@budlum.network`'e raporlanır.
4. 90 gün coordinated disclosure penceresine uyulur.

**Kapsam dışı:** sosyal mühendislik, üçüncü parti altyapı (RPC/HSM vendor),
mainnet'te gerçek fon drain, kullanıcı verisi sızıntısı.

---

## Disclaimer

Budlum Core is experimental software. Do not use it to secure real funds, production validator keys, or sensitive private data without an independent security review.
