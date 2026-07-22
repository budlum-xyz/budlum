# Mainnet Lockdown Checklist —

**Status:** ADIM 1 lockdown checklist.
**Authority:** CI is the only judge. A launch lock cannot be declared while any required or extended main-branch gate is red or pending without an explicit incident waiver.
**Scope:** final pre-launch review after  → 11.20 evidence is present.

## Lock criteria

| Gate | Required evidence | Status rule |
| --- | --- | --- |
| Specs frozen | `docs/spec-review/`, `scripts/check-spec-coverage.sh` | Must be green in Repo Lint |
| Economy and fork choice | `Economy Invariants`, `Fork-Choice Invariants` | Must be green |
| Storage and node class | `StorageProvider Gate`, `Node Classification` | Must be green |
| Network hardening | `Network Hardening`, `Fuzz Quick` | Must be green |
| Wallet core | `Wallet Core ()` | Must be green |
| Governance | `Governance Invariants ()` | Must be green |
| PoA compliance isolation | `PoA Compliance Isolation ()` and legacy PoA isolation gate | Must be green |
| Audit/HSM docs | `Audit Prep ()`, validator key-management, HSM policy | Must be green |
| Determinism/genesis | `Genesis Reproducibility`, cross-platform determinism jobs | Must be green |
| Stability window | All required + extended main gates | 7 consecutive days green before launch lock |

## Manual launch-lock review

1. Confirm latest `origin/main` SHA and attach CI run links.
2. Confirm `docs/THREAT_MODEL.md` is v2 and residual risks are accepted or assigned.
3. Confirm `docs/audit_prep/README.md` evidence map is complete.
4. Confirm YubiHSM 2 / PKCS#11 operator policy is acknowledged by validator operators.
5. Confirm `budlumdevnet` remains a read-only reference and no generated secrets are committed.
6. Confirm all , 11.10, 11.12, 11.14, 11.16, 11.18 and 11.20 gates are green on main.
7. Confirm emergency halt, rollback communication and restart owners are assigned.

## Emergency procedures

- **Halt trigger:** only systemic consensus, signer-integrity, state-root, or bridge-safety risk.
- **No silent rollback:** any rollback requires public incident record, affected range, root cause and operator acknowledgement.
- **Communication:** publish incident hash, affected SHA/range, recommended operator action and next checkpoint.
- **Recovery:** prefer parameter disablement, domain freeze, or validator rotation over chain rollback where possible.

## Waiver policy

A waiver can never bypass CI. It can only postpone a non-launch-blocking operational . Waivers must include:

- owner
- expiry date
- affected risk ID from `docs/THREAT_MODEL.md`
- compensating control
- follow-up ADIM

## Lock output

When the checklist is complete, produce a launch-lock record containing:

- main SHA
- CI summary
- audit package revision
- validator key-policy revision
- threat model revision
- operator sign-off list
