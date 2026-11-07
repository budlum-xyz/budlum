# Lane D live audit: initial CI baseline

This is a partial WP-04 record, not a completed finding audit.

- Observed main and local starting commit: `20140e87061efc9d8d4076e04305c1318705e348`.
- Observed on 2026-11-07 UTC using the GitHub Actions API filtered by that commit.
- All runs listed below were pending or queued when observed; none had a conclusion. These are not evidence of a passing or failing gate.

| Workflow | Run | State |
|---|---:|---|
| Audit Guard | 42344580595 | pending |
| Benchmark | 42344580693 | pending |
| CI | 42344580642 | pending |
| Cargo Vet | 42344580635 | pending |
| Determinism | 42344580594 | pending |
| Diverse Double Compiling | 42344580783 | queued |
| Extra Tooling (security + quality) | 42344580628 | queued |
| Grype | 42344580650 | pending |
| Miri UB Check | 42344580585 | pending |
| OSV Scanner | 42344580577 | pending |
| PKCS#11 3.2 post-quantum token | 42344580670 | pending |
| Provenance (SBOM attestation) | 42344580663 | pending |
| Security Audit | 42344580588 | pending |
| Semgrep | 42344580674 | pending |
| Semver Check | 42344580608 | pending |
| Solidity | 42344580589 | pending |
| Supply Chain Extra (udeps + geiger) | 42344580634 | pending |
| Typos | 42344580656 | queued |

These are the runs returned for this commit, not a claim that every configured workflow ran. Runner memory limits and per-finding classifications remain unverified. Earlier failed runs belong to different commits and are not evidence of failures at this baseline.
