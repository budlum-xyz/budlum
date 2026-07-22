# Validator Key Management —  Mainnet Policy

**Status:** ADIM 1 policy baseline.
**Hardware standard:** YubiHSM 2 compatible PKCS#11.
**Scope:** validator operators, ceremony participants, and incident responders.

## Policy summary

1. Mainnet validator signing keys must be hardware-backed through PKCS#11.
2. Disk-backed plaintext validator keys are forbidden for mainnet operation.
3. Mock HSM backends are allowed only in devnet/test contexts and must fail closed in mainnet policy checks.
4. BLS/PQ capability metadata must be bound to the signer configuration before a validator is advertised as supporting those signature families.
5. Operational recovery must prefer rotation and re-onboarding over copying private key material.

## Required operator setup

| Control | Requirement |
| --- | --- |
| Hardware | YubiHSM 2 or compatible PKCS#11 device approved by operations |
| PIN handling | PIN is supplied via environment/secret manager and must not be written to repo, logs, or runbooks |
| Slot/object IDs | Recorded in an operator-private inventory; public runbooks reference only labels and ceremony IDs |
| Backups | Backup material is encrypted, access-split, and tested during dry-run ceremony |
| Monitoring | Signer health, failed PIN attempts, and unexpected mechanism errors are alerting events |

## Key rotation

Rotation is mandatory when any of the following occurs:

- HSM loss, suspected tampering, or unplanned factory reset.
- PIN exposure, operator offboarding, or split-knowledge quorum loss.
- Validator identity migration during planned mainnet ceremony.
- Any CI or runtime evidence that a signer advertised unsupported BLS/PQ capability metadata.

Rotation steps:

1. Generate replacement key material inside the approved HSM boundary.
2. Register the replacement public identity through the validator onboarding flow.
3. Wait for the configured governance/activation window before removing the old identity.
4. Preserve signed rotation evidence in the audit package.
5. Confirm the old key is disabled, not exported.

## Backup and loss scenario

- Backup is for HSM recovery material only, not plaintext operational key dumps.
- Backup quorum must require at least two independent custodians.
- A lost HSM triggers immediate validator pause, incident ticket, and replacement ceremony.
- If recovery cannot be completed safely, slash-risk mitigation takes precedence over uptime.

## Emergency halt interaction

Emergency halt procedures are documented in `docs/operations/PRODUCTION_RUNBOOK.md`. Key-management incidents may justify halt escalation only when validator-signing integrity is at systemic risk. Individual validator hardware failure should normally be handled by jailing/unbonding/rotation, not chain halt.

## Audit evidence

Auditors should cross-check this document with:

- `docs/operations/HSM_BLS_PQ_POLICY.md`
- `docs/operations/HSM_VENDOR_NATIVE_GUIDE.md`
- `src/crypto/mainnet_policy.rs`
- `src/crypto/pkcs11.rs`
- CI jobs: `Budlum Core`, `Miri UB Denetimi`, and `Audit Prep ()`
