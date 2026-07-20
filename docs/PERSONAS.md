# Budlum personas (Phase 0.36)

Same binary, three operator shapes. Configs are Strict Config V2 (`deny_unknown_fields`).

| Persona | File | Role | Network | Keys |
| --- | --- | --- | --- | --- |
| **End user** | `config/personas/user-devnet.toml` | `rpc` | devnet | none |
| **Developer** | `config/personas/developer.toml` | `validator` | devnet | local disk OK |
| **Enterprise PoA** | `config/personas/enterprise-poa.toml` | `validator` | mainnet | **PKCS#11 only** |

## Compatibility matrix

| Capability | User | Developer | Enterprise PoA |
| --- | --- | --- | --- |
| Sync / verify settlement | ✓ | ✓ | ✓ |
| Public JSON-RPC (local) | ✓ | ✓ | ✓ (auth) |
| Operator RPC | — | ✓ localhost | ✓ localhost |
| Produce blocks | — | ✓ devnet | ✓ HSM |
| Disk `ValidatorKeys` (BLS/PQ) | — | ✓ devnet only | **forbidden** |
| Bridge mint (non-PoW domains) | — | if features on | policy + `bridge_enabled` |
| Bridge mint from **PoW** domains | `pow-header-chain-v1` only; legacy proofs gated | same | same |
| `VerifyMerkle` inside STARK | Production-gated (Z-B 3.5) | Testing/experimental | Production-gated |
| B.U.D. storage network | — | — | — | **Phase 0.38 only** |

## Run

```bash
# User
cargo run -- --config config/personas/user-devnet.toml

# Developer (set API key if auth_required)
export BUDLUM_RPC_API_KEY=dev-secret
cargo run -- --config config/personas/developer.toml

# Enterprise (HSM + secrets outside git)
export BUDLUM_PKCS11_TOKEN_PIN=...
export BUDLUM_RPC_API_KEY=...
# Add [validator.signer.pkcs11] in a private overlay or env-specific file
cargo run --release -- --config config/personas/enterprise-poa.toml
```

See also `archive/ORG_ROADMAP_AUDIT.md` for budlum-xyz org roadmap mapping.
