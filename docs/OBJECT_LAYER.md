# Universal Object Layer (UOL)

## 1. Architecture and Non-Wrapping Invariants

The Universal Object Layer (`src/object_layer/`) lets assets from chartered external domains reside and compose inside Budlum without minting wrapped copies (`N-1` through `N-12`):

- **Single identity (`N-1`)**: every asset class and asset derives a deterministic 32-byte identity from its home domain and canonical home contract/token reference:
  - `AssetClassId = H("BDLM_OBJECT_LAYER_CLASS_V1", home_domain_id, len(class_ref), class_ref)`
  - `AssetId = H("BDLM_OBJECT_LAYER_ASSET_V1", class_id, len(native_id), native_id)`
  - `DependencyId = H("BDLM_OBJECT_LAYER_DEP_V1", home_domain, home_height, home_block_hash, len(event_id), event_id)`
  - `HomeIdentity = H("BDLM_HOME_IDENTITY_V1", home_domain, len(home_address), home_address)`
- **Pure class rules (`N-2`, `N-12`)**: class rules execute over `(class_slice, asset_slice, verb)` only; they never read the clock, registry globals, or unrelated classes.
- **Single location & zero minting (`N-3`, `N-4`, `N-5`)**: unique/record assets inhabit exactly one `Location` (`Home`, `ObjectLayer`, `Departing`), and fungible balances change strictly through proven home arrivals, composite transfers, departures, or emergency escapes. When measured home custody falls below `recorded_custody`, `AuditCustody` freezes the class while keeping `Depart` open (`N-6`).
- **Family isolation**: core files (`ids.rs`, `charter.rs`, `rule.rs`, `registry.rs`, `tx.rs`, `mod.rs`) never branch on `HomeVmFamily`; all VM-specific address formats, event codecs, slice rules, and canonical endpoint builds live behind `FamilyProfile` (`evm.rs`, `cosmwasm.rs`, `svm.rs`, `move.rs`), enforced by `object_layer_core_has_no_family_branch`.

---

## 2. Supported VM Family Profiles

| Family | CAIP-2 Namespace | Slice Read Rule | Templates | Canonical Endpoint Artifacts |
|---|---|---|---|---|
| **EVM** | `eip155` | `AccountAndStorageProof` | `FungibleV1`, `UniqueV1`, `RecordV1` | `contracts/object-layer/evm/` |
| **CosmWasm** | `cosmos` | `EndpointEvent` | `FungibleV1`, `UniqueV1`, `RecordV1` | `contracts/object-layer/cosmwasm/` |
| **SVM** | `solana` | `AccountAndStorageProof` | `FungibleV1`, `UniqueV1`, `RecordV1` | `contracts/object-layer/svm/` |
| **Move** | `aptos` | `EndpointEvent` | `FungibleV1`, `UniqueV1`, `RecordV1` | `contracts/object-layer/move/` |

---

## 3. State Transition Door (`SettlementTx::ObjectLayer`)

All writes enter exclusively through `SettlementTx::ObjectLayer(Box<ObjectLayerTx>)` (`N-8`):

- `Charter`: registers a `DomainCharter` once its endpoint & verifier code hashes match the canonical pinned digests and the external domain is active.
- `RegisterClass` / `RefreshClass` / `AuditCode` / `AuditCustody`: registers audited template classes (`FungibleV1`, `UniqueV1`, `RecordV1`) with `>= 3` verified reference transition samples, refreshes home slice fields, and freezes classes whose upgrade authority changes or whose custody falls into deficit.
- `Arrive` / `SetTentativeConsent` / `Resolve`: processes proven home arrivals. `Phase::Tentative` requires explicit recipient opt-in (`SetTentativeConsent { consent: true }`), obeys the **single-dependency rule** (at most one unresolved `TentativeDependency` per recipient), blocks `Depart` until `Resolve`, and clears upon finality resolution.
- `Call` / `Offer` / `Accept` / `HomeCall`: runs failure-atomic composites (`<= 16` calls) and standing offers with `Payment`, `Holds`, `SignedBy`, and `EscapeAddress` conditions.
- `Depart` / `ConfirmDeparture` / `SetEscapeAddress` / `Adopt`: returns assets to their home chain, binds per-account home escape addresses (`<= 128` bytes), and adopts `Holder::Home` balances into a post-quantum `Holder::Account`.
- `Challenge` / `Rebut`: opens a 200-block rule-fidelity challenge (`DEFAULT_CHALLENGE_WINDOW_BLOCKS = 200`) against an active class; timely registrant rebuttal clears the challenge, whereas expiry freezes the class (`FreezeReason::UnrebuttedChallenge`).

### Testnet `45261` Posture

`ACTIVATION` ships with `height: None`, keeping `SettlementTx::ObjectLayer` closed on public testnet `45261` (`object_layer_is_closed_on_testnet`, `settlement_door_refuses_object_layer_on_testnet`) until post-launch milestone `M7` governance activation.

---

## 4. Public Read-Only JSON-RPC Methods

All three methods are classified as `(Listener::Public, Effect::Read)` in `src/rpc/method_class.rs`:

1. `bud_getCharter(domain_id: u32)` — returns the `DomainCharter` for `domain_id`, or `null`.
2. `bud_getAssetClass(class_id: String)` — returns `{ class, recordedCustody }` for a 32-byte hex `AssetClassId`, or `null`.
3. `bud_getAsset(asset_id: String)` — returns the `UniqueAsset` placement record for a 32-byte hex `AssetId`, or `null`.
