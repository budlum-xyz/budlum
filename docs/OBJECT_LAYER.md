# Universal Object Layer (UOL): integrator guide

The object layer is where Budlum settles assets that were born on another
chain without moving them out of that chain's rule. A bridge takes an asset as
an opaque payload and mints a new representation at the destination; the
source's rules are lost at the hop. The object layer keeps them: every asset
lives under the rule of the chain it was born on, and the interface is shared.

Code: `src/object_layer/`. Values marked TESTNET-DEFAULT are genesis
parameters.

**Status on the testnet.** The object layer is closed. `ACTIVATION` in
`src/object_layer/tx.rs` carries no height, so every `ObjectLayerTx` is refused
with `TxRefusal::Closed`; `object_layer_is_closed_on_testnet` is the test that
holds that. Nothing in this guide is a claim that an asset can be placed today.
Once the activation height is set the registration described below opens in
the same block.

## 1. The four ideas

| Idea | What it means |
|---|---|
| **Domain** | A chain Budlum settles for. It has a charter: an endpoint contract, the canonical code hashes of that endpoint and its verifier, and the data policy. |
| **Class** | One asset kind on one domain: an ERC-20, an NFT collection, a data record type. A class is described by a **rule**. |
| **Rule** | The class's state-transition function, as one of the closed templates: `FungibleV1`, `UniqueV1`. `Program` and `Replica` are closed doors (UOL-K1 to UOL-K4) and are refused. |
| **Placement** | Where one unit of value actually sits: on its home chain, in the object layer, or in a departure that is mid-flight. Every asset has exactly one placement. |

## 2. Identity

Every identifier is a hash of its inputs, so two nodes that agree on the
inputs agree on the identifier and nobody has to be trusted to keep a counter
in step.

| Identifier | Derivation |
|---|---|
| `AssetClassId` | `H("BDLM_OBJECT_LAYER_CLASS_V1", home_domain, len, class_ref)` |
| `AssetId` | `H("BDLM_OBJECT_LAYER_ASSET_V1", class_id, len, native_id)` |
| `DependencyId` | `H("BDLM_OBJECT_LAYER_DEP_V1", home_domain, home_height, home_block_hash, len, event_id)` |
| `DepartureId` | `H("BDLM_OBJECT_LAYER_DEPARTURE_V1", ...)` |
| arrival key | `H("BDLM_OBJECT_LAYER_ARRIVAL_V1", ...)`, the single-use set |

The two rows written with `...` are derived in `src/object_layer/ids.rs`, which
is the authority for their exact field lists; this guide names them so an
integrator knows they exist and can find them, and it does not restate the
field order, because two copies of a preimage are two identifiers that drift.

`class_ref` is the family's canonical encoding of the asset kind and the home
contract address, so `src/object_layer/family/<family>.rs` decides what a
contract address looks like and nothing else does.

## 3. The charter

A domain is usable only after its charter is accepted. The charter binds the
endpoint contract, the code hashes of the endpoint and of the verifier, an
upgrade notice window, a silence window and a data policy. Admission checks
that the submitted `CodeProof` agrees with the declared hashes and that both
are the canonical hashes the chain carries for that family:

- `charter_refuses_non_canonical_endpoint`: a non-canonical endpoint is
  refused.
- `charter_is_idempotent_for_same_endpoint`: re-submitting the same binding
  returns `false` and writes nothing; a *different* binding for a domain
  already chartered is `AlreadyChartered`.

Stale endpoint headers freeze the domain's classes. That path is not open yet;
when it lands it will set a freeze reason on the class, not refuse new
charters.

## 4. Registering a class

1. The registrant signs a `ClassRegistration`: home domain, kind, contract,
   rule, the class slice, the slice source, at least `min_reference_samples`
   reference samples (TESTNET-DEFAULT 3), and a bond of at least
   `min_class_bond`.
2. Every reference sample is the slice before, the verbs the home domain ran,
   and the slice after. The chain executes the rule over each sample and
   compares the result with the recorded after-slice **byte for byte** in the
   canonical encoding. One mismatch refuses the whole registration.
3. The samples are kept. `sample_commitment` is their hash, and the samples
   themselves are what a rebuttal is measured against (section 6).

A class with a closed rule (`Program`, `Replica`) is refused with
`ClassClosedRule`, and a template that does not belong to the family is
`TemplateNotForFamily`.

## 5. Placement: arrive, call, depart

| Direction | Door | What must be shown |
|---|---|---|
| home to object layer | `Arrive(HomeEventProof)` | an `Arrive` event emitted by the charter's endpoint, proven final |
| inside the object layer | `Call`, `Offer`/`Accept` | nothing external; the rule runs over the class's slice |
| object layer to home | `Depart`, then `ConfirmDeparture` | the departure id, then the home endpoint's confirmation |
| emergency | `record_escape` | the endpoint's escape event, after the silence window |

`Arrive` is final-phase only in this tree: a tentative proof is refused with
`TentativeClosed`. Anybody may carry an arrival; the carrier is not trusted,
because the proof is what is checked. An arrival id is spent once
(`ArrivalAlreadyUsed`), so one home deposit cannot fund two placements.

`Call` runs up to `MAX_COMPOSITE_CALLS` (16) calls as one atomic composite:
either every call applies or the registry is left byte for byte unchanged
(`composite_refusal_does_not_mutate`).

## 6. The fidelity challenge

A rule is a claim, and a rule that does not reproduce its samples is a class
that is misdescribing its home chain. The challenge is two steps
(Section 9.3.5 item 3):

1. **`Challenge { class, bond }`** opens a window of `challenge_window`
   heights (TESTNET-DEFAULT 100). The challenger posts at least
   `min_class_bond`. Opening a challenge freezes nothing: an accusation is not
   a verdict, and a griefer must not be able to stop a class for the price of
   one transaction. One window per class at a time
   (`ChallengeWindowOpen`).
2. **`Rebut { class, moves }`** is the registrant's answer. It is not a
   paragraph: the moves are executed by the class's own rule from the first
   stored sample's before-state, and the result must equal that sample's
   after-state. `FidelityChallenge::answer_from` publishes the moves that
   answer, so the target is never secret. A rebuttal from anybody but the
   registrant is `NotAuthorized`; a late one is `ChallengeWindowClosed`.

The window is settled by block-end maintenance, not by a transaction
(`ObjectLayerRegistry::settle_challenge`), so nobody chooses the height at
which somebody else's challenge is decided:

- **Upheld**: the class freezes with `FreezeReason::FidelityChallengeUpheld`
  and the registrant's bond is the amount the caller slashes. The reward
  split is the existing `ChallengeReward` rule; this registry does not invent
  a second one.
- **Rebutted**: the challenger's bond is at stake and the class keeps trading.

The two counters the metric table names are on the registry:
`challenges_upheld` and `challenges_rejected`.

## 7. Custody

`AuditCustody { class, home_custody }` compares the amount the object layer
records for a class with the amount the home endpoint reports holding. A
negative delta freezes the class with `FreezeReason::CustodyDeficit`. The
recorded amount is what placements add up to, never a number supplied by the
caller.

## 8. What the layer never does

- **It never mints** (N-5). Fungible balances grow only from an arrival whose
  home custody the endpoint measured, and shrink only by a departure or an
  escape. `object_layer_never_mints` sums both sides.
- **It never takes a bridge's word.** A departure is confirmed by the home
  endpoint's own event, and an escape needs the silence window.
- **It never guesses a family.** Every family-specific encoding lives behind
  `FamilyProfile`, and the four profiles are the closed list.
- **It never opens a closed door.** `Program` and `Replica` classes, the
  household-key allowance, guest placement and the two class rules of
  UOL-K1 to UOL-K4 stay closed until the conditions of Section 9.8 are met.

## 9. Reading state

Once the RPC step lands, the reads are `bud_getCharter`, `bud_getAssetClass`
and `bud_getAsset`, plus the object-layer section of `bud_getSettlementInfo`.
They are reads only: every write is a signed `SettlementTx::ObjectLayer`
transaction applied in a block. That door is the next step of the package and
is not in this tree yet, which is why the activation height is still unset.

## 10. The header

`GlobalBlockHeader` carries `object_layer_root` under a presence tag: `None`
while the registry holds no record, so an unused object layer does not move
the settlement root (`object_layer_empty_registry_keeps_state_root`). The
header version that adds the field is a separate step of the package and is
not in this tree yet; the settled root the registry exposes today is
`ObjectLayerRegistry::root`, and it is already what a header would commit.
