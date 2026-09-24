# FSF adaptation plan for Budlum — clean-room, multi-stage

This is the follow-up plan for `docs/FSF_PROJECT_FIT.md`.  The fit matrix is
only phase 0: it tells us what is worth learning from FSF-listed projects and
where license boundaries sit.  It is **not** a completed port and it is **not**
permission to copy upstream source into Budlum.

## Non-negotiable rule

Budlum learns concepts and interface shapes, then writes Budlum-native code.
No GPL/AGPL source enters this PolyForm-Shield tree unless a separate legal and
provenance decision creates an explicit isolation boundary.  Even permissive
projects need normal provenance review for cryptography, model weights,
datasets, test vectors, and generated artifacts.

## Phases

### Phase 0 — inventory and boundary map (done)

Commit: `f6d94a3`.

- FSF High Priority areas and Free Software Directory HPP collection were read.
- Useful projects were mapped to Budlum modules.
- Import boundaries were classified: permissive, boundary-only, design-only,
  review-first.
- `tools/fsf_project_fit.py --self-test --check` pins the curation file.

### Phase 1 — design briefs, no product code

Each brief must answer: Budlum module, threat model, license/provenance boundary,
what we copy **conceptually**, what we explicitly do **not** copy, and which tests
will prove the Budlum-native implementation.

1. **Federation events** — Matrix / Pump.io / Activity Streams inspiration.
   - Modules: `src/ai_inference`, RPC event feeds, SocialFi bridge.
   - Output: Budlum event envelope spec and golden JSON fixtures.
2. **Receipt/accountability model** — GNU Taler inspiration.
   - Modules: economy, settlement, wallet-core.
   - Output: anonymous-customer/auditable-operator receipt threat model.
3. **Compliance gate** — FOSSology / licenseutils inspiration.
   - Modules: `xtask/gates`, supply-chain workflows.
   - Output: import-boundary gate that blocks unreviewed GPL/AGPL vendoring.
4. **Local i18n/accessibility seam** — Argos / STT family inspiration.
   - Modules: docs/UI/Lubot/off-chain assistant.
   - Output: provider trait and deterministic fixture format, no model asset import.
5. **Network privacy seam** — Tor / I2P / GNUnet design inspiration.
   - Modules: `src/network`, devnet, RPC exposure.
   - Output: proxy/egress boundary tests and leak model.
6. **Privacy research** — Monero/Zcash-style research inspiration.
   - Modules: note-packing, wallet privacy, settlement privacy research.
   - Output: research memo only; no new cryptographic primitive without a BPQS-like bar.

### Phase 2 — first safe Budlum-native code

Start with the least license-risky, highest gate value item.  This guardrail may
land before the Phase 1 briefs are all written, because it prevents the mistake
the briefs are meant to avoid: turning research into an unreviewed source import.

- `xtask/gates` import-boundary gate:
  - reads `docs/FSF_PROJECT_FIT.md` and `docs/FSF_ADAPTATION_PLAN.md`;
  - rejects controlled FSF project names in product code and vendored-looking
    GPL/AGPL/LGPL/MPL source bundles unless an explicit `BUDLUM_IMPORT_BOUNDARY.md`
    note records the boundary;
  - has self-tests proving it catches an unreviewed copyleft import and accepts a
    documented design-only reference.

This gives the rest of the adaptation work a hard guardrail before any feature
code starts.

### Phase 3 — module implementations, one at a time

Only after Phase 1 briefs and Phase 2 guardrail:

1. Federation event envelope + tests. **Started** in `src/ai_inference/social.rs`
   with `FederatedAiOutputEvent`: a Budlum-native event id and deterministic
   JSON transport view for AI outputs minted into SocialFi.
2. Receipt/accountability model + tests. **Started** in `src/ai/types.rs` and
   `src/ai/registry.rs` with `AiAgentPaymentReceipt`: a public receipt id, payer
   commitment and terminal settlement fields derived from the canonical settled
   payment record.
3. Offline i18n provider seam + fixtures. **Started** in
   `src/ai_inference/i18n.rs` with local-only provider identifiers,
   deterministic locale canonicalization, exact fixture lookup, localized-text
   commitments and STT transcript provenance commitments.
4. Network proxy/privacy seam tests. **Started** in `src/network/privacy.rs`
   with strict/public/devnet egress policies, proxy/overlay route validation,
   resolution-free target classification and redacted audit labels.
5. Privacy research prototypes behind non-default features, if approved.

## Current status

- Phase 0 is complete.
- The Phase 2 import-boundary guardrail is now coded as `fsf-import-boundaries`
  so later work cannot accidentally vendor FSF/copyleft source while the design
  briefs are being written.
- Phase 1 design briefs are still needed; the first federation-event,
  receipt/accountability, offline i18n/accessibility and network privacy seams
  are intentionally small and native, and should be backed by fuller briefs
  before expanding their bridge surfaces.
- No FSF upstream code has been imported.
- No claim is made that all FSF-inspired tooling is fully coded.
