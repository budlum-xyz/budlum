# Lubot

The **off-chain skeleton** of the decentralised artificial intelligence layer
of Budlum L1.

> **Location, 2026-08-13:** this workspace was moved into the main repository
> from the separate `budlum-xyz/lubot` repository. The chain side lives in
> `src/lubot/` and `src/ai/`; the off-chain skeleton stands in this `lubot/`
> directory as its own Cargo workspace, in the same pattern as budzero. All
> Lubot work is collected into a single pull request.

- **The on-chain side** is in the budlum main repository, under `src/lubot/`:
  the model registry, the operator compute bond, Pollen grants, the B.U.D.
  AI dataset tags and the SocialFi bridge. This workspace does not touch it; it
  is its off-chain complement.
- **The closed-loop principle:** Lubot reads only data that carries a Pollen
  grant, a B.U.D. `StorageDeal` tag or a SocialFi origin. In this skeleton
  there is not a single path that reads outside data; even open data sets are
  registered with B.U.D. first.
- **The base model:** the the upstream vendor V4 family, with MIT weights.
  `V4-Flash-Base` is the default, and the decision is reconfirmed before the
  first fine-tune.
- **Tier naming, 2026-08-13:** the upstream vendor's variant names are not used in Lubot.
  The Flash-based tier is served as **`lubot-light`** and the Pro-based tier as
  **`lubot-normal`**. Multiplier labels such as 0.5x or 10x do not exist in
  Lubot, and the check lives in the code, at
  `lubot-serve::config::assert_served_name_is_ours`.
- **Attribution policy:** the "the upstream vendor to Lubot" rename is done only in our
  own code. Copied third party code and weight names stay as they are, and the
  MIT notice together with the "is the base of" attribution appears in
  `NOTICE.md` and on the model card.

## Status

The skeleton: compilable drafts, configuration and research reports. No part of
it is production yet, and hash verification is deliberately **fail-closed**, in
`lubot-data::verify`.

## Structure

| Crate | Job |
|---|---|
| `lubot-core` | The model identity, the dataset types and the LoRA manifest; mirror types, per decision K3 |
| `lubot-data` | Closed-loop source checking, the record format, fail-closed verification |
| `lubot-serve` | The a resident-batch engine and a resident-graph engine bridge configuration; the weight name is preserved and the served name is ours |
| `lubot-tune` | The training plan, LoRA in BF16 or FP16, with FP4 absent from the type system, plus the output hash lock |
| `lubot-ops` | The operator CLI skeleton: register, bond, serve, tune, status |

## Building

```bash
cargo check --workspace
cargo test --workspace
```

## Decisions

K2, the base model, is abstract and approved before the first fine-tune. K3,
the type binding, is deferred, and the skeleton suits either option. The method
is LoRA SFT, decided 2026-08-13.

## Documents

`ARCHITECTURE.md` in this directory is the layer summary.

The following documents were referenced by earlier versions of this README and
**do not exist anywhere in the tree**; they are recorded here as unresolved
references rather than repeated as though they resolved:
`docs/ARASTIRMA_RAPORU_2026-08-13.md`, `docs/MIMARI_ONERISI_2026-08-13.md`,
`docs/EGITIM_VERISI_STRATEJISI_2026-08-13.md` and
`docs/ACIK_KAYNAK_VERI_ARASTIRMASI_2026-08-13.md`. There is no `docs/`
directory under `crates/lubot/`.

Fine-tuning run artefacts, meaning notebooks, seed data, run guides and the
status matrix, are not kept in this repository: content that cannot be executed
belongs outside the code base.
