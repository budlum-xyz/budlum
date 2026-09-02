# AI inference layer

The **off-chain skeleton** of the decentralised artificial intelligence layer
of Budlum L1.

> The chain side lives in `src/ai_inference/` and `src/ai/`; the off-chain
> skeleton stands in this directory as its own Cargo workspace, in the same
> pattern as budzero.

- **The on-chain side** is in the budlum main repository, under `src/ai_inference/`:
  the model registry, the operator compute bond, Pollen grants, the B.U.D.
  AI dataset tags and the SocialFi bridge. This workspace does not touch it; it
  is its off-chain complement.
- **The closed-loop principle:** AI inference layer reads only data that carries a Pollen
  grant, a B.U.D. `StorageDeal` tag or a SocialFi origin. In this skeleton
  there is not a single path that reads outside data; even open data sets are
  registered with B.U.D. first.
- **The base model:** an operator configuration value; a permissively licensed
  base family is expected, and no name is pinned here. The light tier is the
  default, and the decision is reconfirmed before the first fine-tune.
- **Tier naming:** upstream variant names are not used in the AI inference
  layer. The smaller base is served as **`ai_inference-light`** and the larger
  base as **`ai_inference-normal`**. Multiplier labels such as 0.5x or 10x do
  not exist in the AI inference layer, and the check lives in the code, at
  `ai-serve::config::assert_served_name_is_ours`.
- **Attribution policy:** the rename to our own served name is done only in our
  own code. Third party weight names stay as they are, and the base model's
  licence notice together with the "is the base of" attribution appears in the
  attribution notice and on the model card.

## Status

The skeleton: compilable drafts, configuration and research reports. No part of
it is production yet, and hash verification is deliberately **fail-closed**, in
`ai-data::verify`.

## Structure

| Crate | Job |
|---|---|
| `ai-core` | The model identity, the dataset types and the LoRA manifest; mirror types, per decision K3 |
| `ai-data` | Closed-loop source checking, the record format, fail-closed verification |
| `ai-serve` | The serving bridge configuration; the weight name is preserved and the served name is ours |
| `ai-tune` | The training plan, LoRA in BF16 or FP16, with FP4 absent from the type system, plus the output hash lock |
| `ai-ops` | The operator CLI skeleton: register, bond, serve, tune, status |

## Building

```bash
cargo check --workspace
cargo test --workspace
```

## Decisions

K2, the base model, is abstract and approved before the first fine-tune. K3,
the type binding, is deferred, and the skeleton suits either option. The method
is LoRA SFT.

## Documents

`ARCHITECTURE.md` in this directory is the layer summary.

Fine-tuning run artefacts, meaning notebooks, seed data, run guides and the
status matrix, are not kept in this repository: content that cannot be executed
belongs outside the code base.
