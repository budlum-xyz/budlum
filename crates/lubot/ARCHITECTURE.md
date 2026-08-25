# Lubot architecture summary

This file summarises the layers. It used to point at a full version,
`docs/MIMARI_ONERISI_2026-08-13.md`, but that file does not exist anywhere in
the tree; the pointer is recorded here as a missing reference rather than
repeated as though it resolved.

## Layers

```
[ On chain - budlum/main/src/lubot/ ]        (exists; this repo does not touch it)
   model registry - operator compute bond - Pollen - B.U.D. - SocialFi
                        ^ hash and reference matching
[ This repo - the off-chain skeleton ]
   lubot-core   : ModelId (a 32-byte hash, mirroring the AiModelId form),
                  dataset types, LoRaManifest
   lubot-data   : closed-loop source checking over 3 channels, the record
                  format, fail-closed hash verification
   lubot-serve  : the vLLM and SGLang bridge; the weight name is preserved and
                  the served name is ours
   lubot-tune   : TunePlan (LoRA in BF16 or FP16, with no FP4), the output hash
                  lock
   lubot-ops    : the CLI skeleton
```

## Principles

1. **Closed loop:** there is no path that reads outside data; every set enters
   through a B.U.D. `StorageDeal`, a `TrainingCorpus` tag and hash
   verification.
2. **Fail closed:** an unverified hash is a refusal, and `lubot-data::verify`
   deliberately returns `Err`. Real SHA-256 arrives in production.
3. **Attribution:** third party names are preserved; only our own layer carries
   the name "Lubot".
4. **Language:** the whole tree, documents included, is English. This principle
   used to read "documents in Turkish, code identifiers in English"; the
   repository-wide rule replaced it, and the `tree-is-english` gate enforces it.
5. **No shell scripts:** no shell code is hosted in the repository; the training
   phase runs in outside containers and is only documented.

## Decision status, 2026-08-13

| Decision | Status |
|---|---|
| K1 skeleton and repository | produced; awaiting review |
| K2 base model | abstract; the light tier is the default, with approval before the first run |
| K3 type binding | deferred; the skeleton suits either option |
| K5 method | LoRA SFT with a BF16 adapter |
| K6 data source | **HYBRID**: open sets enter the network with a B.U.D. record |
| K7 tier naming | **light**, Flash based, and **normal**, Pro based; there are no multiplier labels |

## Deepening, 2026-08-13

- `lubot-data`: real SHA-256 verification (`verify_sha256`, `content_id_of`),
  JSONL records built on serde_json, and a draft structural chat template.
- `lubot-serve`: the tier naming (`lubot-light-*` and `lubot-normal-*`), the
  multiplier label check, and a fail-closed chain RPC draft
  (`chain::NotConnected`).
- `lubot-core`: the `ModelTier` type, light or normal; `ModelSpec` carries the
  tier.

## The system prompt, 2026-08-25

The prompt handed to a model before the first user message lives in
`lubot-core/src/system_prompt.rs` as a `const`, not in a configuration file.
A prompt is the part of the product a user is asked to trust without being able
to read the weights; loading it from a mutable file at runtime would let two
operators claim the same model while running different instructions, and
nothing in the tree would notice.

Because it is source, its claims are checkable, and they are checked in two
places:

- `lubot-core` tests assert the prompt is internally consistent - the ceilings
  it states match the table it declares, the reading-only boundary keeps all
  three of its reasons, and it does not overstate what is cryptographically
  proven.
- The `lubot-prompt-is-true` gate checks the half those tests cannot see: that
  the numbers the prompt tells a user are the numbers `src/lubot/perception.rs`
  actually admits by. It fails in both directions, because which of the two is
  wrong is a judgement a gate should not make.

The prompt states why Lubot reads and does not generate, at length and with the
measurements behind it. That is deliberate. An unexplained boundary reads as a
missing feature and gets removed by the next contributor who thinks they are
adding symmetry.

## On-device residency, 2026-08-25

`lubot-serve/src/residency.rs` plans where each part of a model lives on the
machine an operator actually owns. The motivating fact is that engines
requiring the whole model resident in accelerator memory restrict the operator
set to data-centre hardware, which contradicts the effort tiers: a tier no
consumer device can serve is a tier no consumer device can earn from.

A mixture-of-experts model activates a small fraction of its parameters per
token. The dense part - attention, shared experts, embeddings, the output head
- is needed for every token and earns residency. Routed experts are needed one
subset at a time and can be staged from slower storage on demand. So memory
stops being a requirement and becomes a placement.

One invariant governs the whole module: **placement decides speed and never
semantics.** A device short on memory produces the same tokens, more slowly. It
does not drop to a smaller quantisation, a shorter context or a different
routing rule. On this chain that is not a preference: answers are grouped by an
exact 32-byte commitment, and an operator whose engine quietly reduced
precision under memory pressure would stop agreeing while appearing healthy -
the symptom would be a request that never finalises, which reads as a liveness
fault rather than the configuration error it is. `SemanticProfile` is therefore
carried through the planner untouched, and the invariant is a test rather than
a comment.

Two consequences follow from the same rule. A device that cannot hold the dense
part is refused rather than degraded, because streaming a weight every token
needs is not a slow plan but a plan that re-reads the same bytes every step.
And weights are placements of B.U.D. content, addressed by `ContentId`; there
is no path that stages a shard the chain has not seen, because an operator who
could stage a shard from anywhere could stage a different one, and the model
commitment would then describe something other than what ran.

Deliberately absent: prefetch policy, learned hot-sets, eviction heuristics.
Those have to be measured on real hardware before they are believed, and an
unmeasured policy written into the tree reads as a decision when it is a guess.
