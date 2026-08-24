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
