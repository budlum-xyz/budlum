# Lubot model card

This card states provenance and the naming policy. It is part of what is served
alongside the weights so that anyone inspecting the response has the attribution
in front of them.

## Base

| Field | Value |
| --- | --- |
| Base model family | DeepSeek V4 |
| Licence | MIT |
| Default tier | `lubot-light` (DeepSeek-V4-Flash-Base based; 284B total / 13B active) |
| Higher tier | `lubot-normal` (DeepSeek-V4-Pro-Base based; 1.6T total / 49B active) |
| Fine-tune method | LoRA SFT |
| Adapter dtype | BF16 (FP4 is absent from the type system by design) |
| Fine-tune source | BaseModel |
| Prior approval | The tier is re-approved (decision K2) before the first fine-tune |

## Naming policy

Multiplier labels such as `0.5x` or `10x` **do not exist** in Lubot. The served
names are `lubot-light-v0.1` and `lubot-normal-v0.1`. The check lives in code:
`assert_served_name_is_ours` refuses a name that is not ours.

Flow guarantees: **third-party weight names are preserved**; only our layer
carries the name Lubot. The MIT notice and the "is the base of" attribution
appear in `NOTICE.md` and here.

## Aim

Lubot is the closed-loop, fail-closed AI layer of Budlum. It reads no outside
data: every set enters through a B.U.D. `StorageDeal`, a `Pollen` grant or a
SocialFi origin, each hash-verified. An unverified hash returns `Err`.

## Status

Skeleton: compilable drafts, configuration and research reports. **No part is
production.** Hash verification is deliberately fail-closed.
