# Lubot system-prompt set

This directory is the **served system prompt set** for Lubot — the AI layer of
Budlum. It is the brand-facing identity of the protocol's thinking surface,
consistent with the architecture and with the paradigm-shift definition in
`budlum` (`docs/ARCHITECTURE.md` and the paradigm source).

## Design doctrine

The set is **proof-first**, built on the invariant: *accept nothing you cannot
point to evidence for*. It is concrete to the code, not aspirational — every
doctrine line names the real mechanism behind it (`output_commitment`, the
effort ceiling, `Pollen` grants, the fail-closed STARK path).

It is also deliberately **ask-user and plan-shaping**: the constructor profile
elicits intent, produces a plan, then verifies. It is not a narrator.

## Layers (top = applied last, most role-specific)

| File | Layer | Applies to |
| --- | --- | --- |
| [`core.md`](core.md) | Identity + doctrine. Immutable; wins on conflict. | All roles |
| [`constructor.md`](constructor.md) | Turn a request into a verified plan. Ask first, then build. | Builders on/for the protocol |
| [`operator.md`](operator.md) | Register, serve, be paid. Machine you own + ceiling + closed loop. | Compute operators |
| [`verifier.md`](verifier.md) | k-of-n attestation; bit-identical agreement; fail closed. | Verifiers |
| [`assistant.md`](assistant.md) | User-facing voice; honesty; bar-not-wish claims. | End users |
| [`model-card.md`](model-card.md) | Provenance + naming + status. | Everyone inspecting a served response |

## Precedence

`core.md` encodes Budlum's invariants and is **not** overridden by a role layer.
Where a role layer and the core disagree, the core wins. Where a role layer is
present, `lubot-serve::prompt::LayeredPrompt` stitches core → role.

## Attribution

Base weights are the DeepSeek V4 family (MIT), preserved and attributed in
`NOTICE.md` and `model-card.md`. Only our own layer carries the name Lubot.

## Names

`lubot-light` and `lubot-normal`; no multiplier labels. `assert_served_name_is_ours`
is the enforcement point.
