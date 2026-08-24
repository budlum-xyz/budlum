# AI Inference Layer (module README)

**This is the AI layer's own README, as the module-separation rule requires.**
The root `README.md` is only a dashboard; maturity and risk warnings live here.

## Status

- **Maturity:** live (verifier network + RPC + ZKVM host call).
- **Code location:** `src/ai/`, `mod.rs` (soft-incentive reward + P5
  deadline/escrow), `registry.rs` (`AiRegistry`: request/result/outcome +
  agreement threshold + equivocation detection), `types.rs` (`AiModelSpec`,
  `AiInferenceRequest/Result/Outcome`, `AiRequestId`, `BoundedBytes`),
  `execution/` (bounded model class, fixed-point MLP guest + host evaluator,
  structural and STARK verification).
- **Test count:** 188 `#[test]` functions under `src/ai/` (`mod.rs` 130,
  `execution/guest.rs` 39, `execution/verify.rs` 16, `execution/model_class.rs`
  3). Counted, not estimated; `registry.rs` and `types.rs` carry no test of
  their own and are exercised through `mod.rs`.
- **RPC endpoints (6):** `bud_aiGetModel`, `bud_aiRegisterModel`,
  `bud_aiSubmitRequest`, `bud_aiSubmitResult`, `bud_aiGetOutcome`,
  `bud_aiGetActiveVerifiers`.
- **ZKVM host call:** `Syscall imm=6` -> a `0x00A1_00A1` event -> automatic
  `AiInferenceRequest` creation (`budzero/bud-vm/src/lib.rs`).

## Maturity warnings

- **Attestation model (-1).** On-chain AI inference is off-chain computation
  plus on-chain attestation (k-of-n verifier agreement). It is **not zkML**:
  proving large models on chain is not practical in 2026 (the determinism
  problem). Tier -2 is STARK-provable inference for restricted model classes
  (BudZKVM).
- **Determinism risk.** The same model can produce different output on
  different hardware, so `agreement_threshold` may never be met. The bounded
  model class in `execution/model_class.rs` is the answer to this for the
  fixed-point MLP path: a whitelisted shape, integer arithmetic, and a host
  evaluator the guest result is compared against. Models outside that class
  still depend on attestation, and their limits must be documented before
  mainnet.
- **The AI - B.U.D./Pollen AccessGrant admission gate.** `input_ref` can still
  be legacy opaque bytes; but when it carries the Pollen `AiDataInputRef`
  prefix, the executor refuses the request with `ai_data_access_denied` unless
  a valid `AccessGrant` is present (`src/execution/executor.rs`). There is no
  DAO or admin override. HPKE hard enforcement is still tier -2 encryption
  work.

## Security (P5 shipped)

- **Deadline enforcement:** `request_deadline_blocks` / `result_deadline_blocks`
  (request/result expiry -> reject).
- **Equivocation detection:** conflicting commitments from the same verifier
  raise a dispute flag.
- **Fee escrow reclaim:** the fee is returned on timeout (findings 4-5, P5).
- **Soft incentive:** a minority verifier is NOT slashed, it is only left out
  of the reward.

## Bounded execution path

`execution/` is the part that does not rely on attestation alone:

- `model_class.rs` - the v1 whitelist: `MAX_MLP_WIDTH = 64`,
  `MAX_MLP_LAYERS = 4`, `MAX_MLP_PARAMS`. Guest memory is usually the binding
  limit rather than the parameter budget, and `FixedPointMlpSpec::validate`
  rejects the difference instead of letting it appear as a truncated forward
  pass.
- `guest.rs` - a bit-exact host forward pass (i32 MAC, ReLU),
  domain-separated input/output commitments, and guest bytecode that runs the
  same forward pass in the VM over a host-published memory image. The guest
  result is checked against the host evaluator.
- `verify.rs` - `ExecutionVerifyReport`: commitment agreement, model binding,
  program-hash match, and the weights digest the proof carries. STARK
  verification over a postcard `ProofEnvelope` is optional on top of it.

## Next

Deeper AI - B.U.D. AccessGrant integration (P5 RFC, after Pollen P1) and the
dispute/timeout edge-case test matrix.
