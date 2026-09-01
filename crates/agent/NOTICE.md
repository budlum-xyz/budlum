# NOTICE - Attribution

Agent builds on the third-party works below. This notice is the technical form
of the attribution policy: copied third-party code and weight names are kept as
they are, and the name "Agent" is used only for our own layer.

## 1. DeepSeek V4 (the base model - MIT)

- Checkpoints: `deepseek-ai/DeepSeek-V4-Flash-Base`,
  `deepseek-ai/DeepSeek-V4-Pro-Base` and the instruct variants (Hugging Face /
  ModelScope).
- Licence: MIT - "Copyright (c) 2023 DeepSeek". The copyright and permission
  notice has to be preserved in distributed copies.
- Agent fine-tuning outputs are named "Agent-{version} (based on
  DeepSeek-V4-…-Base)"; the model card states the base explicitly.
- Source: https://huggingface.co/deepseek-ai/DeepSeek-V4-Flash/blob/main/LICENSE
  (verified on 2026-08-13).

## 2. Candidate datasets (licences are re-verified before use)

| Set | Licence | Status |
|---|---|---|
| turkish-nlp-suite/InstrucTurca | Apache-2.0 | verified |
| hasankursun/turkish-corpus-100b | Apache-2.0 | verified (the sft split is a candidate) |
| ogulcanaydogan/Turkish-LLM-v10-Training | open (card to be verified) | conditional candidate |
| merve/turkish_instructions | the card is empty (to be verified) | conditional candidate |
| BAAI/Infinity-Instruct | CC-BY-SA-4.0 | conditional (a ShareAlike derivative note) |
| Magpie datasets | CC BY-NC + Llama | not suitable (NC) |
