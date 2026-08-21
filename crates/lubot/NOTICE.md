# NOTICE - Atıf Bildirimi

Lubot, aşağıdaki üçüncü taraf eserlere dayanır. Bu bildirim, atıf politikasının
teknik karşılığıdır: kopyalanan üçüncü taraf kodu ve ağırlık adları olduğu gibi
korunur; "Lubot" adı yalnızca kendi katmanımızda kullanılır.

## 1. DeepSeek V4 (taban model - MIT)

- Checkpoint'ler: `deepseek-ai/DeepSeek-V4-Flash-Base`, `deepseek-ai/DeepSeek-V4-Pro-Base`
  ve instruct varyantları (Hugging Face / ModelScope).
- Lisans: MIT - "Copyright (c) 2023 DeepSeek". Telif ve izin bildirimi, dağıtılan
  kopyalarda korunmalıdır.
- Lubot ince ayar çıktıları "Lubot-{sürüm} (DeepSeek-V4-…-Base tabanlı)" olarak
  adlandırılır; model kartı tabanı açıkça belirtir.
- Kaynak: https://huggingface.co/deepseek-ai/DeepSeek-V4-Flash/blob/main/LICENSE
  (2026-08-13'te doğrulandı).

## 2. Aday veri setleri (lisansları kullanım öncesi yeniden doğrulanır)

| Set | Lisans | Durum |
|---|---|---|
| turkish-nlp-suite/InstrucTurca | Apache-2.0 | doğrulandı |
| hasankursun/turkish-corpus-100b | Apache-2.0 | doğrulandı (sft split aday) |
| ogulcanaydogan/Turkish-LLM-v10-Training | açık (kart doğrulanacak) | şartlı aday |
| merve/turkish_instructions | kart boş (doğrulanacak) | şartlı aday |
| BAAI/Infinity-Instruct | CC-BY-SA-4.0 | şartlı (ShareAlike türev notu) |
| Magpie veri setleri | CC BY-NC + Llama | uygun değil (NC) |
