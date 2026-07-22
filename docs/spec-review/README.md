#  Spec Review Checklist

**Durum:**  kabul kapısı
**Amaç:** Kod yazmadan önce ana mainnet spec'lerinin interface freeze, ADR bağı, güvenlik kabul kriteri ve CI kapısı bakımından gözden geçirildiğini kanıtlamak.

Her spec review dosyası aşağıdaki checklist'i eksiksiz taşır:

- [x] Interface frozen marker present (`INTERFACE_FROZEN: true`)
- [x] ADR link present
- [x] Scope and non-goals documented
- [x] Security/threat interaction documented
- [x] State/root/supply interaction documented where relevant
- [x] Test or CI gate defined
- [x] Implementation  and owner path identified

`./scripts/check-spec-coverage.sh` bu klasördeki zorunlu review kayıtlarının varlığını ve checklist satırlarını CI'da doğrular.

##  review kayıtları

| Spec | Review | Durum |
|---|---|---|
| `docs/GENESIS_REWARD_POOL_SPEC.md` | `GENESIS_REWARD_POOL_SPEC_REVIEW.md` | Approved |
| `docs/BUD_STORAGE_TECHNICAL_SPEC.md` | `BUD_STORAGE_TECHNICAL_SPEC_REVIEW.md` | Approved |
| `docs/DOMAIN_FORK_CHOICE_SPEC.md` | `DOMAIN_FORK_CHOICE_SPEC_REVIEW.md` | Approved |
| `docs/EIP1559_FEE_MARKET_SPEC.md` | `EIP1559_FEE_MARKET_SPEC_REVIEW.md` | Approved |

---

*Co-authored-by: ARENA1 <arena1@budlum.ai>*
