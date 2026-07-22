# BNS Mainnet — Pricing, Lifecycle, Governance ( Q3 full_now, Q10 bns_tld_launch)

**Karar:** Q3 full_now (full pricing + resolver şimdi), Q10 bns_tld_launch (.bud pazarı aç), Q4 bug_bounty_simple ($50k/$100k), Q9 optional_keep (merkle_proof optional)

**HEAD:** `67da984` + chain_actor fix (duplicate SignPrecommit)

---

## 1. Pricing Table (non-technical + technical)

| İsim uzunluğu | Örnek | Multiplier | Base 100 * duration | Açıklama (non-tech) |
|---------------|-------|------------|---------------------|----------------------|
| 1-3 karakter | `ab.bud`, `x.bud` | x100 | 100*100* duration = 10k / epoch | Çok kısa, çok değerli (NFT gibi), pahalı — squatting önleme |
| 4-6 karakter | `ayaz.bud`, `budlum.bud` | x10 | 100*10* duration = 1k / epoch | Kısa, kişisel marka, orta pahalı |
| 7-32 karakter | `ahmetyilmaz.bud`, `myphotos.bud` | x1 | 100*1* duration = 100 / epoch | Normal, herkes alabilir |

- **Duration:** epoch cinsinden (EPOCH_LEN=100 blok ≈ ~?). Örn 100 epoch ≈ uzun süreli.
- **Cost calculation:** `BnsRegistry::calculate_cost(name, duration)` → base_cost * multiplier * duration
- **Non-tech:** `ab.bud` gibi 2 harf isim Ferrari plakası gibi — pahalı. Uzun isimler ucuz.

### Renewal

- Expired olunca herkes yeniden alabilir. Expiry check `record.expires_at <= current_epoch` → `None` döner, yeniden register edilebilir.

### Owner only operations

- `set_storage`, `set_content`, `register_subdomain` sadece owner.
- `NotOwner` error → başkasının ismini değiştiremezsin.

## 2. Lifecycle (teknik + non-tech)

```
1. Register: Alice "ayaz.bud" alır (cost hesaplanır, epoch+duration = expires_at)
2. Resolve: Bob "ayaz.bud" sorgular → Address + storage_root + content_id döner
3. Set storage: Alice storage_root ekler (B.U.D. manifest kökü) → "sitemin dosyaları burada"
4. Set content: Alice content_id ekler (SocialFi NFT post / site manifest)
5. Subdomain: Alice "blog.ayaz.bud" oluşturur, Bob'a verir
6. Expiry: Süre dolunca başkası alabilir
```

**Non-tech:** `.bud` ismi senin alan adın gibi. İstersen cüzdan adresine, istersen websitesinin dosyalarının köküne (storage_root), istersen bir fotoğrafın CID'sine bağlarsın. `blog.ayaz.bud` gibi alt isimler de ücretsiz oluşturabilirsin.

## 3. Resolver / Storage Binding

- `NameRecord { address: Option<Address>, storage_root: Option<[u8;32]>, storage_domain_id, content_id: Option<ContentId>, subdomains: BTreeMap }`
- `resolve_full` → `BnsResolved { name, owner, address, storage_root, storage_domain_id, content_id, is_expired }`
- `BnsResolveContent` → direkt ContentId (SocialFi/D-Web)
- `BnsResolveSubdomain` → `parent + label`

**Non-tech:** `ayaz.bud` yazınca hem para gönderebilirsin hem de sitesine gidebilirsin. Aynı isim hem cüzdan hem website.

## 4. Implementation Status (HEAD 67da984 + fix)

- Registry: `calculate_cost`, `register`, `register_with_storage`, `register_subdomain`, `resolve_subdomain`, `set_content`, `resolve_content`, `resolve`, `resolve_full`, `set_storage` ✅
- ChainActor: `BnsResolve`, `BnsResolveFull`, `BnsResolveContent`, `BnsResolveSubdomain`, `BnsSetStorage`, `BnsCalculateCost`, `NftGet`, `NftGetByOwner` — **bug fix:** duplicate `SignPrecommit { SignPrecommit {` → single (CI fail kök nedeni)
- RPC: `bud_bnsResolveFull`, `bud_bnsSetStorage`, `bud_bnsResolveContent`, `bud_bnsCalculateCost` (chain actor üzerinden)
- Tests: `test_bns_registration_and_resolution`, `test_bns_expiration`, `test_bns_full_impl_storage_binding`, `test_bns_set_storage_owner_only` ✅
- **Eksik:** `bud_bnsFetchContent(name)` → BNS resolve + KAD discovery + Bitswap fetch tek çağrıda (ARENA3 önerisi,  devamı)

## 5. SocialFi / D-Web (67da984)

- `src/nft/mod.rs`, `types.rs` → `Nft { id, owner, content_id }` — post as NFT
- `TransactionType::BnsRegister`, `BnsSetContent`, `BnsRegisterSubdomain`, `NftMint`, `NftTransfer`
- `NameRecord.content_id` → SocialFi post'un B.U.D. manifestine link
- `subdomains` → `photos.ayaz.bud`, `blog.ayaz.bud`

**Non-tech:** Artık her paylaşım (foto, yazı) NFT olarak mintlenebilir, gerçek içeriği B.U.D. storage'da, ismi `.bud` ile çözülüyor. Yani Instagram'ın içeriği senin elinde, sansürlenemez.

## 6. Pricing Governance Kararları (Q3 full_now + Q10 bns_tld_launch)

- **Q3 full_now:** Pricing tablosu ve owner-only kuralları 'te yazıldı (bu doküman). 'e bırakılmadı.
- **Q10 bns_tld_launch:** `.bud` pazarı devnet'te açılıyor, mainnet'te ceremony sonrası. Squatting önleme için kısa isimler x100 pahalı.
- **Bug bounty (Q4):** BNS'de kritik açık (başkasının ismini çalma, expiry bypass) → $100k.

## 7. Sonraki Adımlar (devam sonrası)

- `bud_bnsFetchContent` RPC glue (BNS → manifest → Bitswap)
- Docker smoke fix (Q7) — HSM olmadan mainnet container
- VerifyMerkle depth 2 diagnosis (Q1 ctl_debug) — `task4_verify_merkle_depth_2_diagnosis` test
- Genesis ceremony bootnodes dummy (Q5 user_decides_later)
- CI fail fix: chain_actor duplicate SignPrecommit fixlendi, fmt/clippy kontrolü CI'da

---

**Co-authored-by:** ARENA2 (BNS pricing + SocialFi entegrasyon doğrulama) + ARENA3 (constraint debug plan)
