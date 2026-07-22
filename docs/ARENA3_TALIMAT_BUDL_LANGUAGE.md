# ARENA3 TALİMATI — budl Programlama Dili Organizasyonu

**Tarih:** 2026-07-22
**Hazırlayan:** ARENA1 · **Hedef ajan:** ARENA3
**Branch (ARENA3 kendi branch'inde çalışır):** `restructure/budl-language`
**⚠️ Base branch:** `restructure/monorepo-folders` — ARENA3 `restructure/budl-language`'i **bu branch'tan** açmalı (main'de hâlâ `budzero/` adıyla duruyor; `budZero/` ve `budl/` restructure branch'ında mevcut).
**Yetkili:** Ayaz · **Bu talimatı Ayaz ARENA3'e iletir.**

---

## 0. Bağlam

Budlum ekosistemi tek repoda (budlum) konsolide ediliyor. 4 üst klasör: budlumCore, budZero, B.U.D. (Lubot içinde). Bu talimat **yalnızca budZero/ içindeki `budl/`** programlama dili organizasyonunu kapsar — src/ bölmesinden BAĞIMSIZDIR (çakışma yok, paralel güvenli).

**budl** = Budlum'un kendi programlama dilidir. BudZKVM (zkVM) üzerinde çalışan, zk-proof-native (STARK) akıllı-kontrat/program dili. ARENA1 `budZero/budl/README.md` iskeletini oluşturdu; ARENA3 bunu tam haline getirir.

## 1. Kapsam (ARENA3)

`budZero/` kökünde şu an dağınık duran `.bud` örnek dosyalarını ve dil materyalini `budZero/budl/` altında organize et:
- `budZero/example.bud`, `example2.bud`, `example_loop.bud`, `test_prover.bud`, `budZero/control_flow.bud` → `budZero/budl/examples/` altına taşı.

## 2. Görevler

1. **Örnekleri taşı:** Yukarıdaki `.bud` dosyalarını `budZero/budl/examples/`'a `git mv` ile taşı. (bud-compiler bunları referans alıyorsa yolunu güncelle — kontrol et.)
2. **Dil spec'i yaz** (`budZero/budl/SPEC.md`):
   - Sözdizimi (syntax): değişken, fonksiyon, kontrol akışı,opcode mapping.
   - Tip sistemi (varsa).
   - budl → bud-isa bytecode derleme akışı (bud-compiler).
   - Örneklerin açıklaması (her .bud dosyası ne demonstrasyon yapıyor).
3. **Opcode → dil mapping'i** (`budZero/budl/OPCODES.md`): bud-isa opcode seti (0x00–0x22) ve bunların budl seviyesinde karşılığı. D2 gizlilik opcode'ları (PrivacyCommit 0x20, NullifierCheck 0x21, SumConservation 0x22) dahil — dil seviyesinde commitment/nullifier/sum-conservation desteği.
4. **README güncelle:** `budZero/budl/README.md`'yi eksiksiz, güncel, doğru veriyle yaz (eski/yanlış veri yok). "Detaylı yaz, baştan savma olmasın."
5. **Pipeline dokümantasyonu:** `budl → (bud-compiler) → bud-isa bytecode → (bud-vm) → execution trace → (bud-proof) STARK` akışını net belgele.

## 3. Bağımlılıklar / mevcut altyapı (doğrula, kör inanma)

- `budZero/bud-compiler/` — derleyici (AST → bytecode). parser.rs, codegen.rs, ast.rs.
- `budZero/bud-isa/` — opcode seti (lib.rs, Opcode enum 0x00–0x22).
- `budZero/bud-vm/` — VM + execution trace (poseidon4_hash burada, Goldilocks).
- `budZero/bud-proof/` — Plonky3 STARK AIR (plonky3_air.rs).
- `.bud` örnekleri budZero/ kökünde.

## 4. Kabul kriterleri

- [ ] `.bud` örnekleri `budZero/budl/examples/` altında.
- [ ] `budZero/budl/SPEC.md` + `OPCODES.md` yazıldı, güncel/doğru.
- [ ] `budZero/budl/README.md` eksiksiz.
- [ ] `cd budZero && cargo check` temiz (taşıma bir şey kırmadı).
- [ ] CI yeşil (budZero workspace).
- [ ] Commit hash + CI linki raporlandı.
- [ ] `budlumdevnet`/`budlumdevnet2` DOKUNULMADI (artık referans değil ama yine de değiştirme).

## 5. Ortam

- `source /home/user/setup.sh` (Rust 1.94.0 + protoc).
- Doğrulama: `cd budZero && cargo check -j 1`. CI yegâne hakem.
- budl/ work budZero/ workspace'inin BİR PARÇASI mı yoksa ayrı mı — ARENA3 karar versin (Cargo.toml'a member olarak eklenebilir ya da sadece dokümantasyon klasörü kalabilir). Tercih: dokümantasyon + examples klasörü (compile katmanı değil).

## 6. Raporlama

Bitince STATUS_ONLINE.md'ye entry + commit hash + CI linki. Talimatları eksiksiz uygula (rule 7).

---
*ARENA1 tarafından hazırlandı. Ayaz bunu ARENA3'e iletir (branch: `restructure/budl-language`). src/ bölmesi (budlumCore/B.U.D.) ARENA1'de, çakışma yok.*
