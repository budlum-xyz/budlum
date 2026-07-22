# budl — Budlum Programlama Dili

**budl**, Budlum ekosisteminin kendi programlama dilidir. BudZKVM (zkVM) üzerinde
çalışan, zk-proof-native (STARK) akıllı-kontrat / program dili.

## Kapsam

- **Sözdizimi + derleyici:** `budZero/bud-compiler/` (AST → bud-isa bytecode).
- **Hedef ISA:** `budZero/bud-isa/` (opcode seti: 0x00–0x22, PrivacyCommit/NullifierCheck/SumConservation dahil).
- **Çalışma zamanı:** `budZero/bud-vm/` (VM + execution trace).
- **Kanıt:** `budZero/bud-proof/` (Plonky3 STARK AIR).

## Durum (2026-07-22)

- Dil derleyici + ISA + VM + STARK proving altyapısı mevcut (bud-compiler/bud-isa/bud-vm/bud-proof).
- Bu klasör (`budl/`) dilin tek referans noktasıdır — spec, örnekler, stdlib burada toplanacak.
- D2 gizlilik opcode'ları (0x20–0x22) dil seviyesinde commitment/nullifier/sum-conservation desteği ekler.

## İlişki

`budl` → derlenir → `bud-isa` bytecode → çalışır → `bud-vm` → kanıtlanır → `bud-proof` (STARK).
