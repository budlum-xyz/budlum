# BudL: Dil Spesifikasyonu (v0.1)

> BudZKVM üzerinde çalışan akıllı kontrat dili. STARK-provable, deterministik,
> gas-metered. Bu doküman dilin gramerini, tiplerini, opcode mapping'ini ve
> gas modelini tanımlar.
>
> **Sürüm:** v0.1 (2026-07-19) · **Durum:** Draft
> **Uygulama:** `budzero/bud-compiler/` (lexer + parser + sema + codegen)

---

## 1. Genel Bakış

BudL, BudZKVM (Budlum'un zero-knowledge sanal makinesi) için tasarlanmış bir
akıllı kontrat dilidir. Özellikleri:

- **Deterministik:** Aynı giriş her zaman aynı çıktı (konsensüs gereği).
- **STARK-provable:** Her BudL programı bir BudZKVM execution trace üretir;
  bu trace Plonky3 STARK prover tarafından prove edilir.
- **Gas-metered:** Her opcode'un sabit gas maliyeti vardır.
- **Storage:** Kalıcı durum (`sread`/`swrite` opcode'ları).
- **Cryptography:** Poseidon hash, VerifyMerkle (64-depth SMT, mainnet-gated,
  see "VerifyMerkle soundness" below).

---

## 2. Dil Graumeri (BNF)

```
contract     := 'contract' ident '{' contract_body '}'
             // Her kontrat bir `main` fonksiyonu ICERMELIDIR: codegen
             // giristeki jump'i ona yamalar. Yoksa derleme
             // `Codegen error: main function not found` ile durur.
contract_body := (struct_decl | fn_decl | storage_decl)*

struct_decl  := 'struct' ident '{' (field_decl)+ '}'
field_decl   := ident ':' type ','          // trailing comma zorunlu

fn_decl      := 'pub'? 'fn' ident '(' params? ')' ('->' type)? block
params       := param (',' param)*
param        := ident ':' type

storage_decl := 'storage' '{' (field_decl)* '}'

block        := '{' stmt* '}'
stmt         := let_stmt | if_stmt | while_stmt | emit_stmt
             | match_stmt | assign_stmt | return_stmt | expr_stmt

let_stmt     := 'let' ident (':' type)? '=' expr ';'
if_stmt      := 'if' expr block ('else' (if_stmt | block))?
while_stmt   := 'while' expr block
emit_stmt    := 'emit' ident '(' expr? (',' expr)* ')' ';'
match_stmt   := 'match' expr '{' match_arm* '}'
match_arm    := pattern '=>' block ','
assign_stmt  := ident '=' expr ';'
return_stmt  := 'return' expr? ';'
expr_stmt    := expr ';'

expr         := binop_expr | unary_expr | literal | ident | call_expr
             | member_access | index_access
binop_expr   := expr op expr
op           := '+' | '-' | '*' | '/' | '==' | '!=' | '<' | '>' | '<=' | '>='
             | '&&' | '||' | '&' | '|' | '^'
literal      := int_literal | bool_literal | string_literal
call_expr    := ident '(' args? ')'
member_access := expr '.' ident
```

---

## 3. Tipler

| BudL Tipi | Boyut | Açıklama |
|-----------|-------|----------|
| `u64` | Goldilocks alan elemanı | Tek tamsayı tipi. Aşağıdaki uyarıyı oku |
| `field` | Goldilocks alan elemanı | `u64` ile aynı temsil, niyeti açık yazar |
| `bool` | 1-bit | Boolean (`true`/`false`) |
| `Address` | 32-byte, opak | Budlum adresi. Kopyalanır, karşılaştırılır, hash'lenir |
| `Hash32` | 32-byte, opak | Poseidon/SHA-256 hash. `Address` ile değiştirilemez |
| `struct` | değişken | Kullanıcı tanımlı kompozit tip |

> [!WARNING]
> **`u64` bir makine tamsayısı değildir.** BudZKVM Goldilocks cisminde
> çalışır, yani modül `P = 2^64 - 2^32 + 1`. `u64::MAX` ile `P` arasında
> yaklaşık 4.29e9 değer vardır ve orada aritmetik sarmaz, **mod P'ye düşer**.
> Para tutan bir alanda bu fark sessizdir. VM bunu kendi testlerinde
> kilitliyor (`add_is_goldilocks_field_not_wrapping`).

> [!NOTE]
> `u32`, `u128` ve işaretli tipler **yok**, ve eksiklik değil kısıt.
> Bir değerin 32 bite sığdığını kanıtlamak AIR'de range-check sütunları
> ister, o sütunlar yok; range-check olmadan `u32` yazmak 64-bit bir
> register'a etiket yapıştırmaktır. Derleyici bu adları kullanan bir
> programı, nedenini söyleyerek reddeder.

> [!NOTE]
> `Address` ve `Hash32` **opaktır**: `==`, atama ve hash girdisi olmak
> dışında bir şey yapamazlar. VM register'ı 8 byte, bu değerler 32 byte;
> aritmetiğe izin vermek dört limb'den birinde işlem yapıp hiçbir şeyin
> toplamı olmayan bir sayı üretirdi. Derleme hatası verir.

### Struct Örneği

```budl
contract Token {
    struct UserData {
        owner: Address,
        amount: u64,
        nonce: u64,
    }

    fn record(owner: Address, amount: u64) -> u64 {
        let entry = UserData { owner: owner, amount: amount, nonce: 0 };
        return entry.amount;
    }

    pub fn main() {
        let who = msg::sender();
        let recorded = record(who, 100);
        emit Recorded(recorded);
    }
}
```

Bu örnek derlenir ve `every_example_in_the_specification_compiles` testi
bunu her koşuda doğrular. Önceki sürümü derlenmiyordu: `caller()`,
`sread_u64()` ve `swrite_u64()` diye fonksiyonlar yok, `[u8; 32]` diye bir
tip yok, ve struct'lar `contract` gövdesinin içinde tanımlanır.

---

## 4. Opcode Mapping

BudL ifadeleri BudZKVM ISA opcode'larına derlenir:

### Aritmetik

| BudL | Opcode | Gas | Açıklama |
|------|--------|-----|----------|
| `a + b` | `Add (0x01)` | 1 | Toplama |
| `a - b` | `Sub (0x02)` | 1 | Çıkarma |
| `a * b` | `Mul (0x03)` | 3 | Çarpma |
| `a / b` | `Div (0x04)` | 10 | Bölme |
| `1 / a` | `Inv (0x05)` | 50 | Çarpımsal ters (field inversion) |

### Mantık & Karşılaştırma

| BudL | Opcode | Gas | Açıklama |
|------|--------|-----|----------|
| `a && b` | `And (0x06)` | 1 | VE |
| `a \|\| b` | `Or (0x07)` | 1 | VEYA |
| `a ^ b` | `Xor (0x08)` | 1 | XOR |
| `!a` | `Not (0x09)` | 1 | DEĞİL |
| `a == b` | `Eq (0x0A)` | 1 | Eşit |
| `a != b` | `Neq (0x0B)` | 1 | Eşit değil |
| `a < b` | `Lt (0x0C)` | 1 | Küçük |
| `a > b` | `Gt (0x0D)` | 1 | Büyük |
| `a <= b` | `Lte (0x0E)` | 1 | Küçük eşit |
| `a >= b` | `Gte (0x0F)` | 1 | Büyük eşit |

### Kontrol Akışı

| BudL | Opcode | Gas | Açıklama |
|------|--------|-----|----------|
| `if/else` | `Jnz (0x11)` | 2 | Jump-if-nonzero |
| `while` | `Jmp (0x10)` + `Jnz` | 2/iter | Döngü |
| `fn()` | `Call (0x12)` + `Ret (0x13)` | 5 | Fonksiyon çağrısı |

### Bellek & Stack

| BudL | Opcode | Gas | Açıklama |
|------|--------|-----|----------|
| `let x = val` | `Push (0x16)` | 1 | Stack'e push |
| `x` (read) | `Load (0x14)` | 1 | Memory'den load |
| `x = val` (write) | `Store (0x15)` | 1 | Memory'ye store |
| `_` (discard) | `Pop (0x17)` | 1 | Stack'ten pop |

### Kriptografi

| BudL | Opcode | Gas | Açıklama |
|------|--------|-----|----------|
| `hash(data)` | `Poseidon (0x19)` | 100 | Poseidon hash |
| `assert!(cond)` | `Assert (0x18)` | 1 | Assertion (fail = revert) |
| `verify_merkle(...)` | `VerifyMerkle (0x1E)` | 5000 | 64-depth SMT verification |
| `verify_inference(...)` | `VerifyInference (0x1F)` | 10000 | AI inference proof verify |

### Depolama

| BudL | Opcode | Gas | Açıklama |
|------|--------|-----|----------|
| `sread(key)` | `SRead (0x1B)` | 100 | Storage okuma |
| `swrite(key, val)` | `SWrite (0x1C)` | 500 | Storage yazma |

### Sistem

| BudL | Opcode | Gas | Açıklama |
|------|--------|-----|----------|
| `emit Event(...)` | `Log (0x1A)` | 10 | Event yayını |
| `syscall(imm)` | `Syscall (0x1D)` | değişken | Host-call (AI request vb.) |
| `halt` | `Halt (0x00)` | 0 | Program sonu |

---

## 5. Gas Modeli

Her opcode'un sabit gas maliyeti vardır (yukarıdaki tablo). Toplam gas =
tüm opcode'ların gas toplamı. `gas_limit` aşılırsa program revert eder.

```
total_gas = sum(opcode_gas for each executed opcode)
if total_gas > gas_limit → revert (Out Of Gas)
```

### Gas Maliyet Kategorileri

| Kategori | Gas | Örnek |
|----------|-----|-------|
| Arithmetic basit | 1 | Add, Sub, Eq |
| Arithmetic orta | 3-10 | Mul, Div |
| Field inversion | 50 | Inv |
| Hash | 100 | Poseidon |
| Storage okuma | 100 | SRead |
| Storage yazma | 500 | SWrite |
| Merkle verify | 5000 | VerifyMerkle |
| AI inference | 10000 | VerifyInference |

---

## 6. Stdlib (Planlanan)

### Bugün çağrılabilen fonksiyonlar

Bu liste derleyicinin gerçekten tanıdığı adlardır. Kaynak:
`bud-compiler/src/sema.rs` (tip imzası) ve `codegen.rs` (opcode).

| Fonksiyon | Opcode Mapping | Açıklama |
|-----------|---------------|----------|
| `poseidon(a: u64, b: u64) -> u64` | Poseidon | İki alan elemanını hash'ler |
| `msg::sender() -> u64` | Syscall(imm=1) | Çağıran |
| `msg::nonce() -> u64` | Syscall(imm=3) | Çağıranın nonce'u |
| `block::number() -> u64` | Syscall(imm=2) | Blok yüksekliği |
| `verify_merkle_proof(root, leaf, path) -> u64` | VerifyMerkle | 64-derinlik SMT, mainnet'te kapalı |
| `emit Event(...)` | Log | Event yayını (fonksiyon değil, deyim) |

### Planlanan, henüz yok

Aşağıdakiler **çağrılamaz**; bir öncekiyle karıştırılmasın diye ayrı tabloda.
Önceki sürümde ikisi aynı tablodaydı ve spec'in kendi örnekleri olmayan
fonksiyonları çağırıyordu.

| Fonksiyon | Neden yok |
|-----------|-----------|
| `sread(key)` / `swrite(key, val)` | Opcode var, dilde yüzeyi yok |
| `timestamp()` | Syscall numarası ayrılmadı |
| `chain_id()` | Syscall numarası ayrılmadı |
| `verify_sig(msg, sig, pk)` | Ed25519 doğrulama devresi yok |
| `hash(bytes)` | Değişken uzunluklu girdi yok (`poseidon` iki alan elemanı alır) |

`msg::sender()` bugün `u64` döner, `Address` değil. Adres 32 byte, register
8 byte; syscall'ın dört limb döndürmesi ve çağrı yerinin bunu bir `Address`
olarak bağlaması gerekir. O iş yapılana kadar imza dürüst tutuluyor.

---

## 7. Örnek Program

```budl
contract SimpleToken {
    struct Balance {
        owner: Address,
        amount: u64,
    }

    fn mint(to: Address, amount: u64) -> u64 {
        let entry = Balance { owner: to, amount: amount };
        return entry.amount;
    }

    pub fn main() {
        let who = msg::sender();
        let height = block::number();
        let minted = mint(who, 50);
        emit Mint(minted);
    }
}
```

Depolama (`sread`/`swrite`) opcode seviyesinde vardır ama **dilde henüz
yüzeyi yoktur**: `sread_u64` diye bir fonksiyon çağıramazsın. Yukarıdaki
örnek bu yüzden depolamaya dokunmuyor. §6'daki tablo hangi çağrının gerçek
olduğunu söyler.

---

## 8. Derleme Akışı

```
.bud source → Lexer (tokens) → Parser (AST) → Sema (type check) → Codegen (ISA bytecode)
```

- **Lexer:** `budzero/bud-compiler/src/lexer.rs`
- **Parser:** `budzero/bud-compiler/src/parser.rs`
- **AST:** `budzero/bud-compiler/src/ast.rs`
- **Sema:** `budzero/bud-compiler/src/sema.rs`
- **Codegen:** `budzero/bud-compiler/src/codegen.rs`

Derlenen bytecode BudZKVM'de çalışır → execution trace → Plonky3 STARK proof.

---
## 9. Kanıtlanabilirlik Sınırı: Dallanan Programlar

`bud-proof` içindeki AIR, bir Program CTL (LogUp) ile her CPU satırını tam
olarak bir ön-işlenmiş program satırıyla eşler (`plonky3_air.rs`,
`preprocessed_trace()` ve Program CTL bloğu). Bu eşleme **her komutun en az bir
kez çalıştırılmasını** gerektirir.

Sonuç: yürütülmeyen bir komut bırakan program STARK doğrulamasında
`OodEvaluationMismatch` ile reddedilir. BudL'de `if`, `while` ve `for`
alınmayan dalı atlayan `Jmp`/`Jnz` üretir, dolayısıyla **dallanan sözleşmeler
şu an kanıtlanamaz.**

| Program şekli | Derleme | Yürütme | Kanıt | Doğrulama |
|---|---|---|---|---|
| Düz kod, `emit` dahil | ✅ | ✅ | ✅ | ✅ |
| Her komutu çalıştıran sıçrama (`Jmp +1`) | ✅ | ✅ | ✅ | ✅ |
| Komut atlayan dal (`if`/`while`/`for`) | ✅ | ✅ | ✅ | ❌ |

Ölçüm: `Jmp +1` (hiçbir komut atlamaz) doğrulanır; `Jmp +2` (bir komut atlar)
`OodEvaluationMismatch` verir. Sıçramanın kendisi değil, **atlanan komut**
sorundur.

Sınır `budzero/bud-cli/tests/toolchain_end_to_end.rs` ve
`plonky3_prover.rs` kanaryalarıyla kilitlidir. Program CTL satır-başına çokluk
(multiplicity) taşıyacak şekilde genişletildiğinde bu testler kırmızıya döner ve
bu bölümün güncellenmesini zorlar.

**Üretim etkisi:** BudL sözleşme yürütme katmanı mainnet'te açık değildir; bu
sınır kapatılmadan dallanan sözleşmeler zincir üzerinde kanıtlanamaz.

---

## 10. Genel Girdi Sözleşmesi: `event_digest`

`ExecutionPublicInputs::event_digest` bir **hash değildir.** AIR, sekiz adet
küçük-endian `u32` limb taşıyan toplamsal bir akümülatör bağlar
(`COL_EVENT_DIGEST_0..8`): her `Log` satırı `rs1` işleneninin düşük 32 bitini
limb 0'a ekler, limb 1..8 sıfır kalır.

Bu alanı `bud_proof::event_digest_from_events()` ile üretin. `keccak256(events)`
yazmak, doğrulaması her zaman `OodEvaluationMismatch` ile başarısız olan bir
kanıt üretir: `bud-cli` tam olarak bunu yapıyordu ve `prove`/`run` komutları
hiç çalışmıyordu.

---
## 11. Struct Bellek Yerleşimi ve Host Bellek Tabanı

Derleyici prologu heap işaretçisini (`r31`) `bud_compiler::HEAP_BASE`
(**4096**) adresine kurar; struct literal'leri bu adresin üzerine tahsis edilir.

Bu yüzden BudZKVM'i barındıran her host, VM belleğini en az
`bud_compiler::MIN_VM_MEMORY_BYTES` (**8192**) olarak açmalıdır. Daha küçük bir
bellek, struct kullanan **her** sözleşmede ilk tahsiste `InvalidMemoryAccess`
verir.

`bud-cli` bu değeri `1024` olarak kullanıyordu; derleyicinin kendi testleri
`8192` kullandığı için hata yalnızca CLI üzerinden görülüyordu. Üretim yolu
(`src/execution/zkvm.rs`) zaten `8192` kullanıyor.

Sınır `bud-cli/tests/toolchain_end_to_end.rs` içindeki üç testle kilitlidir:
struct sözleşmesi derlenip **çalıştırılır** (doğru sonucu üretir), taban
ilişkisi (`MIN > HEAP_BASE`) doğrulanır ve `1024` baytlık bir VM'in hâlâ hata
vermesi kanarya olarak tutulur.

**Not:** bellek düzeltmesi çalıştırmayı mümkün kılar, kanıtlamayı değil. Struct
kullanan sözleşmeler bir yardımcı fonksiyon + prolog üretir; `Call`/`Ret` şekli
en az bir komutu yürütülmeden bırakır, dolayısıyla §9'daki Program CTL sınırına
takılır. Test bunu koşullu doğrular: doğrulama **tam olarak** her komut
çalıştığında başarılı olmalıdır.

---
## 12. AIR Kanıt Kapsamı: Opcode Matrisi

`bud-proof` içindeki AIR tüm opcode'ları kısıtlar, ancak **kısıtlanmış olmak
kanıtlanmış olmak değildir.** Ölçüm sırasında dört opcode'un hiçbir prover
testinde geçmediği bulundu:

| Opcode | Önceki durum | Neden önemli |
|---|---|---|
| `Store` (0x15) | kanıt testi yok | struct alan yazımı buraya iner |
| `Assert` (0x18) | kanıt testi yok | `constrain(...)` buraya iner |
| `Jmp` (0x10) | kanıt testi yok | tüm kontrol akışının temeli |
| `Syscall` (0x1D) | kanıt testi yok | `caller()`, `block_height()` buraya iner |

Dördü de artık `plonky3_prover.rs` içinde prove→verify round-trip ile
kapsanmıştır. Yeni bir opcode eklendiğinde aynı şey yapılmalıdır: AIR kısıtı
yazmak yeterli değil, o opcode'u içeren bir programın kanıtı üretilip
doğrulanmalıdır.

---


## VerifyMerkle soundness

`VerifyMerkle (0x1E)` is gated off on mainnet
(`MainnetActivation::default().verify_merkle_enabled == false`). The reason has
always been recorded as "unfinished path verification"; this section says which
part.

The AIR already constrains most of the path. Each `VerifyMerkle` step is
followed by 64 expansion rows, and the AIR checks the leaf binding
(`original -> first expansion: current == rs2_val`), the round chain
(`round' == round + 1`, first round zero), the Poseidon single-round S-box
identities and output on every expansion row, and the final accumulator against
the claimed root through an inverse witness. Negative tests cover a skipped
round, a tampered accumulator and a tampered S-box.

**Closed: the direction bits.** `merkle_bit` chooses which side of the Poseidon
pair the sibling sits on, which is the part of a Merkle path that says *where*
the leaf is. It used to be constrained only to be boolean, the AIR comment
said the prover "can simply provide a valid bit column". Measured against that
version: flipping the round-0 bit, recomputing the chain and leaving
`merkle_key` untouched produced a different root, and the proof verified.

`COL_MERKLE_KEY_REM` carries `key >> round`, and the AIR ties it down with

```text
seed:        first expansion row's rem == merkle_key
every round: rem == 2 * rem' + bit
last round:  rem == bit          (so rem' would be zero)
```

With `bit` boolean, `rem = 2 * rem' + bit` is one step of binary long division
and has exactly one solution per round, so the chain forces
`bit_r = (key >> r) & 1`. Terminating at zero also pins `key` to 64 bits, which
the previous constraints assumed without checking.
`rejects_verify_merkle_with_flipped_direction_bit` pins this, and it fails when
the remainder chain is removed.

**Closed: the witness is bound to memory.** `COL_VM_MERKLE_SIBLING` and
`COL_VM_MERKLE_KEY` used to be free witness columns, the AIR consumed them as
Poseidon inputs and nothing tied them to the bytes at `path_addr`. Measured:

```text
expansion rows              = 64
rows carrying memory_addr   =  0
path words in the argument  =  0  (of 65)
```

The VM reads all 65 words, but those reads never entered the memory argument,
so a prover could supply a path that was never written.

Each expansion row now emits its sibling read and the original step emits the
key read, and both appear on the *demand* side of the memory LogUp at an
address the AIR derives rather than the prover chooses:

```text
key:      addr = imm
round r:  addr = imm + 8 + 8 * r
```

Two details made this work. A row that supplies a memory entry without a
matching demand unbalances the LogUp, so adding the reads to the table alone
turned every proof into `InvalidProof` until the demand side was extended in
the same shape. And the expansion rows carried a synthetic instruction with
`imm: 0`, so the derived addresses landed near zero while the table supplied
the real ones, measured as a 7-of-8 mismatch across the first rows. The
expansion rows carry the real immediate now.

`rejects_verify_merkle_with_a_sibling_not_in_memory` pins it, and removing the
Merkle terms from the demand side drops four Merkle tests.

**What remains before the gate can open.** The path is now sound in the STARK:
direction bits are bound to the key, the key and siblings are bound to memory,
the Poseidon chain and the final root are constrained. What has not happened
is an external review of the whole opcode against a real sparse-Merkle-tree
deployment, which is what `MainnetActivation` is for. `verify_merkle_enabled`
stays false until then, but it is now a process gate rather than a known
soundness hole.
