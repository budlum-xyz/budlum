# BudL — Dil Spesifikasyonu (v0.1)

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
- **Cryptography:** Poseidon hash, VerifyMerkle (64-depth SMT — mainnet-gated,
  see "VerifyMerkle soundness" below).

---

## 2. Dil Graumeri (BNF)

```
contract     := 'contract' ident '{' contract_body '}'
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
| `u32` | 32-bit | Tamsayı (dizi index, sayaç) |
| `u64` | 64-bit | Tamsayı (varsayılan) |
| `u128` | 128-bit | Geniş tamsayı (tutar) |
| `bool` | 1-bit | Boolean (`true`/`false`) |
| `Address` | 256-bit | Budlum adresi (32-byte) |
| `Hash32` | 256-bit | SHA-256/Poseidon hash |
| `struct` | değişken | Kullanıcı tanımlı kompozit tip |

### Struct Örneği

```budl
struct UserData {
    owner: Address,
    amount: u64,
    nonce: u64,
    tags: [u8; 32],  // fixed-size byte array (gelecek)
}

contract Token {
    storage {
        balances: Hash32,  // Merkle root of balance tree
        total_supply: u64,
    }

    pub fn transfer(to: Address, amount: u64) -> bool {
        let caller_addr = caller();
        let caller_bal = sread_u64(caller_addr);
        if (caller_bal < amount) {
            return false;
        }
        swrite_u64(caller_addr, caller_bal - amount);
        let to_bal = sread_u64(to);
        swrite_u64(to, to_bal + amount);
        emit Transfer(caller_addr, to, amount);
        return true;
    }
}
```

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

| Fonksiyon | Opcode Mapping | Açıklama |
|-----------|---------------|----------|
| `hash(data: Vec<u8>) -> Hash32` | Poseidon | Hash hesapla |
| `caller() -> Address` | Syscall(imm=1) | Çağıran adres |
| `block_height() -> u64` | Syscall(imm=2) | Mevcut blok yüksekliği |
| `timestamp() -> u64` | Syscall(imm=3) | Blok timestamp |
| `chain_id() -> u64` | Syscall(imm=4) | Chain ID |
| `verify_sig(msg, sig, pk) -> bool` | Syscall(imm=5) | Ed25519 imza doğrula |
| `verify_merkle(root, leaf, proof) -> bool` | VerifyMerkle | 64-depth SMT |
| `emit Event(...)` | Log | Event yayın |

---

## 7. Örnek Program

```budl
contract SimpleToken {
    storage {
        total_supply: u64,
    }

    struct Balance {
        owner: Address,
        amount: u64,
    }

    pub fn mint(to: Address, amount: u64) {
        let caller_addr = caller();
        let current = sread_u64(caller_addr);
        swrite_u64(caller_addr, current + amount);
        emit Mint(to, amount);
    }

    pub fn balance_of(addr: Address) -> u64 {
        let bal = sread_u64(addr);
        return bal;
    }
}
```

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
## 9. Kanıtlanabilirlik Sınırı — Dallanan Programlar

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

## 10. Genel Girdi Sözleşmesi — `event_digest`

`ExecutionPublicInputs::event_digest` bir **hash değildir.** AIR, sekiz adet
küçük-endian `u32` limb taşıyan toplamsal bir akümülatör bağlar
(`COL_EVENT_DIGEST_0..8`): her `Log` satırı `rs1` işleneninin düşük 32 bitini
limb 0'a ekler, limb 1..8 sıfır kalır.

Bu alanı `bud_proof::event_digest_from_events()` ile üretin. `keccak256(events)`
yazmak, doğrulaması her zaman `OodEvaluationMismatch` ile başarısız olan bir
kanıt üretir — `bud-cli` tam olarak bunu yapıyordu ve `prove`/`run` komutları
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
## 12. AIR Kanıt Kapsamı — Opcode Matrisi

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
the leaf is. It used to be constrained only to be boolean — the AIR comment
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

**Still open: the witness is not bound to memory.** Two columns remain free:

- `COL_VM_MERKLE_SIBLING` is consumed as a Poseidon input, with nothing tying it
  to the bytes at `path_addr + 8 + i * 8`.
- `COL_VM_MERKLE_KEY` is constrained only for continuity across rows, not
  against the word at `path_addr`.

The VM reads all 65 words (`bud-vm/src/lib.rs`), but those reads do not enter
the memory argument (`COL_MEM_ADDR` / `COL_MEM_VAL`), so a prover can supply a
path that was never in memory. Until that is closed, a proof shows only that
*some* consistent path exists, not that it is the one the program read —
`verify_merkle_enabled` stays false.
