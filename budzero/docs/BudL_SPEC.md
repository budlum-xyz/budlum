# BudL: Language Specification (v0.1)

> The smart contract language running on BudZKVM. STARK-provable, deterministic,
> gas-metered. This document defines the grammar of the language, its types, the
> opcode mapping and the gas model.
>
> **Version:** v0.1 (2026-07-19) · **Status:** Draft
> **Implementation:** `budzero/bud-compiler/` (lexer + parser + sema + codegen)

---

## 1. Overview

BudL is a smart contract language designed for BudZKVM (Budlum's zero-knowledge
virtual machine). Its properties:

- **Deterministic:** the same input always gives the same output (a consensus requirement).
- **STARK-provable:** every BudL program produces a BudZKVM execution trace;
  that trace is proven by the Plonky3 STARK prover.
- **Gas-metered:** every opcode has a fixed gas cost.
- **Storage:** persistent state (the `sread`/`swrite` opcodes).
- **Cryptography:** Poseidon hash, VerifyMerkle (64-depth SMT, mainnet-gated,
  see "VerifyMerkle soundness" below).

---

## 2. Language Grammar (BNF)

```
contract     := 'contract' ident '{' contract_body '}'
             // Every contract MUST CONTAIN a `main` function: codegen
             // patches the entry jump to it. Without one, compilation stops
             // with `Codegen error: main function not found`.
contract_body := (struct_decl | fn_decl | storage_decl)*

struct_decl  := 'struct' ident '{' (field_decl)+ '}'
field_decl   := ident ':' type ','          // trailing comma required

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

## 3. Types

| BudL type | Size | Description |
|-----------|-------|----------|
| `u64` | Goldilocks field element | The only integer type. Read the warning below |
| `field` | Goldilocks field element | Same representation as `u64`, states the intent explicitly |
| `bool` | 1-bit | Boolean (`true`/`false`) |
| `Address` | 32-byte, opaque | A Budlum address. Copied, compared, hashed |
| `Hash32` | 32-byte, opaque | A Poseidon/SHA-256 hash. Not interchangeable with `Address` |
| `struct` | variable | A user-defined composite type |

> [!WARNING]
> **`u64` is not a machine integer.** BudZKVM works in the Goldilocks field,
> so the modulus is `P = 2^64 - 2^32 + 1`. There are roughly 4.29e9 values
> between `u64::MAX` and `P`, and arithmetic there does not wrap, it **falls
> to mod P**. In a field holding money that difference is silent. The VM locks
> this down in its own tests (`add_is_goldilocks_field_not_wrapping`).

> [!NOTE]
> `u32`, `u128` and the signed types **do not exist**, and that is a constraint
> rather than an omission. Proving that a value fits in 32 bits asks for
> range-check columns in the AIR, and those columns do not exist; writing `u32`
> without a range check is sticking a label on a 64-bit register. The compiler
> rejects a program that uses those names, and says why.

> [!NOTE]
> `Address` and `Hash32` are **opaque**: they can do nothing beyond `==`,
> assignment and being a hash input. A VM register is 8 bytes and these values
> are 32 bytes; allowing arithmetic would operate on one of four limbs and
> produce a number that is the sum of nothing. It is a compile error.

### Struct example

```budl
contract Token {
    struct UserData {
        owner: Address,
        amount: u64,
        nonce: u64,
    }

    // `owner` is an `Address`; TODAY an Address value can only arrive as a
    // parameter. `msg::sender()` returns `u64` (see section 6), and because
    // struct field types are checked, handing it straight to `owner` is a
    // compile error. That is the boundary, and the example does not hide it.
    fn record(owner: Address, amount: u64) -> u64 {
        let entry = UserData { owner: owner, amount: amount, nonce: 0 };
        return entry.amount;
    }

    pub fn main() {
        let word = msg::sender();
        emit Recorded(word);
    }
}
```

This example compiles, and the `every_example_in_the_specification_compiles`
test verifies that on every run. The previous version did not compile: there
are no functions called `caller()`, `sread_u64()` or `swrite_u64()`, there is
no type called `[u8; 32]`, and structs are defined inside the `contract` body.

---

## 4. Opcode Mapping

BudL expressions compile to BudZKVM ISA opcodes:

### Arithmetic

| BudL | Opcode | Gas | Description |
|------|--------|-----|----------|
| `a + b` | `Add (0x01)` | 1 | Addition |
| `a - b` | `Sub (0x02)` | 1 | Subtraction |
| `a * b` | `Mul (0x03)` | 3 | Multiplication |
| `a / b` | `Div (0x04)` | 10 | Division |
| `1 / a` | `Inv (0x05)` | 50 | Multiplicative inverse (field inversion) |

### Logic and comparison

| BudL | Opcode | Gas | Description |
|------|--------|-----|----------|
| `a && b` | `And (0x06)` | 1 | AND |
| `a \|\| b` | `Or (0x07)` | 1 | OR |
| `a ^ b` | `Xor (0x08)` | 1 | XOR |
| `!a` | `Not (0x09)` | 1 | NOT |
| `a == b` | `Eq (0x0A)` | 1 | Equal |
| `a != b` | `Neq (0x0B)` | 1 | Not equal |
| `a < b` | `Lt (0x0C)` | 1 | Less than |
| `a > b` | `Gt (0x0D)` | 1 | Greater than |
| `a <= b` | `Lte (0x0E)` | 1 | Less or equal |
| `a >= b` | `Gte (0x0F)` | 1 | Greater or equal |

### Control flow

| BudL | Opcode | Gas | Description |
|------|--------|-----|----------|
| `if/else` | `Jnz (0x11)` | 2 | Jump-if-nonzero |
| `while` | `Jmp (0x10)` + `Jnz` | 2/iter | Loop |
| `fn()` | `Call (0x12)` + `Ret (0x13)` | 5 | Function call |

### Memory and stack

| BudL | Opcode | Gas | Description |
|------|--------|-----|----------|
| `let x = val` | `Push (0x16)` | 1 | Push onto the stack |
| `x` (read) | `Load (0x14)` | 1 | Load from memory |
| `x = val` (write) | `Store (0x15)` | 1 | Store to memory |
| `_` (discard) | `Pop (0x17)` | 1 | Pop from the stack |

### Cryptography

| BudL | Opcode | Gas | Description |
|------|--------|-----|----------|
| `hash(data)` | `Poseidon (0x19)` | 100 | Poseidon hash |
| `assert!(cond)` | `Assert (0x18)` | 1 | Assertion (fail = revert) |
| `verify_merkle(...)` | `VerifyMerkle (0x1E)` | 5000 | 64-depth SMT verification |
| `verify_inference(...)` | `VerifyInference (0x1F)` | 10000 | AI inference proof verify |

### Storage

| BudL | Opcode | Gas | Description |
|------|--------|-----|----------|
| `sread(key)` | `SRead (0x1B)` | 100 | Storage read |
| `swrite(key, val)` | `SWrite (0x1C)` | 500 | Storage write |

### System

| BudL | Opcode | Gas | Description |
|------|--------|-----|----------|
| `emit Event(...)` | `Log (0x1A)` | 10 | Event emission |
| `syscall(imm)` | `Syscall (0x1D)` | variable | Host call (AI request and so on) |
| `halt` | `Halt (0x00)` | 0 | End of program |

---

## 5. Gas Model

Every opcode has a fixed gas cost (the table above). Total gas = the sum of the
gas of all opcodes. If `gas_limit` is exceeded the program reverts.

```
total_gas = sum(opcode_gas for each executed opcode)
if total_gas > gas_limit -> revert (Out Of Gas)
```

### Gas cost categories

| Category | Gas | Example |
|----------|-----|-------|
| Arithmetic, simple | 1 | Add, Sub, Eq |
| Arithmetic, medium | 3-10 | Mul, Div |
| Field inversion | 50 | Inv |
| Hash | 100 | Poseidon |
| Storage read | 100 | SRead |
| Storage write | 500 | SWrite |
| Merkle verify | 5000 | VerifyMerkle |
| AI inference | 10000 | VerifyInference |

---

## 6. Stdlib (planned)

### Functions callable today

This list is the set of names the compiler actually knows. Sources:
`bud-compiler/src/sema.rs` (the type signature) and `codegen.rs` (the opcode).

| Function | Opcode mapping | Description |
|-----------|---------------|----------|
| `poseidon(a: u64, b: u64) -> u64` | Poseidon | Hashes two field elements |
| `msg::sender() -> u64` | Syscall(imm=1) | The caller |
| `msg::nonce() -> u64` | Syscall(imm=3) | The caller's nonce |
| `block::number() -> u64` | Syscall(imm=2) | Block height |
| `verify_merkle_proof(root, leaf, path) -> u64` | VerifyMerkle | 64-depth SMT, gated off on mainnet |
| `emit Event(...)` | Log | Event emission (a statement, not a function) |

### Planned, not there yet

The following **cannot be called**; they sit in a separate table so they are
not confused with the previous one. In an earlier version the two were in the
same table and the spec's own examples called functions that did not exist.

| Function | Why it is missing |
|-----------|-----------|
| `sread(key)` / `swrite(key, val)` | The opcode exists, the language has no surface for it |
| `timestamp()` | No syscall number reserved |
| `chain_id()` | No syscall number reserved |
| `verify_sig(msg, sig, pk)` | No Ed25519 verification circuit |
| `hash(bytes)` | No variable-length input (`poseidon` takes two field elements) |

`msg::sender()` returns `u64` today, not `Address`. An address is 32 bytes and
a register is 8; the syscall would have to return four limbs and the call site
would have to bind them as an `Address`. Until that work is done the signature
is kept honest.

---

## 7. Example program

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
        let height = block::number();
        let nonce = msg::nonce();
        emit Mint(height);
    }
}
```

Storage (`sread`/`swrite`) exists at the opcode level but **has no surface in
the language yet**: you cannot call a function named `sread_u64`. That is why
the example above does not touch storage. The table in section 6 says which
call is real.

---

## 8. Compilation flow

```
.bud source -> Lexer (tokens) -> Parser (AST) -> Sema (type check) -> Codegen (ISA bytecode)
```

- **Lexer:** `budzero/bud-compiler/src/lexer.rs`
- **Parser:** `budzero/bud-compiler/src/parser.rs`
- **AST:** `budzero/bud-compiler/src/ast.rs`
- **Sema:** `budzero/bud-compiler/src/sema.rs`
- **Codegen:** `budzero/bud-compiler/src/codegen.rs`

The compiled bytecode runs on BudZKVM -> execution trace -> Plonky3 STARK proof.

---
## 9. Branching programs: Program CTL multiplicity

The AIR in `bud-proof` links CPU rows to preprocessed program rows with a
Program CTL (LogUp) (`plonky3_air.rs`, `preprocessed_trace()` and the Program
CTL block).

That mapping was originally written as a **permutation**: the ROM side gave
every program row a fixed weight of `1`, so every instruction had to be
executed exactly once. Branching breaks that assumption by definition -- the
instruction on the skipped branch never runs, while a loop body runs many
times -- and an honest prover would get `InvalidProof`.

The mapping is now a real **lookup**. `COL_PROG_MULT` (column 753) carries, for
each ROM row, how many times that pc was executed in the trace; the LogUp
weight of the ROM side is that count. A zero multiplicity is a skipped
instruction, a multiplicity of `N` is a loop body that went round `N` times,
and neither unbalances the argument.

Soundness: the multiplicity lives in the committed main trace (it cannot be
put in the preprocessed table because the verifier does not see the trace) and
the `prog_mult * (1 - pre_active) = 0` constraint prevents weight being written
to a pc that is not in the program.

| Program shape | Compile | Execute | Prove | Verify |
|---|---|---|---|---|
| Straight-line code, `emit` included | OK | OK | OK | OK |
| A jump that executes every instruction (`Jmp +1`) | OK | OK | OK | OK |
| A branch that skips instructions (`if`/`else`) | OK | OK | OK | OK |
| A loop (`while`/`for`) | OK | OK | OK | OK |

Locking tests: `bud-proof/tests/compiled_branching.rs` proves the compiler's
`if` and `while` output end to end; the `PROVABLE_PROGRAMS` list in
`bud-cli/tests/toolchain_end_to_end.rs` includes the `example_loop.bud` and
`control_flow.bud` programs.

---

## 10. The public input contract: `event_digest`

`ExecutionPublicInputs::event_digest` is **not a hash.** The AIR binds an
additive accumulator carrying eight little-endian `u32` limbs
(`COL_EVENT_DIGEST_0..8`): every `Log` row adds the low 32 bits of its `rs1`
operand to limb 0, and limbs 1..8 stay zero.

Produce this field with `bud_proof::event_digest_from_events()`. Writing
`keccak256(events)` produces a proof whose verification always fails with
`OodEvaluationMismatch`: `bud-cli` was doing exactly that, and its `prove`/`run`
commands never worked.

---
## 11. Struct memory layout and the host memory base

The compiler prologue sets the heap pointer (`r31`) to the address
`bud_compiler::HEAP_BASE` (**4096**); struct literals are allocated above that
address.

Therefore every host that embeds BudZKVM must open the VM memory to at least
`bud_compiler::MIN_VM_MEMORY_BYTES` (**8192**). A smaller memory gives
`InvalidMemoryAccess` on the first allocation in **every** contract that uses a
struct.

`bud-cli` was using `1024` for this value; because the compiler's own tests use
`8192`, the bug was only visible through the CLI. The production path
(`src/execution/zkvm.rs`) already uses `8192`.

The boundary is locked by three tests in
`bud-cli/tests/toolchain_end_to_end.rs`: a struct contract is compiled and
**executed** (it produces the right result), the base relationship
(`MIN > HEAP_BASE`) is verified, and a `1024`-byte VM still erroring is kept as
a canary.

**Note:** contracts that use structs emit a helper function plus a prologue,
and the `Call`/`Ret` shape leaves at least one instruction unexecuted. Because
the Program CTL multiplicity column in section 9 now covers that case, a
skipped instruction does not block proving.

---
## 12. AIR proof coverage: the opcode matrix

The AIR in `bud-proof` constrains every opcode, but **being constrained is not
the same as being proven.** During measurement four opcodes were found to
appear in no prover test:

| Opcode | Previous state | Why it matters |
|---|---|---|
| `Store` (0x15) | no proof test | struct field writes land here |
| `Assert` (0x18) | no proof test | `constrain(...)` lands here |
| `Jmp` (0x10) | no proof test | the basis of all control flow |
| `Syscall` (0x1D) | no proof test | `caller()`, `block_height()` land here |

All four are now covered by a prove-verify round trip in `plonky3_prover.rs`.
The same must be done when a new opcode is added: writing an AIR constraint is
not enough, a proof of a program containing that opcode must be produced and
verified.

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
