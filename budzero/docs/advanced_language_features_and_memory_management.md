# Advanced language features and memory management

Earlier chapters examined how the virtual machine works, the mathematics of ZK proofs, and how the compiler turns code into basic bytecode. But simple addition and subtraction and a flat execution flow are not enough to write modern, real-world contracts.

Three basic features make a programming language powerful:

1. **Functions**, so code can be reused.
2. A **type system**, so errors are caught at compile time.
3. **Data structures (structs)** and their memory management, so complex data models can be built.

This chapter walks step by step through how the BudZKVM compiler (bud-compiler) adapts these three large features to the ZK-STARK constraints and the limited register architecture. Welcome to one of the hardest and most enjoyable parts of designing a ZK language from scratch.

---

## 1. User-defined functions and caller-saved registers

### Why functions

Writing a large contract requires splitting the code into pieces. In code that both verifies a signature and checks a balance, separating those into functions (`verify_signature` and `check_balance`) improves readability.

In BudL a function is defined and called like this:

```rust
fn add_and_mul(a: u64, b: u64, c: u64) -> u64 {
    let sum = a + b;
    return sum * c;
}

pub fn main() {
    let res = add_and_mul(1, 2, 42);
    emit Result(res);
}
```

### The Call and Ret opcodes

Our virtual machine has two special instructions for function calls: `Call` and `Ret`.

* `Call`: saves the current instruction line (the program counter) onto the stack and jumps to the target function's line.
* `Ret`: takes the address at the top of the stack and returns to it.

But there is a large problem: **the register limit.** BudVM has only 32 registers (`R0`..`R31`). If `main` has saved an important value in `R5` and calls `add_and_mul`, that function may unknowingly use `R5` for its own work and overwrite it. On return to `main` the data in `R5` would be corrupted.

### The caller-saved register strategy

To solve this the compiler uses a **caller-saved** approach:

1. Just before making a call, `main` secures every register it is actively using (say `R1`, `R2`, `R3`) by pushing them onto the stack in order.
2. The function's parameters (`1, 2, 42`) are placed into freshly allocated registers.
3. The `Call` instruction runs. The callee uses whatever registers it wants, freely.
4. When the callee finishes it pushes the result onto the stack and does `Ret`.
5. Resuming, `main`'s first job is to restore the old register values from the stack with `Pop`.

Function calls of unlimited depth can therefore be made safely with only 32 registers.

---

## 2. Semantic analysis and the static type system

A compiler that merely holds variables is very dangerous. If the user writes `let x = true; let y = x + 5;`, at machine level that runs as `1 + 5 = 6` and becomes a logic bug. In ZK contracts bugs can cost millions.

### What is the semantic analyzer?

It is the checking phase during compilation, after the parser has produced the syntax tree and before code generation.

The semantic analyzer enforces these rules:

* **Type mismatch:** is a `bool` or a `field` being assigned where a `u64` is expected?
* **Function signatures:** does the call `add_and_mul(1, 2, 42)` take exactly 3 `u64` parameters? If a parameter is missing or a type is wrong, compilation stops (`CompileError::TypeError`).
* **Return types:** if a function declares `-> u64`, does the `return` expression inside really produce a `u64`?
* **Unknown variables:** is an undeclared variable being accessed (`a = 5`)?

The supported basic types are:

- `u64`: a 64-bit unsigned integer.
- `bool`: a logical true/false.
- `field`: a Goldilocks finite field element ($p = 2^{64} - 2^{32} + 1$), for the cryptographic computations specific to ZK proofs.
- `struct`: user-defined complex data types.

---

## 3. Structs and dynamic (heap) memory management

### Why we need memory

Registers are very fast but structurally they are just numbers. If the user has data like this:

```rust
struct User {
    id: u64,
    balance: u64,
    is_active: bool,
}
```

carrying that `User` in registers is hard (it needs 3 different registers and creates confusion when passing it to functions). Instead we must hold this data as a block in **memory** and carry only the block's starting address (a pointer) in the variable.

### Reserving r31 as HEAP_PTR

BudVM has a large unused memory space. The compiler sacrifices register 31 (`r31`) for a special purpose: the **heap pointer**. When the program starts, `r31` is set to a certain memory address (for example `4096`), which is the beginning of the free memory pool.

### Struct literals (creating an object)

When the user writes `let u = User { id: 1, balance: 100, is_active: true };`, the compiler does the following behind the scenes:

1. it allocates a new pointer register and copies the value of `r31` into it (address 4096, say),
2. it writes the `id` value `1` to memory address `4096` (`Opcode::Store`),
3. it writes the `balance` value `100` to memory address `4096 + 8 = 4104`,
4. it writes the `is_active` value `true (1)` to memory address `4104 + 8 = 4112`,
5. it advances `r31` (the heap pointer) by the size of the new object (3 fields * 8 bytes = 24) to `4120`,
6. it assigns the variable `u` only the object's starting address, `4096`.

### Field access

When the user later writes `let b = u.balance;`:

1. the semantic analyzer knows `u` is a `User` struct and that the `balance` field is its second element (offset 8 bytes),
2. the compiler emits `Opcode::Load`. That instruction goes to the address `u` holds (4096), adds the offset (8) to reach address 4104, reads the value `100` there and assigns it to `b`.

Thanks to this pass-by-reference approach:

- when structs are passed to functions as arguments, a whole data set is not copied - only a single pointer address is passed,
- the ZKVM's execution trace shrinks enormously and the prover's proving time speeds up considerably.

The combination of all these systems is what makes BudZKVM not a toy doing simple arithmetic but a ZK contract language at the level of modern languages such as Rust and Solidity.
