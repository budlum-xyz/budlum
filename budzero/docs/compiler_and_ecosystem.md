# The compiler and the ecosystem (bud-compiler and bud-cli)

We now have an instruction set (the ISA), a virtual machine that runs those instructions and produces an execution trace, and a ZK prover (Plonky3) that proves the trace correct mathematically.

But there is a problem: no developer wants to sit down and hand-write bytecode as `Instruction { opcode: Add, dst: 1, src1: 2, src2: 3, imm: 0 }`. Developers need to write high-level code such as `let a = b + c;`. That is where the **compiler** comes in.

## The Bud compiler (bud-compiler)

The `bud-compiler` crate takes the simple high-level or assembly-like language we call Bud and turns it into the bytecode our VM understands. Writing a compiler is an art in itself, but the basic steps are:

1. **Lexer:** it reads the source character by character and splits it into meaningful words (tokens). For example `let x = 5;` becomes `[LET, IDENT(x), EQ, NUMBER(5), SEMICOLON]`.

   > [!NOTE]
   > **Comment support:** at the lexer layer, single-line (`// ...`) and multi-line block comments (`/* ... */`) are scanned dynamically with Logos-based rules and cleanly ignored before compilation (`logos::skip`).

2. **Parser:** it takes the token stream and builds an abstract syntax tree (AST). This tree reflects the logical structure of the code.

   #### Operator precedence and parentheses

   The most common mistake in flat, recursive-descent parser designs is resolving arithmetic expressions in a flat left-to-right order. For example, a flat parser gives `20` for `2 + 3 * 4` when mathematically it must be `14`.

   In the Bud compiler this is solved by layering **operator precedence**:
   * **`parse_expr`**: resolves the comparison operators (`==`, `!=`, `<`, `>`, `<=`, `>=`).
   * **`parse_arith`**: resolves addition and subtraction (`+`, `-`).
   * **`parse_term`**: resolves multiplication and division (`*`, `/`).
   * **`parse_primary`**: resolves the highest-precedence items - literal numbers, hexadecimal numbers (`0x...`), variable names and **parenthesized groups** (`( ... )`).

   Groupings such as `(2 + 3) * 4` and precedence-bearing expressions such as `2 + 3 * 4` therefore compile in full agreement with the mathematical rules.

   #### Panic-free error handling (result-based parsing)

   In early compiler designs the parser threw `panic!()` at any syntax error and the compiler boundary caught those panics with `std::panic::catch_unwind`. That approach is both fragile and contrary to Rust's safety philosophy.

   The parser architecture was redesigned to be entirely **result based**:
   * every parse method now returns `Result<ASTNode, CompileError>`,
   * on an error the compiler produces `CompileError::ParserError(String)` and propagates it cleanly upward (with the `?` operator) instead of panicking,
   * all of the compiler's error paths are guarded by the `test_parser_error_propagation` negative tests.

3. **Semantic analyzer:** it catches logical errors - are the variables declared? do the types agree? is there an unused variable?
4. **Code generation:** this is where our ISA comes in. Traversing the AST, an appropriate `Instruction` is produced for each node. For example `x = 5` becomes `Load R1, 5`.

### Control flow: `while` and `for`

The Bud language now supports two basic loop forms:

```bud
while (count < 4) {
    count = count + 1;
}

for i in 0..5 {
    sum = sum + i;
}
```

`while` translates directly into a condition + `Jnz` + backward `Jmp` pattern. `for i in start..end` is reduced by the compiler to this logic:

1. `start` is loaded into a loop register.
2. `end` is computed once and held as the fixed range bound.
3. On each iteration `loop_reg < end_reg` is compared.
4. After the body runs, `loop_reg = loop_reg + 1`.

This form uses a half-open range: `0..5` produces the values `0,1,2,3,4`.

### Register allocation

One of the hardest parts of writing a compiler is register management. We have 32 registers. What happens if a program has 50 variables? The compiler must free the registers of variables that are out of scope and allocate them to new ones. In very complex programs, when registers fill up, variables are written to memory/storage (this is called spilling).

## Tying the system together with the CLI (bud-cli)

The "conductor" that brings all these modules together is the command-line tool `bud-cli`.

The full flow of the system:

1. the user runs `bud-cli run --program mycode.bud`,
2. the CLI reads the file and hands it to `bud-compiler`, which returns the bytecode (the instruction list),
3. the CLI loads that bytecode into `bud-vm` and runs the VM,
4. the VM finishes and produces an execution trace along with the results,
5. the CLI takes that trace and sends it to the `bud-proof` module (Plonky3),
6. Plonky3 checks the AIR constraints, applies the matrix mathematics and produces a **ZK proof**,
7. optionally that proof is verified in a very short time with the `verify` function.

A sample loop program sits at the repository root:

```bash
nix develop --command cargo run -p bud-cli -- run --program example_loop.bud
```

This example uses both `for` and `while`. The expected event output is `[10, 6]`:

* `for i in 0..5`: `0 + 1 + 2 + 3 + 4 = 10`
* `while count < 4`: `0 + 1 + 2 + 3 = 6`

```rust
// A sample flow from inside bud-cli
let trace = vm.trace; // the logs the VM produced
let num_steps = trace.len();

// Producing the proof (heavy)
let proof = Prover::prove(&trace, num_steps);
println!("Proof generated ({} bytes)", proof.data.len());

// Verifying the proof (very fast)
let ok = Prover::verify(&proof, num_steps);
println!("Proof valid: {}", ok);
```

## Budlum L1 integration

BudZKVM bytecode can now run inside the Budlum L1 `infra` repository as a `TransactionType::ContractCall`. In this integration:

1. the client places the BudZKVM bytecode into the `tx.data` field as a little-endian `u64` instruction byte string,
2. L1's `src/execution/zkvm.rs` decodes the bytecode,
3. the VM runs with a gas limit,
4. a proof is produced with `bud-proof` and verified,
5. only after a successful execution are the sender's fee and nonce state updated.

The bytecode produced in the CLI and the L1 transaction payload format therefore stay the same.

## Conclusion and what comes next

Congratulations. Starting from scratch you have designed a full-fledged ZKVM that defines its own instruction set, runs code, and proves the result correct cryptographically.

**Completed (31/31 opcodes in production, 51 tests, 0 failures):**
* the AIR constraints of every opcode are done (comparison 64-bit decomposition, bitwise algebraic equivalence, Poseidon4 hash, storage STORAGE_BASE memory LogUp, poseidon4-based VerifyMerkle),
* `postcard` serialization (bounded, DoS protected),
* structured tracing across the whole pipeline with `RUST_LOG=info`,
* 8 negative tests (tampered comparison, bitwise, Poseidon S-box, storage, PC, public inputs, program, proof bytes),
* CI: fmt + check + clippy + test + docs link check + cargo deny.

**What is next (performance)?**
* a benchmark suite (criterion), proving/verification time measurements,
* prover parallelization (Rayon),
* proof size optimization (FRI parameter tuning).

**What is next (language and compiler)?**
* struct/record support, mappings (Map<K,V>), a standard library,
* better error messages and source spans (miette),
* a debug mode and a step-by-step interactive debugger.

**What is next (ZK work)?**
* recursive proof aggregation (many transactions -> one block proof),
* ZK mode (zero knowledge), WASM/EVM verifier targets,
* full multi-round Poseidon AIR verification.
