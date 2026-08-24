# What is a ZKVM and why build our own?

Welcome. Writing a virtual machine or a compiler is one of the most enjoyable subjects in software engineering. Once zero-knowledge proofs enter the picture it becomes both fascinating and demanding.

This chapter settles the basic concepts and then examines the reasons behind our architectural decisions.

## A traditional VM vs a ZKVM

A traditional virtual machine (the JVM, the EVM, a WASM engine) can be thought of as a state machine. Code (bytecode) and an initial state go in, the VM executes the instructions step by step, and a new final state comes out.

**But how do we trust that this state was computed correctly?**
In the traditional world the only way is **re-execution**. If I claim a program's result is `X`, you run the same program on your own computer and see whether you get `X`. That is why tens of thousands of nodes run the same code over and over in the blockchain world (Ethereum, for example). It is very slow and expensive.

A **ZKVM** changes that paradigm. While running the code, a ZKVM simultaneously produces a **mathematical proof** of that execution.
* Producing the proof (proving) is hard and needs hardware.
* But verifying the proof is incredibly fast (milliseconds) and removes the need to re-execute.

## Why build our own ZKVM?

There are excellent ZKVMs on the market: RISC Zero, SP1, Cairo. Why sit down and write our own virtual machine called "BudZKVM" from scratch?

1. **Learning and mastery:** the best way to understand how a ZKVM works is to open it up and build one. You can only learn how polynomials, AIR (algebraic intermediate representation) constraints and CPU architecture come together by getting your hands dirty.
2. **Customization:** a general-purpose ZKVM (a RISC-V-based one, say) can do everything but may be slow at certain operations. If you want to add cryptographic opcodes specific to your application or blockchain (built-in Keccak or Poseidon hash instructions, for example), owning your ISA is a big advantage.
3. **Performance:** in a ZKVM architecture the VM must be designed to be ZK-friendly. Traditional architectures seated inside a ZK circuit can produce enormous proof sizes. BudZKVM is designed specifically to be ZK-friendly, from register access to control flow.

## What does ZK-friendly design mean?

If you are a programmer, an if-else block or an array access is very cheap for you. But for a ZK prover:
* `if-else` conditions must be expressed with polynomial equations, without raising the degree.
* Random memory (RAM) access is very expensive. In the world of polynomials, RAM means a table and a lookup in that table.
* Standard 32-bit or 64-bit integer arithmetic is hard in ZK, because ZKVMs compute over a prime field, that is modulo a prime.

Crafting a ZKVM is the art of making traditional software engineering and the constraints of this polynomial mathematics work in harmony.

In the next chapter we start building from the lowest hardware layer, examining the language our virtual machine will speak: the **instruction set architecture (ISA)** and the bytecode design (`bud-isa`).
