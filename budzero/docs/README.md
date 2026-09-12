# Crafting a ZKVM: the BudZKVM guide

This book is a guide to designing, from scratch, a virtual machine and a ZKVM (zero-knowledge virtual machine) that can cryptographically prove the correctness of the programs running on it.

Following the philosophy of "Crafting Interpreters", the guide is entirely practical, code-driven and step by step. The **BudZKVM** project serves as the worked example.

## Who is this book for?
* Developers curious about cryptography and ZK-STARK concepts.
* Anyone who wants to write their own virtual machine, instruction set (ISA) or compiler.
* Anyone who wants to see how modern ZK proving frameworks such as Plonky3 are used in a real project.

## The main components of the BudZKVM architecture
BudZKVM is designed modularly. Through the book we build these components step by step:

1. **`bud-isa` (instruction set architecture):** the hardware instructions the VM understands and how they are encoded in bytecode.
2. **`bud-vm` (the virtual machine):** the core that runs bytecode step by step (fetch-decode-execute) and updates register and memory state.
3. **`bud-compiler` (the compiler):** it translates the high-level BudL language into `bud-isa` bytecode. Basic control flow is supported, including `while` and `for i in start..end`.
4. **`bud-proof` (the ZK prover):** a Plonky3-based module that takes the VM's execution trace and produces a cryptographic proof (a STARK proof) that it ran correctly.
5. **`bud-cli` (the command line):** the interface that brings all these modules together for the user.

## A note on current status

BudZKVM is a ZKVM whose every opcode has AIR constraints and a prover/verifier path exercised by the workspace tests (`cargo test --workspace` in `budzero/`; CI measures the count, this page does not repeat it). Production scope is narrower than implementation scope: `MainnetActivation::default()` keeps `VerifyMerkle`, `VerifyInference`, `PrivacyCommit`, `NullifierCheck` and `SumConservation` **off** until the post-ceremony activation, `VerifyInference` has an opcode and a gate but no verification circuit yet, and the BudL language is still marked Draft in [BudL_SPEC.md](BudL_SPEC.md). Implemented is not the same as activated; the sections below say which one they mean.

## Contents

- [Introduction: what is a ZKVM and why build our own?](introduction.md)
- [Instruction set architecture and bytecode (bud-isa)](isa_and_bytecode.md)
- [Building the virtual machine (bud-vm)](virtual_machine.md)
  - [BudVM trace schema v2](vm_trace_schema.md)
- [Designing a ZK-friendly architecture](zk_friendly_architecture.md)
- [STARK, AIR and Plonky3 (bud-proof)](stark_and_plonky3.md)
- [The compiler and the ecosystem (bud-compiler and bud-cli)](compiler_and_ecosystem.md)
- [Prover stabilization and tests](prover_stabilization_and_tests.md)
- [Production hardening and soundness](production_hardening_and_soundness.md)
- [Advanced language features and memory management](advanced_language_features_and_memory_management.md)
- [Stabilization status](STABILIZATION.md)

## Developer documentation

- [Development workflow](development.md)
- [Adding an opcode](adding_opcodes.md)
- [Proof format release checklist](proof_format_release_checklist.md)

---
> **Note:** the code samples in this guide are written in Rust. Familiarity with Rust's basic memory-safety concepts will help.
