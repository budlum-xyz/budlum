// Unsafe kilidi: bu crate su an 0 unsafe. Bir `unsafe` blok girdigi an
// the build FAILs (a regression gate). The same policy as the main crate.
#![forbid(unsafe_code)]
pub mod ast;
pub mod codegen;
pub mod lexer;
pub mod parser;
pub mod sema;

use bud_isa::IsaProfile;
use tracing::debug;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileError {
    LexerError(String),
    ParserError(String),
    SemanticError(String),
    CodegenError(String),
    ExperimentalOpcodeDisabled(String),
    RegisterExhausted,
}

impl std::fmt::Display for CompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CompileError::LexerError(msg) => write!(f, "Lexer error: {}", msg),
            CompileError::ParserError(msg) => write!(f, "Parser error: {}", msg),
            CompileError::SemanticError(msg) => write!(f, "Semantic error: {}", msg),
            CompileError::CodegenError(msg) => write!(f, "Codegen error: {}", msg),
            CompileError::ExperimentalOpcodeDisabled(msg) => {
                write!(f, "Experimental opcode error: {}", msg)
            }
            CompileError::RegisterExhausted => {
                write!(f, "Register exhausted: maximum 31 registers allowed")
            }
        }
    }
}

impl std::error::Error for CompileError {}

/// Byte offset where the generated prologue points the heap pointer (`r31`).
///
/// Struct literals allocate above this address, so a VM whose memory is
/// smaller than this cannot run any program that uses a struct, it faults
/// with `InvalidMemoryAccess` on the first allocation. Hosts must size their
/// `Vm` with at least [`MIN_VM_MEMORY_BYTES`].
pub const HEAP_BASE: i32 = 4096;

/// Smallest `Vm` memory size that can run compiler output.
///
/// The prologue sets the heap pointer to [`HEAP_BASE`]; anything at or below
/// that leaves no allocatable space. `bud-cli` used to build `Vm::new(1024)`,
/// which made every struct-using contract fail at runtime while the compiler's
/// own tests passed because they sized their VM at 8192.
pub const MIN_VM_MEMORY_BYTES: usize = 8192;

pub fn compile(source: &str, profile: IsaProfile) -> Result<Vec<u64>, CompileError> {
    debug!(profile = ?profile, source_len = source.len(), "Starting compilation");

    let mut parser = parser::Parser::new(source)?;
    let contract = parser.parse_contract()?;
    debug!(functions = contract.functions.len(), "Parsing complete");

    let mut sema = sema::SemanticAnalyzer::new();
    sema.analyze(&contract)?;
    debug!("Semantic analysis complete");

    let mut codegen = codegen::Codegen::new_with_profile(profile);
    let bytecode = codegen.generate(&contract)?;
    debug!(instructions = bytecode.len(), "Code generation complete");

    Ok(bytecode)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "experimental")]
    fn compiles_for_loop_to_executable_bytecode() {
        let source = r#"
            contract ForTest {
                pub fn main() {
                    let sum = 0;
                    for i in 0..5 {
                        sum = sum + i;
                    }
                    if (sum == 10) {
                        emit Success(sum);
                    }
                }
            }
        "#;

        let bytecode = compile(source, IsaProfile::Experimental).unwrap();

        let mut vm = bud_vm::Vm::new(1024);
        vm.run(&bytecode).unwrap();

        assert_eq!(vm.events, vec![10]);
    }

    /// The same gate applies to `Hash32`.
    ///
    /// A separate test, because `is_opaque_bytes32` covers both types
    /// (`Type::Address | Type::Hash32`), and one of them dropping off the list
    /// would stay invisible behind the test for the other - measured: when
    /// `Hash32` is removed, only this test turns red.
    #[test]
    fn rejects_arithmetic_on_hash32() {
        let source = r"
            contract C {
                fn combine(a: Hash32, b: Hash32) -> u64 {
                    let c = a + b;
                    return 1;
                }

                pub fn main() {
                    emit E(1);
                }
            }
        ";
        match compile(source, IsaProfile::Production) {
            Ok(_) => panic!("addition over Hash32 compiled; the type is nothing but a label"),
            Err(CompileError::SemanticError(msg)) => {
                assert!(
                    msg.contains("Hash32"),
                    "refused for the wrong reason: {msg}"
                )
            }
            Err(other) => panic!("SemanticError bekleniyordu, gelen: {other:?}"),
        }
    }

    /// Esitlik karsilastirmasi **serbest** kalmali.
    ///
    /// Measures that the gate itself is bounded. Beside the forbidden arithmetic and
    /// siralamaya; `==` ve `!=` bu tiplerin varlik sebebi. Kapi onlari da
    /// kesseydi tip kullanilamaz hale gelirdi ve bu test, asiri genis bir
    /// yasagi yakalayan taraf.
    #[test]
    fn equality_on_opaque_identities_stays_allowed() {
        for op in ["==", "!="] {
            let source = format!(
                "contract T {{ pub fn f(a: Address, b: Address) {{ \
                 let c = a {op} b; }} pub fn main() {{ }} }}"
            );
            let res = compile(&source, IsaProfile::Production);
            assert!(
                res.is_ok(),
                "`{op}` was refused over Address: the gate overshot its purpose - \
                 these types exist precisely to be compared. {res:?}"
            );
        }
    }

    #[test]
    fn rejects_experimental_in_production() {
        // All 31 opcodes are now production-ready.
        // Production profile must compile.
        // With a typical contract using both control flow and arithmetic.
        let source = "contract T { pub fn main() { let x = 1 + 2; } }";
        let res = compile(source, IsaProfile::Production);
        assert!(res.is_ok());
    }

    #[test]
    #[cfg(feature = "experimental")]
    fn test_operator_precedence_and_parentheses() {
        let source = r#"
            contract PrecedenceTest {
                pub fn main() {
                    let a = 2 + 3 * 4;
                    let b = (2 + 3) * 4;
                    let c = 0x10;
                    emit Result(a, b, c);
                }
            }
        "#;

        let bytecode = compile(source, IsaProfile::Experimental).unwrap();

        let mut vm = bud_vm::Vm::new(1024);
        vm.run(&bytecode).unwrap();

        assert_eq!(vm.events, vec![14, 20, 16]);
    }

    /// The bytecode the compiler produces must give the **right result** for the
    /// four uncovered operators too.
    ///
    /// Measured: `BinOp` carries ten operators, but only `+ - * == >=` appeared
    /// in the tests that run on the VM and verify the result. The code
    /// generated for `Neq`, `Lt`, `Gt` and `Lte` had never been executed - they
    /// were only measured at the "did it compile" level. A code generator
    /// emitting `Gt` in place of `Lt` would pass all of those tests.
    ///
    /// (`Div` is absent here: it is now refused over `u64`, for the reason
    /// given in the `division_over_u64_is_refused` test.)
    #[test]
    #[cfg(feature = "experimental")]
    fn the_uncovered_operators_produce_the_right_result() {
        let source = r#"
            contract OperatorTest {
                pub fn main() {
                    let unequal = 3 != 4;
                    let smaller = 3 < 4;
                    let greater = 3 > 4;
                    let smaller_or_equal = 4 <= 4;
                    emit Result(unequal, smaller, greater, smaller_or_equal);
                }
            }
        "#;

        let bytecode = compile(source, IsaProfile::Experimental).expect("compilation");
        let mut vm = bud_vm::Vm::new(1024);
        vm.run(&bytecode).expect("execution");

        assert_eq!(
            vm.events,
            vec![1, 1, 0, 1],
            "expected in order: 3!=4 true, 3<4 true, 3>4 false, 4<=4 true"
        );
    }

    /// **Every** reserved type name has to be refused.
    ///
    /// `RESERVED_TYPE_NAMES` carries thirteen names and none of them had a test.
    /// The list carries a silent trap: `Type::from_str` accepts every unrecognised
    /// name as a **struct name**. So if a name drops off the list
    /// `u128` is not refused but turns into an "undefined struct" error - or,
    /// if a struct is defined under that name, it compiles silently and the
    /// developer believes they got 128-bit arithmetic. There is no such thing
    /// on the VM.
    ///
    /// Each name is asserted separately: a single loop assertion would hide one name
    /// dropping off the list under the success of the others.
    #[test]
    fn reserved_type_names_are_refused() {
        // (name, the fragment that must appear in the error text)
        let names = [
            ("u8", "Goldilocks"),
            ("u16", "Goldilocks"),
            ("u32", "range-check"),
            ("u128", "multi-limb"),
            ("i8", "unsigned"),
            ("i16", "unsigned"),
            ("i32", "unsigned"),
            ("i64", "unsigned"),
            ("usize", "one integer type"),
            ("isize", "one integer type"),
            ("String", "no string type"),
            ("str", "no string type"),
            ("Vec", "no dynamic collections"),
        ];

        for (name, expected) in names {
            let source = format!(
                r#"
                contract T {{
                    pub fn f(x: {name}) -> u64 {{
                        return 1;
                    }}

                    pub fn main() {{
                        emit E(1);
                    }}
                }}
            "#
            );

            match compile(&source, IsaProfile::Production) {
                Ok(_) => panic!("`{name}` was accepted as a BudL type"),
                Err(CompileError::SemanticError(msg)) => {
                    assert!(
                        msg.contains("is not a BudL type"),
                        "`{name}` was refused but not by the reserved name gate: {msg}"
                    );
                    assert!(
                        msg.contains(expected),
                        "the reason for `{name}` was lost; `{expected}` was expected: {msg}"
                    );
                }
                Err(other) => panic!("`{name}`: a SemanticError was expected, got: {other:?}"),
            }
        }
    }

    /// A control group: five valid type names must be **accepted**.
    ///
    /// Shows that the reserved name gate does not overreach and swallow valid types.
    /// Without it, breaking `from_str` so that it refuses every name
    /// would leave the test above green.
    #[test]
    fn valid_type_names_are_accepted() {
        for name in ["u64", "bool", "field", "Address", "Hash32"] {
            let source = format!(
                r#"
                contract T {{
                    pub fn f(x: {name}) -> u64 {{
                        return 1;
                    }}

                    pub fn main() {{
                        emit E(1);
                    }}
                }}
            "#
            );

            compile(&source, IsaProfile::Production)
                .unwrap_or_else(|e| panic!("the valid type `{name}` was refused: {e:?}"));
        }
    }

    /// `/` over `u64` must be **refused**.
    ///
    /// The VM executes `Opcode::Div` as Goldilocks field division
    /// (`rs1 * rs2^-1 mod p`), and the AIR constraint pins that down
    /// (`rd * rs2 = rs1`). That is the right choice in a ZK circuit; integer
    /// division would additionally require a range check.
    ///
    /// But a developer writing `u64` expects integer division. Measured:
    /// without the gate, `7 / 2` returned **9223372034707292164**, and `7 / 0`
    /// returned **0** with no error at all. Both produce contracts that branch
    /// on a silently wrong number, so this is cut off at compile time.
    #[test]
    #[cfg(feature = "experimental")]
    fn division_over_u64_is_refused() {
        let source = r#"
            contract DivU64 {
                pub fn main() {
                    let quotient = 7 / 2;
                    emit Result(quotient);
                }
            }
        "#;

        match compile(source, IsaProfile::Experimental) {
            Ok(_) => {
                panic!("`7 / 2` compiled over u64; field division looks like integer division")
            }
            Err(CompileError::SemanticError(msg)) => assert!(
                msg.contains("field division"),
                "refused but for another reason: {msg}"
            ),
            Err(other) => panic!("SemanticError bekleniyordu, gelen: {other:?}"),
        }
    }

    /// A control group: `/` must stay **free** over `field`.
    ///
    /// The gate targets only `u64`. Without this test an overly broad
    /// yasak (her tipte Div reddi) fark edilmeden gecerdi.
    #[test]
    #[cfg(feature = "experimental")]
    fn bolme_field_uzerinde_serbest_kalir() {
        let source = r#"
            contract DivField {
                pub fn bol(a: field, b: field) -> field {
                    return a / b;
                }

                pub fn main() {
                    emit Ready(1);
                }
            }
        "#;

        compile(source, IsaProfile::Experimental)
            .expect("division over `field` was refused; the gate is too broad");
    }

    #[test]
    #[cfg(feature = "experimental")]
    fn test_comments_support() {
        let source = r#"
            // This is a single-line comment at the beginning
            contract CommentsTest {
                /*
                 * This is a multi-line block comment
                 * describing the main function.
                 */
                pub fn main() {
                    let x = 100; // Single-line comment after code
                    /* Inline block comment */ let y = 200;
                    emit Result(x, y);
                }
            }
        "#;

        let bytecode = compile(source, IsaProfile::Experimental).unwrap();

        let mut vm = bud_vm::Vm::new(1024);
        vm.run(&bytecode).unwrap();

        assert_eq!(vm.events, vec![100, 200]);
    }

    #[test]
    fn test_parser_error_propagation() {
        let source = r#"
            contract BadSyntax {
                pub fn main() {
                    let x = ;
                }
            }
        "#;

        let res = compile(source, IsaProfile::Production);
        assert!(res.is_err());
        assert!(matches!(res.unwrap_err(), CompileError::ParserError(_)));
    }

    #[test]
    fn test_lexer_error_propagation() {
        // Invalid characters (`@`, `~`) must surface as LexerError,
        // Not be silently replaced by Token::Error.
        let source = r#"
            contract LexerFail {
                pub fn main() {
                    let x = @invalid;
                }
            }
        "#;

        let res = compile(source, IsaProfile::Production);
        assert!(res.is_err(), "invalid token must fail compilation");
        let err = res.unwrap_err();
        assert!(
            matches!(err, CompileError::LexerError(_)),
            "expected LexerError, got {:?}",
            err
        );
    }

    #[test]
    fn test_large_integer_literal_compilation() {
        // The VM/AIR operate over the Goldilocks field, so the largest
        // Valid literal is P-1 = 18446744069414584320 (values >= P are
        // Rejected - see test_integer_literal_exceeding_field_modulus).
        let source = r#"
            contract LargeIntTest {
                pub fn main() {
                    let max_field = 18446744069414584320; // P - 1
                    let large_val = 1152921504606846975;   // 2^60 - 1
                    emit Result(max_field, large_val);
                }
            }
        "#;

        let bytecode =
            compile(source, IsaProfile::Production).expect("Should compile large literals");
        let mut vm = bud_vm::Vm::new(8192);
        vm.run(&bytecode).expect("VM should run");

        assert_eq!(vm.events.len(), 2);
        assert_eq!(vm.events[0], 18446744069414584320); // P - 1
        assert_eq!(vm.events[1], 1152921504606846975); // 2^60 - 1
    }

    /// An integer literal >= the Goldilocks modulus P is rejected at
    /// Compile time: it is not a canonical field element, and field
    /// Arithmetic would otherwise silently reduce it mod P (a hidden,
    /// Surprising value).
    #[test]
    fn test_integer_literal_exceeding_field_modulus_rejected() {
        // 0xFFFFFFFFFFFFFFFF is u64::MAX, which is >= P.
        let source = r#"
            contract TooLargeLiteral {
                pub fn main() {
                    let x = 0xFFFFFFFFFFFFFFFF;
                    emit Result(x);
                }
            }
        "#;

        let res = compile(source, IsaProfile::Production);
        assert!(res.is_err(), "literal >= P must be rejected");
        match res.unwrap_err() {
            CompileError::CodegenError(msg) => {
                assert!(
                    msg.contains("exceeds the Goldilocks field modulus"),
                    "got: {msg}"
                );
            }
            other => panic!("expected CodegenError, got: {other:?}"),
        }
    }

    #[test]
    fn test_integer_literal_boundary_values() {
        // Covers the exact threshold where codegen switches from a
        // Single Load immediate to the base-2^30 decomposition.
        let source = r#"
            contract BoundaryTest {
                pub fn main() {
                    let a = 2147483647;          // i32::MAX
                    let b = 2147483648;          // i32::MAX + 1
                    let c = 4294967295;          // 0xFFFFFFFF
                    let d = 4294967296;          // 2^32
                    emit Result(a, b, c, d);
                }
            }
        "#;

        let bytecode =
            compile(source, IsaProfile::Production).expect("Should compile boundary literals");
        let mut vm = bud_vm::Vm::new(8192);
        vm.run(&bytecode).expect("VM should run boundary literals");

        assert_eq!(
            vm.events,
            vec![2147483647, 2147483648, 4294967295, 4294967296]
        );
    }

    #[test]
    fn test_verify_merkle_proof_constant_path_ok() {
        // Path must be a compile-time constant address that fits in i32.
        let source = r#"
            contract MerklePathOk {
                pub fn main() {
                    let ok = verify_merkle_proof(0, 0, 256);
                    emit Result(ok);
                }
            }
        "#;

        let res = compile(source, IsaProfile::Production);
        assert!(
            res.is_ok(),
            "constant i32 path should compile: {:?}",
            res.err()
        );
    }

    #[test]
    fn test_verify_merkle_proof_rejects_dynamic_path() {
        // Dynamic path expressions are rejected to avoid passing a
        // Register number as the immediate path address.
        let source = r#"
            contract MerklePathDynamic {
                pub fn main() {
                    let addr = 256;
                    let bad = verify_merkle_proof(0, 0, addr);
                    emit Result(bad);
                }
            }
        "#;

        let res = compile(source, IsaProfile::Production);
        assert!(res.is_err(), "dynamic path must fail compilation");
        assert!(matches!(res.unwrap_err(), CompileError::CodegenError(_)));
    }

    #[test]
    fn test_verify_merkle_proof_rejects_out_of_range_path() {
        // Path addresses above i32::MAX cannot be encoded as an immediate.
        let source = r#"
            contract MerklePathBig {
                pub fn main() {
                    let bad = verify_merkle_proof(0, 0, 2147483648);
                    emit Result(bad);
                }
            }
        "#;

        let res = compile(source, IsaProfile::Production);
        assert!(res.is_err(), "path > i32::MAX must fail compilation");
        assert!(matches!(res.unwrap_err(), CompileError::CodegenError(_)));
    }

    #[test]
    fn test_register_allocator_reclamation() {
        // Without reclamation, compiling this expression would require >32 registers
        // Because each `+` would allocate a new temporary register.
        // With reclamation, temporaries are reused, so this easily compiles.
        let mut source = String::from("contract RegTest { pub fn main() { let x = 1");
        for _ in 0..50 {
            source.push_str(" + 1");
        }
        source.push_str("; emit Result(x); } }");

        let bytecode = compile(&source, IsaProfile::Production)
            .expect("Should reclaim registers and not exhaust them");
        let mut vm = bud_vm::Vm::new(8192);
        vm.run(&bytecode).expect("VM should run");
        assert_eq!(vm.events, vec![51]);
    }

    #[test]
    fn test_user_function_calls() {
        let source = r#"
            contract CallTest {
                fn add_and_mul(a: u64, b: u64, c: u64) -> u64 {
                    let sum = a + b;
                    return sum * c;
                }

                fn get_magic() -> u64 {
                    return 42;
                }

                pub fn main() {
                    let magic = get_magic();
                    let res = add_and_mul(1, 2, magic);
                    emit Result(res);
                }
            }
        "#;

        let bytecode =
            compile(source, IsaProfile::Production).expect("Should compile function calls");
        let mut vm = bud_vm::Vm::new(8192);
        vm.run(&bytecode).expect("VM should run");

        // (1 + 2) * 42 = 126
        assert_eq!(vm.events, vec![126]);
    }

    #[test]
    fn test_struct_compilation() {
        let source = r#"
            contract StructTest {
                struct Point {
                    x: u64,
                    y: u64,
                }

                fn get_x(p: Point) -> u64 {
                    return p.x;
                }

                pub fn main() {
                    let p = Point { x: 10, y: 20 };
                    let z = p.y + get_x(p);
                    emit Result(z);
                }
            }
        "#;

        let bytecode = compile(source, IsaProfile::Production).expect("Should compile structs");
        let mut vm = bud_vm::Vm::new(8192);
        vm.run(&bytecode).expect("VM should run");

        // P.y (20) + p.x (10) = 30
        assert_eq!(vm.events, vec![30]);
    }

    // === PATTERN MATCHING (match expressions) ========================

    /// `match` on an integer scrutinee dispatches to the correct arm.
    /// 0 → 100, 1 → 200, anything else → 999.
    ///
    /// Limitation: `match` is only allowed as an expression
    /// Statement (its result register is not yet surfaced as a
    /// Value to `let`/`return` bindings). This is a deliberate
    /// Boundary - surfacing a value requires a dedicated
    /// "result register" convention that conflicts with the
    /// Current `r31` HEAP_PTR reservation; it is deferred.
    /// For now the test asserts the dispatch + jump-chain codegen
    /// By emitting different events per arm inside a block.
    #[test]
    fn test_match_integer_scrutinee_dispatches_correctly() {
        let source = r#"
            contract MatchTest {
                pub fn main() {
                    let x = 0;
                    match (x) {
                        0 => { emit Result(100); },
                        1 => { emit Result(200); },
                        _ => { emit Result(999); },
                    };
                }
            }
        "#;
        let bytecode =
            compile(source, IsaProfile::Production).expect("match should compile in production");
        let mut vm = bud_vm::Vm::new(8192);
        vm.run(&bytecode).expect("VM should run");
        assert_eq!(vm.events, vec![100]);
    }

    /// `match` arms can have a *block* body (multiple statements).
    /// Verifies that the body of an arm runs to completion before the
    /// Post-match control flow continues.
    #[test]
    fn test_match_arm_with_block_body() {
        let source = r#"
            contract MatchBlock {
                pub fn main() {
                    let x = 0;
                    let a = 10;
                    let b = 20;
                    match (x) {
                        0 => {
                            let sum = a + b;
                            emit Result(sum);
                        },
                        _ => {
                            emit Result(0);
                        },
                    };
                }
            }
        "#;
        let bytecode =
            compile(source, IsaProfile::Production).expect("match with block body should compile");
        let mut vm = bud_vm::Vm::new(8192);
        vm.run(&bytecode).expect("VM should run");
        // 0 → 10 + 20 = 30
        assert_eq!(vm.events, vec![30]);
    }

    /// The wildcard arm (`_`) is required for exhaustive matching
    /// (semantic-checked); the parser only requires syntactic
    /// Validity. Verifies the parser rejects patterns that are not
    /// Integer literals or `_`.
    #[test]
    fn test_match_rejects_non_integer_pattern() {
        let source = r#"
            contract BadMatch {
                pub fn main() {
                    let x = 0;
                    match (x) {
                        foo => { emit Result(1); },
                        _ => { emit Result(0); },
                    };
                }
            }
        "#;
        let res = compile(source, IsaProfile::Production);
        assert!(res.is_err(), "non-integer, non-wildcard pattern must fail");
    }

    // === FIELD ACCESS TYPE AWARENESS ===========================================

    /// `FieldAccess` must resolve the offset against the base expression's
    /// *actual* struct layout. `A` and `B` both declare a field named
    /// `name`, but at different positions (offset 0 vs offset 8). The
    /// Legacy codegen scanned every struct layout and used the first hit,
    /// So one of the two reads below returned the wrong word, and because
    /// The layouts live in a hash map, *which* one was wrong depended on
    /// Iteration order. Type-aware resolution reads each field from its
    /// Own struct's layout, making the result correct and deterministic.
    #[test]
    fn test_field_access_resolves_correct_layout_on_name_collision() {
        let source = r#"
            contract FieldCollision {
                struct A {
                    name: u64,
                    value: u64,
                }
                struct B {
                    tag: u64,
                    name: u64,
                    value: u64,
                }

                pub fn main() {
                    let a = A { name: 111, value: 222 };
                    let b = B { tag: 333, name: 444, value: 555 };
                    let an = a.name;
                    let bn = b.name;
                    emit Result(an);
                    emit Result(bn);
                }
            }
        "#;

        let bytecode =
            compile(source, IsaProfile::Production).expect("collision structs should compile");
        let mut vm = bud_vm::Vm::new(8192);
        vm.run(&bytecode).expect("VM should run");

        // A.name lives at offset 0 of A (111); b.name at offset 8 of B (444).
        // A layout scan that picked the wrong struct would yield 222 or 333.
        assert_eq!(vm.events, vec![111, 444]);
    }

    /// A function parameter typed as a struct carries its struct type into
    /// Codegen, so a field access on the parameter resolves against *that*
    /// Struct's layout - not a different struct that shares the field name.
    /// `P.a` is at offset 0 while `Q.a` is at offset 8.
    #[test]
    fn test_field_access_on_struct_parameter_uses_param_type() {
        let source = r#"
            contract ParamField {
                struct P {
                    a: u64,
                    b: u64,
                }
                struct Q {
                    z: u64,
                    a: u64,
                    b: u64,
                }

                fn read_a(s: P) -> u64 {
                    return s.a;
                }

                pub fn main() {
                    let p = P { a: 7, b: 8 };
                    let q = Q { z: 9, a: 10, b: 11 };
                    let from_param = read_a(p);
                    let qa = q.a;
                    emit Result(from_param);
                    emit Result(qa);
                }
            }
        "#;

        let bytecode =
            compile(source, IsaProfile::Production).expect("param struct access should compile");
        let mut vm = bud_vm::Vm::new(8192);
        vm.run(&bytecode).expect("VM should run");

        // Read_a reads P.a at offset 0 (7); q.a reads Q.a at offset 8 (10).
        assert_eq!(vm.events, vec![7, 10]);
    }

    // === STRUCT LITERAL FIELD ORDER ============================================

    /// A struct literal whose fields are written in a different order than
    /// The struct declaration must still lay each value out at its
    /// *declared* offset. The legacy codegen stored fields in the literal's
    /// Textual order while `FieldAccess` reads by declaration order, so a
    /// Reordered literal silently swapped the stored values.
    #[test]
    fn test_struct_literal_field_order_independent_of_declaration() {
        let source = r#"
            contract LiteralOrder {
                struct Point {
                    x: u64,
                    y: u64,
                }

                pub fn main() {
                    // Fields written in REVERSE declaration order.
                    let p = Point { y: 20, x: 10 };
                    emit Result(p.x);
                    emit Result(p.y);
                }
            }
        "#;

        let bytecode =
            compile(source, IsaProfile::Production).expect("reordered literal should compile");
        let mut vm = bud_vm::Vm::new(8192);
        vm.run(&bytecode).expect("VM should run");

        // P.x must be 10 and p.y must be 20 regardless of literal order.
        // The legacy store-by-literal-order yields [20, 10] here.
        assert_eq!(vm.events, vec![10, 20]);
    }

    /// Reordered literals stay correct when the struct is passed to a
    /// Function and its fields are read there. Three fields written in a
    /// Shuffled order must each land at their declared offset.
    #[test]
    fn test_struct_literal_reordered_through_function_param() {
        let source = r#"
            contract LiteralOrderParam {
                struct Rec {
                    a: u64,
                    b: u64,
                    c: u64,
                }

                fn sum(r: Rec) -> u64 {
                    return r.a + r.b + r.c;
                }

                pub fn main() {
                    // Shuffled: declared order is a, b, c.
                    let r = Rec { c: 3, a: 1, b: 2 };
                    let total = sum(r);
                    emit Result(r.b);
                    emit Result(total);
                }
            }
        "#;

        let bytecode =
            compile(source, IsaProfile::Production).expect("shuffled literal should compile");
        let mut vm = bud_vm::Vm::new(8192);
        vm.run(&bytecode).expect("VM should run");

        // R.b must be 2 (declared offset 8); a + b + c = 1 + 2 + 3 = 6.
        assert_eq!(vm.events, vec![2, 6]);
    }

    // === PARTIAL LITERAL REJECTION =============================================

    /// A struct literal that omits a declared field is rejected at compile
    /// Time. Leaving a field uninitialized would read undefined memory at
    /// Its (declared) offset in the VM, so sema requires every field -
    /// Fail-fast, mirroring Rust's exhaustive struct literals.
    #[test]
    fn test_struct_literal_missing_field_rejected() {
        let source = r#"
            contract PartialLiteral {
                struct Point {
                    x: u64,
                    y: u64,
                }

                pub fn main() {
                    // `y` is missing.
                    let p = Point { x: 10 };
                    emit Result(p.x);
                }
            }
        "#;

        let res = compile(source, IsaProfile::Production);
        assert!(res.is_err(), "partial struct literal must be rejected");
        match res.unwrap_err() {
            CompileError::SemanticError(msg) => {
                assert!(
                    msg.contains("missing field") && msg.contains('y'),
                    "error should name the missing field, got: {msg}"
                );
            }
            other => panic!("expected SemanticError, got: {other:?}"),
        }
    }

    /// A struct literal providing every declared field still compiles and
    /// Runs - the exhaustiveness check rejects only *partial* literals.
    #[test]
    fn test_struct_literal_with_all_fields_compiles() {
        let source = r#"
            contract FullLiteral {
                struct Point {
                    x: u64,
                    y: u64,
                }

                pub fn main() {
                    let p = Point { x: 10, y: 20 };
                    emit Result(p.x + p.y);
                }
            }
        "#;

        let bytecode =
            compile(source, IsaProfile::Production).expect("complete literal must compile");
        let mut vm = bud_vm::Vm::new(8192);
        vm.run(&bytecode).expect("VM should run");
        assert_eq!(vm.events, vec![30]);
    }

    /// A struct literal that initializes the same field twice is rejected
    /// At compile time. Without this check, codegen stores both values at
    /// The field's single declared offset and the last write silently
    /// Wins - a hidden, order-dependent value.
    #[test]
    fn test_struct_literal_duplicate_field_rejected() {
        let source = r#"
            contract DuplicateField {
                struct Point {
                    x: u64,
                    y: u64,
                }

                pub fn main() {
                    // `x` is initialized twice.
                    let p = Point { x: 1, y: 2, x: 3 };
                    emit Result(p.x);
                }
            }
        "#;

        let res = compile(source, IsaProfile::Production);
        assert!(res.is_err(), "duplicate field literal must be rejected");
        match res.unwrap_err() {
            CompileError::SemanticError(msg) => {
                assert!(
                    msg.contains("more than once") && msg.contains('x'),
                    "error should name the duplicated field, got: {msg}"
                );
            }
            other => panic!("expected SemanticError, got: {other:?}"),
        }
    }

    // === STRUCT TYPE REFERENCE VALIDATION ======================================

    /// A function parameter typed as a struct that is not declared is
    /// Rejected. `Type::from_str` would otherwise turn the unknown name
    /// Into a phantom struct type, silently disabling field validation on
    /// The parameter (a soundness gap).
    #[test]
    fn test_undefined_struct_type_in_param_rejected() {
        let source = r#"
            contract BadParamType {
                struct Point {
                    x: u64,
                    y: u64,
                }

                // `Ponit` is a typo - not a declared struct.
                fn read(p: Ponit) -> u64 {
                    return p.x;
                }

                pub fn main() {
                    let p = Point { x: 1, y: 2 };
                    emit Result(read(p));
                }
            }
        "#;

        let res = compile(source, IsaProfile::Production);
        assert!(
            res.is_err(),
            "undefined struct type in param must be rejected"
        );
        match res.unwrap_err() {
            CompileError::SemanticError(msg) => {
                assert!(
                    msg.contains("Undefined struct type") && msg.contains("Ponit"),
                    "error should name the undefined struct type, got: {msg}"
                );
            }
            other => panic!("expected SemanticError, got: {other:?}"),
        }
    }

    /// A struct field typed as an undeclared struct is rejected (the
    /// Referenced name never appears as a declared struct).
    #[test]
    fn test_undefined_struct_type_in_field_rejected() {
        let source = r#"
            contract BadFieldType {
                struct Wrapper {
                    inner: Missing,
                }

                pub fn main() {
                    emit Result(0);
                }
            }
        "#;

        let res = compile(source, IsaProfile::Production);
        assert!(
            res.is_err(),
            "undefined struct type in field must be rejected"
        );
        match res.unwrap_err() {
            CompileError::SemanticError(msg) => {
                assert!(
                    msg.contains("Undefined struct type") && msg.contains("Missing"),
                    "error should name the undefined struct type, got: {msg}"
                );
            }
            other => panic!("expected SemanticError, got: {other:?}"),
        }
    }

    /// A struct field may reference another struct declared *later* in the
    /// Contract (forward reference). Validation runs after all structs are
    /// Registered, so this still compiles - the check rejects only truly
    /// Undefined struct names, not forward references.
    #[test]
    fn test_struct_field_forward_reference_compiles() {
        let source = r#"
            contract ForwardRef {
                struct Outer {
                    inner: Inner,
                }
                struct Inner {
                    v: u64,
                }

                pub fn main() {
                    emit Result(0);
                }
            }
        "#;

        let res = compile(source, IsaProfile::Production);
        assert!(
            res.is_ok(),
            "forward struct reference should compile: {:?}",
            res.err()
        );
    }

    // === OPERATOR TYPE HARDENING ===============================================

    /// Arithmetic on struct values (heap pointers) is rejected, adding two
    /// Pointers is meaningless and previously type-checked silently (the VM
    /// Would compute over raw pointer words).
    #[test]
    fn test_struct_arithmetic_rejected() {
        let source = r#"
            contract StructArith {
                struct Point {
                    x: u64,
                    y: u64,
                }

                pub fn main() {
                    let p = Point { x: 1, y: 2 };
                    let q = Point { x: 3, y: 4 };
                    let bad = p + q;
                    emit Result(p.x);
                }
            }
        "#;

        let res = compile(source, IsaProfile::Production);
        assert!(res.is_err(), "struct arithmetic must be rejected");
        match res.unwrap_err() {
            CompileError::SemanticError(msg) => {
                assert!(
                    msg.contains("cannot be applied"),
                    "expected operator-type error, got: {msg}"
                );
            }
            other => panic!("expected SemanticError, got: {other:?}"),
        }
    }

    /// Ordering comparisons on struct values (heap pointers) are rejected.
    #[test]
    fn test_struct_ordering_rejected() {
        let source = r#"
            contract StructOrder {
                struct Point {
                    x: u64,
                    y: u64,
                }

                pub fn main() {
                    let p = Point { x: 1, y: 2 };
                    let q = Point { x: 3, y: 4 };
                    let bad = p < q;
                    emit Result(p.x);
                }
            }
        "#;

        let res = compile(source, IsaProfile::Production);
        assert!(res.is_err(), "struct ordering must be rejected");
        match res.unwrap_err() {
            CompileError::SemanticError(msg) => {
                assert!(
                    msg.contains("cannot be applied"),
                    "expected operator-type error, got: {msg}"
                );
            }
            other => panic!("expected SemanticError, got: {other:?}"),
        }
    }

    /// Equality on struct values stays allowed (comparing two pointers for
    /// Equality is meaningful) - the hardening rejects only arithmetic and
    /// Ordering on struct/void operands.
    #[test]
    fn test_struct_equality_still_allowed() {
        let source = r#"
            contract StructEq {
                struct Point {
                    x: u64,
                    y: u64,
                }

                pub fn main() {
                    let p = Point { x: 1, y: 2 };
                    let q = Point { x: 1, y: 2 };
                    let same = p == q;
                    emit Result(same);
                }
            }
        "#;

        let res = compile(source, IsaProfile::Production);
        assert!(
            res.is_ok(),
            "struct equality should still compile: {:?}",
            res.err()
        );
    }

    // === CONDITION TYPE HARDENING ==============================================

    /// Branching on a struct value (a heap pointer, always non-zero) is
    /// Rejected - the branch would be trivially true, a near-certain bug.
    #[test]
    fn test_if_on_struct_condition_rejected() {
        let source = r#"
            contract StructCond {
                struct Point {
                    x: u64,
                    y: u64,
                }

                pub fn main() {
                    let p = Point { x: 1, y: 2 };
                    if (p) {
                        emit Result(1);
                    }
                }
            }
        "#;

        let res = compile(source, IsaProfile::Production);
        assert!(res.is_err(), "if-condition on a struct must be rejected");
        match res.unwrap_err() {
            CompileError::SemanticError(msg) => {
                assert!(msg.contains("condition must be a scalar"), "got: {msg}");
            }
            other => panic!("expected SemanticError, got: {other:?}"),
        }
    }

    /// `constrain` on a struct value (always non-zero) is rejected for the
    /// Same reason - the assertion would be vacuously satisfied.
    #[test]
    fn test_constrain_on_struct_condition_rejected() {
        let source = r#"
            contract StructConstrain {
                struct Point {
                    x: u64,
                    y: u64,
                }

                pub fn main() {
                    let p = Point { x: 1, y: 2 };
                    constrain(p);
                }
            }
        "#;

        let res = compile(source, IsaProfile::Production);
        assert!(res.is_err(), "constrain on a struct must be rejected");
        match res.unwrap_err() {
            CompileError::SemanticError(msg) => {
                assert!(msg.contains("condition must be a scalar"), "got: {msg}");
            }
            other => panic!("expected SemanticError, got: {other:?}"),
        }
    }

    /// A scalar condition (here a comparison result) still compiles, the
    /// Check rejects only struct/void conditions.
    #[test]
    fn test_scalar_condition_still_compiles() {
        let source = r#"
            contract ScalarCond {
                pub fn main() {
                    let a = 1;
                    let b = 2;
                    if (a == b) {
                        emit Result(1);
                    }
                    constrain(a);
                }
            }
        "#;

        let res = compile(source, IsaProfile::Production);
        assert!(
            res.is_ok(),
            "scalar conditions should compile: {:?}",
            res.err()
        );
    }

    // === COMPARISON RETURN TYPE ================================================

    /// A comparison result is typed as Bool, so it can be used directly as
    /// A boolean condition (and emitted as a 0/1 flag).
    #[test]
    fn test_comparison_result_is_bool_condition() {
        let source = r#"
            contract CmpBool {
                pub fn main() {
                    let a = 1;
                    let b = 2;
                    let flag = a == b;
                    if (flag) {
                        emit Result(1);
                    }
                }
            }
        "#;

        let res = compile(source, IsaProfile::Production);
        assert!(
            res.is_ok(),
            "comparison result as bool condition should compile: {:?}",
            res.err()
        );
    }

    /// A comparison result is Bool, not the operand type, using it in u64
    /// Arithmetic is now a type mismatch (the behavior change from typing
    /// Comparisons as Bool).
    #[test]
    fn test_comparison_result_rejected_in_arithmetic() {
        let source = r#"
            contract CmpArith {
                pub fn main() {
                    let a = 1;
                    let b = 2;
                    let x = (a == b) * 2;
                    emit Result(x);
                }
            }
        "#;

        let res = compile(source, IsaProfile::Production);
        assert!(
            res.is_err(),
            "comparison result used in arithmetic must be a type mismatch"
        );
        match res.unwrap_err() {
            CompileError::SemanticError(msg) => {
                assert!(msg.contains("mismatch"), "got: {msg}");
            }
            other => panic!("expected SemanticError, got: {other:?}"),
        }
    }

    /// A type the spec advertises but the language does not have must say so.
    ///
    /// `BudL_SPEC.md` listed `u32`, `u128`, `Address` and `Hash32` in its type
    /// table. Only the last two now exist. The first two fell through to
    /// `Type::Struct(name)`, so an author writing `amount: u128` was told
    /// "Undefined struct type 'u128'", which points at the struct machinery
    /// instead of at the fact that the type is not real.
    #[test]
    fn a_reserved_type_name_says_the_type_does_not_exist() {
        for (name, expect) in [
            ("u32", "range-check"),
            ("u128", "multi-limb"),
            ("i64", "unsigned"),
            ("String", "no string type"),
        ] {
            let source = format!(
                r#"
                contract C {{
                    fn takes(x: {name}) -> u64 {{
                        return 1;
                    }}

                    pub fn main() {{
                        emit E(1);
                    }}
                }}
            "#
            );
            let err = compile(&source, IsaProfile::Production)
                .expect_err("a non-existent type must not compile");
            match err {
                CompileError::SemanticError(msg) => {
                    assert!(
                        msg.contains("is not a BudL type"),
                        "{name}: expected a 'not a BudL type' diagnostic, got: {msg}"
                    );
                    assert!(
                        msg.contains(expect),
                        "{name}: the message should explain why, got: {msg}"
                    );
                    assert!(
                        !msg.contains("struct"),
                        "{name}: must not be reported as a struct problem, got: {msg}"
                    );
                }
                other => panic!("{name}: expected SemanticError, got: {other:?}"),
            }
        }
    }

    /// `Address` and `Hash32` are real types now, and a contract may use them.
    ///
    /// Before this they were treated as struct names, so both examples in
    /// `BudL_SPEC.md` failed to compile with "Undefined struct type 'Address'".
    #[test]
    fn address_and_hash32_are_types_rather_than_phantom_structs() {
        let source = r#"
            contract C {
                fn holds(who: Address, digest: Hash32) -> u64 {
                    let a = who;
                    let d = digest;
                    return 1;
                }

                pub fn main() {
                    let sender = msg::sender();
                    emit E(1);
                }
            }
        "#;
        compile(source, IsaProfile::Production)
            .expect("Address and Hash32 must be accepted as types");
    }

    /// Arithmetic on a 32-byte value is refused rather than truncated.
    ///
    /// A VM register holds 8 bytes. Permitting `+` on a 32-byte value would
    /// compile to an operation on one limb of four and produce a number that
    /// is not the sum of anything, which is exactly the class of silent wrong
    /// answer that a type is supposed to prevent.
    #[test]
    fn arithmetic_on_an_opaque_32_byte_type_is_refused() {
        // `<=` and `>=` were missing from the list. The gate (`sema.rs`,
        // `is_opaque_bytes32`) covers both, but that coverage had never been
        // measured: an operator dropping off the list would make removing the
        // gate for that operator invisible.
        for op in ["+", "-", "*", "/", "<", ">", "<=", ">="] {
            let source = format!(
                r#"
                contract C {{
                    fn combine(a: Address, b: Address) -> u64 {{
                        let c = a {op} b;
                        return 1;
                    }}

                    pub fn main() {{
                        emit E(1);
                    }}
                }}
            "#
            );
            match compile(&source, IsaProfile::Production) {
                Ok(_) => panic!("`a {op} b` on two Addresses compiled; the type is a label"),
                Err(CompileError::SemanticError(msg)) => assert!(
                    msg.contains("Address"),
                    "`{op}` was rejected for the wrong reason: {msg}"
                ),
                Err(other) => panic!("`{op}`: expected a SemanticError, got: {other:?}"),
            }
        }
    }

    /// The canary for the test above: the rejection has to be about the type,
    /// not an accident of parsing.
    #[test]
    fn the_opaque_type_rejection_names_the_type() {
        let source = r#"
            contract C {
                fn combine(a: Address, b: Address) -> u64 {
                    let c = a + b;
                    return 1;
                }

                pub fn main() {
                    emit E(1);
                }
            }
        "#;
        let err = compile(source, IsaProfile::Production)
            .expect_err("adding two addresses must not compile");
        match err {
            CompileError::SemanticError(msg) => {
                assert!(
                    msg.contains("Address") && msg.contains("opaque"),
                    "the diagnostic should name the type and say it is opaque, got: {msg}"
                );
            }
            other => panic!("expected SemanticError, got: {other:?}"),
        }
    }

    /// Equality and assignment stay available, or the types are useless.
    #[test]
    fn opaque_types_can_still_be_compared_and_copied() {
        let source = r#"
            contract C {
                fn compare(a: Address, b: Address) -> bool {
                    let copy = a;
                    return a == b;
                }

                pub fn main() {
                    emit E(1);
                }
            }
        "#;
        compile(source, IsaProfile::Production)
            .expect("equality and copying must remain legal for Address");
    }

    /// Every `budl` block in the specification has to compile.
    ///
    /// Both declare `Address` fields
    /// and call `caller()`, `sread_u64()` and `swrite_u64()`, none of which
    /// existed. A specification whose own examples do not compile teaches the
    /// wrong language, and nothing in CI noticed for as long as the examples
    /// were only read by people.
    #[test]
    fn every_example_in_the_specification_compiles() {
        let spec = include_str!("../../docs/BudL_SPEC.md");
        let mut blocks = Vec::new();
        let mut rest = spec;
        while let Some(start) = rest.find("```budl\n") {
            let after = &rest[start + 8..];
            let Some(end) = after.find("```") else { break };
            blocks.push(&after[..end]);
            rest = &after[end + 3..];
        }
        assert!(
            !blocks.is_empty(),
            "no ```budl blocks found in BudL_SPEC.md; this test would be vacuous"
        );
        for (i, block) in blocks.iter().enumerate() {
            if let Err(e) = compile(block, IsaProfile::Production) {
                panic!(
                    "BudL_SPEC.md example {i} does not compile: {e}\n\
                     ---- source ----\n{block}"
                );
            }
        }
    }

    /// Fuzz-style crash gate: the BudL parser + semantic analyzer + codegen
    /// (3379 lines) must never panic on arbitrary or mutated input - only
    /// return an error. A panic is a bug (a crash), not a language error.
    ///
    /// This is the deterministic, in-tree counterpart to the libFuzzer targets
    /// (which need a nightly toolchain); it is reproducible from a fixed seed
    /// and runs in a plain `cargo test`.
    #[test]
    fn compiler_never_panics_on_adversarial_or_mutated_input() {
        let mut rng = Rng(0x9E3779B97F4A7C15);
        let total = 1200;
        let mut panics = 0u32;

        // 1) Pure random garbage (lexer/parser), 2) structured nesting
        // (parser/sema), 3) mutation of a known-good program (sema/codegen
        // deep paths).
        for i in 0..total {
            let source = match i % 3 {
                0 => random_garbage(&mut rng, 260),
                1 => random_nested_contract(&mut rng),
                _ => mutate_template(&mut rng),
            };

            let result = std::panic::catch_unwind(|| {
                let _ = crate::compile(&source, IsaProfile::Production);
            });
            if result.is_err() {
                panics += 1;
                if panics <= 3 {
                    eprintln!("PANIC on iteration {i}:\n{source}");
                }
            }
        }
        assert_eq!(panics, 0, "the BudL compiler must never panic on input");
    }

    // --- deterministic fuzz helpers (no external deps) ---

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x >> 12;
            x ^= x << 25;
            x ^= x >> 27;
            self.0 = x;
            x.wrapping_mul(0x2545F4914F6CDD1D)
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
        fn pick(&mut self, cs: &[char]) -> char {
            cs[self.below(cs.len() as u64) as usize]
        }
        fn push(&mut self) -> String {
            self.next().to_string()
        }
    }

    const ALPHABET: &[char] = &[
        'a', 'b', 'c', '0', '1', '2', '3', '4', '5', ' ', '\n', '\t', '{', '}', '(', ')', ':', ';',
        '+', '-', '*', '/', '=', '>', '<', '.', ',', '"', '\'', '|', '@', '$', '%', '&', '!', '?',
        '_', '[', ']', '#', '~', '^', '\\',
    ];

    fn random_garbage(rng: &mut Rng, max_len: usize) -> String {
        let n = 1 + rng.below(max_len.max(1) as u64) as usize;
        (0..n).map(|_| rng.pick(ALPHABET)).collect()
    }

    fn random_nested_contract(rng: &mut Rng) -> String {
        let tokens = [
            "contract",
            "pub",
            "fn",
            "main",
            "let",
            "field",
            "u64",
            "Address",
            "Hash32",
            "if",
            "else",
            "while",
            "for",
            "match",
            "return",
            "struct",
            "true",
            "false",
            "Immutable",
            "operator",
            "=>",
            "::",
            ",",
        ];
        let mut s = String::new();
        let depth = 1 + rng.below(6) as usize;
        s.push_str("contract ");
        s.push_str(&rng.push());
        s.push_str(" { ");
        for _ in 0..depth {
            s.push_str("pub fn ");
            s.push_str(&rng.push());
            s.push_str("(a: field, b: u64) -> field { ");
            for _ in 0..(1 + rng.below(4)) {
                s.push_str("let x = a ");
                s.push_str(tokens[rng.below(tokens.len() as u64) as usize]);
                s.push_str(" b; ");
            }
            s.push_str("return a; } ");
        }
        s.push('}');
        s
    }

    fn mutate_template(rng: &mut Rng) -> String {
        let base = "contract T { pub fn f(a: field, b: field) -> field { let c = a + b; return c; } pub fn main() { } }";
        let mut bytes = base.as_bytes().to_vec();
        for _ in 0..(1 + rng.below(8)) {
            if bytes.is_empty() {
                break;
            }
            let idx = rng.below(bytes.len() as u64) as usize;
            match rng.below(3) {
                0 => bytes[idx] = rng.pick(ALPHABET) as u8,
                1 => {
                    if !bytes.is_empty() {
                        bytes.remove(idx);
                    }
                }
                _ => bytes.insert(idx, rng.pick(ALPHABET) as u8),
            }
        }
        String::from_utf8_lossy(&bytes).into_owned()
    }
}
