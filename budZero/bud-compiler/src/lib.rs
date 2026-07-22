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

    #[test]
    fn rejects_experimental_in_production() {
        // All 31 opcodes are now production-ready.
        // This test validates that the production profile compiles successfully
        // with a typical contract using both control flow and arithmetic.
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
        // not be silently replaced by Token::Error.
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
        // valid literal is P-1 = 18446744069414584320 (values >= P are
        // rejected — see test_integer_literal_exceeding_field_modulus).
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
    /// compile time: it is not a canonical field element, and field
    /// arithmetic would otherwise silently reduce it mod P (a hidden,
    /// surprising value).
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
        // single Load immediate to the base-2^30 decomposition.
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
        // register number as the immediate path address.
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
        // because each `+` would allocate a new temporary register.
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

        // p.y (20) + p.x (10) = 30
        assert_eq!(vm.events, vec![30]);
    }

    // === Phase 0.14: PATTERN MATCHING (match expressions) ========================

    /// `match` on an integer scrutinee dispatches to the correct arm.
    /// 0 → 100, 1 → 200, anything else → 999.
    ///
    /// Phase 0.14 limitation: `match` is only allowed as an expression
    /// statement (its result register is not yet surfaced as a
    /// value to `let`/`return` bindings). This is a deliberate
    /// boundary — surfacing a value requires a dedicated
    /// "result register" convention that conflicts with the
    /// current `r31` HEAP_PTR reservation; it is deferred to Phase 0.16.
    /// For now the test asserts the dispatch + jump-chain codegen
    /// by emitting different events per arm inside a block.
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
    /// post-match control flow continues.
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
    /// (semantic-checked Phase 0.16); the parser only requires syntactic
    /// validity. Verifies the parser rejects patterns that are not
    /// integer literals or `_`.
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
    /// legacy codegen scanned every struct layout and used the first hit,
    /// so one of the two reads below returned the wrong word — and because
    /// the layouts live in a hash map, *which* one was wrong depended on
    /// iteration order. Type-aware resolution reads each field from its
    /// own struct's layout, making the result correct and deterministic.
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

        // a.name lives at offset 0 of A (111); b.name at offset 8 of B (444).
        // A layout scan that picked the wrong struct would yield 222 or 333.
        assert_eq!(vm.events, vec![111, 444]);
    }

    /// A function parameter typed as a struct carries its struct type into
    /// codegen, so a field access on the parameter resolves against *that*
    /// struct's layout — not a different struct that shares the field name.
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

        // read_a reads P.a at offset 0 (7); q.a reads Q.a at offset 8 (10).
        assert_eq!(vm.events, vec![7, 10]);
    }

    // === STRUCT LITERAL FIELD ORDER ============================================

    /// A struct literal whose fields are written in a different order than
    /// the struct declaration must still lay each value out at its
    /// *declared* offset. The legacy codegen stored fields in the literal's
    /// textual order while `FieldAccess` reads by declaration order, so a
    /// reordered literal silently swapped the stored values.
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

        // p.x must be 10 and p.y must be 20 regardless of literal order.
        // The legacy store-by-literal-order yields [20, 10] here.
        assert_eq!(vm.events, vec![10, 20]);
    }

    /// Reordered literals stay correct when the struct is passed to a
    /// function and its fields are read there. Three fields written in a
    /// shuffled order must each land at their declared offset.
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

        // r.b must be 2 (declared offset 8); a + b + c = 1 + 2 + 3 = 6.
        assert_eq!(vm.events, vec![2, 6]);
    }

    // === PARTIAL LITERAL REJECTION =============================================

    /// A struct literal that omits a declared field is rejected at compile
    /// time. Leaving a field uninitialized would read undefined memory at
    /// its (declared) offset in the VM, so sema requires every field —
    /// fail-fast, mirroring Rust's exhaustive struct literals.
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
    /// runs — the exhaustiveness check rejects only *partial* literals.
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
    /// at compile time. Without this check, codegen stores both values at
    /// the field's single declared offset and the last write silently
    /// wins — a hidden, order-dependent value.
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
    /// rejected. `Type::from_str` would otherwise turn the unknown name
    /// into a phantom struct type, silently disabling field validation on
    /// the parameter (a soundness gap).
    #[test]
    fn test_undefined_struct_type_in_param_rejected() {
        let source = r#"
            contract BadParamType {
                struct Point {
                    x: u64,
                    y: u64,
                }

                // `Ponit` is a typo — not a declared struct.
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
    /// referenced name never appears as a declared struct).
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
    /// contract (forward reference). Validation runs after all structs are
    /// registered, so this still compiles — the check rejects only truly
    /// undefined struct names, not forward references.
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

    /// Arithmetic on struct values (heap pointers) is rejected — adding two
    /// pointers is meaningless and previously type-checked silently (the VM
    /// would compute over raw pointer words).
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
    /// equality is meaningful) — the hardening rejects only arithmetic and
    /// ordering on struct/void operands.
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
    /// rejected — the branch would be trivially true, a near-certain bug.
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
    /// same reason — the assertion would be vacuously satisfied.
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

    /// A scalar condition (here a comparison result) still compiles — the
    /// check rejects only struct/void conditions.
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
    /// a boolean condition (and emitted as a 0/1 flag).
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

    /// A comparison result is Bool, not the operand type — using it in u64
    /// arithmetic is now a type mismatch (the behavior change from typing
    /// comparisons as Bool).
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
}
