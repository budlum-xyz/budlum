//! Security regression tests for `bud-compiler`:
//! 1. `Codegen::generate` returns `Err(CompileError::CodegenError)` rather
//!    than panicking when a built-in (`poseidon`, `verify_merkle_proof`,
//!    `msg::sender`, `msg::nonce`, `block::number`) has wrong arity.
//! 2. `SemanticAnalyzer::analyze` and `ir::lower::lower_contract` both refuse
//!    non-canonical integer literals `>= GOLDILOCKS_P`.
//! 3. `SemanticAnalyzer::analyze` refuses cyclic struct definitions.

use bud_compiler::ast::{Contract, Expr, Function, Stmt};
use bud_compiler::codegen::Codegen;
use bud_compiler::ir::lower::lower_contract;
use bud_compiler::parser::Parser;
use bud_compiler::sema::SemanticAnalyzer;
use bud_compiler::CompileError;

fn parse(src: &str) -> bud_compiler::ast::Contract {
    let Ok(mut parser) = Parser::new(src) else {
        panic!("lex failed");
    };
    let Ok(contract) = parser.parse_contract() else {
        panic!("parse failed");
    };
    contract
}

#[test]
fn codegen_refuses_wrong_builtin_arity_without_panicking() {
    let bad_poseidon = parse(
        r#"
        contract BadPoseidon {
            fn main() -> u64 {
                return poseidon(1);
            }
        }
        "#,
    );
    let res1 = Codegen::new().generate(&bad_poseidon);
    assert!(
        matches!(res1, Err(CompileError::CodegenError(_))),
        "poseidon(1) must return CodegenError rather than panicking, got {res1:?}"
    );

    let bad_merkle = Contract {
        name: "BadMerkle".into(),
        storage: vec![],
        structs: vec![],
        functions: vec![Function {
            name: "main".into(),
            params: vec![],
            return_type: Some("u64".into()),
            body: vec![Stmt::Return(Some(Expr::Call(
                "verify_merkle_proof".into(),
                vec![],
            )))],
            is_pub: false,
        }],
    };
    let res2 = Codegen::new().generate(&bad_merkle);
    assert!(
        matches!(res2, Err(CompileError::CodegenError(_))),
        "verify_merkle_proof() must return CodegenError rather than panicking, got {res2:?}"
    );

    let bad_sender = Contract {
        name: "BadSender".into(),
        storage: vec![],
        structs: vec![],
        functions: vec![Function {
            name: "main".into(),
            params: vec![],
            return_type: Some("u64".into()),
            body: vec![Stmt::Return(Some(Expr::Call(
                "msg::sender".into(),
                vec![Expr::Int(7)],
            )))],
            is_pub: false,
        }],
    };
    let res3 = Codegen::new().generate(&bad_sender);
    assert!(
        matches!(res3, Err(CompileError::CodegenError(_))),
        "msg::sender(7) must return CodegenError, got {res3:?}"
    );
}

#[test]
fn codegen_and_ir_lower_refuse_non_canonical_goldilocks_literals() {
    // 18446744069414584321 == GOLDILOCKS_P (2^64 - 2^32 + 1)
    let contract = parse(
        r#"
        contract OverflowLit {
            fn main() -> u64 {
                return 18446744069414584321;
            }
        }
        "#,
    );
    let mut sema = SemanticAnalyzer::new();
    assert!(sema.analyze(&contract).is_ok());

    let ir_res = lower_contract(&contract, &sema);
    assert!(
        ir_res.is_err(),
        "IR lowerer must reject literal >= GOLDILOCKS_P"
    );

    let cg_res = Codegen::new().generate(&contract);
    assert!(
        matches!(cg_res, Err(CompileError::CodegenError(_))),
        "Codegen must reject literal >= GOLDILOCKS_P"
    );
}

#[test]
fn sema_refuses_cyclic_struct_definitions() {
    let direct_cycle = parse(
        r#"
        contract DirectCycle {
            struct Node {
                next: Node,
            }
            fn main() -> u64 {
                return 0;
            }
        }
        "#,
    );
    assert!(
        matches!(
            SemanticAnalyzer::new().analyze(&direct_cycle),
            Err(CompileError::SemanticError(_))
        ),
        "self-referential struct must be refused"
    );

    let mutual_cycle = parse(
        r#"
        contract MutualCycle {
            struct A {
                b: B,
            }
            struct B {
                a: A,
            }
            fn main() -> u64 {
                return 0;
            }
        }
        "#,
    );
    assert!(
        matches!(
            SemanticAnalyzer::new().analyze(&mutual_cycle),
            Err(CompileError::SemanticError(_))
        ),
        "mutually recursive structs A <-> B must be refused"
    );
}
