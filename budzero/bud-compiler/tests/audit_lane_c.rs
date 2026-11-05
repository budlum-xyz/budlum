//! Lane C live-verification regression tests for `bud-compiler` (WP-03).
//!
//! Previously fixed findings only: every test here is green and stays permanent
//! (directive section 14.1 rule 7). It lives in the `bud-compiler` package because
//! `budzero/` is a virtual workspace and a root-level `tests/` directory belongs to no
//! package, so cargo would never compile it (see `budzero/tests/audit_lane_c.rs`).

// A panic is how a test reports a broken invariant (the same exemption the other
// budzero integration tests carry).
#![allow(clippy::unwrap_used, clippy::expect_used)]

use bud_compiler::{compile, CompileError};
use bud_isa::IsaProfile;

fn run_events(src: &str) -> Vec<u64> {
    let bytecode = compile(src, IsaProfile::Production).expect("compiles");
    let mut vm = bud_vm::Vm::new(bud_compiler::MIN_VM_MEMORY_BYTES);
    vm.run(&bytecode).expect("vm runs");
    vm.events.clone()
}

/// BLG-114: a `match` integer pattern above `i32::MAX` is not truncated.
#[test]
fn audit_lane_c_blg_114_match_pattern_is_not_truncated_to_i32() {
    let src = r#"
        contract WidePattern {
            fn probe(x: u64) -> u64 {
                match (x) {
                    4294967296 => { emit Result(1); },
                    _ => { emit Result(0); },
                };
                return 0;
            }
            pub fn main() {
                let a = probe(0);
                let b = probe(4294967296);
            }
        }
    "#;
    assert_eq!(run_events(src), vec![0, 1]);
}

/// BLG-114: a `let` inside a match arm does not clobber the outer variable.
#[test]
fn audit_lane_c_blg_114_arm_let_does_not_clobber_outer_variable() {
    let src = r#"
        contract ArmScope {
            pub fn main() {
                let x = 1;
                let y = 0;
                match (y) {
                    0 => { let x = 5; emit Result(x); },
                    _ => { },
                };
                emit Result(x);
            }
        }
    "#;
    assert_eq!(run_events(src), vec![5, 1]);
}

/// BLG-114: duplicate `main` and a literal at or above the field modulus are refused.
#[test]
fn audit_lane_c_blg_114_duplicate_main_and_oversized_literal_are_refused() {
    let dup = "contract C { pub fn main() { } pub fn main() { constrain(0); } }";
    assert!(compile(dup, IsaProfile::Production).is_err());
    let big = "contract C { pub fn main() { let x = 0xFFFFFFFFFFFFFFFF; } }";
    assert!(matches!(
        compile(big, IsaProfile::Production),
        Err(CompileError::CodegenError(_))
    ));
}

/// BLG-198: long binary and field chains return a parser error instead of
/// overflowing the stack.
#[test]
fn audit_lane_c_blg_198_long_operator_and_field_chains_return_parser_error() {
    let terms = 20_000;
    let sum = vec!["1"; terms].join(" + ");
    let fields = format!("a{}", ".f".repeat(terms));
    for expr in [sum, fields] {
        let src = format!("contract T {{ pub fn main() {{ let x = {expr}; }} }}");
        let res = compile(&src, IsaProfile::Production);
        assert!(
            matches!(res, Err(CompileError::ParserError(_))),
            "{:?}",
            res.err()
        );
    }
}

/// BLG-198: a field read on an unknown struct type is refused, not scanned.
#[test]
fn audit_lane_c_blg_198_unknown_struct_field_read_is_refused() {
    let src = "contract T { pub fn main() { let v = 1; let y = v.f; } }";
    assert!(compile(src, IsaProfile::Production).is_err());
}

/// BLG-338: a `let` inside a branch body must not keep its register after the branch,
/// or many sequential branches run the compiler out of registers.
#[test]
fn audit_lane_c_blg_338_sequential_branches_release_their_registers() {
    let mut body = String::from("let c = 1;\n");
    for i in 0..200 {
        body.push_str(&format!(
            "if (c == 1) {{ let t{i} = {i}; emit Result(t{i}); }}\n"
        ));
    }
    let src = format!("contract T {{ pub fn main() {{ {body} }} }}");
    let res = compile(&src, IsaProfile::Production);
    assert!(res.is_ok(), "register exhaustion: {:?}", res.err());
    let mut body = String::from("let c = 1;\n");
    for i in 0..200 {
        body.push_str(&format!(
            "while (c == 0) {{ let t{i} = {i}; emit Result(t{i}); }}\n"
        ));
    }
    let src = format!("contract T {{ pub fn main() {{ {body} }} }}");
    let res = compile(&src, IsaProfile::Production);
    assert!(res.is_ok(), "register exhaustion in while: {:?}", res.err());
}

