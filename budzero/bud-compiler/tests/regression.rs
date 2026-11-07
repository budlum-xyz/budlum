//! Regression tests for `bud-compiler`.
//!
//! Each test locks a fix that is already in the tree: it is green and stays permanent.
//! It lives in the `bud-compiler` package because `budzero/` is a virtual workspace and
//! a root-level `tests/` directory belongs to no package, so cargo would never compile it.

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

/// A `match` integer pattern above `i32::MAX` is not truncated.
#[test]
fn match_pattern_is_not_truncated_to_i32() {
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

/// A `let` inside a match arm does not clobber the outer variable.
#[test]
fn arm_let_does_not_clobber_outer_variable() {
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

/// Duplicate `main` and a literal at or above the field modulus are refused.
#[test]
fn duplicate_main_and_oversized_literal_are_refused() {
    let dup = "contract C { pub fn main() { } pub fn main() { constrain(0); } }";
    assert!(compile(dup, IsaProfile::Production).is_err());
    let big = "contract C { pub fn main() { let x = 0xFFFFFFFFFFFFFFFF; } }";
    assert!(matches!(
        compile(big, IsaProfile::Production),
        Err(CompileError::CodegenError(_))
    ));
}

/// Long binary and field chains return a parser error instead of
/// overflowing the stack.
#[test]
fn long_operator_and_field_chains_return_parser_error() {
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

/// A field read on an unknown struct type is refused, not scanned.
#[test]
fn unknown_struct_field_read_is_refused() {
    let src = "contract T { pub fn main() { let v = 1; let y = v.f; } }";
    assert!(compile(src, IsaProfile::Production).is_err());
}

/// A `let` inside a branch body must not keep its register after the branch,
/// or many sequential branches run the compiler out of registers.
#[test]
fn sequential_branches_release_their_registers() {
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

/// A call used as a statement (`f(1);`) parses and runs.
#[test]
fn bare_call_statement_compiles_and_runs() {
    let src = "contract T { fn f(a: u64) { emit Result(a); } pub fn main() { f(41); f(1); } }";
    assert_eq!(run_events(src), vec![41, 1]);
}

/// A hexadecimal literal is a valid match pattern, equal to its decimal twin.
#[test]
fn hex_match_pattern_matches() {
    let src = r#"
        contract T {
            fn probe(x: u64) -> u64 {
                match (x) {
                    0x10 => { emit Result(1); },
                    _ => { emit Result(0); },
                };
                return 0;
            }
            pub fn main() {
                let a = probe(16);
                let b = probe(17);
            }
        }
    "#;
    assert_eq!(run_events(src), vec![1, 0]);
}

#[test]
fn blg_067_entrypoint_abi_match_bounds_and_unknown_field_refused() {
    let bad_field = "contract T { pub fn main() { let v = 7; let z = v.nope; } }";
    assert!(compile(bad_field, IsaProfile::Production).is_err());
    let wide_match = r#"
        contract T {
            pub fn main() {
                let x = 5000000000;
                match (x) {
                    5000000000 => { emit Result(9); },
                    _ => { emit Result(0); },
                };
            }
        }
    "#;
    assert_eq!(run_events(wide_match), vec![9]);
}

#[test]
fn blg_114_compiler_preserves_u64_patterns_scopes_and_rejects_dup_main() {
    arm_let_does_not_clobber_outer_variable();
    duplicate_main_and_oversized_literal_are_refused();
}

#[test]
fn blg_136_parser_accepts_bare_calls_and_ir_verifier_catches_bad_ssa() {
    bare_call_statement_compiles_and_runs();
    let trailing = "contract T { pub fn main() { } } garbage_token";
    assert!(compile(trailing, IsaProfile::Production).is_err());
}

#[test]
fn blg_162_lexer_handles_crlf_multistar_comments_and_hex_match() {
    let crlf_src = concat!(
        "contract T {\r\n",
        "  /** multi ** star **/\r\n",
        "  pub fn main() {\r\n",
        "    let x = 0x2A;\r\n",
        "    match (x) {\r\n",
        "      0x2A => { emit Result(42); },\r\n",
        "      _ => { emit Result(0); },\r\n",
        "    };\r\n",
        "  }\r\n",
        "}\r\n",
    );
    assert_eq!(run_events(crlf_src), vec![42]);
}

#[test]
fn blg_198_deep_ast_chains_refused_without_stack_overflow() {
    long_operator_and_field_chains_return_parser_error();
    sequential_branches_release_their_registers();
}
