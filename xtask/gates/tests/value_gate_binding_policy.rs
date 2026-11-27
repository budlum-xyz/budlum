//! Source contracts for the binding floor at the certificate decision boundary.
//! These do not replace certificate, route, or proof-liveness runtime tests.

use std::collections::BTreeSet;
use syn::visit::Visit;
use syn::{Expr, FnArg, Item, Pat, Stmt, Type};

const SOURCE: &str = include_str!("../../../src/settlement/finality_gate.rs");

fn path_is(expression: &Expr, segments: &[&str]) -> bool {
    let Expr::Path(path) = expression else {
        return false;
    };
    path.qself.is_none()
        && path.path.segments.len() == segments.len()
        && path
            .path
            .segments
            .iter()
            .zip(segments)
            .all(|(actual, expected)| actual.ident == *expected)
}

fn type_is(value: &Type, name: &str) -> bool {
    matches!(value, Type::Path(path) if path.qself.is_none() && path.path.is_ident(name))
}

fn unconditional(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().all(|attribute| {
        !attribute.path().is_ident("cfg") && !attribute.path().is_ident("cfg_attr")
    })
}

fn named_function<'a>(file: &'a syn::File, name: &str) -> Result<&'a syn::ItemFn, String> {
    let mut found = None;
    for item in &file.items {
        if let Item::Fn(function) = item {
            if function.sig.ident != name {
                continue;
            }
            if found.is_some() || !unconditional(&function.attrs) {
                return Err(format!(
                    "{name} needs an unambiguous, unconditional definition"
                ));
            }
            found = Some(function);
        }
    }
    found.ok_or_else(|| format!("missing function {name}"))
}

fn pattern_variants(pattern: &Pat, names: &mut BTreeSet<String>) -> Result<(), String> {
    match pattern {
        Pat::Path(path) if path.qself.is_none() && path.path.segments.len() == 2 => {
            let mut parts = path.path.segments.iter();
            if parts.next().is_none_or(|part| part.ident != "Self") {
                return Err("minimum pattern is not a ValueGate variant".into());
            }
            let name = parts
                .next()
                .ok_or_else(|| "minimum pattern has no variant".to_owned())?;
            if !names.insert(name.ident.to_string()) {
                return Err("minimum pattern repeats a variant".into());
            }
            Ok(())
        }
        Pat::Or(or) => {
            for case in &or.cases {
                pattern_variants(case, names)?;
            }
            Ok(())
        }
        _ => Err("minimum patterns must be explicit, unguarded variants".into()),
    }
}

fn check_minimum(source: &str) -> Result<(), String> {
    let file = syn::parse_file(source).map_err(|error| error.to_string())?;
    let variants = file
        .items
        .iter()
        .find_map(|item| match item {
            Item::Enum(item) if item.ident == "ValueGate" => Some(
                item.variants
                    .iter()
                    .map(|variant| variant.ident.to_string())
                    .collect::<BTreeSet<_>>(),
            ),
            _ => None,
        })
        .ok_or_else(|| "ValueGate enum is missing".to_owned())?;
    let mut found = None;
    for item in &file.items {
        let Item::Impl(implementation) = item else {
            continue;
        };
        if implementation.trait_.is_some() || !type_is(&implementation.self_ty, "ValueGate") {
            continue;
        }
        for item in &implementation.items {
            let syn::ImplItem::Fn(method) = item else {
                continue;
            };
            if method.sig.ident != "required_binds" {
                continue;
            }
            if found.is_some()
                || !unconditional(&implementation.attrs)
                || !unconditional(&method.attrs)
            {
                return Err("the minimum needs an unambiguous, unconditional definition".into());
            }
            found = Some(method);
        }
    }
    let method =
        found.ok_or_else(|| "ValueGate does not declare its minimum bindings".to_owned())?;
    if method.sig.constness.is_none()
        || method.sig.inputs.len() != 1
        || !matches!(method.sig.inputs.first(), Some(FnArg::Receiver(_)))
    {
        return Err("the binding minimum must be a const policy of the gate itself".into());
    }
    let [Stmt::Expr(Expr::Match(choice), None)] = method.block.stmts.as_slice() else {
        return Err("the minimum must explicitly cover each value gate".into());
    };
    if !path_is(&choice.expr, &["self"]) {
        return Err("the minimum must match the gate, not caller data".into());
    }
    let mut declared = BTreeSet::new();
    for arm in &choice.arms {
        pattern_variants(&arm.pat, &mut declared)?;
        if !path_is(&arm.body, &["FinalityBinds", "EVENT_ROOT"]) {
            return Err("an event-backed gate lost its event-root floor".into());
        }
    }
    if declared != variants || declared.is_empty() {
        return Err("not every value gate declares the same event-backed contract".into());
    }
    Ok(())
}

fn gate_minimum(expression: &Expr) -> bool {
    matches!(expression, Expr::MethodCall(call)
        if call.method == "required_binds" && call.args.is_empty()
            && call.turbofish.is_none() && path_is(&call.receiver, &["gate"]))
}

fn minimum_union(expression: &Expr) -> bool {
    let Expr::MethodCall(call) = expression else {
        return false;
    };
    if call.method != "union" || call.args.len() != 1 || call.turbofish.is_some() {
        return false;
    }
    call.args.first().is_some_and(|other| {
        (gate_minimum(&call.receiver) && path_is(other, &["required_binds"]))
            || (path_is(&call.receiver, &["required_binds"]) && gate_minimum(other))
    })
}

fn enforced(statement: &Stmt, domain: &str) -> bool {
    let Stmt::Expr(Expr::Try(propagated), Some(_)) = statement else {
        return false;
    };
    let Expr::Call(call) = propagated.expr.as_ref() else {
        return false;
    };
    path_is(&call.func, &["enforce_required_binds"])
        && call.args.len() == 3
        && call
            .args
            .iter()
            .zip(["cert", domain, "required_binds"])
            .all(|(argument, name)| path_is(argument, &[name]))
}

fn target_enforced(statement: &Stmt) -> bool {
    let Stmt::Expr(Expr::If(branch), _) = statement else {
        return false;
    };
    let Expr::Let(condition) = branch.cond.as_ref() else {
        return false;
    };
    let Pat::TupleStruct(pattern) = condition.pat.as_ref() else {
        return false;
    };
    pattern.path.is_ident("Some")
        && pattern.elems.len() == 1
        && pattern.elems.first().is_some_and(
            |value| matches!(value, Pat::Ident(name) if name.ident == "dst" && name.mutability.is_none()),
        )
        && path_is(&condition.expr, &["target_domain"])
        && branch.else_branch.is_none()
        && matches!(branch.then_branch.stmts.as_slice(), [only] if enforced(only, "dst"))
}

#[derive(Default)]
struct BeforeFloor {
    issue: Option<&'static str>,
}

impl<'ast> Visit<'ast> for BeforeFloor {
    fn visit_expr_return(&mut self, expression: &'ast syn::ExprReturn) {
        let is_refusal = expression.expr.as_ref().is_some_and(
            |value| matches!(value.as_ref(), Expr::Call(call) if path_is(&call.func, &["Err"])),
        );
        if !is_refusal {
            self.issue = Some("a success or opaque return can bypass the binding floor");
        }
        syn::visit::visit_expr_return(self, expression);
    }

    fn visit_macro(&mut self, _expression: &'ast syn::Macro) {
        self.issue = Some("an opaque macro precedes the binding floor");
    }

    fn visit_pat_ident(&mut self, pattern: &'ast syn::PatIdent) {
        if ["gate", "required_binds", "enforce_required_binds"]
            .iter()
            .any(|name| pattern.ident == *name)
        {
            self.issue = Some("the gate, request, or enforcer is shadowed before the floor");
        }
        syn::visit::visit_pat_ident(self, pattern);
    }

    fn visit_item(&mut self, _item: &'ast syn::Item) {
        self.issue = Some("a nested declaration precedes the binding floor");
    }
}

fn check_floor_use(source: &str) -> Result<(), String> {
    let file = syn::parse_file(source).map_err(|error| error.to_string())?;
    let function = named_function(&file, "check_certificate_value_gate")?;
    for (name, expected_type) in [("gate", "ValueGate"), ("required_binds", "FinalityBinds")] {
        let parameters = function
            .sig
            .inputs
            .iter()
            .filter(|argument| {
                let FnArg::Typed(argument) = argument else {
                    return false;
                };
                matches!(argument.pat.as_ref(), Pat::Ident(pattern)
                    if pattern.ident == name && pattern.mutability.is_none()
                        && pattern.by_ref.is_none() && pattern.subpat.is_none())
                    && type_is(&argument.ty, expected_type)
            })
            .count();
        if parameters != 1 {
            return Err(format!(
                "{name} must retain its unambiguous policy input type"
            ));
        }
    }
    let statements = &function.block.stmts;
    let at = statements
        .iter()
        .position(|statement| {
            matches!(statement, Stmt::Local(local)
                if matches!(&local.pat, Pat::Ident(name)
                    if name.ident == "required_binds" && name.mutability.is_none())
                && local.init.as_ref().is_some_and(|init| init.diverge.is_none() && minimum_union(&init.expr)))
        })
        .ok_or_else(|| "the decision does not combine its own floor with caller demands".to_owned())?;
    if !statements
        .get(at + 1)
        .is_some_and(|next| enforced(next, "source_domain"))
        || !statements.get(at + 2).is_some_and(target_enforced)
    {
        return Err("both domains must immediately consume the derived binding set".into());
    }
    let mut earlier = BeforeFloor::default();
    for statement in statements.iter().take(at) {
        earlier.visit_stmt(statement);
    }
    if let Some(issue) = earlier.issue {
        return Err(issue.to_owned());
    }
    Ok(())
}

const GOOD: &str = r"
enum ValueGate { BridgeMint, UniversalPayment }
impl ValueGate {
    const fn required_binds(self) -> FinalityBinds {
        match self {
            Self::BridgeMint | Self::UniversalPayment => FinalityBinds::EVENT_ROOT,
        }
    }
}
fn check_certificate_value_gate(cert: &Cert, gate: ValueGate, source_domain: u32,
    target_domain: Option<u32>, required_binds: FinalityBinds) -> Result<(), Error> {
    let required_binds = gate.required_binds().union(required_binds);
    enforce_required_binds(cert, source_domain, required_binds)?;
    if let Some(dst) = target_domain {
        enforce_required_binds(cert, dst, required_binds)?;
    }
    Ok(())
}
";

const FLOOR: &str = "let required_binds = gate.required_binds().union(required_binds);";

#[test]
fn live_value_gates_declare_their_binding_floor() {
    check_minimum(SOURCE).expect("gate-owned binding minimum");
}

#[test]
fn live_certificate_gate_applies_the_floor_to_both_domains() {
    check_floor_use(SOURCE).expect("source and destination consume the effective requirement");
}

#[test]
fn the_declared_and_consumed_policy_is_recognized() {
    check_minimum(GOOD).expect("explicit minimum");
    check_floor_use(GOOD).expect("minimum union is consumed");
}

#[test]
fn a_raw_caller_mask_or_only_an_empty_check_is_not_a_floor() {
    for replacement in ["", "if required_binds.is_empty() { return Err(Missing); }"] {
        assert!(check_floor_use(&GOOD.replace(FLOOR, replacement)).is_err());
    }
}

#[test]
fn a_conditional_or_mutable_floor_is_refused() {
    for replacement in [
        format!("if enabled {{ {FLOOR} }}"),
        FLOOR.replace("let required_binds", "let mut required_binds"),
    ] {
        assert!(check_floor_use(&GOOD.replace(FLOOR, &replacement)).is_err());
    }
}

#[test]
fn a_floor_after_the_source_check_is_refused() {
    let swapped = GOOD.replace(
        &format!("{FLOOR}\n    enforce_required_binds(cert, source_domain, required_binds)?;"),
        &format!("enforce_required_binds(cert, source_domain, required_binds)?;\n    {FLOOR}"),
    );
    assert_ne!(swapped, GOOD);
    assert!(check_floor_use(&swapped).is_err());
}

#[test]
fn the_destination_cannot_drop_the_derived_requirement() {
    let changed = GOOD.replace(
        "enforce_required_binds(cert, dst, required_binds)?;",
        "enforce_required_binds(cert, dst, FinalityBinds::NONE)?;",
    );
    assert!(check_floor_use(&changed).is_err());
}

#[test]
fn an_early_success_or_opaque_return_is_not_certified() {
    for before in [
        "return Ok(());",
        "return another_route();",
        "unknown_macro!();",
    ] {
        let changed = GOOD.replace(FLOOR, &format!("{before}\n    {FLOOR}"));
        assert!(check_floor_use(&changed).is_err());
    }
}

#[test]
fn explicit_earlier_refusals_do_not_mask_the_policy() {
    let changed = GOOD.replace(
        FLOOR,
        &format!("if invalid {{ return Err(Missing); }}\n    {FLOOR}"),
    );
    check_floor_use(&changed).expect("refusal preserves the floor on admitted paths");
}

#[test]
fn an_empty_or_incomplete_minimum_is_refused() {
    assert!(
        check_minimum(&GOOD.replace("FinalityBinds::EVENT_ROOT", "FinalityBinds::NONE")).is_err()
    );
    assert!(check_minimum(&GOOD.replace(
        "BridgeMint, UniversalPayment",
        "BridgeMint, UniversalPayment, AddedGate"
    ))
    .is_err());
}

#[test]
fn a_guarded_arm_is_not_an_unconditional_minimum() {
    let changed = GOOD.replace(
        "Self::BridgeMint | Self::UniversalPayment =>",
        "Self::BridgeMint | Self::UniversalPayment if enabled =>",
    );
    assert!(check_minimum(&changed).is_err());
}

#[test]
fn comments_cannot_supply_a_missing_policy() {
    let changed = format!("/* {GOOD} */\n{}", GOOD.replace(FLOOR, ""));
    assert!(check_floor_use(&changed).is_err());
}

#[test]
fn the_gate_and_requested_mask_cannot_be_shadowed_before_the_floor() {
    for shadow in [
        "let gate = another_gate;",
        "let required_binds = FinalityBinds::NONE;",
    ] {
        let changed = GOOD.replace(FLOOR, &format!("{shadow}\n    {FLOOR}"));
        assert!(syn::parse_file(&changed).is_ok());
        assert!(check_floor_use(&changed).is_err());
    }
}

#[test]
fn similarly_named_methods_on_different_parameter_types_do_not_count() {
    for (old, new) in [
        ("gate: ValueGate", "gate: AnotherGate"),
        (
            "required_binds: FinalityBinds",
            "required_binds: AnotherSet",
        ),
    ] {
        let changed = GOOD.replace(old, new);
        assert_ne!(changed, GOOD);
        assert!(syn::parse_file(&changed).is_ok());
        assert!(check_floor_use(&changed).is_err());
    }
}

#[test]
fn feature_gated_minimum_declarations_are_not_certified() {
    let changed = GOOD.replace(
        "impl ValueGate {",
        "#[cfg(feature = \"optional_policy\")]\nimpl ValueGate {",
    );
    assert!(syn::parse_file(&changed).is_ok());
    assert!(check_minimum(&changed).is_err());
}

#[test]
fn feature_gated_decision_functions_are_not_certified() {
    let changed = GOOD.replace(
        "fn check_certificate_value_gate(",
        "#[cfg(feature = \"optional_policy\")]\nfn check_certificate_value_gate(",
    );
    assert!(syn::parse_file(&changed).is_ok());
    assert!(check_floor_use(&changed).is_err());
}
