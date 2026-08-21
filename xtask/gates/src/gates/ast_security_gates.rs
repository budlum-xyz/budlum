//! Round 5 kök çözüm: `syn` tabanlı AST güvenlik gate'leri.
//!
//! Substring+brace-walk gate'ler (`zero_address_sender_is_verified`,
//! `tee_trust_boundary_is_structural`, `gov_slash_evidence_is_validator_only`)
//! Strix'in parser-seviyesi düşüncesini modelleyemedi: her turda yeni bir
//! varyant (closure, nested helper, nested conditional, move closure,
//! collection item) buldu. Bu modül aynı üç korumayı GERÇEK Rust AST'si
//! üzerinde doğrular; `syn::visit` ile fonksiyon gövdeleri geçilir, closure
//! ve nested bloklar AST düğümleri olarak ayırt edilir.
//!
//! Korumalar:
//!   1. zero-address: `validate_transaction_with_context` içinde, zero-address
//!      dalındaki başarı (`Ok(())` / `return Ok(())`), `if tx.verify()`
//!      bloğunun DOĞRUDAN içinde (closure, nested fn item, nested if, match
//!      arm, loop dışında) olmalı ve verify bloğundan sonraki yol fail-closed
//!      olmalı (`return Err` / `Err` tail).
//!   2. TEE: `sign_with_privacy` içinde `verifier.verify_quote` çağrısı sonucu
//!      (attestation) `if !verify_measurement/backend/report_data` koşullarında
//!      DOĞRUDAN `return Err` ile kullanılmalı (closure/nested blok decoy'u
//!      sayılmaz) ve bu guard'lar başarıdan ÖNCE gelmeli.
//!   3. gov-slash: `execute_proposal` içindeki `SlashValidator` dalında digest
//!      karşılaştırması success'i yönlendirmeli: ya `if digest == evidence_hash`
//!      bloğunda DOĞRUDAN `return true;`, ya da `.any(|..| { ..; digest == hash })`
//!      closure'ında TAIL ifade olarak.
//!
//! Sertleştirme notu (Round 5 sonrası): Strix'in son tur bulguları
//! (nested conditional `return true`, nested-item `Ok(())`, nested conditional
//! `return Err`, closure decoy) AST seviyesinde de kapatıldı; her visitor
//! nesting sayacı taşıyor ve yalnızca hedef bloğun DOĞRUDAN üyesi olan
//! kontrolleri sayıyor.

use quote::ToTokens;
use std::path::Path;
use syn::visit::{self, Visit};
use syn::{Expr, ExprCall, ExprReturn, Stmt};

/// Whitespace-compact token metni: token akışındaki boşlukları atar, böylece
/// karşılaştırmalar biçimlendirmeden bağımsız olur.
fn compact<T: ToTokens>(t: &T) -> String {
    t.to_token_stream()
        .to_string()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

/// `Ok(())` çağrısı mı? Path'in son segmenti `Ok` ve tek argüman boş tuple.
fn is_ok_unit_call(node: &ExprCall) -> bool {
    matches!(node.func.as_ref(), Expr::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "Ok"))
        && node.args.len() == 1
        && matches!(&node.args[0], Expr::Tuple(t) if t.elems.is_empty())
}

/// Herhangi bir `Ok(...)` çağrısı mı? (sıralama kontrolü için; payload tipi
/// önemsiz.)
fn is_ok_call(node: &ExprCall) -> bool {
    matches!(node.func.as_ref(), Expr::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "Ok"))
}

/// `Err(...)` çağrısı mı? (tail fail-closed formu için.)
fn is_err_call(node: &ExprCall) -> bool {
    matches!(node.func.as_ref(), Expr::Path(p) if p.path.segments.last().is_some_and(|s| s.ident == "Err"))
}

/// `if tx.verify() { .. }` bloğunun içini gez; başarı yalnızca doğrudan
/// (nesting == 0) `Ok(())` / `return Ok(())` olarak sayılır. Closure, nested
/// fn item, nested if, match arm ve loop içindeki `Ok(())` decoy'dur (Strix
/// CWE-697, round 8/10 bulguları: nested helper ve nested-item decoy).
#[derive(Default)]
struct VerifySuccess {
    found: bool,
    nesting: usize,
}

impl<'ast> Visit<'ast> for VerifySuccess {
    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if self.nesting == 0 && is_ok_unit_call(node) {
            self.found = true;
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_return(&mut self, node: &'ast ExprReturn) {
        if self.nesting == 0 {
            if let Some(expr) = &node.expr {
                if matches!(expr.as_ref(), Expr::Call(c) if is_ok_unit_call(c)) {
                    self.found = true;
                }
            }
        }
        visit::visit_expr_return(self, node);
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        self.nesting += 1;
        visit::visit_expr_closure(self, node);
        self.nesting -= 1;
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.nesting += 1;
        visit::visit_item_fn(self, node);
        self.nesting -= 1;
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.nesting += 1;
        visit::visit_expr_if(self, node);
        self.nesting -= 1;
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        self.nesting += 1;
        visit::visit_expr_match(self, node);
        self.nesting -= 1;
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        self.nesting += 1;
        visit::visit_expr_loop(self, node);
        self.nesting -= 1;
    }
}

/// Sıralı olarak zero-address dalını gez: `if tx.verify()`'yi bul, içini
/// `VerifySuccess` ile kontrol et, sonrasındaki ifadelerin fail-closed
/// olduğunu doğrula.
#[derive(Default)]
struct ZeroBlockCheck {
    guarded_success: bool,
    after_verify_has_success: bool,
}

/// Verify bloğundan sonra gelen ifade fail-closed mu? Yalnızca `return Err`,
/// `Err(...)` tail veya çıplak `return;` sayılır; bir yardımcı çağrısı, macro
/// veya değer ifadesi, dışarıya başarı sızdırabilir (Strix CWE-697, round
/// 6/7 bulguları: helper ve tail success).
fn stmt_fails_closed(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Expr(Expr::Return(ret), _) => match &ret.expr {
            None => true,
            Some(e) => compact(e).contains("Err"),
        },
        Stmt::Expr(Expr::Call(call), None) => is_err_call(call),
        _ => false,
    }
}

/// İfadede herhangi bir `Ok(())` var mı? (verify öncesi guard'sız başarıyı
/// yakalar.)
fn stmt_contains_unit_ok(stmt: &Stmt) -> bool {
    struct UnitOkFinder {
        found: bool,
    }
    impl<'ast> Visit<'ast> for UnitOkFinder {
        fn visit_expr_call(&mut self, node: &'ast ExprCall) {
            if is_ok_unit_call(node) {
                self.found = true;
            }
            visit::visit_expr_call(self, node);
        }
    }
    let mut f = UnitOkFinder { found: false };
    f.visit_stmt(stmt);
    f.found
}

impl<'ast> Visit<'ast> for ZeroBlockCheck {
    fn visit_block(&mut self, node: &'ast syn::Block) {
        let mut after_verify = false;
        for stmt in &node.stmts {
            if let Stmt::Expr(Expr::If(ifn), _) = stmt {
                let cond = compact(&ifn.cond);
                if !after_verify && !cond.starts_with('!') && cond.contains("tx.verify()") {
                    let mut vs = VerifySuccess::default();
                    vs.visit_block(&ifn.then_branch);
                    self.guarded_success = vs.found;
                    // Else dalındaki başarı verify tarafından korunmuyor.
                    if let Some((_, else_expr)) = &ifn.else_branch {
                        if let Expr::Block(else_block) = else_expr.as_ref() {
                            let mut evs = VerifySuccess::default();
                            evs.visit_block(&else_block.block);
                            if evs.found {
                                self.after_verify_has_success = true;
                            }
                        }
                    }
                    after_verify = true;
                    continue;
                }
            }
            if after_verify && !stmt_fails_closed(stmt) {
                self.after_verify_has_success = true;
            }
            if !after_verify && stmt_contains_unit_ok(stmt) {
                // Verify öncesi başarı, guard'sız başarıdır (örn.
                // `if !tx.verify() { return Ok(()); }`).
                self.after_verify_has_success = true;
            }
        }
    }
}

/// `validate_transaction_with_context` fonksiyonuna çapalanır; zero-address
/// dalını bulur ve `ZeroBlockCheck` ile doğrular.
#[derive(Default)]
struct ZeroAddressFinder {
    result: Option<ZeroBlockCheck>,
    in_validate: bool,
}

impl<'ast> Visit<'ast> for ZeroAddressFinder {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if node.sig.ident == "validate_transaction_with_context" {
            let prev = self.in_validate;
            self.in_validate = true;
            visit::visit_item_fn(self, node);
            self.in_validate = prev;
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if node.sig.ident == "validate_transaction_with_context" {
            let prev = self.in_validate;
            self.in_validate = true;
            visit::visit_impl_item_fn(self, node);
            self.in_validate = prev;
        }
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        if self.in_validate && self.result.is_none() {
            let cond = compact(&node.cond);
            if cond.contains("Address::zero") {
                let mut check = ZeroBlockCheck::default();
                check.visit_block(&node.then_branch);
                self.result = Some(check);
                return;
            }
        }
        visit::visit_expr_if(self, node);
    }
}

/// TEE guard'ının `then` bloğunu gez; `return Err` yalnızca doğrudan
/// (nesting == 0) sayılır. Closure/nested if/nested item/match arm/loop
/// içindeki `return Err` decoy'dur (Strix CWE-697, round 5/6/7/10 bulguları).
#[derive(Default)]
struct GuardErrCheck {
    found: bool,
    nesting: usize,
}

impl<'ast> Visit<'ast> for GuardErrCheck {
    fn visit_expr_return(&mut self, node: &'ast ExprReturn) {
        if self.nesting == 0 {
            if let Some(expr) = &node.expr {
                if compact(expr).contains("Err") {
                    self.found = true;
                }
            }
        }
        visit::visit_expr_return(self, node);
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        self.nesting += 1;
        visit::visit_expr_closure(self, node);
        self.nesting -= 1;
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.nesting += 1;
        visit::visit_item_fn(self, node);
        self.nesting -= 1;
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.nesting += 1;
        visit::visit_expr_if(self, node);
        self.nesting -= 1;
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        self.nesting += 1;
        visit::visit_expr_match(self, node);
        self.nesting -= 1;
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        self.nesting += 1;
        visit::visit_expr_loop(self, node);
        self.nesting -= 1;
    }
}

#[allow(clippy::struct_excessive_bools)]
struct TeeVisitor {
    in_sign_with_privacy: bool,
    has_quote_call: bool,
    has_verify_quote: bool,
    measurement_guard: bool,
    backend_guard: bool,
    report_guard: bool,
    saw_success: bool,
    measurement_after_success: bool,
    backend_after_success: bool,
    report_after_success: bool,
}

impl TeeVisitor {
    fn new() -> Self {
        Self {
            in_sign_with_privacy: false,
            has_quote_call: false,
            has_verify_quote: false,
            measurement_guard: false,
            backend_guard: false,
            report_guard: false,
            saw_success: false,
            measurement_after_success: false,
            backend_after_success: false,
            report_after_success: false,
        }
    }
}

impl<'ast> Visit<'ast> for TeeVisitor {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if node.sig.ident == "sign_with_privacy" {
            let prev = self.in_sign_with_privacy;
            self.in_sign_with_privacy = true;
            visit::visit_item_fn(self, node);
            self.in_sign_with_privacy = prev;
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if node.sig.ident == "sign_with_privacy" {
            let prev = self.in_sign_with_privacy;
            self.in_sign_with_privacy = true;
            visit::visit_impl_item_fn(self, node);
            self.in_sign_with_privacy = prev;
        }
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        let method = node.method.to_string();
        let recv = node.receiver.to_token_stream().to_string();
        if self.in_sign_with_privacy && method == "quote" {
            self.has_quote_call = true;
        }
        if self.in_sign_with_privacy && method == "verify_quote" && recv.contains("verifier") {
            self.has_verify_quote = true;
        }
        visit::visit_expr_method_call(self, node);
    }

    fn visit_expr_call(&mut self, node: &'ast ExprCall) {
        if self.in_sign_with_privacy && is_ok_call(node) {
            // Kaynak siralidir (pre-order): guard'lar success'ten sonra
            // islenirse asagida yakalanir.
            self.saw_success = true;
        }
        visit::visit_expr_call(self, node);
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        if self.in_sign_with_privacy {
            let cond = compact(&node.cond);
            let which = if cond.contains("verify_measurement") {
                Some(0)
            } else if cond.contains("backend") {
                Some(1)
            } else if cond.contains("verify_report_data") {
                Some(2)
            } else {
                None
            };
            if let Some(kind) = which {
                let mut g = GuardErrCheck::default();
                g.visit_block(&node.then_branch);
                let ok = g.found;
                let after_success = self.saw_success;
                match kind {
                    0 => {
                        self.measurement_guard = ok;
                        self.measurement_after_success = after_success;
                    }
                    1 => {
                        self.backend_guard = ok;
                        self.backend_after_success = after_success;
                    }
                    _ => {
                        self.report_guard = ok;
                        self.report_after_success = after_success;
                    }
                }
                return;
            }
        }
        visit::visit_expr_if(self, node);
    }
}

/// `if digest == evidence_hash { .. }` bloğunun içini gez; `return true;`
/// yalnızca doğrudan (nesting == 0) sayılır (Strix CWE-697, round 10 bulgusu:
/// nested conditional `return true` decoy).
#[derive(Default)]
struct TopLevelTrue {
    found: bool,
    nesting: usize,
}

impl<'ast> Visit<'ast> for TopLevelTrue {
    fn visit_expr_return(&mut self, node: &'ast ExprReturn) {
        if self.nesting == 0 {
            if let Some(expr) = &node.expr {
                if compact(expr) == "true" {
                    self.found = true;
                }
            }
        }
        visit::visit_expr_return(self, node);
    }

    fn visit_expr_closure(&mut self, node: &'ast syn::ExprClosure) {
        self.nesting += 1;
        visit::visit_expr_closure(self, node);
        self.nesting -= 1;
    }

    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        self.nesting += 1;
        visit::visit_item_fn(self, node);
        self.nesting -= 1;
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        self.nesting += 1;
        visit::visit_expr_if(self, node);
        self.nesting -= 1;
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        self.nesting += 1;
        visit::visit_expr_match(self, node);
        self.nesting -= 1;
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        self.nesting += 1;
        visit::visit_expr_loop(self, node);
        self.nesting -= 1;
    }
}

/// `.any(|..| { .. })` closure'ının tail ifadesi digest karşılaştırması mı?
/// Sondaki `;`'li ifade veya `true` gibi bir değer, karşılaştırmayı
/// yönlendirmez (Strix CWE-697, round 8 bulgusu: tail formun override'ı).
fn closure_tail_is_digest_cmp(body: &Expr) -> bool {
    let last: Option<&Expr> = match body {
        Expr::Block(b) => match b.block.stmts.last() {
            Some(Stmt::Expr(e, None)) => Some(e),
            _ => None,
        },
        other => Some(other),
    };
    last.is_some_and(|e| {
        let c = compact(e);
        c.contains("evidence_hash") && c.contains("==")
    })
}

/// Closure gövdesinde herhangi bir digest karşılaştırması var mı? (Tail
/// olmasa da `has_digest_condition` için yeterli; `digest_guards_return`
/// yalnızca tail formda.)
fn closure_has_digest_cmp(body: &Expr) -> bool {
    let c = compact(body);
    c.contains("evidence_hash") && c.contains("sha2")
}

#[allow(clippy::struct_excessive_bools)]
struct GovSlashVisitor {
    in_execute_proposal: bool,
    in_slash_validator: bool,
    has_digest_condition: bool,
    digest_guards_return: bool,
}

impl GovSlashVisitor {
    fn new() -> Self {
        Self {
            in_execute_proposal: false,
            in_slash_validator: false,
            has_digest_condition: false,
            digest_guards_return: false,
        }
    }
}

impl<'ast> Visit<'ast> for GovSlashVisitor {
    fn visit_item_fn(&mut self, node: &'ast syn::ItemFn) {
        if node.sig.ident == "execute_proposal" {
            let prev = self.in_execute_proposal;
            self.in_execute_proposal = true;
            visit::visit_item_fn(self, node);
            self.in_execute_proposal = prev;
        }
    }

    fn visit_impl_item_fn(&mut self, node: &'ast syn::ImplItemFn) {
        if node.sig.ident == "execute_proposal" {
            let prev = self.in_execute_proposal;
            self.in_execute_proposal = true;
            visit::visit_impl_item_fn(self, node);
            self.in_execute_proposal = prev;
        }
    }

    fn visit_expr_match(&mut self, node: &'ast syn::ExprMatch) {
        if self.in_execute_proposal {
            let scrut = node.expr.to_token_stream().to_string();
            if scrut.contains("p_type") {
                for arm in &node.arms {
                    let pat = arm.pat.to_token_stream().to_string();
                    if pat.contains("SlashValidator") {
                        let prev = self.in_slash_validator;
                        self.in_slash_validator = true;
                        visit::visit_expr(self, &arm.body);
                        self.in_slash_validator = prev;
                        return;
                    }
                }
            }
        }
        visit::visit_expr_match(self, node);
    }

    fn visit_expr_if(&mut self, node: &'ast syn::ExprIf) {
        if self.in_slash_validator {
            let cond = compact(&node.cond);
            if cond.contains("evidence_hash") {
                self.has_digest_condition = true;
                let mut v = TopLevelTrue::default();
                v.visit_block(&node.then_branch);
                if v.found {
                    self.digest_guards_return = true;
                }
                return;
            }
        }
        visit::visit_expr_if(self, node);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if self.in_slash_validator && node.method == "any" {
            for arg in &node.args {
                if let Expr::Closure(c) = arg {
                    if closure_has_digest_cmp(&c.body) {
                        self.has_digest_condition = true;
                        if closure_tail_is_digest_cmp(&c.body) {
                            self.digest_guards_return = true;
                        }
                    }
                }
            }
        }
        visit::visit_expr_method_call(self, node);
    }
}

/// Hangi korumaların bu dosyada aranacağı.
#[derive(Clone, Copy)]
struct Checks {
    zero_address: bool,
    tee: bool,
    gov_slash: bool,
}

fn judge_file(src: &str, checks: Checks) -> Vec<String> {
    let mut problems = Vec::new();
    let ast: syn::File = match syn::parse_file(src) {
        Ok(f) => f,
        Err(e) => {
            problems.push(format!("parse error: {e}"));
            return problems;
        }
    };

    if checks.zero_address {
        let mut finder = ZeroAddressFinder::default();
        finder.visit_file(&ast);
        match &finder.result {
            Some(check) => {
                if !check.guarded_success || check.after_verify_has_success {
                    problems.push(String::from(
                        "AST: validate_transaction_with_context zero-address dalinda gercek bir guard'li basari yok: Ok(()) tx.verify() blogunun dogrudan icinde olmali (closure, nested fn, nested if, match arm veya loop disinda) ve verify sonrasi yol fail-closed olmali (return Err / Err). CWE-306 guard'i dogrulanamadi.",
                    ));
                }
            }
            None => {
                problems.push(String::from(
                    "AST: validate_transaction_with_context icinde Address::zero dali bulunamadi; CWE-306 guard'i eksik.",
                ));
            }
        }
    }

    if checks.tee {
        let mut tee = TeeVisitor::new();
        tee.visit_file(&ast);
        if !tee.has_quote_call || !tee.has_verify_quote {
            problems.push(String::from(
                "AST: sign_with_privacy quote->verify_quote zinciri yok.",
            ));
        }
        if !tee.measurement_guard {
            problems.push(String::from(
                "AST: verify_measurement fail-closed guard yok veya return Err closure/nested blok icinde.",
            ));
        }
        if !tee.backend_guard {
            problems.push(String::from(
                "AST: backend fail-closed guard yok veya return Err closure/nested blok icinde.",
            ));
        }
        if !tee.report_guard {
            problems.push(String::from(
                "AST: verify_report_data fail-closed guard yok veya return Err closure/nested blok icinde.",
            ));
        }
        let after_success = [
            (tee.measurement_after_success, "verify_measurement"),
            (tee.backend_after_success, "backend"),
            (tee.report_after_success, "verify_report_data"),
        ];
        for (after, name) in after_success {
            if after {
                problems.push(format!(
                    "AST: {name} guard'i sign_with_privacy icinde success'ten sonra geliyor; attestation kontrolu calismadan basari donulemez."
                ));
            }
        }
    }

    if checks.gov_slash {
        let mut gs = GovSlashVisitor::new();
        gs.visit_file(&ast);
        if !gs.has_digest_condition {
            problems.push(String::from(
                "AST: SlashValidator dalinda digest kosulu (if digest == evidence_hash veya .any closure tail'i) yok.",
            ));
        } else if !gs.digest_guards_return {
            problems.push(String::from(
                "AST: SlashValidator dalinda digest kosulu success'i yonlendirmiyor: if blogunda dogrudan return true yok veya .any closure tail'i digest karsilastirmasi degil.",
            ));
        }
    }

    problems
}

/// # Errors
///
/// AST tabanlı bulgular.
pub fn run(root: &Path) -> Result<String, String> {
    let mut problems = Vec::new();
    let plan: &[(&str, Checks)] = &[
        (
            "src/core/account.rs",
            Checks {
                zero_address: true,
                tee: false,
                gov_slash: true,
            },
        ),
        (
            "crates/wallet-core/src/lib.rs",
            Checks {
                zero_address: false,
                tee: true,
                gov_slash: false,
            },
        ),
        (
            "crates/wallet-core/src/tee.rs",
            Checks {
                zero_address: false,
                tee: false,
                gov_slash: false,
            },
        ),
    ];
    for (rel, checks) in plan {
        let p = root.join(rel);
        let src = match std::fs::read_to_string(&p) {
            Ok(s) => s,
            Err(e) => {
                problems.push(format!("cannot read {}: {e}", p.display()));
                continue;
            }
        };
        problems.extend(judge_file(&src, *checks));
    }

    if problems.is_empty() {
        return Ok(String::from(
            "AST security gates OK: zero-address, TEE trust boundary and gov-slash evidence are enforced on the real Rust AST.",
        ));
    }
    Err(problems.join("\n"))
}

// Self-test kanaryaları: her biri gate'in reddetmesi/kabul etmesi gereken
// bir kaynak ağacı. Const olarak tutulması self_test'i kısa tutar.
const GOOD_TREE: &str = r#"
fn validate_transaction_with_context(&self, tx: &Transaction) -> Result<(), String> {
    if tx.from == Address::zero() {
        if tx.verify() {
            return Ok(());
        }
        return Err("x".into());
    }
    Ok(())
}
impl Wallet {
    fn sign_with_privacy(&self, runtime: &dyn TeeQuoter, verifier: &dyn TeeQuoteVerifier) -> Result<[u8; 64], WalletError> {
        let quote = runtime.quote([0u8; 32]).unwrap();
        let attestation = verifier.verify_quote(&quote).unwrap();
        if !attestation.verify_measurement(&[0u8; 32]) { return Err(WalletError::TeeUnavailable("x".into())); }
        if attestation.backend != TeeBackendKind::ClientSgx { return Err(WalletError::TeeUnavailable("x".into())); }
        if !attestation.verify_report_data(&[0u8; 32]) { return Err(WalletError::TeeUnavailable("x".into())); }
        Ok([0u8; 64])
    }
}
fn execute_proposal(&mut self, proposal: &Proposal) {
    match &proposal.p_type {
        ProposalType::SlashValidator { address, evidence_hash } => {
            if sha2::Sha256::digest(&bytes).as_slice() == evidence_hash {
                return true;
            }
        }
    }
}
"#;
const GOOD_ANY_TREE: &str = r#"
fn execute_proposal(&mut self, proposal: &Proposal) {
    match &proposal.p_type {
        ProposalType::SlashValidator { address, evidence_hash } => {
            let evidence_matches = records.iter().any(|record| {
                if record.report.role != crate::registry::role::roles::VALIDATOR {
                    return false;
                }
                let bytes = bincode::serialize(&record.report).expect("x");
                sha2::Sha256::digest(&bytes).as_slice() == evidence_hash
            });
        }
    }
}
"#;
const ZA_BAD: &str = "\nfn validate_transaction_with_context(&self, tx: &Transaction) -> Result<(), String> {\n    if tx.from == Address::zero() {\n        return Ok(());\n    }\n    Ok(())\n}\n";
const ZA_NESTED_ITEM: &str = "\nfn validate_transaction_with_context(&self, tx: &Transaction) -> Result<(), String> {\n    if tx.from == Address::zero() {\n        if tx.verify() {\n            fn decoy() -> Result<(), String> { Ok(()) }\n        }\n        return helper_accepting_zero_address(tx);\n    }\n    Ok(())\n}\n";
const ZA_CLOSURE_DECOY: &str = "\nfn validate_transaction_with_context(&self, tx: &Transaction) -> Result<(), String> {\n    if tx.from == Address::zero() {\n        if tx.verify() {\n            let _d = || { return Ok(()); };\n        }\n        return Err(\"x\".into());\n    }\n    Ok(())\n}\n";
const ZA_FAILED_VERIFY: &str = "\nfn validate_transaction_with_context(&self, tx: &Transaction) -> Result<(), String> {\n    if tx.from == Address::zero() {\n        if !tx.verify() {\n            return Ok(());\n        }\n        return Err(\"x\".into());\n    }\n    Ok(())\n}\n";
const TEE_NESTED_CONDITIONAL: &str = r#"
impl Wallet {
    fn sign_with_privacy(&self, runtime: &dyn TeeQuoter, verifier: &dyn TeeQuoteVerifier) -> Result<[u8; 64], WalletError> {
        let quote = runtime.quote([0u8; 32]).unwrap();
        let attestation = verifier.verify_quote(&quote).unwrap();
        if !attestation.verify_measurement(&[0u8; 32]) { if false { return Err(WalletError::TeeUnavailable("x".into())); } }
        if attestation.backend != TeeBackendKind::ClientSgx { if false { return Err(WalletError::TeeUnavailable("x".into())); } }
        if !attestation.verify_report_data(&[0u8; 32]) { if false { return Err(WalletError::TeeUnavailable("x".into())); } }
        Ok([0u8; 64])
    }
}
"#;
const TEE_CLOSURE_DECOY: &str = r#"
impl Wallet {
    fn sign_with_privacy(&self, runtime: &dyn TeeQuoter, verifier: &dyn TeeQuoteVerifier) -> Result<[u8; 64], WalletError> {
        let quote = runtime.quote([0u8; 32]).unwrap();
        let attestation = verifier.verify_quote(&quote).unwrap();
        if !attestation.verify_measurement(&[0u8; 32]) { let _d = || { return Err(WalletError::TeeUnavailable("x".into())); }; }
        if attestation.backend != TeeBackendKind::ClientSgx { return Err(WalletError::TeeUnavailable("x".into())); }
        if !attestation.verify_report_data(&[0u8; 32]) { return Err(WalletError::TeeUnavailable("x".into())); }
        Ok([0u8; 64])
    }
}
"#;
const TEE_AFTER_SUCCESS: &str = r#"
impl Wallet {
    fn sign_with_privacy(&self, runtime: &dyn TeeQuoter, verifier: &dyn TeeQuoteVerifier) -> Result<[u8; 64], WalletError> {
        let quote = runtime.quote([0u8; 32]).unwrap();
        let attestation = verifier.verify_quote(&quote).unwrap();
        Ok([0u8; 64]);
        if !attestation.verify_measurement(&[0u8; 32]) { return Err(WalletError::TeeUnavailable("x".into())); }
        if attestation.backend != TeeBackendKind::ClientSgx { return Err(WalletError::TeeUnavailable("x".into())); }
        if !attestation.verify_report_data(&[0u8; 32]) { return Err(WalletError::TeeUnavailable("x".into())); }
    }
}
"#;
const GOV_NESTED_CONDITIONAL: &str = r"
fn execute_proposal(&mut self, proposal: &Proposal) {
    match &proposal.p_type {
        ProposalType::SlashValidator { address, evidence_hash } => {
            if sha2::Sha256::digest(&bytes).as_slice() == evidence_hash {
                if false { return true; }
            }
            true
        }
    }
}
";
const GOV_NON_TAIL: &str = r"
fn execute_proposal(&mut self, proposal: &Proposal) {
    match &proposal.p_type {
        ProposalType::SlashValidator { address, evidence_hash } => {
            let ok = records.iter().any(|record| {
                sha2::Sha256::digest(&bytes).as_slice() == evidence_hash;
                true
            });
        }
    }
}
";

/// # Errors
///
/// Kanaryalar.
fn expect_problem(
    problems: &mut Vec<String>,
    src: &str,
    checks: Checks,
    needle: &str,
    vacuous: &str,
) {
    let finds = judge_file(src, checks);
    if !finds.iter().any(|p| p.contains(needle)) {
        problems.push(format!("VACUOUS: {vacuous} (got {finds:?})"));
    }
}

fn expect_clean(problems: &mut Vec<String>, src: &str, checks: Checks, broken: &str) {
    let finds = judge_file(src, checks);
    if !finds.is_empty() {
        problems.push(format!("BROKEN: {broken}: {finds:?}"));
    }
}

/// # Errors
///
/// Kanaryalar.
pub fn self_test() -> Result<String, String> {
    let mut problems = Vec::new();
    let all = Checks {
        zero_address: true,
        tee: true,
        gov_slash: true,
    };
    let za_only = Checks {
        zero_address: true,
        tee: false,
        gov_slash: false,
    };
    let tee_only = Checks {
        zero_address: false,
        tee: true,
        gov_slash: false,
    };
    let gov_only = Checks {
        zero_address: false,
        tee: false,
        gov_slash: true,
    };

    // Iyi agaclar: uc korumanin da dogru sekli.
    expect_clean(&mut problems, GOOD_TREE, all, "good tree rejected");
    expect_clean(
        &mut problems,
        GOOD_ANY_TREE,
        gov_only,
        "good .any tail tree rejected",
    );

    // Zero-address: guard'siz, nested-item, closure-decoy, failed-verify.
    expect_problem(
        &mut problems,
        ZA_BAD,
        za_only,
        "zero-address",
        "unguarded zero-address success accepted",
    );
    expect_problem(
        &mut problems,
        ZA_NESTED_ITEM,
        za_only,
        "zero-address",
        "nested-item Ok(()) decoy with a tail helper success accepted",
    );
    expect_problem(
        &mut problems,
        ZA_CLOSURE_DECOY,
        za_only,
        "zero-address",
        "closure-decoy Ok(()) accepted as guarded success",
    );
    expect_problem(
        &mut problems,
        ZA_FAILED_VERIFY,
        za_only,
        "zero-address",
        "failed-verify branch success accepted",
    );

    // TEE: nested conditional, closure decoy, success-sonrasi guard.
    expect_problem(
        &mut problems,
        TEE_NESTED_CONDITIONAL,
        tee_only,
        "guard yok",
        "TEE nested conditional return Err decoy accepted",
    );
    expect_problem(
        &mut problems,
        TEE_CLOSURE_DECOY,
        tee_only,
        "guard yok",
        "TEE closure-decoy return Err accepted",
    );
    expect_problem(
        &mut problems,
        TEE_AFTER_SUCCESS,
        tee_only,
        "success'ten sonra",
        "TEE guards after the success were accepted",
    );

    // Gov-slash: nested conditional return true, non-tail closure.
    expect_problem(
        &mut problems,
        GOV_NESTED_CONDITIONAL,
        gov_only,
        "yonlendirmiyor",
        "gov-slash nested conditional return true accepted",
    );
    expect_problem(
        &mut problems,
        GOV_NON_TAIL,
        gov_only,
        "yonlendirmiyor",
        "gov-slash non-tail .any closure accepted",
    );

    if !problems.is_empty() {
        return Err(problems.join("\n  "));
    }
    Ok(String::from(
        "AST security gates self-test OK: good tree passes, decoy variants rejected.",
    ))
}
