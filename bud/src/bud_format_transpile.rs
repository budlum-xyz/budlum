//! .bud transpile - compiles to bash, plus the AST transform.
//!
//! HONESTY (K19/K38): the claim "bash transpile 10x" DID NOT HOLD UP UNDER
//! MEASUREMENT - an echo script makes the code bigger (the ratio is below 1) and
//! the gate REFUSES it (the canary test). The AST part is a stub; no ratio is
//! claimed for it.
//!
//! Gate: K-BUD-TRANSPILE.

#![forbid(unsafe_code)]

#[derive(Debug, Clone)]
pub struct BashTranspile {
    pub script: String,
    pub original_size: usize,
}

impl BashTranspile {
    pub fn transpile(code: &str) -> Self {
        // Simple: code -> bash script that prints code. `printf` is used, not
        // `echo`: echo takes a leading -n or -e in the code as an option.
        let script = format!(
            "#!/bin/bash\nprintf '%s\\n' '{}'",
            code.replace("'", "'\\''")
        );
        Self {
            script,
            original_size: code.len(),
        }
    }

    pub fn ratio(&self) -> f64 {
        if self.script.is_empty() {
            return 1.0;
        }
        self.original_size as f64 / self.script.len() as f64
    }

    pub fn is_deterministic(&self) -> bool {
        // bash script deterministic if no $RANDOM, date, etc
        // Whole words only: "update" is not "date". The words that make a
        // script differ from run to run are the clock, the random sources and
        // the shell's own counters.
        const NONDETERMINISTIC: [&str; 6] = [
            "RANDOM",
            "SRANDOM",
            "SECONDS",
            "EPOCHSECONDS",
            "urandom",
            "date",
        ];
        !self
            .script
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(|word| NONDETERMINISTIC.contains(&word))
    }
}

#[derive(Debug, Clone)]
pub struct AstTransform {
    pub ast_json: String,
    pub original_size: usize,
}

impl AstTransform {
    pub fn transform(code: &str) -> Self {
        // stub: AST = {"type":"File","body":[...]}
        // K38: UTF-8 safe truncation - a byte slice must NOT split a multi-byte character, so no panic.
        let snippet: String = code.chars().take(100).collect();
        // The snippet is JSON-escaped, so quotes and backslashes in the code
        // still give valid JSON.
        let quoted = serde_json::to_string(&snippet).unwrap_or_else(|_| "\"\"".to_string());
        let ast = format!("{{\"type\":\"File\",\"body\":[{quoted}]}}");
        Self {
            ast_json: ast,
            original_size: code.len(),
        }
    }

    pub fn ratio(&self) -> f64 {
        self.original_size as f64 / self.ast_json.len() as f64
    }
}

pub struct TranspileGates;

impl TranspileGates {
    pub fn k_bud_transpile(t: &BashTranspile) -> Result<(), &'static str> {
        if !t.is_deterministic() {
            return Err("K-BUD-TRANSPILE: not deterministic");
        }
        if t.ratio() < 1.0 {
            return Err("K-BUD-TRANSPILE: ratio <1");
        }
        Ok(())
    }
    pub fn k_bud_ast(a: &AstTransform) -> Result<(), &'static str> {
        if a.ast_json.is_empty() {
            return Err("K-BUD-AST: empty");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transpile() {
        let code = "fn main() { println!(\"hello\"); }";
        let t = BashTranspile::transpile(code);
        // The real measurement: a bash echo script does NOT shrink the code, it
        // grows it (the ratio is below 1). The claim "bash transpile 10x" is
        // false, and the gate has to REFUSE it - this is the canary.
        assert!(t.ratio() < 1.0);
        assert!(TranspileGates::k_bud_transpile(&t).is_err());
    }
    #[test]
    fn determinism_looks_at_words_not_substrings() {
        assert!(BashTranspile::transpile("let update = 1;").is_deterministic());
        assert!(!BashTranspile::transpile("echo $RANDOM").is_deterministic());
        assert!(!BashTranspile::transpile("echo $SECONDS").is_deterministic());
        assert!(!BashTranspile::transpile("$(date)").is_deterministic());
    }
    #[test]
    fn the_script_does_not_use_echo_options() {
        let t = BashTranspile::transpile("-n x");
        assert!(t.script.contains("printf '%s\\n' '-n x'"), "{}", t.script);
    }
    #[test]
    fn ast_json_is_valid_for_quotes_and_backslashes() {
        let a = AstTransform::transform("let s = \"a\\b\";");
        let v: serde_json::Value = serde_json::from_str(&a.ast_json).expect("valid json");
        assert!(v.is_object());
    }
    #[test]
    fn ast() {
        let code = "let x = 1;";
        let a = AstTransform::transform(code);
        assert!(TranspileGates::k_bud_ast(&a).is_ok());
    }
}
