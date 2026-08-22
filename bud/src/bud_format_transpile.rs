//! .bud Transpile - bash'e derlenir + AST dönüşümü
//! DÜRÜSTLÜK (K19/K38): "bash transpile 10x" iddiası ÖLÇÜLÜMDE TUTMADI - echo-script
//! kodu büyütür (ratio < 1), kapı RED verir (kanarya testi). AST stub'tır; oran iddiası yok.
//! Kapı K-BUD-TRANSPILE

#![forbid(unsafe_code)]

#[derive(Debug, Clone)]
pub struct BashTranspile {
    pub script: String,
    pub original_size: usize,
}

impl BashTranspile {
    pub fn transpile(code: &str) -> Self {
        // Simple: code -> bash script that echoes code
        let script = format!("#!/bin/bash\necho '{}'", code.replace("'", "'\\''"));
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
        !self.script.contains("$RANDOM") && !self.script.contains("date")
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
        // K38: UTF-8 güvenli kırpma - bayt dilimi çok baytlı karakteri BÖLEMEZ (panik yok)
        let snippet: String = code.chars().take(100).collect();
        let ast = format!("{{\"type\":\"File\",\"body\":[\"{}\"]}}", snippet);
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
        // Gerçek ölçüm: bash echo-script kodu KÜÇÜLTMEZ, büyütür (ratio < 1).
        // "bash transpile 10x" iddiası yanlıştır - kapı RED vermelidir (kanarya).
        assert!(t.ratio() < 1.0);
        assert!(TranspileGates::k_bud_transpile(&t).is_err());
    }
    #[test]
    fn ast() {
        let code = "let x = 1;";
        let a = AstTransform::transform(code);
        assert!(TranspileGates::k_bud_ast(&a).is_ok());
    }
}
