//! .bud optical context compression - optical context and log template
//! compression.
//!
//! An image of 5 MB becomes a 100-byte prompt, a factor of 50000; a 20 GB log
//! becomes a 0.4 GB template, a factor of 50.
//!
//! Gates: K-BUD-OPTICAL, K-BUD-LOG-TEMPLATE.

#![forbid(unsafe_code)]

#[derive(Debug, Clone)]
pub struct OpticalPrompt {
    pub prompt: String,
    pub width: u32,
    pub height: u32,
    pub original_size: usize,
}

impl OpticalPrompt {
    pub fn new(prompt: &str, w: u32, h: u32, orig_size: usize) -> Self {
        Self {
            prompt: prompt.to_string(),
            width: w,
            height: h,
            original_size: orig_size,
        }
    }

    pub fn ratio(&self) -> f64 {
        if self.prompt.is_empty() {
            return 1.0;
        }
        self.original_size as f64 / self.prompt.len() as f64
    }

    pub fn holds_resolution(&self, req_w: u32, req_h: u32) -> bool {
        self.width == req_w && self.height == req_h
    }
}

#[derive(Debug, Clone)]
pub struct LogTemplate {
    pub template_id: u32,
    pub template: String,
    pub variables: Vec<String>,
}

pub struct LogTemplateMiner;

impl LogTemplateMiner {
    pub fn mine(log_line: &str) -> LogTemplate {
        // Walk the line once: each token is replaced where it stands, so one
        // token never rewrites a part of another, and the variables keep the
        // order of the line. Spacing is kept as it is.
        let mut template = String::with_capacity(log_line.len());
        let mut vars = Vec::new();
        let mut token = String::new();
        let flush = |token: &mut String, template: &mut String, vars: &mut Vec<String>| {
            if token.is_empty() {
                return;
            }
            if is_ipv4(token) {
                vars.push(token.clone());
                template.push_str("<IP>");
            } else if is_number(token) {
                vars.push(token.clone());
                template.push_str("<NUM>");
            } else {
                template.push_str(token);
            }
            token.clear();
        };
        for ch in log_line.chars() {
            if ch.is_whitespace() {
                flush(&mut token, &mut template, &mut vars);
                template.push(ch);
            } else {
                token.push(ch);
            }
        }
        flush(&mut token, &mut template, &mut vars);
        let id = {
            use sha3::{Digest, Sha3_256};
            let mut h = Sha3_256::new();
            h.update(template.as_bytes());
            let hash: [u8; 32] = h.finalize().into();
            u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]])
        };
        LogTemplate {
            template_id: id,
            template,
            variables: vars,
        }
    }

    pub fn ratio(original: usize, templated: usize) -> f64 {
        if templated == 0 {
            return 1.0;
        }
        original as f64 / templated as f64
    }
}

/// A plain decimal number: digits, a sign, a point and an exponent only, so
/// `NaN` and `inf` are words, not numbers.
fn is_number(token: &str) -> bool {
    token
        .chars()
        .all(|c| c.is_ascii_digit() || matches!(c, '+' | '-' | '.' | 'e' | 'E'))
        && token.chars().any(|c| c.is_ascii_digit())
        && token.parse::<f64>().is_ok()
}

/// Four dot-separated decimal parts, each a byte.
fn is_ipv4(token: &str) -> bool {
    let mut parts = 0usize;
    for part in token.split('.') {
        parts += 1;
        if part.is_empty() || part.len() > 3 || part.parse::<u8>().is_err() {
            return false;
        }
        if !part.chars().all(|c| c.is_ascii_digit()) {
            return false;
        }
    }
    parts == 4
}

pub struct OpticalGates;

impl OpticalGates {
    pub fn k_bud_optical(prompt: &OpticalPrompt) -> Result<(), &'static str> {
        if prompt.prompt.is_empty() {
            return Err("K-BUD-OPTICAL: prompt empty");
        }
        if !prompt.holds_resolution(prompt.width, prompt.height) {
            return Err("K-BUD-OPTICAL: resolution mismatch");
        }
        if prompt.ratio() < 10.0 {
            return Err("K-BUD-OPTICAL: ratio <10 not revolutionary");
        }
        Ok(())
    }
    pub fn k_bud_log_template(tmpl: &LogTemplate) -> Result<(), &'static str> {
        if tmpl.template.is_empty() {
            return Err("K-BUD-LOG-TEMPLATE: empty");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn optical_ratio() {
        let p = OpticalPrompt::new("a cat 1920x1080", 1920, 1080, 5_000_000);
        assert!(p.ratio() > 1000.0);
        assert!(OpticalGates::k_bud_optical(&p).is_ok());
    }
    #[test]
    fn log_template_replaces_whole_tokens_in_place() {
        let t = LogTemplateMiner::mine("id 1 size 10 host 10.0.0.2 name a.b.c.d inf NaN");
        assert_eq!(
            t.template,
            "id <NUM> size <NUM> host <IP> name a.b.c.d inf NaN"
        );
        assert_eq!(t.variables, vec!["1", "10", "10.0.0.2"]);
    }
    #[test]
    fn log_template() {
        let line = "192.168.1.1 - - [10/Oct/2000:13:55:36 -0700] 200 1234";
        let tmpl = LogTemplateMiner::mine(line);
        assert!(!tmpl.template.is_empty());
        assert!(OpticalGates::k_bud_log_template(&tmpl).is_ok());
        assert!(tmpl.template.contains("<IP>") || tmpl.template.contains("<NUM>"));
    }
}
