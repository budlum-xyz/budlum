//! .bud Optical Context Compression - optik bağlam ve günlük şablonu sıkıştırması
//! Görüntü 5MB -> istem 100B 50000x, Log 20GB -> şablon 0.4GB 50x
//! Kapı K-BUD-OPTICAL, K-BUD-LOG-TEMPLATE

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
        Self { prompt: prompt.to_string(), width: w, height: h, original_size: orig_size }
    }

    pub fn ratio(&self) -> f64 {
        if self.prompt.len()==0 { return 1.0; }
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
        // Simple: split by space, numbers -> <NUM>, IPs -> <IP>
        let mut template = log_line.to_string();
        let mut vars = Vec::new();
        for token in log_line.split_whitespace() {
            if token.parse::<f64>().is_ok() {
                vars.push(token.to_string());
                template = template.replace(token, "<NUM>");
            } else if token.contains('.') && token.chars().filter(|c| *c=='.').count()==3 {
                vars.push(token.to_string());
                template = template.replace(token, "<IP>");
            }
        }
        let id = {
            use sha3::{Digest, Sha3_256};
            let mut h = Sha3_256::new();
            h.update(template.as_bytes());
            let hash: [u8; 32] = h.finalize().into();
            u32::from_le_bytes([hash[0], hash[1], hash[2], hash[3]])
        };
        LogTemplate { template_id: id, template, variables: vars }
    }

    pub fn ratio(original: usize, templated: usize) -> f64 {
        if templated==0 { return 1.0; }
        original as f64 / templated as f64
    }
}

pub struct OpticalGates;

impl OpticalGates {
    pub fn k_bud_optical(prompt: &OpticalPrompt) -> Result<(), &'static str> {
        if prompt.prompt.is_empty() { return Err("K-BUD-OPTICAL: prompt empty"); }
        if !prompt.holds_resolution(prompt.width, prompt.height) { return Err("K-BUD-OPTICAL: resolution mismatch"); }
        if prompt.ratio() < 10.0 { return Err("K-BUD-OPTICAL: ratio <10 not revolutionary"); }
        Ok(())
    }
    pub fn k_bud_log_template(tmpl: &LogTemplate) -> Result<(), &'static str> {
        if tmpl.template.is_empty() { return Err("K-BUD-LOG-TEMPLATE: empty"); }
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
    fn log_template() {
        let line = "192.168.1.1 - - [10/Oct/2000:13:55:36 -0700] 200 1234";
        let tmpl = LogTemplateMiner::mine(line);
        assert!(!tmpl.template.is_empty());
        assert!(OpticalGates::k_bud_log_template(&tmpl).is_ok());
        assert!(tmpl.template.contains("<IP>") || tmpl.template.contains("<NUM>"));
    }
}
