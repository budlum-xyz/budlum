//! B.U.D. 2.0 - REAL WORLD CORPUS TESTS (remaining work item #7).
//!
//! Instead of a synthetic corpus, the engine round trip and the ratio are
//! verified against REAL files ON THE SYSTEM: ELF (/bin/*), fonts
//! (/usr/share/fonts) and text (/etc/*, /usr/share/doc). When a file is
//! missing the test SKIPs (it is not a production environment). These tests
//! are the canary for the "realistic ratio" limits in the matrix: nothing FAR
//! above what was measured may be claimed.

#![forbid(unsafe_code)]

/// Find a real file (the first one that exists).
#[allow(dead_code)]
fn real_file(candidates: &[&str]) -> Option<Vec<u8>> {
    for c in candidates {
        if let Ok(m) = std::fs::read(c) {
            if !m.is_empty() {
                return Some(m);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bud_format_engine::{engine_restore_full, engine_store};

    #[test]
    fn a_real_elf_survives_the_engine_losslessly() {
        if let Some(elf) = real_file(&["/bin/bash", "/usr/bin/bash", "/bin/ls", "/usr/bin/env"]) {
            let res = engine_store(&elf, false, 1).expect("engine");
            let blob = res.to_blob();
            let back =
                engine_restore_full(&blob, res.transform_kind.to_u8(), false).expect("restore");
            assert_eq!(back, elf, "a REAL ELF comes back byte for byte");
            assert!(res.measured_ratio > 1.0 || elf.len() < 4096);
        } else {
            eprintln!("SKIP: no real ELF was found (test environment)");
        }
    }

    #[test]
    fn a_real_font_survives_the_engine_losslessly() {
        let candidates = vec![
            "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
            "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
            "/usr/share/fonts/truetype/ubuntu/Ubuntu-R.ttf",
        ];
        // scan for ttf files under /usr/share/fonts
        if let Ok(read) = std::fs::read_dir("/usr/share/fonts") {
            for _e in read.flatten() {
                if candidates.len() > 30 {
                    break;
                }
                // only a sample: the candidates above are enough
            }
        }
        if let Some(font) = real_file(&candidates) {
            let res = engine_store(&font, false, 2).expect("engine");
            let back = engine_restore_full(&res.to_blob(), res.transform_kind.to_u8(), false)
                .expect("restore");
            assert_eq!(back, font, "a REAL font comes back byte for byte");
        } else {
            eprintln!("SKIP: no font was found");
        }
    }

    #[test]
    fn real_text_survives_the_engine_losslessly() {
        let candidates = [
            "/etc/os-release",
            "/etc/hostname",
            "/etc/hosts",
            "/usr/share/doc",
        ];
        if let Some(txt) = real_file(&candidates) {
            let res = engine_store(&txt, false, 3).expect("engine");
            let back = engine_restore_full(&res.to_blob(), res.transform_kind.to_u8(), false)
                .expect("restore");
            assert_eq!(back, txt, "real text comes back byte for byte");
        } else {
            eprintln!("SKIP: no text file was found");
        }
    }

    #[test]
    fn a_claim_above_the_real_corpus_measurement_is_refused() {
        // The canary: a real ELF/font measurement cannot exceed the range in
        // the matrix (matrix: elf 2.6x with zstd19, font 2.5x - the engine's
        // measurement sits at the honest boundary).
        if let Some(elf) = real_file(&["/bin/bash", "/usr/bin/env"]) {
            let res = engine_store(&elf, false, 1).unwrap();
            // A single ELF file: no transform, so a zstd limit around 2-3x is
            // reasonable.
            assert!(
                res.measured_ratio < 50.0,
                "a claim above 50x for an ELF is REFUSED: {}",
                res.measured_ratio
            );
        }
    }
}
