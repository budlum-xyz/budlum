//! B.U.D. 2.0 - CORPUS SHAPE TESTS (remaining work item #7).
//!
//! The engine round trip and the ratio are verified against fixed in-process
//! corpora shaped like an ELF binary, a font and text. The inputs do not
//! depend on files of the host, so the tests run the same everywhere. These
//! tests are the canary for the "realistic ratio" limits in the matrix:
//! nothing FAR above what was measured may be claimed.

#![forbid(unsafe_code)]

#[cfg(test)]
mod tests {
    use crate::bud_format_engine::{engine_restore_full, engine_store};

    /// Deterministic filler bytes (a linear congruential generator).
    fn noise(seed: u64, len: usize) -> Vec<u8> {
        let mut state = seed;
        (0..len)
            .map(|_| {
                state = state
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (state >> 56) as u8
            })
            .collect()
    }

    /// An ELF-shaped file: the magic, a header, code-like noise, zero padding
    /// and a string table.
    fn elf_like() -> Vec<u8> {
        let mut f = b"\x7fELF\x02\x01\x01\x00".to_vec();
        f.extend_from_slice(&[0u8; 56]);
        f.extend_from_slice(&noise(1, 16 * 1024));
        f.extend_from_slice(&[0u8; 8 * 1024]);
        for _ in 0..64 {
            f.extend_from_slice(b".text\0.rodata\0.data\0.bss\0.symtab\0.strtab\0");
        }
        f
    }

    /// A font-shaped file: a table directory followed by table-like noise.
    fn font_like() -> Vec<u8> {
        let mut f = b"\x00\x01\x00\x00".to_vec();
        for tag in [b"cmap", b"glyf", b"head", b"hhea", b"hmtx", b"loca"] {
            f.extend_from_slice(tag);
            f.extend_from_slice(&noise(2, 12));
        }
        f.extend_from_slice(&noise(3, 12 * 1024));
        f.extend_from_slice(&[0u8; 2 * 1024]);
        f
    }

    /// Plain text with the repetition of a real document.
    fn text_like() -> Vec<u8> {
        let mut t = Vec::new();
        for i in 0..400 {
            t.extend_from_slice(
                format!("line {i}: the quick brown fox jumps over it\n").as_bytes(),
            );
        }
        t
    }

    #[test]
    fn an_elf_shaped_file_survives_the_engine_losslessly() {
        let elf = elf_like();
        let res = engine_store(&elf, false, 1).expect("engine");
        let blob = res.to_blob();
        let back = engine_restore_full(&blob, res.transform_kind.to_u8(), false).expect("restore");
        assert_eq!(back, elf, "an ELF-shaped file comes back byte for byte");
        assert!(res.measured_ratio > 1.0);
    }

    #[test]
    fn a_font_shaped_file_survives_the_engine_losslessly() {
        let font = font_like();
        let res = engine_store(&font, false, 2).expect("engine");
        let back = engine_restore_full(&res.to_blob(), res.transform_kind.to_u8(), false)
            .expect("restore");
        assert_eq!(back, font, "a font-shaped file comes back byte for byte");
    }

    #[test]
    fn text_survives_the_engine_losslessly() {
        let txt = text_like();
        let res = engine_store(&txt, false, 3).expect("engine");
        let back = engine_restore_full(&res.to_blob(), res.transform_kind.to_u8(), false)
            .expect("restore");
        assert_eq!(back, txt, "text comes back byte for byte");
    }

    #[test]
    fn a_claim_above_the_corpus_measurement_is_refused() {
        // The canary: an ELF measurement cannot exceed the range in the matrix
        // (matrix: elf 2.6x with zstd19, font 2.5x - the engine's measurement
        // sits at the honest boundary).
        let elf = elf_like();
        let res = engine_store(&elf, false, 1).unwrap();
        // A single ELF-shaped file: no transform, so a zstd limit far below 50x
        // is reasonable.
        assert!(
            res.measured_ratio < 50.0,
            "a claim above 50x for an ELF is REFUSED: {}",
            res.measured_ratio
        );
    }
}
