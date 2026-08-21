//! `BudZero` ZKVM fuzz tohum korpusu ureteci.
//!
//! `scripts/generate_zkvm_seed_corpus.sh` yerine gecer.
//!
//! # Shell surumunun sessiz hatasi
//!
//! Betik tohumlari `printf "\x01\x01..."` ile yaziyordu. `printf`'in kacis
//! dizisi yorumu **kabuga ve yapiya gore degisir**: bash'in yerlesik
//! `printf`'i `\x` anlar, `/usr/bin/printf` (coreutils) `\x`'i anlar ama
//! dash'in yerlesigi anlamaz ve dizgiyi harfi harfine yazar. Yani ayni
//! betik `bash` ile calistiginda 8 baytlik bir ikili dosya, `sh` ile
//! calistiginda 32 baytlik bir metin dosyasi uretiyordu ve **ikisi de
//! sessizce basariliydi**.
//!
//! Rust'ta tohum bir `&[u8]` sabiti; yorumlanacak bir kacis dizisi yok.
//!
//! Ayrica betigin son satiri `ls -1 "$OUT_DIR"/*.bud | wc -l` ile sayiyordu;
//! bu, dizin bos oldugunda glob'un genislememesi yuzunden `ls: no such
//! file` yazip **1** sayardi. Burada sayim yazilan dosyalarin kendisinden
//! geliyor.

use std::path::{Path, PathBuf};

/// Bir tohum: dosya adi ve tam ikili icerigi.
struct Seed {
    name: &'static str,
    what: &'static str,
    bytes: &'static [u8],
}

/// Bes tohum. Opcode degerleri `bud-isa` ile ayni olmali; bir opcode
/// degisirse buradaki tohum bayatlar ama fuzz'i bozmaz (fuzzer gecersiz
/// programi da besler), o yuzden bu bir kapi degil bir kolaylik.
const SEEDS: &[Seed] = &[
    Seed {
        name: "01_simple_add.bud",
        what: "Add (0x01) + Halt (0x00)",
        bytes: &[0x01, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00],
    },
    Seed {
        name: "02_branch_loop.bud",
        what: "Jmp (0x0A) ile dallanma dongusu",
        bytes: &[
            0x0a, 0x01, 0x02, 0x03, 0x05, 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ],
    },
    Seed {
        name: "03_verify_merkle_0x1E.bud",
        what: "VerifyMerkle (0x1E) yol dogrulamasi",
        bytes: &[0x1e, 0x01, 0x02, 0x03, 0x00, 0x01, 0x00, 0x00],
    },
    Seed {
        name: "04_poseidon_hash.bud",
        what: "Poseidon (0x1D) hash turu",
        bytes: &[0x1d, 0x01, 0x02, 0x03, 0x0a, 0x00, 0x00, 0x00],
    },
    Seed {
        name: "05_memory_ops.bud",
        what: "SRead (0x10) + SWrite (0x11)",
        bytes: &[0x10, 0x01, 0x02, 0x00, 0x11, 0x01, 0x02, 0x00],
    },
];

/// Tohumlari `out_dir` icine yaz.
///
/// # Errors
///
/// Dizin olusturulamazsa ya da bir dosya yazilamazsa.
pub fn generate(out_dir: &Path) -> Result<String, String> {
    std::fs::create_dir_all(out_dir)
        .map_err(|e| format!("{} olusturulamadi: {e}", out_dir.display()))?;

    let mut written: Vec<String> = Vec::with_capacity(SEEDS.len());
    let mut total_bytes = 0usize;
    for seed in SEEDS {
        let path = out_dir.join(seed.name);
        std::fs::write(&path, seed.bytes)
            .map_err(|e| format!("{} yazilamadi: {e}", path.display()))?;

        // Yazdiktan sonra geri oku. Bu bir titizlik degil: shell surumunun
        // hatasi tam olarak "yazdim sandi, baska sey yazdi" idi ve kimse
        // bakmadi.
        let back =
            std::fs::read(&path).map_err(|e| format!("{} okunamadi: {e}", path.display()))?;
        if back != seed.bytes {
            return Err(format!(
                "{}: {} bayt yazildi, {} bayt geri okundu",
                path.display(),
                seed.bytes.len(),
                back.len()
            ));
        }
        total_bytes += seed.bytes.len();
        written.push(format!("  [+] {} ({})", path.display(), seed.what));
    }

    Ok(format!(
        "BudZero ZKVM tohum korpusu: {} dosya, {} bayt -> {}\n{}",
        written.len(),
        total_bytes,
        out_dir.display(),
        written.join("\n")
    ))
}

/// Varsayilan cikti dizini: `<kok>/fuzz/corpus/zkvm`.
#[must_use]
pub fn default_out_dir(root: &Path) -> PathBuf {
    root.join("fuzz").join("corpus").join("zkvm")
}

/// Kanarya: uretecin gercekten ikili yazdigini kanitlar.
///
/// Shell surumunun hatasi ikili yerine metin yazmakti ve bu disaridan
/// gorunmuyordu. Burada tohumlarin ikili oldugu (yazdirilabilir ASCII
/// olmadigi) ve geri okundugunda birebir esit oldugu dogrulanir.
///
/// # Errors
///
/// Uretim basarisiz olursa ya da yazilan tohum metne benziyorsa.
pub fn self_test() -> Result<String, String> {
    let tmp = std::env::temp_dir().join(format!("budlum-seed-selftest-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    generate(&tmp)?;

    for seed in SEEDS {
        let path = tmp.join(seed.name);
        let bytes =
            std::fs::read(&path).map_err(|e| format!("{} okunamadi: {e}", path.display()))?;
        if bytes != seed.bytes {
            return Err(format!("{}: geri okuma esit degil", seed.name));
        }
        // Shell'in `\x01`'i harfi harfine yazdigi durumda dosya tamamen
        // yazdirilabilir ASCII olurdu. En az bir kontrol baytı bekliyoruz.
        if !bytes.iter().any(|b| *b < 0x20) {
            return Err(format!(
                "{}: hicbir kontrol bayti yok, bu bir metin dosyasi; \
                 shell surumunun `printf \\x` hatasi geri gelmis olabilir",
                seed.name
            ));
        }
    }

    let count = std::fs::read_dir(&tmp)
        .map_err(|e| format!("{} listelenemedi: {e}", tmp.display()))?
        .count();
    let _ = std::fs::remove_dir_all(&tmp);

    if count != SEEDS.len() {
        return Err(format!(
            "{} tohum bekleniyordu, {count} bulundu",
            SEEDS.len()
        ));
    }
    Ok(format!(
        "tohum korpusu kanaryasi OK: {count} dosya ikili yazildi ve geri okundu"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_seed_is_binary_not_text() {
        for seed in SEEDS {
            assert!(
                seed.bytes.iter().any(|b| *b < 0x20),
                "{} yazdirilabilir ASCII; shell'in printf hatasi",
                seed.name
            );
        }
    }

    #[test]
    fn seed_names_are_unique() {
        let mut names: Vec<&str> = SEEDS.iter().map(|s| s.name).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "tohum adlari benzersiz olmali");
    }

    #[test]
    fn generate_writes_exactly_the_declared_bytes() {
        let tmp = std::env::temp_dir().join("budlum-seed-unit-test");
        let _ = std::fs::remove_dir_all(&tmp);
        generate(&tmp).expect("uretim basarili olmali");
        for seed in SEEDS {
            let got = std::fs::read(tmp.join(seed.name)).expect("tohum okunmali");
            assert_eq!(got, seed.bytes, "{}", seed.name);
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn self_test_passes_on_a_clean_run() {
        let msg = self_test().expect("kanarya gecmeli");
        assert!(msg.contains("OK"), "{msg}");
    }

    #[test]
    fn default_out_dir_is_under_fuzz_corpus() {
        let d = default_out_dir(Path::new("/repo"));
        assert!(d.ends_with("fuzz/corpus/zkvm"), "{}", d.display());
    }
}
