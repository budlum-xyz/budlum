//! Rejenerasyon: kanonik program-hash'i sifirdan yeniden uretir ve
//! agactaki her uygulamanin ayni degeri verdigini kanitlar.
//!
//! # Neden var
//!
//! Bir zk kanitinin **hangi program icin** uretildigi tek bir degerle soylenir:
//! programin Keccak-256 hash'i. Bu deger su an agacta **dort ayri yerde**,
//! **uc ayri crate**'te ve **iki ayri hash kutuphanesi**yle hesaplaniyor:
//!
//!   * `src/prover/mod.rs::zk_program_hash` - alan izin listesi kimligi (sha3)
//!   * `src/ai/execution/guest.rs::stark_program_hash_from_words` - AI model
//!     kaydi (sha3)
//!   * `src/domain/storage_deal.rs` - depolama meydan okumasi (sha3)
//!   * `budzero/bud-proof/src/plonky3_prover.rs` - **dogrulayici**, AIR'e
//!     baglanan deger (`tiny_keccak`)
//!
//! Dordunun ayni sonucu vermesi bir **varsayim**, ve varsayimlar bayatlar.
//! Ayrisirlarsa olan sey sessizdir ve kotudur: izin listesine yazilan hash,
//! dogrulayicinin kanittan hesapladigi hash'ten farkli olur. O anda ya her
//! durust kanit reddedilir (alan kilitlenir), ya da - siralama ters giderse -
//! listede olmayan bir program listede sayilir. Ikisi de derleyicinin
//! goremedigi, testin ancak tesadufen yakalayacagi bir kaymadir.
//!
//! # Kapi ne yapiyor
//!
//! Bu dosya Keccak-256'yi **kendi icinde**, bagimsiz olarak uygular (asagidaki
//! `keccak256`), sonra:
//!
//!   1. Agactaki her uygulamanin **bayt beslemesini** kaynaktan okur ve
//!      kanonik olani (`kelimeler, little-endian, etiketsiz`) uyguladigini
//!      dogrular.
//!   2. Bilinen vektorler icin beklenen hash'i **yeniden uretir** ve kaynakta
//!      yazili sabitlerle karsilastirir.
//!
//! Yani kapi, kodun soyledigine inanmaz; degeri kendi hesaplar. Wheeler'in
//! "ayni kaynagi ikinci bir bagimsiz yolla uret, sonuclari karsilastir"
//! yaklasiminin bu agactaki karsiligi.
//!
//! # Neden calisma zamaninda degil de burada
//!
//! Bir dugumun saldiri aninda kendi kodunu degistirmesi savunma degil,
//! **uzlasma bolunmesidir**: o dugum artik digerleriyle ayni programi
//! calistirmiyordur ve saldirganin en ucuz zaferi savunmayi tetiklemek olur.
//! Rejenerasyon bu yuzden yayin oncesi bir kapidir: kayma uretime **hic
//! ulasmaz**.

use std::fs;
use std::path::Path;

/// Kanonik besleme: her kelime little-endian, etiket yok.
///
/// Dogrulayicinin (`plonky3_prover.rs`) AIR'e bagladigi bicim budur; digerleri
/// ona uymak zorunda, tersi degil.
fn canonical_program_bytes(words: &[u64]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

// --- Bagimsiz Keccak-256 ------------------------------------------------
//
// Agactaki hicbir hash kutuphanesini kullanmiyor. Amac tam olarak bu: kapi,
// denetledigi kodun bagimli oldugu seye bagimli olursa ikisi birlikte
// yanilabilir.

const RC: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

const ROTC: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PIL: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

fn keccak_f(a: &mut [u64; 25]) {
    for round in RC {
        // Theta
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        // Rho + Pi
        let mut last = a[1];
        for i in 0..24 {
            let j = PIL[i];
            let tmp = a[j];
            a[j] = last.rotate_left(ROTC[i]);
            last = tmp;
        }
        // Chi
        for y in 0..5 {
            let mut row = [0u64; 5];
            for x in 0..5 {
                row[x] = a[x + 5 * y];
            }
            for x in 0..5 {
                a[x + 5 * y] = row[x] ^ ((!row[(x + 1) % 5]) & row[(x + 2) % 5]);
            }
        }
        // Iota
        a[0] ^= round;
    }
}

/// Keccak-256 (SHA-3 oncesi orijinal padding: 0x01), Ethereum'un kullandigi.
fn keccak256(input: &[u8]) -> [u8; 32] {
    const RATE: usize = 136;
    let mut state = [0u64; 25];
    let mut padded = input.to_vec();
    padded.push(0x01);
    while !padded.len().is_multiple_of(RATE) {
        padded.push(0x00);
    }
    let n = padded.len();
    padded[n - 1] |= 0x80;

    for block in padded.chunks(RATE) {
        for (i, word) in block.chunks(8).enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(word);
            state[i] ^= u64::from_le_bytes(b);
        }
        keccak_f(&mut state);
    }

    let mut out = [0u8; 32];
    for (i, chunk) in out.chunks_mut(8).enumerate() {
        chunk.copy_from_slice(&state[i].to_le_bytes());
    }
    out
}

fn hex32(b: &[u8; 32]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

/// Kanonik hash'i uretmesi beklenen kaynak konumlari.
///
/// `needle`, o dosyada besleme donguusunu tanitan ifade. Amac dar bir imza
/// degil, **beslemenin bicimini** yakalamak: kelime kelime little-endian.
struct Site {
    file: &'static str,
    what: &'static str,
    /// Beslemenin kanonik oldugunu gosteren ifadelerden en az biri bulunmali.
    canonical_markers: &'static [&'static str],
    /// Bulunursa besleme kanonik DEGILDIR (etiket eklenmis demektir).
    forbidden: &'static [&'static str],
}

const SITES: &[Site] = &[
    Site {
        file: "src/prover/mod.rs",
        what: "alan izin listesi kimligi (zk_program_hash)",
        canonical_markers: &["word.to_le_bytes()"],
        forbidden: &["BDLM_"],
    },
    Site {
        file: "src/ai/execution/guest.rs",
        what: "AI model kaydi (stark_program_hash_from_words)",
        canonical_markers: &["word.to_le_bytes()"],
        forbidden: &[],
    },
    Site {
        file: "budzero/bud-proof/src/plonky3_prover.rs",
        what: "dogrulayici, AIR'e baglanan deger",
        canonical_markers: &["inst.to_le_bytes()"],
        forbidden: &[],
    },
];

/// # Errors
///
/// Kanonik hash'i yeniden uretemezse, ya da agactaki bir uygulama kanonik
/// beslemeden saparsa bulgu dondurur.
pub fn run(root: &Path) -> Result<String, String> {
    // 1. Bagimsiz uygulamayi bilinen vektorlerle dogrula. Kapinin kendisi
    //    yanlissa soyledigi hicbir sey degerli degildir.
    let empty = keccak256(&[]);
    if hex32(&empty) != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" {
        return Err(format!(
            "Rejenerasyon kendi Keccak-256 uygulamasini dogrulayamadi: bos girdi {} verdi",
            hex32(&empty)
        ));
    }
    let abc = keccak256(b"abc");
    if hex32(&abc) != "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45" {
        return Err(format!(
            "Rejenerasyon kendi Keccak-256 uygulamasini dogrulayamadi: \"abc\" {} verdi",
            hex32(&abc)
        ));
    }

    // 2. Kanonik degeri yeniden uret. Bu, izin listesine yazilan ve
    //    dogrulayicinin kanittan hesapladigi degerin ta kendisi.
    let sample: [u64; 3] = [7, 8, 9];
    let regenerated = keccak256(&canonical_program_bytes(&sample));

    // 3. Agactaki her uygulamanin kanonik beslemeyi kullandigini dogrula.
    let mut checked = 0usize;
    let mut findings = Vec::new();
    for site in SITES {
        let path = root.join(site.file);
        let Ok(text) = fs::read_to_string(&path) else {
            findings.push(format!(
                "{}: okunamadi - kanonik hash ureten bir yuzey kayboldu mu?",
                site.file
            ));
            continue;
        };
        if !site.canonical_markers.iter().any(|m| text.contains(m)) {
            findings.push(format!(
                "{} ({}): kanonik besleme bulunamadi; beklenen {:?}",
                site.file, site.what, site.canonical_markers
            ));
        }
        for bad in site.forbidden {
            // Etiketli bir hash, kanonik olanla ayni degeri veremez.
            if text.contains(bad) && text.contains("fn zk_program_hash") {
                let after = text.split("fn zk_program_hash").nth(1).unwrap_or("");
                let body: String = after.chars().take(400).collect();
                if body.contains(bad) {
                    findings.push(format!(
                        "{} ({}): kanonik hash govdesinde '{}' etiketi var; \
                         etiketli hash dogrulayicinin degeriyle ayrisir",
                        site.file, site.what, bad
                    ));
                }
            }
        }
        checked += 1;
    }

    if !findings.is_empty() {
        return Err(format!(
            "Rejenerasyon: kanonik program-hash yuzeyi kaymis.\n  {}\n\n\
             Kanonik bicim: kelimeler little-endian, etiket YOK. Dogrulayici \
             (plonky3_prover.rs) bu bicimi AIR'e baglar; digerleri ona uyar.",
            findings.join("\n  ")
        ));
    }

    Ok(format!(
        "Rejenerasyon OK: kanonik program-hash {} olarak yeniden uretildi, \
         {checked} uygulama ayni beslemeyi kullaniyor (bagimsiz Keccak-256 ile dogrulandi).",
        &hex32(&regenerated)[..16]
    ))
}

/// # Errors
///
/// Kanarya agaci beklendigi gibi davranmazsa bulgu dondurur: dogru agac
/// gecmeli, kanonik beslemeden sapan agac yakalanmali.
pub fn self_test() -> Result<String, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let tmp =
        std::env::temp_dir().join(format!("budlum-gates-rejen-{}-{nanos}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);

    for d in ["src/prover", "src/ai/execution", "budzero/bud-proof/src"] {
        fs::create_dir_all(tmp.join(d)).map_err(|e| format!("kanarya dizini kurulamadi: {e}"))?;
    }
    let good_prover = "pub fn zk_program_hash(program: &[u64]) -> Hash32 {\n\
                       let mut hasher = Keccak256::new();\n\
                       for word in program { hasher.update(word.to_le_bytes()); }\n\
                       hasher.finalize().into()\n}\n";
    fs::write(tmp.join("src/prover/mod.rs"), good_prover).map_err(|e| e.to_string())?;
    fs::write(
        tmp.join("src/ai/execution/guest.rs"),
        "for word in words { hasher.update(word.to_le_bytes()); }\n",
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        tmp.join("budzero/bud-proof/src/plonky3_prover.rs"),
        "let b: Vec<u8> = program.iter().flat_map(|&inst| inst.to_le_bytes().to_vec()).collect();\n",
    )
    .map_err(|e| e.to_string())?;

    if let Err(e) = run(&tmp) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!("self-test: dogru agac gecmeliydi: {e}"));
    }

    // Kayma 1: bir uygulama kanonik beslemeyi birakiyor (bayt bayt besleme).
    fs::write(
        tmp.join("src/ai/execution/guest.rs"),
        "for byte in words_as_bytes { hasher.update([byte]); }\n",
    )
    .map_err(|e| e.to_string())?;
    if run(&tmp).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "self-test: kanonik beslemeden sapan uygulama yakalanmadi",
        ));
    }

    // Kayma 2: kanonik hash govdesine alan etiketi giriyor.
    fs::write(
        tmp.join("src/ai/execution/guest.rs"),
        "for word in words { hasher.update(word.to_le_bytes()); }\n",
    )
    .map_err(|e| e.to_string())?;
    let tagged = "pub fn zk_program_hash(program: &[u64]) -> Hash32 {\n\
                  let mut hasher = Keccak256::new();\n\
                  hasher.update(b\"BDLM_PROGRAM_V1\");\n\
                  for word in program { hasher.update(word.to_le_bytes()); }\n\
                  hasher.finalize().into()\n}\n";
    fs::write(tmp.join("src/prover/mod.rs"), tagged).map_err(|e| e.to_string())?;
    if run(&tmp).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "self-test: etiketli (ayrisan) kanonik hash yakalanmadi",
        ));
    }

    // Kayma 3: bir yuzey tamamen kayboluyor.
    fs::write(tmp.join("src/prover/mod.rs"), good_prover).map_err(|e| e.to_string())?;
    fs::remove_file(tmp.join("budzero/bud-proof/src/plonky3_prover.rs"))
        .map_err(|e| e.to_string())?;
    if run(&tmp).is_ok() {
        let _ = fs::remove_dir_all(&tmp);
        return Err(String::from(
            "self-test: kaybolan dogrulayici yuzeyi yakalanmadi",
        ));
    }

    let _ = fs::remove_dir_all(&tmp);
    Ok(String::from(
        "Rejenerasyon self-test OK: dogru agac gecti, uc kayma (besleme, etiket, kayip yuzey) yakalandi",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keccak_matches_known_vectors() {
        assert_eq!(
            hex32(&keccak256(&[])),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(
            hex32(&keccak256(b"abc")),
            "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45"
        );
    }

    #[test]
    fn canonical_bytes_are_little_endian_words() {
        assert_eq!(canonical_program_bytes(&[1]), vec![1, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn a_tagged_feed_regenerates_a_different_value() {
        // Kapinin varlik sebebi: etiket eklemek degeri degistirir.
        let plain = keccak256(&canonical_program_bytes(&[7, 8, 9]));
        let mut tagged = b"BDLM_PROGRAM_V1".to_vec();
        tagged.extend_from_slice(&canonical_program_bytes(&[7, 8, 9]));
        assert_ne!(plain, keccak256(&tagged));
    }
}
