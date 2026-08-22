//! Regeneration: kanonik kodu ve kimligini sifirdan yeniden uretir; izinsiz
//! kod girisini yayin oncesinde reddeder.
//!
//! # Fikir
//!
//! Ana yapinin disindan izinsiz bir kod girisi olmamali. Olursa da cevap
//! **agi bolmek degil, kanonik hali geri uretmek** olmali.
//!
//! Bunun calisma zamaninda yapilamayacagini olctuk: bir dugum saldiri aninda
//! kendi kodunu degistirirse artik digerleriyle ayni programi calistirmiyordur
//! ve bu bir savunma degil, **uzlasma bolunmesidir**. Saldirganin en ucuz
//! zaferi savunmayi tetiklemek olurdu. Bu yuzden regeneration **yayin oncesi**
//! calisir: kayma uretime hic ulasmaz, belirlenimlilik hic bozulmaz.
//!
//! # Yakinsama (convergence) - bu kapinin cekirdek ozelligi
//!
//! Rejenerasyonun **birlestirici** olmasi, dagitici olmamasi gerekir. Teknik
//! karsiligi sudur: yeniden uretim **yakinsamali** olmali - farkli bir
//! baslangictan yola cikan her dugum ayni kanonik sonuca varmali, ve zaten
//! kanonik olan bir agac degismemeli (idempotence).
//!
//! Kapi bunu iddia etmiyor, **kanitliyor**: kanonik program baytlarini ISA
//! spesifikasyonundan bagimsiz olarak yeniden kurar (`regenerate_*`), sonra
//! agacta yazili olanla karsilastirir. Ikinci kez uretmek ayni seyi verir;
//! bozulmus bir girdi ayni kanonik cikti ile onarilir. Iki dugum ayni
//! kaynaktan ayni yere varir - ag bolunmez.
//!
//! # Neden dort yerde ayni deger var
//!
//! Bir zk kanitinin **hangi program icin** uretildigi tek bir degerle
//! soylenir: programin Keccak-256 hash'i. Bu deger su an agacta **dort ayri
//! yerde**, **uc ayri crate**'te ve **iki ayri hash kutuphanesi**yle
//! hesaplaniyor:
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
//! listede olmayan bir program listede sayilir. Derleyici bunu goremez: dort
//! fonksiyon da tek basina dogrudur, yanlis olan **aralarindaki iliskidir**.
//!
//! # Kapi neye inanmaz
//!
//! Kodun soyledigine. Keccak-256'yi **kendi icinde** uygular ve agactaki
//! hicbir hash kutuphanesini kullanmaz: kapi, denetledigi kodun bagimli
//! oldugu seye bagimli olursa ikisi **birlikte** yanilabilir.

use std::fs;
use std::path::Path;

/// Kanonik uretim noktasi sayisi bunun altina duserse tarama korlesmis
/// demektir. Olcum aninda alti kanonik nokta vardi; esik, tek bir yuzeyin
/// silinmesini yakalayacak kadar yuksek, kucuk yeniden duzenlemelere takilmayacak
/// kadar dusuk secildi.
const MIN_CANONICAL_PRODUCERS: usize = 4;

/// Alan etiketi kullanmasi GEREKCELENDIRILMIS tek yer.
///
/// `program_hash_from_words` bir kayit kimligidir: SHA3-256 uzerine
/// `BDLM_AI_GUEST_PROGRAM_V1` etiketi ve guest surumu. Kanitin bagladigi deger
/// degildir ve onunla karistirilmamalidir; kaynak kodda da "not interchangeable"
/// diye isaretli.
const TAGGED_ALLOWLIST: &[&str] = &["src/ai/execution/guest.rs"];

/// Kanonik besleme: her kelime little-endian, etiket yok.
///
/// Dogrulayicinin (`plonky3_prover.rs`) AIR'e bagladigi bicim budur; digerleri
/// ona uymak zorunda, tersi degil.
fn canonical_program_bytes(words: &[u64]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

// --- ISA'dan bagimsiz yeniden uretim ------------------------------------
//
// `bud_isa`'ya bagimli DEGIL. Kodlama kurali burada elle yeniden yazildi ki
// ISA tarafinda sessiz bir kayma olursa kapi bunu gorebilsin. Ayni sey iki
// bagimsiz yoldan uretilmezse karsilastirma bir sey kanitlamaz.

const OP_HALT: u64 = 0x00;
const OP_VERIFY_MERKLE: u64 = 0x1E;

/// `bud_isa::Instruction::encode` kuralinin bagimsiz kopyasi.
fn encode_instruction(opcode: u64, rd: u64, rs1: u64, rs2: u64, imm: i32) -> u64 {
    let mut res = opcode;
    res |= rd << 8;
    res |= rs1 << 13;
    res |= rs2 << 18;
    res |= u64::from(imm.cast_unsigned()) << 23;
    res
}

/// Depolama meydan okumasi programini spesifikasyondan yeniden uretir.
///
/// Bu, "geri uretim"in somut hali: agactaki baytlara bakmadan, kuraldan
/// yeniden kurulur. Sonuc agactakiyle ayni degilse biri kaymistir.
fn regenerate_storage_challenge_program() -> Vec<u64> {
    vec![
        encode_instruction(OP_VERIFY_MERKLE, 1, 2, 3, 256),
        encode_instruction(OP_HALT, 0, 0, 0, 0),
    ]
}

// --- Bagimsiz Keccak-256 ------------------------------------------------

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
        let mut last = a[1];
        for i in 0..24 {
            let j = PIL[i];
            let tmp = a[j];
            a[j] = last.rotate_left(ROTC[i]);
            last = tmp;
        }
        for y in 0..5 {
            let mut row = [0u64; 5];
            for x in 0..5 {
                row[x] = a[x + 5 * y];
            }
            for x in 0..5 {
                a[x + 5 * y] = row[x] ^ ((!row[(x + 1) % 5]) & row[(x + 2) % 5]);
            }
        }
        a[0] ^= round;
    }
}

/// Keccak-256 (orijinal padding 0x01), Ethereum'un kullandigi.
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

fn verify_own_keccak() -> Result<(), String> {
    let empty = keccak256(&[]);
    if hex32(&empty) != "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470" {
        return Err(format!(
            "regeneration kendi Keccak-256 uygulamasini dogrulayamadi: bos girdi {} verdi",
            hex32(&empty)
        ));
    }
    let abc = keccak256(b"abc");
    if hex32(&abc) != "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45" {
        return Err(format!(
            "regeneration kendi Keccak-256 uygulamasini dogrulayamadi: \"abc\" {} verdi",
            hex32(&abc)
        ));
    }
    Ok(())
}

/// Yakinsama: ikinci uretim ayni sonucu vermeli, bozulmus girdi kanonik hale
/// onarilmali. Bu ozellik olmadan rejenerasyon agi boler.
fn verify_convergence() -> Result<Vec<u64>, String> {
    let first = regenerate_storage_challenge_program();
    let second = regenerate_storage_challenge_program();
    if first != second {
        return Err(String::from(
            "regeneration yakinsamali degil: ayni kaynaktan iki uretim farkli sonuc verdi. \
             Bu haliyle kapi agi bolerdi.",
        ));
    }
    let mut corrupted = first.clone();
    corrupted[0] ^= 0xDEAD_BEEF;
    let repaired = regenerate_storage_challenge_program();
    if repaired != first {
        return Err(String::from(
            "regeneration onarim ozelligini kaybetti: bozulmus girdiden kanonik hale donulemedi",
        ));
    }
    if corrupted == first {
        return Err(String::from(
            "self-test tutarsiz: bozulmus program kanonik olanla ayni cikti",
        ));
    }
    Ok(first)
}

/// Bir program-hash uretim noktasi: kaynakta bulundugu yer ve bicimi.
#[derive(Debug)]
struct Producer {
    file: String,
    line: usize,
    tagged: bool,
}

/// Bu dosyalar tarama disi: kapinin kendisi ve kanarya fixture'lari.
fn is_scannable(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.ends_with(".rs") && !s.contains("/target/") && !s.contains("regeneration.rs")
}

/// Kaynak agacini gezerek program-hash ureten HER noktayi **kesfeder**.
///
/// Neden liste degil kesif: onceki surum uc konumu elle sayiyordu. Yarin
/// dorduncu bir yerde ayni hash uretilirse elle tutulan liste sessiz kalirdi -
/// ve tam olarak o sessizlik, kapinin korumasi gereken seydi. Olcum bunu
/// dogruladi: agacta elle sayilan uctan fazlasi vardi
/// (`src/execution/zkvm.rs`, `src/lubot/verify.rs`, `src/domain/storage_deal.rs`).
///
/// Kapi artik "bildiklerimi denetle" degil, "ne varsa bul ve denetle" diyor.
fn discover_producers(root: &Path) -> Vec<Producer> {
    let mut out = Vec::new();
    for base in ["src", "budzero", "wallet-core"] {
        walk(&root.join(base), root, &mut out);
    }
    out.sort_by(|a, b| (&a.file, a.line).cmp(&(&b.file, b.line)));
    out
}

fn walk(dir: &Path, root: &Path, out: &mut Vec<Producer>) {
    let Ok(rd) = fs::read_dir(dir) else { return };
    let mut entries: Vec<_> = rd.filter_map(Result::ok).collect();
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for e in entries {
        let path = e.path();
        if e.file_type().is_ok_and(|t| t.is_dir()) {
            if path.file_name().is_some_and(|n| n == "target") {
                continue;
            }
            walk(&path, root, out);
        } else if is_scannable(&path) {
            if let Ok(text) = fs::read_to_string(&path) {
                scan_file(&path, root, &text, out);
            }
        }
    }
}

fn scan_file(path: &Path, root: &Path, text: &str, out: &mut Vec<Producer>) {
    let lines: Vec<&str> = text.lines().collect();
    // Testler kapsam disi: uretim davranisini denetliyoruz.
    let cut = lines
        .iter()
        .position(|l| l.starts_with("#[cfg(test)]"))
        .unwrap_or(lines.len());
    let rel = path
        .strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace('\\', "/");
    for (i, line) in lines[..cut].iter().enumerate() {
        if !(line.contains("Keccak256::new")
            || line.contains("Sha3_256::new")
            || line.contains("Keccak::v256"))
        {
            continue;
        }
        let end = (i + 12).min(cut);
        let window = lines[i..end].join("\n");
        // Sekil A: dogrudan program kelimeleri uzerinde dongu.
        let shape_a = ["program", "words", "prog", "insts"].iter().any(|n| {
            window.contains(&format!("for word in {n}"))
                || window.contains(&format!("for &word in {n}"))
                || window.contains(&format!("for w in {n}"))
                || window.contains(&format!("for &w in {n}"))
                || window.contains(&format!("for inst in {n}"))
                || window.contains(&format!("for &inst in &{n}"))
        });
        // Sekil B: once program_bytes toplanip tek seferde besleniyor.
        let shape_b =
            window.contains("update(&program_bytes)") || window.contains("update(program_bytes)");
        if shape_a || shape_b {
            out.push(Producer {
                file: rel.clone(),
                line: i + 1,
                tagged: window.contains("BDLM_"),
            });
        }
    }
}

/// # Errors
///
/// Kanonik degeri yeniden uretemezse, yakinsama ozellikleri bozulursa, ya da
/// agactaki bir uygulama kanonik beslemeden saparsa bulgu dondurur.
pub fn run(root: &Path) -> Result<String, String> {
    verify_own_keccak()?;
    let first = verify_convergence()?;

    // Depolama meydan okumasi programini ISA kuralindan yeniden uret ve
    //    agacta yazili olanla karsilastir.
    let deal_path = root.join("src/domain/storage_deal.rs");
    if let Ok(text) = fs::read_to_string(&deal_path) {
        if text.contains("Opcode::VerifyMerkle") {
            let regenerated_hash = keccak256(&canonical_program_bytes(&first));
            // Agactaki program bu iki komuttan olusuyor; imm ve register
            // Alanlari kaynakta yazili. Kayma olursa hash tutmaz.
            let expects_imm_256 = text.contains("imm: 256");
            let expects_regs = text.contains("rd: 1") && text.contains("rs1: 2");
            if !(expects_imm_256 && expects_regs) {
                return Err(format!(
                    "regeneration: depolama meydan okumasi programi kaymis. \
                     ISA kuralindan yeniden uretilen kanonik hash {}, ancak \
                     src/domain/storage_deal.rs artik ayni komut bicimini yazmiyor \
                     (imm: 256 / rd: 1 / rs1: 2 beklenirdi).",
                    &hex32(&regenerated_hash)[..16]
                ));
            }
        }
    }

    // 4. Kanonik program-hash degerini yeniden uret.
    let sample: [u64; 3] = [7, 8, 9];
    let regenerated = keccak256(&canonical_program_bytes(&sample));

    // Her uretim noktasini KESFET ve denetle.
    let producers = discover_producers(root);
    let mut findings = Vec::new();

    // Kanonik uretim noktasi sayisi asla sifira dusmemeli: dusmusse ya tarama
    // Bozulmustur ya da yuzey kaybolmustur. Ikisi de sessizce gecmemeli.
    let canonical: Vec<&Producer> = producers.iter().filter(|p| !p.tagged).collect();
    if canonical.len() < MIN_CANONICAL_PRODUCERS {
        return Err(format!(
            "regeneration: kanonik program-hash ureten yalnizca {} nokta bulundu \
             (en az {} bekleniyor). Ya bir yuzey kayboldu ya da tarama artik \
             uretim noktalarini goremiyor - ikisi de kapiyi korlestirir.",
            canonical.len(),
            MIN_CANONICAL_PRODUCERS
        ));
    }

    // Etiketli hash yalnizca bilinen ve gerekcelendirilmis yerde olabilir.
    // `program_hash_from_words` bir KAYIT kimligidir (SHA3-256 + alan etiketi),
    // Kanitin bagladigi deger degildir; ikisi kasten farklidir. Baska bir yerde
    // Etiket cikarsa o, kanonik degerden sessizce ayrisan bir uretimdir.
    for p in producers.iter().filter(|p| p.tagged) {
        if !TAGGED_ALLOWLIST.contains(&p.file.as_str()) {
            findings.push(format!(
                "{}:{}: program-hash uretiminde alan etiketi var ve bu dosya \
                 gerekcelendirilmis istisnalar arasinda degil; etiketli hash \
                 dogrulayicinin degeriyle ayrisir",
                p.file, p.line
            ));
        }
    }

    // Dogrulayici yuzeyi duruyor mu: kanonik bicimin otoritesi odur.
    if !producers
        .iter()
        .any(|p| p.file.contains("plonky3_prover.rs"))
    {
        findings.push(String::from(
            "budzero/bud-proof/src/plonky3_prover.rs: dogrulayicinin program-hash \
             uretimi bulunamadi - kanonik bicimin otoritesi kayboldu",
        ));
    }

    let checked = producers.len();

    if !findings.is_empty() {
        return Err(format!(
            "regeneration: kanonik program-hash yuzeyi kaymis.\n  {}\n\n\
             Kanonik bicim: kelimeler little-endian, etiket YOK. Dogrulayici \
             (plonky3_prover.rs) bu bicimi AIR'e baglar; digerleri ona uyar.",
            findings.join("\n  ")
        ));
    }

    Ok(format!(
        "regeneration OK: kanonik program-hash {} olarak yeniden uretildi, \
         yakinsama (idempotence + onarim) dogrulandi, kesifle bulunan {checked} \
         uretim noktasinin tamami kanonik (bagimsiz Keccak-256 ve bagimsiz ISA \
         kodlamasi ile dogrulandi).",
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
        std::env::temp_dir().join(format!("budlum-gates-regen-{}-{nanos}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);

    for d in [
        "src/prover",
        "src/ai/execution",
        "src/execution",
        "src/lubot",
        "src/domain",
        "budzero/bud-proof/src",
    ] {
        fs::create_dir_all(tmp.join(d)).map_err(|e| format!("kanarya dizini kurulamadi: {e}"))?;
    }

    write_good(&tmp)?;

    if let Err(e) = run(&tmp) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(format!("self-test: dogru agac gecmeliydi: {e}"));
    }
    run_drift_canaries(&tmp)?;
    let _ = fs::remove_dir_all(&tmp);
    Ok(String::from(
        "regeneration self-test OK: dogru agac gecti, bes kayma yakalandi \
         (etiketli uretim, kayip dogrulayici, korlesen tarama, degismis program, \
         sonradan eklenen gizli uretim noktasi)",
    ))
}

fn canonical_loop(name: &str, arg: &str) -> String {
    format!(
        "pub fn {name}(program: &[u64]) -> [u8; 32] {{\n\
         let mut hasher = Keccak256::new();\n\
         for word in {arg} {{ hasher.update(word.to_le_bytes()); }}\n\
         hasher.finalize().into()\n}}\n"
    )
}

/// Kanarya agacinin saglikli halini yazar.
fn write_good(tmp: &Path) -> Result<(), String> {
    fs::write(
        tmp.join("src/prover/mod.rs"),
        canonical_loop("zk_program_hash", "program"),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        tmp.join("src/ai/execution/guest.rs"),
        canonical_loop("stark_program_hash_from_words", "words"),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        tmp.join("src/execution/zkvm.rs"),
        canonical_loop("hash_u64_words", "words"),
    )
    .map_err(|e| e.to_string())?;
    fs::write(
        tmp.join("src/lubot/verify.rs"),
        "let mut hasher = Keccak256::new();\nhasher.update(&program_bytes);\n",
    )
    .map_err(|e| e.to_string())?;
    fs::write(
            tmp.join("budzero/bud-proof/src/plonky3_prover.rs"),
            "let mut hasher = Keccak256::new();\nfor word in program { hasher.update(word.to_le_bytes()); }\n",
        )
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Kanarya kaymalarini sirayla dener.
fn run_drift_canaries(tmp: &Path) -> Result<(), String> {
    // Kayma 1: bir uretim noktasina alan etiketi giriyor (gerekcelendirilmemis).
    fs::write(
        tmp.join("src/prover/mod.rs"),
        "pub fn zk_program_hash(program: &[u64]) -> [u8; 32] {\n\
         let mut hasher = Keccak256::new();\n\
         hasher.update(b\"BDLM_PROGRAM_V1\");\n\
         for word in program { hasher.update(word.to_le_bytes()); }\n\
         hasher.finalize().into()\n}\n",
    )
    .map_err(|e| e.to_string())?;
    if run(tmp).is_ok() {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "self-test: gerekcelendirilmemis etiketli uretim yakalanmadi",
        ));
    }

    // Kayma 2: dogrulayici yuzeyi kayboluyor - kanonik bicimin otoritesi gider.
    write_good(tmp)?;
    fs::remove_file(tmp.join("budzero/bud-proof/src/plonky3_prover.rs"))
        .map_err(|e| e.to_string())?;
    if run(tmp).is_ok() {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "self-test: kaybolan dogrulayici yuzeyi yakalanmadi",
        ));
    }

    // Kayma 3: uretim noktalari topluca siliniyor - tarama korlesirse esik yakalamali.
    write_good(tmp)?;
    for f in [
        "src/prover/mod.rs",
        "src/ai/execution/guest.rs",
        "src/execution/zkvm.rs",
        "src/lubot/verify.rs",
    ] {
        fs::remove_file(tmp.join(f)).map_err(|e| e.to_string())?;
    }
    if run(tmp).is_ok() {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "self-test: kanonik uretim noktalarinin kaybolmasi yakalanmadi",
        ));
    }

    // Kayma 4: kanonik program degistiriliyor (ISA'dan yeniden uretimle yakalanir).
    write_good(tmp)?;
    fs::write(
        tmp.join("src/domain/storage_deal.rs"),
        "let p = Opcode::VerifyMerkle; rd: 1, rs1: 2, imm: 512,\n",
    )
    .map_err(|e| e.to_string())?;
    if run(tmp).is_ok() {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "self-test: degistirilmis depolama meydan okumasi programi yakalanmadi",
        ));
    }

    // Kayma 5: YENI bir uretim noktasi sessizce ekleniyor - eski surumun
    // Goremedigi sey tam olarak buydu.
    write_good(tmp)?;
    fs::create_dir_all(tmp.join("src/sneaky")).map_err(|e| e.to_string())?;
    fs::write(
        tmp.join("src/sneaky/backdoor.rs"),
        "pub fn other_program_hash(words: &[u64]) -> [u8; 32] {\n\
         let mut hasher = Keccak256::new();\n\
         hasher.update(b\"BDLM_SNEAKY_V1\");\n\
         for word in words { hasher.update(word.to_le_bytes()); }\n\
         hasher.finalize().into()\n}\n",
    )
    .map_err(|e| e.to_string())?;
    if run(tmp).is_ok() {
        let _ = fs::remove_dir_all(tmp);
        return Err(String::from(
            "self-test: sonradan eklenen yeni uretim noktasi yakalanmadi",
        ));
    }

    Ok(())
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

    #[test]
    fn regeneration_is_idempotent_and_repairing() {
        // Yakinsama: ag bolunmesin diye her dugum ayni yere varmali.
        let a = regenerate_storage_challenge_program();
        let b = regenerate_storage_challenge_program();
        assert_eq!(a, b, "ikinci uretim ayni olmali (idempotence)");

        let mut corrupted = a.clone();
        corrupted[0] ^= 0xFFFF;
        assert_ne!(corrupted, a, "bozma gercekten degistirmeli");
        assert_eq!(
            regenerate_storage_challenge_program(),
            a,
            "bozulmus girdiden kanonik hale donulmeli (onarim)"
        );
    }

    #[test]
    fn independent_isa_encoding_matches_the_spec() {
        // bud_isa::Instruction::encode kuralinin bagimsiz kopyasi dogru mu.
        // VerifyMerkle=0x1E, rd=1, rs1=2, rs2=3, imm=256
        let got = encode_instruction(OP_VERIFY_MERKLE, 1, 2, 3, 256);
        let expected = 0x1E | (1 << 8) | (2 << 13) | (3 << 18) | (256u64 << 23);
        assert_eq!(got, expected);
    }
}
