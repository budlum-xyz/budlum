//! Yerel iki-dugumlu devnet hazirligi.
//!
//! `run_nodes.sh` yerine gecer.
//!
//! # Shell surumunun gercek sorunu
//!
//! Betik `rm -rf ./data/node1.db ./data/node2.db` ile basliyordu ve
//! **calisma dizinine gore** siliyordu. Depo kokunden degil de baska bir
//! yerden cagrilirsa yanlis `data/` dizinini siler; hicbir kontrol yoktu.
//! Burada silme hedefi depo kokune sabitlenmis ve hedefin gercekten bir
//! devnet veri dizini oldugu dogrulaniyor.
//!
//! Ikinci sorun: betigin son satiri kullaniciya `[y/N]` diye soruyordu ama
//! cevabi **hicbir zaman okumuyordu**. Yani soru bir yalandi; betik her
//! zaman yalniz komut satirlarini yazdirip cikiyordu. Burada soru yok,
//! yapilan is yaziliyor.

use std::path::{Path, PathBuf};

/// Bir devnet dugumunun tarifi.
pub struct NodeSpec {
    pub label: &'static str,
    pub port: u16,
    pub db: PathBuf,
    pub dial: Option<String>,
}

/// Devnet veri dizininin altinda beklenen dosyalar. Silme islemi ancak
/// hedefte bunlardan biri varsa ya da dizin bossa yapilir; boylece yanlis
/// bir `data/` dizini silinemez.
const EXPECTED: &[&str] = &["node1.db", "node2.db", "validators.json"];

/// `data/` dizinini temizle ve validator listesini yaz.
///
/// # Errors
///
/// Hedef dizin bir devnet dizinine benzemiyorsa, ya da dosya islemleri
/// basarisiz olursa.
pub fn prepare(root: &Path) -> Result<String, String> {
    let data = root.join("data");

    if data.exists() {
        if !data.is_dir() {
            return Err(format!("{} bir dizin degil", data.display()));
        }
        // Silmeden once bak: burasi gercekten devnet verisi mi? Shell
        // surumu bunu sormuyordu ve calisma dizinine gore siliyordu.
        let mut foreign: Vec<String> = Vec::new();
        for entry in
            std::fs::read_dir(&data).map_err(|e| format!("{} okunamadi: {e}", data.display()))?
        {
            let entry = entry.map_err(|e| format!("dizin girdisi okunamadi: {e}"))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !EXPECTED.contains(&name.as_str()) {
                foreign.push(name);
            }
        }
        if !foreign.is_empty() {
            return Err(format!(
                "{} icinde beklenmeyen girdi(ler) var: {}. \
                 Bu bir devnet veri dizinine benzemiyor ve silinmeyecek. \
                 Shell surumu bunu sormadan siliyordu.",
                data.display(),
                foreign.join(", ")
            ));
        }
        for name in EXPECTED {
            let target = data.join(name);
            if target.is_dir() {
                std::fs::remove_dir_all(&target)
                    .map_err(|e| format!("{} silinemedi: {e}", target.display()))?;
            } else if target.is_file() {
                std::fs::remove_file(&target)
                    .map_err(|e| format!("{} silinemedi: {e}", target.display()))?;
            }
        }
    }

    std::fs::create_dir_all(&data)
        .map_err(|e| format!("{} olusturulamadi: {e}", data.display()))?;

    let validators = data.join("validators.json");
    // Shell surumu bu JSON'u bir heredoc'tan yaziyordu; bicimi bozuk bir
    // heredoc sessizce gecersiz JSON uretirdi. Burada dizgi sabit ve
    // yazildiktan sonra en azindan bicimsel olarak geri okunuyor.
    let body = "{\n  \"validators\": [\n    \"12D3KooWNode1ValidatorAddress12345\"\n  ]\n}\n";
    std::fs::write(&validators, body)
        .map_err(|e| format!("{} yazilamadi: {e}", validators.display()))?;
    let back = std::fs::read_to_string(&validators)
        .map_err(|e| format!("{} okunamadi: {e}", validators.display()))?;
    if !back.contains("validators") || !back.trim_end().ends_with('}') {
        return Err(format!("{} bozuk yazildi", validators.display()));
    }

    let specs = node_specs(root);
    let mut out = vec![format!("devnet hazir: {}", data.display())];
    out.push(String::new());
    for s in &specs {
        out.push(format!("{}:", s.label));
        out.push(format!("  {}", command_line(s, &validators)));
    }
    Ok(out.join("\n"))
}

/// Iki dugumun tarifi: biri validator, digeri ona baglanan gozlemci.
#[must_use]
pub fn node_specs(root: &Path) -> Vec<NodeSpec> {
    let data = root.join("data");
    vec![
        NodeSpec {
            label: "Dugum 1 (validator)",
            port: 4001,
            db: data.join("node1.db"),
            dial: None,
        },
        NodeSpec {
            label: "Dugum 2 (gozlemci, dugum 1'e baglanir)",
            port: 4002,
            db: data.join("node2.db"),
            dial: Some("/ip4/127.0.0.1/tcp/4001".to_string()),
        },
    ]
}

/// Bir dugumu baslatan komut satiri.
#[must_use]
pub fn command_line(spec: &NodeSpec, validators: &Path) -> String {
    let mut s = format!(
        "cargo run -- --port {} --db-path {} --consensus poa --validators-file {}",
        spec.port,
        spec.db.display(),
        validators.display()
    );
    if let Some(dial) = &spec.dial {
        s.push_str(" --dial ");
        s.push_str(dial);
    }
    s
}

/// Kanarya: silme korumasinin gercekten calistigini kanitlar.
///
/// # Errors
///
/// Yabanci bir dosya iceren bir `data/` dizini silinirse.
pub fn self_test() -> Result<String, String> {
    let tmp = std::env::temp_dir().join(format!("budlum-devnet-canary-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("data")).map_err(|e| format!("kanarya dizini: {e}"))?;

    // Yabanci bir dosya koy: silinmemeli.
    let precious = tmp.join("data").join("uretim-verisi.db");
    std::fs::write(&precious, b"silinmemeli").map_err(|e| format!("kanarya dosyasi: {e}"))?;

    let refused = prepare(&tmp);
    if refused.is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(
            "KANARYA DUSTU: yabanci dosya iceren bir data/ dizini temizlendi; \
             shell surumunun kor `rm -rf`'i geri gelmis."
                .to_string(),
        );
    }
    if !precious.is_file() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err("KANARYA DUSTU: yabanci dosya silindi".to_string());
    }

    // Temiz bir dizinde gecmeli.
    std::fs::remove_file(&precious).map_err(|e| format!("kanarya temizligi: {e}"))?;
    prepare(&tmp).map_err(|e| format!("temiz dizinde gecmeliydi: {e}"))?;
    if !tmp.join("data").join("validators.json").is_file() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err("validators.json yazilmadi".to_string());
    }

    let _ = std::fs::remove_dir_all(&tmp);
    Ok("devnet kanaryasi OK: yabanci dosya reddedildi, temiz dizin hazirlandi".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_foreign_file_stops_the_wipe() {
        let tmp = std::env::temp_dir().join("budlum-devnet-foreign");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("data")).expect("dizin");
        let precious = tmp.join("data").join("onemli.db");
        std::fs::write(&precious, b"x").expect("dosya");

        let err = prepare(&tmp).expect_err("yabanci dosya reddedilmeli");
        assert!(err.contains("beklenmeyen girdi"), "{err}");
        assert!(precious.is_file(), "yabanci dosya durmali");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_clean_tree_is_prepared() {
        let tmp = std::env::temp_dir().join("budlum-devnet-clean");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("dizin");
        let msg = prepare(&tmp).expect("temiz agac hazirlanmali");
        assert!(msg.contains("devnet hazir"), "{msg}");
        assert!(tmp.join("data").join("validators.json").is_file());
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn the_observer_dials_the_validator() {
        let specs = node_specs(Path::new("/repo"));
        assert_eq!(specs.len(), 2);
        assert!(specs[0].dial.is_none(), "validator kimseyi aramaz");
        let dial = specs[1].dial.as_deref().expect("gozlemci aramali");
        assert!(dial.contains("4001"), "dugum 1'in portuna: {dial}");
        assert_eq!(specs[1].port, 4002, "iki dugum ayni portu paylasamaz");
    }

    #[test]
    fn the_command_line_carries_every_required_flag() {
        let specs = node_specs(Path::new("/repo"));
        let line = command_line(&specs[0], Path::new("/repo/data/validators.json"));
        for flag in [
            "--port",
            "--db-path",
            "--consensus poa",
            "--validators-file",
        ] {
            assert!(line.contains(flag), "{flag} eksik: {line}");
        }
    }

    #[test]
    fn self_test_passes() {
        let msg = self_test().expect("kanarya gecmeli");
        assert!(msg.contains("OK"), "{msg}");
    }
}
