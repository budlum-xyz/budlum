//! Budlum proje dosyası (`budlum.toml`) şeması.
//!
//! # Bu modülün geçmişi
//!
//! `src/sdk/` beş dosyaydı ve `lib.rs`'ten hiç bildirilmemişti: 1871 satırın
//! tamamı derlenmiyordu. Derlenmediği için ne clippy, ne kapılar, ne testler
//! bakıyordu. Ölçüldü, tahmin edilmedi: dizin bildirildiğinde ortaya çıkan
//! şey, isimlerinin vaat ettiği işi yapmayan üç dosyaydı.
//!
//! * `contracts.rs` - `compile()` bir derleyici değildi. Kaynağın boş olup
//!   olmadığına bakıp `bytecode_hash` alanına kaynağın hash'ini koyuyordu;
//!   kendi yorumu "şimdilik stub" diyordu. `CompiledContract` adlı tipin
//!   içinde bytecode yoktu.
//! * `devnet.rs` - `start_domain()` düğüm başlatmıyordu. Bir dizin oluşturup
//!   bir alanı `Running` yapıyor ve "RPC at 127.0.0.1:port" logluyordu; o
//!   portu dinleyen hiçbir şey yoktu, `rpc_endpoints()` bağlanılamayacak
//!   adresler döndürüyordu.
//! * `runner.rs` - `test()` test koşturmuyordu. Her sözleşme için iki sonuç
//!   uyduruyordu ve `all_passed()` daima `true` dönüyordu: sözleşmesi bozuk
//!   bir geliştiriciye yeşil gösterirdi.
//!
//! Üçü de silindi. Sahte bir devnet'in tutulması için bir neden de yoktu:
//! gerçek 4 düğümlü devnet `ops/docker-compose.yml` ile zaten var, CI'da
//! `devnet-multinode-smoke` işinde gerçek RPC'ye karşı koşuyor. İkinci ve
//! sahte bir kopya, gerçeğinin yanında yalnızca yanıltır.
//!
//! `fixture.rs` de silindi: ürettiği `ProofFixture`, `developer_os.rs`'teki
//! doğrulanan manifest kaydıyla aynı adı taşıyıp farklı şey ifade ediyordu.
//! Tek tip `developer_os.rs`'te yaşıyor.
//!
//! # Geriye kalan
//!
//! Bir dosya biçimi şeması. İddiası yok: bir TOML dosyasını okur, yazar ve
//! varsayılanını üretir. Yaptığı iş kadar söylüyor.
//!
//! WIRING: unwired - this is a file-format schema for a project file that
//! lives outside the node. Nothing in the node reads `budlum.toml`, and
//! nothing should: it describes a developer's project, not chain state.

/// `budlum.toml` proje yapılandırma dosyası şeması.
///
/// Bir Budlum projesinin kök dizinindeki `budlum.toml` dosyası, SDK'nın
/// Projeyi nasıl derleyeceğini, test edeceğini ve devnet'e bağlayacağını tanımlar.
///
/// # Örnek `budlum.toml`
///
/// ```toml
/// [project]
/// Name = "my-budlum-dapp"
/// Version = "0.1.0"
/// Budlum_version = "0.1.0"
///
/// [devnet]
/// Config = "config/devnet.toml"
/// Domains = ["pow", "pos", "poa", "bft"]
///
/// [contracts]
/// Directory = "contracts/"
///
/// [fixtures]
/// Directory = "fixtures/"
/// Seed = 42
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BudlumToml {
    /// Proje meta verileri.
    pub project: ProjectSection,
    /// Devnet yapılandırması.
    #[serde(default)]
    pub devnet: DevnetSection,
    /// Sözleşme dizini yapılandırması.
    #[serde(default)]
    pub contracts: ContractsSection,
    /// Fixture yapılandırması.
    #[serde(default)]
    pub fixtures: FixturesSection,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProjectSection {
    /// Proje adı.
    pub name: String,
    /// Proje sürümü (semver).
    pub version: String,
    /// Hedef Budlum çekirdek sürümü.
    #[serde(default)]
    pub budlum_version: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DevnetSection {
    /// Devnet yapılandırma dosyasının yolu (config/devnet.toml gibi).
    #[serde(default = "default_devnet_config")]
    pub config: String,
    /// Başlatılacak domain'ler.
    #[serde(default = "default_domains")]
    pub domains: Vec<String>,
}

impl Default for DevnetSection {
    fn default() -> Self {
        Self {
            config: default_devnet_config(),
            domains: default_domains(),
        }
    }
}

fn default_devnet_config() -> String {
    "config/devnet.toml".to_string()
}

fn default_domains() -> Vec<String> {
    vec![
        "pow".to_string(),
        "pos".to_string(),
        "poa".to_string(),
        "bft".to_string(),
    ]
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ContractsSection {
    /// Sözleşme kaynak dizini.
    #[serde(default = "default_contracts_dir")]
    pub directory: String,
}

impl Default for ContractsSection {
    fn default() -> Self {
        Self {
            directory: default_contracts_dir(),
        }
    }
}

fn default_contracts_dir() -> String {
    "contracts/".to_string()
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FixturesSection {
    /// Fixture çıktı dizini.
    #[serde(default = "default_fixtures_dir")]
    pub directory: String,
    /// Deterministik fixture üretimi için seed.
    #[serde(default = "default_fixture_seed")]
    pub seed: u64,
}

impl Default for FixturesSection {
    fn default() -> Self {
        Self {
            directory: default_fixtures_dir(),
            seed: default_fixture_seed(),
        }
    }
}

fn default_fixtures_dir() -> String {
    "fixtures/".to_string()
}

fn default_fixture_seed() -> u64 {
    42
}

impl BudlumToml {
    /// `budlum.toml` dosyasını okur ve parse eder.
    pub fn load(path: &std::path::Path) -> Result<Self, BudlumTomlError> {
        let content = std::fs::read_to_string(path).map_err(|e| BudlumTomlError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        toml::from_str(&content).map_err(|e| BudlumTomlError::Parse {
            path: path.to_path_buf(),
            source: e,
        })
    }

    /// Varsayılan proje yapılandırmasını döndürür (yeni proje iskeleti için).
    pub fn default_template(name: &str) -> Self {
        Self {
            project: ProjectSection {
                name: name.to_string(),
                version: "0.1.0".to_string(),
                budlum_version: Some("0.1.0".to_string()),
            },
            devnet: DevnetSection::default(),
            contracts: ContractsSection::default(),
            fixtures: FixturesSection::default(),
        }
    }

    /// Yapılandırmayı TOML olarak dosyaya yazar.
    pub fn save(&self, path: &std::path::Path) -> Result<(), BudlumTomlError> {
        let content = toml::to_string_pretty(self).map_err(|e| BudlumTomlError::Serialize {
            path: path.to_path_buf(),
            source: e,
        })?;
        std::fs::write(path, content).map_err(|e| BudlumTomlError::Io {
            path: path.to_path_buf(),
            source: e,
        })
    }
}

/// `budlum.toml` ile ilgili hatalar.
#[derive(Debug)]
pub enum BudlumTomlError {
    Io {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    Parse {
        path: std::path::PathBuf,
        source: toml::de::Error,
    },
    Serialize {
        path: std::path::PathBuf,
        source: toml::ser::Error,
    },
}

impl std::fmt::Display for BudlumTomlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BudlumTomlError::Io { path, source } => {
                write!(f, "budlum.toml I/O error at {}: {}", path.display(), source)
            }
            BudlumTomlError::Parse { path, source } => {
                write!(
                    f,
                    "budlum.toml parse error at {}: {}",
                    path.display(),
                    source
                )
            }
            BudlumTomlError::Serialize { path, source } => {
                write!(
                    f,
                    "budlum.toml serialize error at {}: {}",
                    path.display(),
                    source
                )
            }
        }
    }
}

impl std::error::Error for BudlumTomlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BudlumTomlError::Io { source, .. } => Some(source),
            BudlumTomlError::Parse { source, .. } => Some(source),
            BudlumTomlError::Serialize { source, .. } => Some(source),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn budlum_toml_default_template_roundtrip() {
        let tmpl = BudlumToml::default_template("test-project");
        let toml_str = toml::to_string_pretty(&tmpl).unwrap();
        let parsed: BudlumToml = toml::from_str(&toml_str).unwrap();
        assert_eq!(parsed.project.name, "test-project");
        assert_eq!(parsed.devnet.domains.len(), 4);
        assert_eq!(parsed.fixtures.seed, 42);
    }

    #[test]
    fn budlum_toml_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("budlum.toml");
        let tmpl = BudlumToml::default_template("save-load-test");
        tmpl.save(&path).unwrap();
        let loaded = BudlumToml::load(&path).unwrap();
        assert_eq!(loaded.project.name, "save-load-test");
        assert_eq!(loaded.project.version, "0.1.0");
    }

    #[test]
    fn budlum_toml_missing_file_returns_io_error() {
        let result = BudlumToml::load(std::path::Path::new("/nonexistent/budlum.toml"));
        assert!(matches!(result, Err(BudlumTomlError::Io { .. })));
    }

    #[test]
    fn budlum_toml_invalid_toml_returns_parse_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("budlum.toml");
        std::fs::write(&path, "not valid toml [[[[").unwrap();
        let result = BudlumToml::load(&path);
        assert!(matches!(result, Err(BudlumTomlError::Parse { .. })));
    }
}
