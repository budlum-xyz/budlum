//! P12-12: BudL sözleşme desteği.
//!
//! BudL (Budlum Language), Budlum zkVM üzerinde çalışan akıllı sözleşmeler için
//! geliştirme dilidir. Bu modül, sözleşmelerin derleme, doğrulama ve dağıtım
//! altyapısını sağlar.
//!
//! # Sözleşme Yaşam Döngüsü
//!
//! ```text
//! Kaynak Kodu → Derleme → Bytecode → Doğrulama → Dağıtım → Çalıştırma
//! ```
//!
//! Şu an sadece sözleşme modeli ve derleme altyapısı tanımlanır.
//! Gerçek BudL derleyicisi ayrı bir araç olarak sağlanacaktır.

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use serde::{Deserialize, Serialize};

/// Sözleşme dili.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContractLanguage {
    /// BudL — Budlum'un native sözleşme dili.
    Budl,
    /// Assembly — Düşük seviye bytecode.
    Assembly,
}

impl std::fmt::Display for ContractLanguage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContractLanguage::Budl => write!(f, "budl"),
            ContractLanguage::Assembly => write!(f, "asm"),
        }
    }
}

/// Derlenmemiş sözleşme kaynak kodu.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudlContract {
    /// Sözleşme adı.
    pub name: String,
    /// Sözleşme dili.
    pub language: ContractLanguage,
    /// Kaynak kodu.
    pub source: String,
    /// Sözleşme sürümü.
    #[serde(default)]
    pub version: String,
}

impl BudlContract {
    /// Yeni bir BudL sözleşmesi oluşturur.
    pub fn new(name: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            language: ContractLanguage::Budl,
            source: source.into(),
            version: "0.1.0".to_string(),
        }
    }

    /// Dosyadan sözleşme yükler.
    pub fn load(path: &std::path::Path) -> Result<Self, ContractError> {
        let content = std::fs::read_to_string(path).map_err(|e| ContractError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;

        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("unknown")
            .to_string();

        let language = match path.extension().and_then(|s| s.to_str()) {
            Some("budl") => ContractLanguage::Budl,
            Some("asm") => ContractLanguage::Assembly,
            _ => ContractLanguage::Budl,
        };

        Ok(Self {
            name,
            language,
            source: content,
            version: "0.1.0".to_string(),
        })
    }

    /// Sözleşmeyi derler (gelecekte gerçek derleyici entegrasyonu).
    ///
    /// Şu an sadece temel doğrulama yapar ve sahte bytecode üretir.
    /// Gerçek BudL derleyicisi eklendiğinde bu fonksiyon güncellenecek.
    pub fn compile(&self) -> Result<CompiledContract, ContractError> {
        // Temel doğrulama
        if self.source.trim().is_empty() {
            return Err(ContractError::EmptySource {
                name: self.name.clone(),
            });
        }

        if self.name.trim().is_empty() {
            return Err(ContractError::InvalidName);
        }

        // Gelecekte: BudL derleyicisi burada çalışacak.
        // Şimdilik: source hash'ini bytecode yerine kullan (stub).
        let source_hash = hash_fields_bytes(&[self.source.as_bytes()]);

        Ok(CompiledContract {
            name: self.name.clone(),
            language: self.language,
            version: self.version.clone(),
            bytecode_hash: source_hash,
            source_size: self.source.len(),
        })
    }
}

/// Derlenmiş sözleşme.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompiledContract {
    /// Sözleşme adı.
    pub name: String,
    /// Sözleşme dili.
    pub language: ContractLanguage,
    /// Sözleşme sürümü.
    pub version: String,
    /// Bytecode hash'i (gerçek bytecode yerine).
    pub bytecode_hash: [u8; 32],
    /// Kaynak kodu boyutu (bayt).
    pub source_size: usize,
}

impl CompiledContract {
    /// Sözleşme deploy ID'si (deterministik: hash(name + bytecode_hash)).
    pub fn deploy_id(&self) -> [u8; 32] {
        hash_fields_bytes(&[self.name.as_bytes(), &self.bytecode_hash])
    }
}

/// Dağıtılmış sözleşme örneği.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeployedContract {
    /// Derlenmiş sözleşme.
    pub compiled: CompiledContract,
    /// Dağıtım adresi.
    pub address: Address,
    /// Dağıtım bloğu.
    pub deploy_height: u64,
    /// Dağıtım transaction hash'i.
    pub deploy_tx_hash: [u8; 32],
}

/// Sözleşme hataları.
#[derive(Debug)]
pub enum ContractError {
    /// I/O hatası.
    Io {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    /// Boş kaynak kodu.
    EmptySource {
        name: String,
    },
    /// Geçersiz sözleşme adı.
    InvalidName,
    /// Derleme hatası (gelecekte detaylandırılacak).
    CompileError {
        name: String,
        message: String,
    },
}

impl std::fmt::Display for ContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContractError::Io { path, source } => {
                write!(f, "Contract I/O error at {}: {}", path.display(), source)
            }
            ContractError::EmptySource { name } => {
                write!(f, "Contract '{}' has empty source code", name)
            }
            ContractError::InvalidName => write!(f, "Contract name is invalid (empty)"),
            ContractError::CompileError { name, message } => {
                write!(f, "Contract '{}' compile error: {}", name, message)
            }
        }
    }
}

impl std::error::Error for ContractError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ContractError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_compile_basic() {
        let contract = BudlContract::new("test_contract", "fn main() {}");
        let compiled = contract.compile().unwrap();
        assert_eq!(compiled.name, "test_contract");
        assert_eq!(compiled.language, ContractLanguage::Budl);
        assert_ne!(compiled.bytecode_hash, [0u8; 32]);
    }

    #[test]
    fn contract_compile_empty_source_fails() {
        let contract = BudlContract::new("empty", "");
        let err = contract.compile().unwrap_err();
        assert!(matches!(err, ContractError::EmptySource { .. }));
    }

    #[test]
    fn contract_compile_empty_name_fails() {
        let contract = BudlContract {
            name: "  ".to_string(),
            language: ContractLanguage::Budl,
            source: "fn main() {}".to_string(),
            version: "0.1.0".to_string(),
        };
        let err = contract.compile().unwrap_err();
        assert!(matches!(err, ContractError::InvalidName));
    }

    #[test]
    fn compiled_contract_deploy_id_is_deterministic() {
        let contract = BudlContract::new("deterministic", "fn main() {}");
        let compiled = contract.compile().unwrap();
        let id1 = compiled.deploy_id();
        let id2 = compiled.deploy_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn different_contracts_have_different_deploy_ids() {
        let c1 = BudlContract::new("contract_a", "fn a() {}").compile().unwrap();
        let c2 = BudlContract::new("contract_b", "fn b() {}").compile().unwrap();
        assert_ne!(c1.deploy_id(), c2.deploy_id());
    }

    #[test]
    fn contract_language_display() {
        assert_eq!(ContractLanguage::Budl.to_string(), "budl");
        assert_eq!(ContractLanguage::Assembly.to_string(), "asm");
    }
}
