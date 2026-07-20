//! P12-12: BudL compile/test çalıştırıcı.
//!
//! BudL SDK'nın derleme ve test çalıştırma altyapısı. Geliştiriciler
//! `bud test` ve `bud compile` komutlarıyla sözleşmelerini derleyip
//! test edebilirler.
//!
//! # İş Akışı
//!
//! ```text
//! BudlRunner::new()
//!   ├── compile() → Vec<CompiledContract>
//!   ├── test()    → Vec<TestResult>
//!   └── deploy()  → Vec<DeployedContract>  (gelecekte)
//! ```

use crate::sdk::contracts::{BudlContract, CompiledContract, ContractError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Test sonucu.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TestResult {
    /// Test adı.
    pub name: String,
    /// Geçti mi?
    pub passed: bool,
    /// Hata mesajı (başarısızsa).
    pub error_message: Option<String>,
    /// Çalışma süresi (ms).
    pub duration_ms: u64,
}

/// Çalıştırma sonucu.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunResult {
    /// Derlenen sözleşmeler.
    pub compiled: Vec<CompiledContract>,
    /// Test sonuçları.
    pub tests: Vec<TestResult>,
    /// Toplam çalışma süresi (ms).
    pub total_duration_ms: u64,
}

impl RunResult {
    /// Tüm testlerin geçip geçmediğini döndürür.
    pub fn all_passed(&self) -> bool {
        self.tests.iter().all(|t| t.passed)
    }

    /// Geçen test sayısı.
    pub fn passed_count(&self) -> usize {
        self.tests.iter().filter(|t| t.passed).count()
    }

    /// Başarısız test sayısı.
    pub fn failed_count(&self) -> usize {
        self.tests.iter().filter(|t| !t.passed).count()
    }

    /// Özet rapor üretir.
    pub fn summary(&self) -> String {
        let total = self.tests.len();
        let passed = self.passed_count();
        let failed = self.failed_count();
        let contracts = self.compiled.len();
        format!(
            "BudL Runner: {} contracts compiled, {} tests ({} passed, {} failed) in {}ms",
            contracts, total, passed, failed, self.total_duration_ms
        )
    }
}

/// Çalıştırıcı hataları.
#[derive(Debug)]
pub enum RunnerError {
    /// Proje dizini bulunamadı.
    ProjectDirNotFound(PathBuf),
    /// Sözleşme dizini bulunamadı.
    ContractsDirNotFound(PathBuf),
    /// Sözleşme hatası.
    ContractError(ContractError),
    /// Yapılandırma hatası.
    ConfigError(String),
    /// I/O hatası.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
}

impl std::fmt::Display for RunnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunnerError::ProjectDirNotFound(p) => {
                write!(f, "Project directory not found: {}", p.display())
            }
            RunnerError::ContractsDirNotFound(p) => {
                write!(f, "Contracts directory not found: {}", p.display())
            }
            RunnerError::ContractError(e) => write!(f, "Contract error: {}", e),
            RunnerError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            RunnerError::Io { path, source } => {
                write!(f, "I/O error at {}: {}", path.display(), source)
            }
        }
    }
}

impl std::error::Error for RunnerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            RunnerError::ContractError(e) => Some(e),
            RunnerError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<ContractError> for RunnerError {
    fn from(e: ContractError) -> Self {
        RunnerError::ContractError(e)
    }
}

/// BudL compile/test çalıştırıcı.
#[derive(Debug)]
pub struct BudlRunner {
    /// Proje kök dizini.
    pub project_dir: PathBuf,
    /// Sözleşme kaynak dizini.
    pub contracts_dir: PathBuf,
    /// Fixture çıktı dizini.
    pub fixtures_dir: PathBuf,
}

impl BudlRunner {
    /// Proje dizininden yeni çalıştırıcı oluşturur.
    pub fn new(project_dir: impl Into<PathBuf>) -> Self {
        let project_dir = project_dir.into();
        Self {
            contracts_dir: project_dir.join("contracts"),
            fixtures_dir: project_dir.join("fixtures"),
            project_dir,
        }
    }

    /// Sözleşme kaynak dosyalarını keşfeder.
    pub fn discover_contracts(&self) -> Result<Vec<BudlContract>, RunnerError> {
        if !self.contracts_dir.exists() {
            return Err(RunnerError::ContractsDirNotFound(self.contracts_dir.clone()));
        }

        let mut contracts = Vec::new();

        let entries = std::fs::read_dir(&self.contracts_dir).map_err(|e| RunnerError::Io {
            path: self.contracts_dir.clone(),
            source: e,
        })?;

        for entry in entries {
            let entry = entry.map_err(|e| RunnerError::Io {
                path: self.contracts_dir.clone(),
                source: e,
            })?;
            let path = entry.path();

            if path.is_file() {
                let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
                if ext == "budl" || ext == "asm" {
                    match BudlContract::load(&path) {
                        Ok(contract) => contracts.push(contract),
                        Err(e) => {
                            tracing::warn!("Skipping contract at {}: {}", path.display(), e);
                        }
                    }
                }
            }
        }

        Ok(contracts)
    }

    /// Tüm sözleşmeleri derler.
    pub fn compile(&self) -> Result<Vec<CompiledContract>, RunnerError> {
        let contracts = self.discover_contracts()?;
        let mut compiled = Vec::new();

        for contract in contracts {
            let c = contract.compile()?;
            tracing::info!("Compiled: {} ({} bytes source)", c.name, c.source_size);
            compiled.push(c);
        }

        Ok(compiled)
    }

    /// Test çalıştırır (şu an stub — gerçek test framework gelecekte).
    ///
    /// Şu an sadece derleme başarısını kontrol eder ve temel test
    /// sonuçları üretir. Gerçek BudL test framework'ü eklendiğinde
    /// bu fonksiyon güncellenecek.
    pub fn test(&self) -> Result<RunResult, RunnerError> {
        let start = std::time::Instant::now();

        let compiled = self.compile()?;

        let mut tests = Vec::new();

        for contract in &compiled {
            // Her derlenen sözleşme için "compiles successfully" testi
            tests.push(TestResult {
                name: format!("{}::compiles", contract.name),
                passed: true,
                error_message: None,
                duration_ms: 1,
            });

            // Bytecode hash sıfır olmamalı
            tests.push(TestResult {
                name: format!("{}::bytecode_hash_nonzero", contract.name),
                passed: contract.bytecode_hash != [0u8; 32],
                error_message: if contract.bytecode_hash == [0u8; 32] {
                    Some("Bytecode hash is all zeros".to_string())
                } else {
                    None
                },
                duration_ms: 0,
            });
        }

        let duration = start.elapsed().as_millis() as u64;

        Ok(RunResult {
            compiled,
            tests,
            total_duration_ms: duration,
        })
    }

    /// Fixture dizininde fixture dosyaları üretir.
    pub fn generate_fixtures(
        &self,
        seed: u64,
    ) -> Result<FixtureOutput, RunnerError> {
        use crate::sdk::fixture::{
            FixtureGenerator, PollenFixtureGenerator, ProofFixtureGenerator,
            RelayerIntentFixtureGenerator,
        };

        if !self.fixtures_dir.exists() {
            std::fs::create_dir_all(&self.fixtures_dir).map_err(|e| RunnerError::Io {
                path: self.fixtures_dir.clone(),
                source: e,
            })?;
        }

        // Proof fixtures
        let proof_gen = ProofFixtureGenerator::new(seed, 4);
        let proof_fixtures = proof_gen.generate();
        let proof_path = self.fixtures_dir.join("proof_fixtures.json");
        let proof_json = serde_json::to_string_pretty(&proof_fixtures).unwrap();
        std::fs::write(&proof_path, proof_json).map_err(|e| RunnerError::Io {
            path: proof_path.clone(),
            source: e,
        })?;

        // Pollen fixtures
        let pollen_gen = PollenFixtureGenerator::new(seed, 3, 5);
        let (asset_fixtures, grant_fixtures) = pollen_gen.generate_all();

        let asset_path = self.fixtures_dir.join("pollen_asset_fixtures.json");
        let asset_json = serde_json::to_string_pretty(&asset_fixtures).unwrap();
        std::fs::write(&asset_path, asset_json).map_err(|e| RunnerError::Io {
            path: self.fixtures_dir.clone(),
            source: e,
        })?;

        let grant_path = self.fixtures_dir.join("pollen_grant_fixtures.json");
        let grant_json = serde_json::to_string_pretty(&grant_fixtures).unwrap();
        std::fs::write(&grant_path, grant_json).map_err(|e| RunnerError::Io {
            path: grant_path.clone(),
            source: e,
        })?;

        // Relayer intent fixtures
        let relayer_gen = RelayerIntentFixtureGenerator::new(seed, 5);
        let relayer_fixtures = relayer_gen.generate();
        let relayer_path = self.fixtures_dir.join("relayer_intent_fixtures.json");
        let relayer_json = serde_json::to_string_pretty(&relayer_fixtures).unwrap();
        std::fs::write(&relayer_path, relayer_json).map_err(|e| RunnerError::Io {
            path: relayer_path.clone(),
            source: e,
        })?;

        Ok(FixtureOutput {
            proof_count: proof_fixtures.len(),
            pollen_asset_count: asset_fixtures.len(),
            pollen_grant_count: grant_fixtures.len(),
            relayer_intent_count: relayer_fixtures.len(),
        })
    }
}

/// Fixture üretim çıktı özeti.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FixtureOutput {
    /// Üretilen proof fixture sayısı.
    pub proof_count: usize,
    /// Üretilen Pollen asset fixture sayısı.
    pub pollen_asset_count: usize,
    /// Üretilen Pollen grant fixture sayısı.
    pub pollen_grant_count: usize,
    /// Üretilen relayer intent fixture sayısı.
    pub relayer_intent_count: usize,
}

impl std::fmt::Display for FixtureOutput {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Fixtures generated: {} proofs, {} pollen assets, {} pollen grants, {} relayer intents",
            self.proof_count,
            self.pollen_asset_count,
            self.pollen_grant_count,
            self.relayer_intent_count
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runner_discovers_contracts() {
        let dir = tempfile::tempdir().unwrap();
        let contracts_dir = dir.path().join("contracts");
        std::fs::create_dir_all(&contracts_dir).unwrap();
        std::fs::write(
            contracts_dir.join("test_contract.budl"),
            "fn main() { return 42; }",
        )
        .unwrap();

        let runner = BudlRunner::new(dir.path());
        let contracts = runner.discover_contracts().unwrap();
        assert_eq!(contracts.len(), 1);
        assert_eq!(contracts[0].name, "test_contract");
    }

    #[test]
    fn runner_compile_and_test() {
        let dir = tempfile::tempdir().unwrap();
        let contracts_dir = dir.path().join("contracts");
        std::fs::create_dir_all(&contracts_dir).unwrap();
        std::fs::write(
            contracts_dir.join("hello.budl"),
            "fn main() { print(\"hello\"); }",
        )
        .unwrap();

        let runner = BudlRunner::new(dir.path());
        let result = runner.test().unwrap();
        assert!(result.all_passed());
        assert_eq!(result.compiled.len(), 1);
        assert_eq!(result.tests.len(), 2); // compiles + bytecode_hash_nonzero
    }

    #[test]
    fn runner_generate_fixtures() {
        let dir = tempfile::tempdir().unwrap();
        let runner = BudlRunner::new(dir.path());
        let output = runner.generate_fixtures(42).unwrap();
        assert_eq!(output.proof_count, 4);
        assert_eq!(output.pollen_asset_count, 3);
        assert_eq!(output.pollen_grant_count, 5);
        assert_eq!(output.relayer_intent_count, 5);

        // Dosyalar oluşturulmuş olmalı
        assert!(dir.path().join("fixtures/proof_fixtures.json").exists());
        assert!(dir.path().join("fixtures/pollen_asset_fixtures.json").exists());
        assert!(dir.path().join("fixtures/pollen_grant_fixtures.json").exists());
        assert!(dir.path().join("fixtures/relayer_intent_fixtures.json").exists());
    }

    #[test]
    fn runner_missing_contracts_dir() {
        let dir = tempfile::tempdir().unwrap();
        let runner = BudlRunner::new(dir.path());
        let result = runner.discover_contracts();
        assert!(matches!(result, Err(RunnerError::ContractsDirNotFound(_))));
    }

    #[test]
    fn run_result_summary() {
        let result = RunResult {
            compiled: vec![],
            tests: vec![
                TestResult {
                    name: "test_a".into(),
                    passed: true,
                    error_message: None,
                    duration_ms: 10,
                },
                TestResult {
                    name: "test_b".into(),
                    passed: false,
                    error_message: Some("failed".into()),
                    duration_ms: 5,
                },
            ],
            total_duration_ms: 15,
        };
        assert!(!result.all_passed());
        assert_eq!(result.passed_count(), 1);
        assert_eq!(result.failed_count(), 1);
        let summary = result.summary();
        assert!(summary.contains("1 passed"));
        assert!(summary.contains("1 failed"));
    }
}
