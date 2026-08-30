//! The Budlum project file (`budlum.toml`) schema.
//!
//! # How this module got here
//!
//! `src/sdk/` was five files and was never declared from `lib.rs`: all 1871
//! lines went uncompiled. Because they did not compile, nothing looked at
//! them - not clippy, not the gates, not the tests. This was measured, not
//! guessed: declaring the directory surfaced three files that did not do the
//! work their names promised.
//!
//! * `contracts.rs` - `compile()` was not a compiler. It checked whether the
//!   source was empty and put the hash of the source into the `bytecode_hash`
//!   field; its own comment said "stub for now". A type called
//!   `CompiledContract` contained no bytecode.
//! * `devnet.rs` - `start_domain()` started no node. It created a directory,
//!   marked a domain `Running` and logged "RPC at 127.0.0.1:port"; nothing was
//!   listening on that port, and `rpc_endpoints()` returned addresses nothing
//!   could connect to.
//! * `runner.rs` - `test()` ran no tests. It invented two results per contract
//!   and `all_passed()` always returned `true`: a developer with a broken
//!   contract would have been shown green.
//!
//! All three were deleted. There was no reason to keep a fake devnet either:
//! the real four-node devnet already exists as `ops/docker-compose.yml` and
//! runs against real RPC in CI's `devnet-multinode-smoke` job. A second, fake
//! copy standing next to the real one only misleads.
//!
//! `fixture.rs` went too: the `ProofFixture` it produced carried the same name
//! as the verified manifest record in `developer_os.rs` while meaning something
//! different. One type now lives, in `developer_os.rs`.
//!
//! # What remains
//!
//! A file-format schema. It claims nothing: it reads a TOML file, writes one,
//! and produces a default. It says exactly as much as it does.
//!
//! # A second measurement: the schema described the deleted tools
//!
//! After those three files went, the schema stayed as it was. `[devnet]`
//! configured the deleted fake devnet, `[contracts]` the deleted fake compiler,
//! `[fixtures]` the deleted fixture generator. There is not one `budlum.toml`
//! in the tree, and no type was left reading these sections (measured: zero
//! uses of `DevnetSection`, `ContractsSection`, `FixturesSection` outside the
//! module).
//!
//! A configuration field is worse than useless when the thing it configures is
//! gone: a developer who writes `domains = ["pow", "pos"]` into the file
//! believes those domains will be started. The three sections were deleted, and
//! what is left is what the project actually has: its name and its version.
//!
//! WIRING: unwired - this is a file-format schema for a project file that
//! lives outside the node. Nothing in the node reads `budlum.toml`, and
//! nothing should: it describes a developer's project, not chain state.

/// The `budlum.toml` project configuration schema.
///
/// The `budlum.toml` at the root of a Budlum project names and versions that
/// project. The build, test and devnet binding sections were removed: those
/// tools were deleted for not meeting their claims, and a field that
/// configures nothing promises a capability that does not exist.
///
/// # Example `budlum.toml`
///
/// The keys are lowercase because that is what the fields deserialize from.
/// This example used to be written with capitals, which would not have parsed
/// for anyone who copied it.
///
/// ```toml
/// [project]
/// name = "my-budlum-dapp"
/// version = "0.1.0"
/// budlum_version = "0.1.0"
/// ```
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BudlumToml {
    /// Project metadata.
    pub project: ProjectSection,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProjectSection {
    /// Project name.
    pub name: String,
    /// Project version, semver.
    pub version: String,
    /// The Budlum core version this targets.
    #[serde(default)]
    pub budlum_version: Option<String>,
}

impl BudlumToml {
    /// Reads and parses a `budlum.toml`.
    ///
    /// # Errors
    ///
    /// Returns `Io` when the file cannot be read or is over the ceiling for a
    /// control file, `Parse` when it is not valid TOML.
    pub fn load(path: &std::path::Path) -> Result<Self, BudlumTomlError> {
        // Bounded: a `budlum.toml` is hand-written configuration. The path
        // comes from the developer's working directory, so the size of this
        // allocation is not the node's to choose.
        let content = crate::core::bounded_read::read_to_string_bounded(
            path,
            crate::core::bounded_read::MAX_CONTROL_FILE_BYTES,
        )
        .map_err(|e| BudlumTomlError::Read {
            path: path.to_path_buf(),
            source: e,
        })?;
        toml::from_str(&content).map_err(|e| BudlumTomlError::Parse {
            path: path.to_path_buf(),
            source: e,
        })
    }

    /// Returns the default project configuration, for scaffolding a new project.
    #[must_use]
    pub fn default_template(name: &str) -> Self {
        Self {
            project: ProjectSection {
                name: name.to_string(),
                version: "0.1.0".to_string(),
                budlum_version: Some("0.1.0".to_string()),
            },
        }
    }

    /// Writes the configuration to a file as TOML.
    ///
    /// # Errors
    ///
    /// Returns `Serialize` when serialization fails, `Io` when the write fails.
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
    /// The file could not be read within the ceiling for a control file.
    ///
    /// Kept separate from [`Self::Io`] because "this file is too big to read"
    /// and "this file could not be opened" send the developer to different
    /// places, and flattening the first into an `io::Error` string would throw
    /// away the limit and the measured size that the reader worked out.
    Read {
        /// The path that was being read.
        path: std::path::PathBuf,
        /// Why the bounded read refused.
        source: crate::core::bounded_read::BoundedReadError,
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
            Self::Io { path, source } => {
                write!(f, "budlum.toml I/O error at {}: {}", path.display(), source)
            }
            Self::Read { path, source } => {
                write!(f, "budlum.toml unreadable at {}: {source}", path.display())
            }
            Self::Parse { path, source } => {
                write!(
                    f,
                    "budlum.toml parse error at {}: {}",
                    path.display(),
                    source
                )
            }
            Self::Serialize { path, source } => {
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
            Self::Io { source, .. } => Some(source),
            Self::Read { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
            Self::Serialize { source, .. } => Some(source),
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
        assert_eq!(parsed.project.version, "0.1.0");
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
        assert!(matches!(result, Err(BudlumTomlError::Read { .. })));
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
