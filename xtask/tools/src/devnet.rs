//! Preparing a local two-node devnet.
//!
//! It replaces `run_nodes.sh`.
//!
//! # The real problem with the shell version
//!
//! The script began with `rm -rf ./data/node1.db ./data/node2.db`, which is
//! relative to the **working directory**. Called from somewhere other than the
//! repository root it deletes the wrong `data/` directory, and there was no
//! check at all. Here the deletion target is pinned to the repository root and
//! the target is verified to really be a devnet data directory.
//!
//! The second problem: the script's last line asked the user `[y/N]` but
//! **never read** the answer. So the question was a lie; the script always
//! just printed the command lines and exited. Here there is no question, and
//! the work being done is written out.

use std::path::{Path, PathBuf};

/// The description of one devnet node.
pub struct NodeSpec {
    pub label: &'static str,
    pub port: u16,
    pub db: PathBuf,
    pub dial: Option<String>,
}

/// The files expected under the devnet data directory. A delete happens only
/// if the target holds one of them or the directory is empty; that way a wrong
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
            return Err(format!("{} is not a directory", data.display()));
        }
        // Look before deleting: is this really devnet data? The shell version
        // never asked and deleted relative to the working directory.
        let mut foreign: Vec<String> = Vec::new();
        for entry in std::fs::read_dir(&data)
            .map_err(|e| format!("{} could not be read: {e}", data.display()))?
        {
            let entry = entry.map_err(|e| format!("dizin girdisi okunamadi: {e}"))?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if !EXPECTED.contains(&name.as_str()) {
                foreign.push(name);
            }
        }
        if !foreign.is_empty() {
            return Err(format!(
                "{} holds unexpected entr(ies): {}. \
                 This does not look like a devnet data directory and will not be deleted. \
                 The shell version deleted it without asking.",
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
        .map_err(|e| format!("{} could not be created: {e}", data.display()))?;

    let validators = data.join("validators.json");
    // The shell version wrote this JSON from a heredoc; a malformed heredoc
    // would silently produce invalid JSON. Here the string is fixed and after
    // writing it is read back at least structurally.
    let body = "{\n  \"validators\": [\n    \"12D3KooWNode1ValidatorAddress12345\"\n  ]\n}\n";
    std::fs::write(&validators, body)
        .map_err(|e| format!("{} could not be written: {e}", validators.display()))?;
    let back = std::fs::read_to_string(&validators)
        .map_err(|e| format!("{} could not be read: {e}", validators.display()))?;
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

/// The description of the two nodes: one validator and one observer dialling
/// it.
#[must_use]
pub fn node_specs(root: &Path) -> Vec<NodeSpec> {
    let data = root.join("data");
    vec![
        NodeSpec {
            label: "Node 1 (validator)",
            port: 4001,
            db: data.join("node1.db"),
            dial: None,
        },
        NodeSpec {
            label: "Node 2 (observer, dials node 1)",
            port: 4002,
            db: data.join("node2.db"),
            dial: Some("/ip4/127.0.0.1/tcp/4001".to_string()),
        },
    ]
}

/// The command line that starts one node.
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

/// The canary: it proves the deletion guard really works.
///
/// # Errors
///
/// If a `data/` directory holding a foreign file gets cleaned.
pub fn self_test() -> Result<String, String> {
    let tmp = std::env::temp_dir().join(format!("budlum-devnet-canary-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(tmp.join("data")).map_err(|e| format!("canary directory: {e}"))?;

    // Place a foreign file: it must not be deleted.
    let precious = tmp.join("data").join("production-data.db");
    std::fs::write(&precious, b"must-not-be-deleted").map_err(|e| format!("canary file: {e}"))?;

    let refused = prepare(&tmp);
    if refused.is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(
            "CANARY FELL: a data/ directory holding a foreign file was cleaned; \
             the blind `rm -rf` of the shell version is back."
                .to_string(),
        );
    }
    if !precious.is_file() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err("CANARY FELL: a foreign file was deleted".to_string());
    }

    // It must pass on a clean directory.
    std::fs::remove_file(&precious).map_err(|e| format!("canary cleanup: {e}"))?;
    prepare(&tmp).map_err(|e| format!("it should have passed on a clean directory: {e}"))?;
    if !tmp.join("data").join("validators.json").is_file() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err("validators.json was not written".to_string());
    }

    let _ = std::fs::remove_dir_all(&tmp);
    Ok(
        "devnet canary OK: a foreign file was refused and a clean directory was prepared"
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_foreign_file_stops_the_wipe() {
        let tmp = std::env::temp_dir().join("budlum-devnet-foreign");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("data")).expect("directory");
        let precious = tmp.join("data").join("important.db");
        std::fs::write(&precious, b"x").expect("file");

        let err = prepare(&tmp).expect_err("a foreign file must be refused");
        assert!(err.contains("unexpected entr"), "{err}");
        assert!(precious.is_file(), "the foreign file must remain");
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_clean_tree_is_prepared() {
        let tmp = std::env::temp_dir().join("budlum-devnet-clean");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).expect("dizin");
        let msg = prepare(&tmp).expect("a clean tree must be prepared");
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
        assert!(dial.contains("4001"), "to node 1's port: {dial}");
        assert_eq!(specs[1].port, 4002, "two nodes cannot share the same port");
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
        let msg = self_test().expect("the canary must pass");
        assert!(msg.contains("OK"), "{msg}");
    }
}
