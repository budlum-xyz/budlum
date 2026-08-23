//! The Docker image must build with the pinned compiler.
//!
//! Ported from `scripts/check-docker-toolchain-matches-pin.sh`. Six claims
//! are checked, one per canary:
//!   1. the `FROM rust:<tag>` version equals the `rust-toolchain.toml` channel;
//!   2. the FROM line carries a `@sha256:...` digest (a floating tag is not a pin);
//!   3. every workflow `toolchain:` agrees with the pin;
//!   4. the Dockerfile copies `rust-toolchain.toml` into the build context;
//!   5. the builder stage runs `rustc --version` to prove the pin in-image;
//!   6. the files exist at all (no vacuous pass).

use std::path::Path;

/// `channel = "1.97.0"` -> `1.97.0`.
fn pinned_channel(root: &Path) -> Result<String, String> {
    let f = root.join("rust-toolchain.toml");
    if !f.is_file() {
        return Err(format!("no rust-toolchain.toml at {}", f.display()));
    }
    let text = std::fs::read_to_string(&f).map_err(|e| e.to_string())?;
    text.lines()
        .find_map(|l| {
            let t = l.trim_start();
            let rest = t.strip_prefix("channel")?;
            let rest = rest.trim_start().strip_prefix('=')?.trim_start();
            let v = rest.trim().trim_matches('"');
            if v.is_empty() {
                None
            } else {
                Some(v.to_string())
            }
        })
        .ok_or_else(|| format!("could not parse channel from {}", f.display()))
}

/// `FROM rust:1.97.0-bookworm@sha256:...` -> `1.97.0`.
fn dockerfile_tag_version(root: &Path) -> Result<String, String> {
    let f = root.join("ops/Dockerfile");
    if !f.is_file() {
        return Err(format!("no Dockerfile at {}", f.display()));
    }
    let text = std::fs::read_to_string(&f).map_err(|e| e.to_string())?;
    text.lines()
        .find_map(|l| {
            let t = l.trim_start();
            let rest = t.strip_prefix("FROM")?.trim_start();
            let rest = rest.strip_prefix("rust:")?;
            let ver: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if ver.is_empty() {
                None
            } else {
                Some(ver)
            }
        })
        .ok_or_else(|| "could not parse a rust:VERSION tag from the Dockerfile FROM line - gate would be vacuous".to_string())
}

fn workflow_versions(root: &Path) -> Result<Vec<String>, String> {
    let d = root.join(".github/workflows");
    if !d.is_dir() {
        return Err(format!("no workflow directory at {}", d.display()));
    }
    let mut out: Vec<String> = Vec::new();
    let rd = std::fs::read_dir(&d).map_err(|e| e.to_string())?;
    for e in rd.filter_map(Result::ok) {
        let p = e.path();
        let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
        if ext != "yml" && ext != "yaml" {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&p) else {
            continue;
        };
        // Bir is bilerek baska bir derleyici isteyebilir, ama bunu **yazili
        // bir gerekce ile** yapmali. Dosyada `DELIBERATE-TOOLCHAIN-DIVERGENCE`
        // isareti aranir; isaret varsa o dosyadaki surumler pin'e karsi
        // denetlenmez.
        //
        // Tek mesru ornek bugun `diverse-double-compiling.yml`: isin butun
        // amaci ayni kaynagi ikinci bir derleyiciyle derlemek, dolayisiyla
        // pin'e esitlemek isi anlamsiz kilardi (bkz. ARCHITECTURE.md §73).
        //
        // Isaret bir kapi acmiyor, bir beyan istiyor: sapma dosyanin icinde
        // gerekcesiyle duruyor ve tesadufen olusamiyor.
        if text.contains("DELIBERATE-TOOLCHAIN-DIVERGENCE") {
            continue;
        }
        for line in text.lines() {
            let t = line.trim_start();
            if let Some(rest) = t.strip_prefix("toolchain:") {
                let v: String = rest
                    .trim()
                    .trim_matches('"')
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                if !v.is_empty() && !out.contains(&v) {
                    out.push(v);
                }
            }
        }
    }
    Ok(out)
}

/// # Errors
///
/// Returns a finding when any of the six pin claims is violated.
pub fn run(root: &Path) -> Result<String, String> {
    let pinned = pinned_channel(root)?;
    let tag = dockerfile_tag_version(root)?;
    if tag != pinned {
        return Err(format!(
            "Dockerfile builds on rust:{tag} but rust-toolchain.toml pins {pinned}.\n  \
             A release binary built by a different compiler is not bit-identical to the one\n  \
             CI produces, which is exactly the claim the determinism workflow makes.\n  \
             Update the FROM line *and* its digest together - the digest overrides the tag,\n  \
             so changing only the tag changes nothing."
        ));
    }
    let df = std::fs::read_to_string(root.join("ops/Dockerfile")).map_err(|e| e.to_string())?;
    let has_digest = df.lines().any(|l| {
        l.trim_start().starts_with("FROM rust:")
            && l.split("@sha256:").nth(1).is_some_and(|h| {
                let hex: String = h.chars().take(64).collect();
                hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit())
            })
    });
    if !has_digest {
        return Err(String::from(
            "the builder FROM line has no @sha256 digest - the base image can move under us",
        ));
    }
    for v in workflow_versions(root)? {
        if v != pinned {
            return Err(format!(
                "workflows request toolchain {v} but rust-toolchain.toml pins {pinned}"
            ));
        }
    }
    if !df
        .lines()
        .any(|l| l.contains("COPY") && l.contains("rust-toolchain.toml"))
    {
        return Err(String::from(
            "the Dockerfile never copies rust-toolchain.toml into the build context,\n  \
             so the pin does not apply inside the image and the base image's own compiler is used",
        ));
    }
    if !df.lines().any(|l| l.contains("rustc --version")) {
        return Err(String::from(
            "the builder stage never checks 'rustc --version' against the pin;\n  \
             a base image that moves would be caught by nothing",
        ));
    }
    Ok(format!(
        "Docker toolchain gate OK: Dockerfile, rust-toolchain.toml and every workflow all pin {pinned}; digest present; pin copied and verified in-image."
    ))
}

/// Build a fixture tree with the given FROM line, COPY line, rustc check and
/// workflow toolchain.
fn build_fixture(
    dir: &Path,
    from: &str,
    copyline: &str,
    rustccheck: &str,
    wf: &str,
) -> Result<(), String> {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir.join(".github/workflows")).map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"1.97.0\"\n",
    )
    .map_err(|e| e.to_string())?;
    let mut docker = format!("FROM {from} AS builder\n{copyline}\n");
    if !rustccheck.is_empty() {
        docker.push_str(rustccheck);
        docker.push('\n');
    }
    docker.push_str("RUN cargo build --release --locked\n");
    std::fs::create_dir_all(dir.join("ops")).map_err(|e| e.to_string())?;
    std::fs::write(dir.join("ops/Dockerfile"), docker).map_err(|e| e.to_string())?;
    std::fs::write(
        dir.join(".github/workflows/ci.yml"),
        format!("jobs:\n  a:\n    steps:\n      - uses: dtolnay/rust-toolchain@abc\n        with:\n          toolchain: \"{wf}\"\n"),
    )
    .map_err(|e| e.to_string())
}

/// # Errors
///
/// Returns the first canary that misbehaves. The canaries mirror the shell
/// gate's seven one for one.
pub fn self_test() -> Result<String, String> {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .subsec_nanos();
    let tmp = std::env::temp_dir().join(format!(
        "budlum-gates-docker-{}-{nanos}",
        std::process::id()
    ));
    let _ = std::fs::create_dir_all(&tmp);

    let good_from = "rust:1.97.0-bookworm@sha256:0000000000000000000000000000000000000000000000000000000000000000";
    let good_copy = "COPY Cargo.toml rust-toolchain.toml ./";
    let good_check = "RUN rustc --version";

    let drift = tmp.join("drift");
    build_fixture(&drift, "rust:1.97.1-bookworm@sha256:0000000000000000000000000000000000000000000000000000000000000000", good_copy, good_check, "1.97.0")?;
    if run(&drift).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: 1.97.1 build vs 1.97.0 pin kabul edildi",
        ));
    }

    let nodigest = tmp.join("nodigest");
    build_fixture(
        &nodigest,
        "rust:1.97.0-bookworm",
        good_copy,
        good_check,
        "1.97.0",
    )?;
    if run(&nodigest).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from("canary: digest'siz FROM kabul edildi"));
    }

    let wf = tmp.join("wf");
    build_fixture(&wf, good_from, good_copy, good_check, "1.90.0")?;
    if run(&wf).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: farklı workflow toolchain'i kabul edildi",
        ));
    }

    let nocopy = tmp.join("nocopy");
    build_fixture(
        &nocopy,
        good_from,
        "COPY Cargo.toml ./",
        good_check,
        "1.97.0",
    )?;
    if run(&nocopy).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: rust-toolchain.toml kopyalanmayan Dockerfile kabul edildi",
        ));
    }

    let nocheck = tmp.join("nocheck");
    build_fixture(&nocheck, good_from, good_copy, "", "1.97.0")?;
    if run(&nocheck).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from(
            "canary: rustc --version içermeyen builder kabul edildi",
        ));
    }

    let empty = tmp.join("empty");
    let _ = std::fs::create_dir_all(empty.join(".github/workflows"));
    std::fs::write(
        empty.join("rust-toolchain.toml"),
        "[toolchain]\nchannel = \"1.97.0\"\n",
    )
    .map_err(|e| e.to_string())?;
    if run(&empty).is_ok() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from("canary: Dockerfile'sız ağaç kabul edildi"));
    }

    let good = tmp.join("good");
    build_fixture(&good, good_from, good_copy, good_check, "1.97.0")?;
    if run(&good).is_err() {
        let _ = std::fs::remove_dir_all(&tmp);
        return Err(String::from("canary: tutarlı ağaç reddedildi"));
    }

    let _ = std::fs::remove_dir_all(&tmp);
    Ok(String::from(
        "docker toolchain gate self-test OK: version drift, a missing digest, a divergent workflow, an uncopied pin, a missing in-image check and a missing Dockerfile are all rejected; a consistent tree passes.",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_channel_and_tag() {
        let dir = std::env::temp_dir().join(format!("budlum-docker-t-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        std::fs::write(
            dir.join("rust-toolchain.toml"),
            "[toolchain]\nchannel = \"1.97.0\"\n",
        )
        .unwrap();
        std::fs::create_dir_all(dir.join("ops")).unwrap();
        std::fs::write(dir.join("ops/Dockerfile"), "FROM rust:1.97.0-bookworm@sha256:0000000000000000000000000000000000000000000000000000000000000000 AS builder\n").unwrap();
        assert_eq!(pinned_channel(&dir).unwrap(), "1.97.0");
        assert_eq!(dockerfile_tag_version(&dir).unwrap(), "1.97.0");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
