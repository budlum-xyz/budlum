//! The FSF high-priority project fit map for Budlum.
//!
//! It replaces `tools/fsf_project_fit.py`.
//!
//! This is a phase-0 clean-room curation layer, not imported upstream code and
//! not a claim that the FSF work is fully adapted. It records which projects
//! listed by fsf.org and the Free Software Directory are useful to Budlum
//! modules and which license boundary is allowed before anyone writes a
//! Budlum-native implementation inspired by them.
//!
//! The generated document is deterministic so CI or a reviewer can see when
//! the project fit matrix changed. Follow-on implementation belongs in
//! separate design docs and commits per module.
//!
//! Modes: `--write` writes `docs/FSF_PROJECT_FIT.md`, `--check` verifies the
//! document and the policy, `--self-test` runs the policy canaries, and no mode
//! prints the document.

use std::collections::HashSet;
use std::path::Path;

use crate::report::Report;

const DOC_REL: &str = "docs/FSF_PROJECT_FIT.md";
const TOOL_REL: &str = "xtask/tools/src/fsf_fit.rs";
const SOURCE_PAGES: &[&str] = &[
    "https://www.fsf.org/campaigns/priority-projects/",
    "https://directory.fsf.org/wiki/Collection:High_Priority_Projects",
];

/// One curated project.
pub struct ProjectFit {
    pub name: &'static str,
    pub fsf_entry: &'static str,
    pub license_summary: &'static str,
    pub boundary: &'static str,
    pub budlum_modules: &'static [&'static str],
    pub adaptation: &'static str,
    pub next_step: &'static str,
}

impl ProjectFit {
    /// The import policy this project falls under.
    #[must_use]
    pub fn risk(&self) -> &'static str {
        let text = format!("{} {}", self.license_summary, self.boundary).to_lowercase();
        if text.contains("agpl")
            || (text.contains("gpl") && !text.contains("lgpl") && !text.contains("exception"))
        {
            return "design-only";
        }
        if text.contains("unknown") || text.contains("mixed") {
            return "review-first";
        }
        if text.contains("lgpl") || text.contains("mpl") {
            return "boundary-ok";
        }
        "permissive-ok"
    }
}

const PROJECTS: &[ProjectFit] = &[
    ProjectFit {
        name: "Matrix Synapse / Matrix protocol",
        fsf_entry: "https://directory.fsf.org/wiki/Matrix-synapse",
        license_summary: "Apache-2.0 in the FSF Directory entry",
        boundary: "Protocol interop and clean-room tests are OK; do not vendor the homeserver.",
        budlum_modules: &["src/network", "src/rpc", "src/ai_inference", "SocialFi bridge"],
        adaptation: "Map Budlum AI/SocialFi output events onto Matrix-style room/event envelopes for federation tests. Keep the implementation native Rust and protocol-level.",
        next_step: "Add event-shape fixtures once the SocialFi bridge exposes a stable outbound schema.",
    },
    ProjectFit {
        name: "Pump.io / Activity Streams",
        fsf_entry: "https://directory.fsf.org/wiki/Pump.io",
        license_summary: "Apache-2.0 in the FSF Directory entry",
        boundary: "Protocol ideas are safe; do not import server code without a separate provenance review.",
        budlum_modules: &["src/ai_inference", "docs/ARCHITECTURE.md", "RPC event feeds"],
        adaptation: "Use Activity Streams vocabulary as a compatibility target for AI-output/feed events, so Budlum events can be mirrored without a centralized SaaS dependency.",
        next_step: "Draft a Budlum event-to-ActivityStreams mapping after CI/Strix on PR #79 is green.",
    },
    ProjectFit {
        name: "Argos Translate",
        fsf_entry: "https://directory.fsf.org/wiki/Argos_Translate",
        license_summary: "Expat/MIT in the FSF Directory entry",
        boundary: "Permissive enough for optional tooling; keep model assets out of consensus/runtime commits.",
        budlum_modules: &["docs", "wallet UX", "Lubot / assistant surface", "i18n pipeline"],
        adaptation: "Treat as an offline translation-provider shape for deterministic doc/UI localization. Budlum code should define a provider trait and golden translation fixtures, not call a hosted API.",
        next_step: "Create an i18n provider seam only if UI/doc localization becomes part of this PR line.",
    },
    ProjectFit {
        name: "Fairseq",
        fsf_entry: "https://directory.fsf.org/wiki/Fairseq",
        license_summary: "Expat/MIT in the FSF Directory entry",
        boundary: "Permissive code, but model weights/datasets need their own provenance; use as benchmark inspiration.",
        budlum_modules: &["crates/ai-inference", "src/ai_inference", "benchmark gates"],
        adaptation: "Use the sequence-to-sequence benchmark pattern as a non-consensus AI inference benchmark profile. No model code belongs in consensus paths.",
        next_step: "Add only a manifest-level benchmark descriptor, not a dependency, when AI benchmark work resumes.",
    },
    ProjectFit {
        name: "CMU Sphinx / Coqui / DeepSpeech family",
        fsf_entry: "https://directory.fsf.org/wiki/CMUSphinx-_Training",
        license_summary: "BSD-2 / MPL-family entries in the FSF Directory collection",
        boundary: "Use via optional process/service boundary; avoid adding STT crates to the node binary.",
        budlum_modules: &["assistant ingestion", "accessibility", "off-chain AI workspace"],
        adaptation: "Model a local speech-to-text adapter for accessibility and assistant ingestion. Consensus data must carry transcripts and provenance, not raw model-side effects.",
        next_step: "Keep as off-chain roadmap item; no runtime dependency in PR #79.",
    },
    ProjectFit {
        name: "GNUnet",
        fsf_entry: "https://directory.fsf.org/wiki/GNUnet",
        license_summary: "unknown / review required in the FSF Directory collection entry",
        boundary: "Design-only until license/provenance is reviewed; do not copy code.",
        budlum_modules: &["src/network", "src/storage", "reputation / trust routing"],
        adaptation: "Borrow the architectural separation: identity, peer discovery, content routing, and reputation should remain separate Budlum modules with explicit threat-model docs.",
        next_step: "Write a design comparison before any P2P routing code is changed.",
    },
    ProjectFit {
        name: "GNU Taler",
        fsf_entry: "https://directory.fsf.org/wiki/Taler",
        license_summary: "AGPL/GPL/LGPL mix in the FSF Directory entry",
        boundary: "Do not import source into this tree. Use only standards-level design notes unless relicensed/isolated.",
        budlum_modules: &["economy", "settlement", "receipt / payment proofs", "wallet-core"],
        adaptation: "Adapt the accountability pattern: anonymous customer side, auditable merchant/operator side, explicit receipts. Implement Budlum-native proofs rather than Taler code.",
        next_step: "Turn into a settlement design memo, not a code dependency.",
    },
    ProjectFit {
        name: "GnuPG / Libgcrypt / GnuTLS",
        fsf_entry: "https://directory.fsf.org/wiki/Gnupg",
        license_summary: "Mixed permissive/GPL/LGPL entries in FSF Directory",
        boundary: "Use protocol/test-vector knowledge or OS process boundary; do not vendor GPL crypto code.",
        budlum_modules: &["wallet-core", "src/crypto", "ops key management", "TLS/network hardening"],
        adaptation: "Add compatibility vectors and key-handling threat-model checks; keep cryptographic primitives in already-vetted Rust crates.",
        next_step: "Use for test-vector sourcing only after provenance is documented in docs/NOTICE.",
    },
    ProjectFit {
        name: "FOSSology / GNU Licenseutils",
        fsf_entry: "https://directory.fsf.org/wiki/FOSSology",
        license_summary: "LGPL/GPL-with-exception / GPL-family entries in FSF Directory",
        boundary: "Process-boundary or clean-room gate only; no GPL source copy.",
        budlum_modules: &["xtask/gates", ".github/workflows", "supply-chain policy"],
        adaptation: "Budlum already has cargo-vet, deny, OSV, grype and license gates. The useful adaptation is a curated import-boundary matrix so GPL/AGPL projects cannot be silently vendored.",
        next_step: "This file is that clean-room adaptation; wire it to CI only after PR #79 stabilizes.",
    },
    ProjectFit {
        name: "Monero Core",
        fsf_entry: "https://directory.fsf.org/wiki/Monero_Core",
        license_summary: "BSD-3-Clause in the FSF Directory entry",
        boundary: "Permissive, but privacy-crypto code still needs independent cryptographic review before reuse.",
        budlum_modules: &["note-packing", "wallet privacy", "settlement privacy research"],
        adaptation: "Use as research reference for decoy/amount privacy threat models. Do not introduce ring-signature code without a bar like BPQS.",
        next_step: "Add to privacy research backlog, not current PR code.",
    },
    ProjectFit {
        name: "Tor / I2P / Ricochet family",
        fsf_entry: "https://directory.fsf.org/wiki/Tor",
        license_summary: "Mixed/varies across entries; Ricochet listed BSD-3-Clause",
        boundary: "Prefer sidecar/proxy compatibility and SOCKS tests over vendored anonymity-network code.",
        budlum_modules: &["src/network", "devnet", "operator privacy", "RPC exposure"],
        adaptation: "Define network egress/proxy seams so nodes and operator tools can run behind Tor/I2P without browser-style leaks.",
        next_step: "Add proxy-seam tests only when network PR scope opens; avoid expanding PR #79 further.",
    },
];

/// The deterministic document.
#[must_use]
pub fn render() -> String {
    let rows: Vec<String> = PROJECTS
        .iter()
        .map(|p| {
            format!(
                "| [{}]({}) | {} | {} | {} | {} |",
                p.name,
                p.fsf_entry,
                p.risk(),
                p.budlum_modules.join("<br>"),
                p.adaptation.replace('|', "\\|"),
                p.next_step.replace('|', "\\|"),
            )
        })
        .collect();
    let sources: Vec<String> = SOURCE_PAGES.iter().map(|url| format!("- {url}")).collect();
    let mut lines: Vec<String> = Vec::new();
    lines.extend(
        [
            "# FSF high-priority project fit for Budlum",
            "",
            "This document is generated by `cargo run --manifest-path xtask/tools/Cargo.toml -- fsf-project-fit --write`",
            "(source: `xtask/tools/src/fsf_fit.rs`). It is **phase 0**:",
            "a clean-room curation of FSF/Free Software Directory project ideas against",
            "Budlum modules, not a completed implementation and not a claim that the FSF",
            "work has been fully adapted. It does **not** copy upstream project code.",
            "Budlum is currently licensed under PolyForm Shield, so GPL/AGPL source",
            "imports are treated as design-only unless a separate legal/provenance",
            "decision creates an explicit boundary.",
            "",
            "Sources inspected:",
        ]
        .map(String::from),
    );
    lines.extend(sources);
    lines.extend(
        [
            "",
            "## Import policy",
            "",
            "- `permissive-ok`: protocol ideas or permissively licensed code may be considered,",
            "  but cryptography/model/data assets still need normal provenance review.",
            "- `boundary-ok`: LGPL/MPL or mixed cases stay behind dynamic/process/protocol",
            "  boundaries unless legal review approves tighter integration.",
            "- `design-only`: GPL/AGPL/copyleft or unknown-license code is not vendored into",
            "  this tree; only independently written Budlum-native implementations are allowed.",
            "- `review-first`: license data is incomplete or mixed; stop and document before coding.",
            "",
            "## Fit matrix",
            "",
            "| FSF-listed project | Policy | Budlum module fit | Clean-room adaptation | Next step |",
            "| --- | --- | --- | --- | --- |",
        ]
        .map(String::from),
    );
    lines.extend(rows);
    lines.extend(
        [
            "",
            "## Current coding decision",
            "",
            "The safe immediate adaptation is the matrix itself: it turns the FSF scan into a",
            "repo-local guardrail for future work. This is deliberately **not** the final",
            "Budlum implementation of any FSF project. The strongest code candidates for",
            "later Budlum-native changes are Matrix/Pump.io-style federation event shapes,",
            "Argos-style offline i18n provider seams, and FOSSology/licenseutils-style",
            "compliance gates. GPL/AGPL projects such as GNU Taler are useful for",
            "architecture but not for direct source import into the current Budlum tree.",
            "",
            "Follow-up work is tracked in `docs/FSF_ADAPTATION_PLAN.md` and must land as",
            "separate module-sized commits with their own tests.",
            "",
        ]
        .map(String::from),
    );
    lines.join("\n")
}

/// The policy findings. Empty means the curation is sound.
#[must_use]
pub fn check_policy() -> Vec<String> {
    let mut errors = Vec::new();
    let mut seen = HashSet::new();
    for p in PROJECTS {
        if !seen.insert(p.name) {
            errors.push(format!("duplicate project: {}", p.name));
        }
        let license = p.license_summary.to_lowercase();
        let boundary = p.boundary.to_lowercase();
        if p.risk() == "permissive-ok" && (license.contains("gpl") || license.contains("agpl")) {
            errors.push(format!("copyleft marked permissive: {}", p.name));
        }
        if p.risk() == "design-only"
            && !boundary.contains("do not")
            && !boundary.contains("design-only")
        {
            errors.push(format!(
                "design-only project lacks hard boundary wording: {}",
                p.name
            ));
        }
        if p.budlum_modules.is_empty() {
            errors.push(format!("no module mapping: {}", p.name));
        }
    }
    errors
}

fn usage() -> Report {
    Report::fail_with(
        "usage: fsf-project-fit [--write] [--check] [--self-test]\n".to_string(),
        2,
    )
}

/// Run the tool with its command line arguments.
#[must_use]
pub fn cli(args: &[&str], root: &Path) -> Report {
    let (mut write, mut check, mut self_test) = (false, false, false);
    for arg in args {
        match *arg {
            "--write" => write = true,
            "--check" => check = true,
            "--self-test" => self_test = true,
            _ => return usage(),
        }
    }
    let errors = check_policy();
    if self_test {
        if !errors.is_empty() {
            return Report::fail_with(format!("{}\n", errors.join("\n")), 1);
        }
        return Report::ok(format!(
            "fsf project fit self-test ok: {} projects\n",
            PROJECTS.len()
        ));
    }
    let content = render();
    let doc = root.join(DOC_REL);
    if write {
        return match std::fs::write(&doc, &content) {
            Ok(()) => Report::ok(format!("wrote {DOC_REL}\n")),
            Err(e) => Report::fail_with(format!("{DOC_REL} could not be written: {e}\n"), 1),
        };
    }
    if check {
        if !errors.is_empty() {
            return Report::fail_with(format!("{}\n", errors.join("\n")), 1);
        }
        let Ok(bytes) = std::fs::read(&doc) else {
            return Report::fail_with(format!("missing {DOC_REL}\n"), 1);
        };
        if String::from_utf8_lossy(&bytes) != content {
            return Report::fail_with(format!("{DOC_REL} is not generated from {TOOL_REL}\n"), 1);
        }
        return Report::ok("fsf project fit doc ok\n".to_string());
    }
    Report::ok(format!("{content}\n"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_curation_passes_its_own_policy() {
        assert_eq!(check_policy(), Vec::<String>::new());
        assert_eq!(PROJECTS.len(), 11);
    }

    #[test]
    fn risk_follows_the_license_text() {
        let base = ProjectFit {
            name: "t",
            fsf_entry: "u",
            license_summary: "MIT",
            boundary: "fine",
            budlum_modules: &["m"],
            adaptation: "a",
            next_step: "n",
        };
        assert_eq!(base.risk(), "permissive-ok");
        let agpl = ProjectFit {
            license_summary: "AGPL",
            ..base
        };
        assert_eq!(agpl.risk(), "design-only");
        let gpl_exception = ProjectFit {
            license_summary: "GPL with exception",
            boundary: "fine",
            ..agpl
        };
        assert_eq!(gpl_exception.risk(), "permissive-ok");
        let lgpl = ProjectFit {
            license_summary: "LGPL",
            ..gpl_exception
        };
        assert_eq!(lgpl.risk(), "boundary-ok");
        let unknown = ProjectFit {
            license_summary: "unknown",
            ..lgpl
        };
        assert_eq!(unknown.risk(), "review-first");
    }

    #[test]
    fn known_projects_land_in_the_expected_policy() {
        let risk_of = |name: &str| {
            PROJECTS
                .iter()
                .find(|p| p.name == name)
                .map(ProjectFit::risk)
        };
        assert_eq!(risk_of("GNU Taler"), Some("design-only"));
        assert_eq!(risk_of("GNUnet"), Some("review-first"));
        assert_eq!(risk_of("Argos Translate"), Some("permissive-ok"));
    }

    #[test]
    fn the_document_has_one_row_per_project_and_ends_with_a_newline() {
        let doc = render();
        assert!(doc.starts_with("# FSF high-priority project fit for Budlum\n"));
        assert!(doc.ends_with("tests.\n"));
        let rows = doc.lines().filter(|l| l.starts_with("| [")).count();
        assert_eq!(rows, PROJECTS.len());
    }

    #[test]
    fn the_committed_document_is_the_generated_one() {
        let path = crate::repo_root().join(DOC_REL);
        let committed = std::fs::read_to_string(path).expect("the document exists");
        assert_eq!(committed, render());
    }

    #[test]
    fn unknown_arguments_are_a_usage_error() {
        assert_eq!(cli(&["--bogus"], Path::new(".")).code, 2);
    }
}
