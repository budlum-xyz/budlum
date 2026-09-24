#!/usr/bin/env python3
"""Budlum/FSF high-priority project fit map.

This is a phase-0 clean-room curation layer, not imported upstream code and
not a claim that the FSF work is fully adapted.  It records which projects
listed by fsf.org / the Free Software Directory are useful to Budlum modules
and, crucially, which license boundary is allowed before anyone writes a
Budlum-native implementation inspired by them.

The generated document is intentionally deterministic so CI or a reviewer can
see when the project fit matrix changed.  Follow-on implementation belongs in
separate design docs and commits per module.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import argparse
import sys

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "FSF_PROJECT_FIT.md"
SOURCE_PAGES = (
    "https://www.fsf.org/campaigns/priority-projects/",
    "https://directory.fsf.org/wiki/Collection:High_Priority_Projects",
)


@dataclass(frozen=True)
class ProjectFit:
    name: str
    fsf_entry: str
    license_summary: str
    boundary: str
    budlum_modules: tuple[str, ...]
    adaptation: str
    next_step: str

    @property
    def risk(self) -> str:
        text = f"{self.license_summary} {self.boundary}".lower()
        if "agpl" in text or "gpl" in text and "lgpl" not in text and "exception" not in text:
            return "design-only"
        if "unknown" in text or "mixed" in text:
            return "review-first"
        if "lgpl" in text or "mpl" in text:
            return "boundary-ok"
        return "permissive-ok"


PROJECTS: tuple[ProjectFit, ...] = (
    ProjectFit(
        name="Matrix Synapse / Matrix protocol",
        fsf_entry="https://directory.fsf.org/wiki/Matrix-synapse",
        license_summary="Apache-2.0 in the FSF Directory entry",
        boundary="Protocol interop and clean-room tests are OK; do not vendor the homeserver.",
        budlum_modules=("src/network", "src/rpc", "src/ai_inference", "SocialFi bridge"),
        adaptation=(
            "Map Budlum AI/SocialFi output events onto Matrix-style room/event envelopes "
            "for federation tests. Keep the implementation native Rust and protocol-level."
        ),
        next_step="Add event-shape fixtures once the SocialFi bridge exposes a stable outbound schema.",
    ),
    ProjectFit(
        name="Pump.io / Activity Streams",
        fsf_entry="https://directory.fsf.org/wiki/Pump.io",
        license_summary="Apache-2.0 in the FSF Directory entry",
        boundary="Protocol ideas are safe; do not import server code without a separate provenance review.",
        budlum_modules=("src/ai_inference", "docs/ARCHITECTURE.md", "RPC event feeds"),
        adaptation=(
            "Use Activity Streams vocabulary as a compatibility target for AI-output/feed events, "
            "so Budlum events can be mirrored without a centralized SaaS dependency."
        ),
        next_step="Draft a Budlum event-to-ActivityStreams mapping after CI/Strix on PR #79 is green.",
    ),
    ProjectFit(
        name="Argos Translate",
        fsf_entry="https://directory.fsf.org/wiki/Argos_Translate",
        license_summary="Expat/MIT in the FSF Directory entry",
        boundary="Permissive enough for optional tooling; keep model assets out of consensus/runtime commits.",
        budlum_modules=("docs", "wallet UX", "Lubot / assistant surface", "i18n pipeline"),
        adaptation=(
            "Treat as an offline translation-provider shape for deterministic doc/UI localization. "
            "Budlum code should define a provider trait and golden translation fixtures, not call a hosted API."
        ),
        next_step="Create an i18n provider seam only if UI/doc localization becomes part of this PR line.",
    ),
    ProjectFit(
        name="Fairseq",
        fsf_entry="https://directory.fsf.org/wiki/Fairseq",
        license_summary="Expat/MIT in the FSF Directory entry",
        boundary="Permissive code, but model weights/datasets need their own provenance; use as benchmark inspiration.",
        budlum_modules=("crates/ai-inference", "src/ai_inference", "benchmark gates"),
        adaptation=(
            "Use the sequence-to-sequence benchmark pattern as a non-consensus AI inference benchmark profile. "
            "No model code belongs in consensus paths."
        ),
        next_step="Add only a manifest-level benchmark descriptor, not a dependency, when AI benchmark work resumes.",
    ),
    ProjectFit(
        name="CMU Sphinx / Coqui / DeepSpeech family",
        fsf_entry="https://directory.fsf.org/wiki/CMUSphinx-_Training",
        license_summary="BSD-2 / MPL-family entries in the FSF Directory collection",
        boundary="Use via optional process/service boundary; avoid adding STT crates to the node binary.",
        budlum_modules=("assistant ingestion", "accessibility", "off-chain AI workspace"),
        adaptation=(
            "Model a local speech-to-text adapter for accessibility and assistant ingestion. "
            "Consensus data must carry transcripts and provenance, not raw model-side effects."
        ),
        next_step="Keep as off-chain roadmap item; no runtime dependency in PR #79.",
    ),
    ProjectFit(
        name="GNUnet",
        fsf_entry="https://directory.fsf.org/wiki/GNUnet",
        license_summary="unknown / review required in the FSF Directory collection entry",
        boundary="Design-only until license/provenance is reviewed; do not copy code.",
        budlum_modules=("src/network", "src/storage", "reputation / trust routing"),
        adaptation=(
            "Borrow the architectural separation: identity, peer discovery, content routing, and reputation should "
            "remain separate Budlum modules with explicit threat-model docs."
        ),
        next_step="Write a design comparison before any P2P routing code is changed.",
    ),
    ProjectFit(
        name="GNU Taler",
        fsf_entry="https://directory.fsf.org/wiki/Taler",
        license_summary="AGPL/GPL/LGPL mix in the FSF Directory entry",
        boundary="Do not import source into this tree. Use only standards-level design notes unless relicensed/isolated.",
        budlum_modules=("economy", "settlement", "receipt / payment proofs", "wallet-core"),
        adaptation=(
            "Adapt the accountability pattern: anonymous customer side, auditable merchant/operator side, explicit receipts. "
            "Implement Budlum-native proofs rather than Taler code."
        ),
        next_step="Turn into a settlement design memo, not a code dependency.",
    ),
    ProjectFit(
        name="GnuPG / Libgcrypt / GnuTLS",
        fsf_entry="https://directory.fsf.org/wiki/Gnupg",
        license_summary="Mixed permissive/GPL/LGPL entries in FSF Directory",
        boundary="Use protocol/test-vector knowledge or OS process boundary; do not vendor GPL crypto code.",
        budlum_modules=("wallet-core", "src/crypto", "ops key management", "TLS/network hardening"),
        adaptation=(
            "Add compatibility vectors and key-handling threat-model checks; keep cryptographic primitives in already-vetted Rust crates."
        ),
        next_step="Use for test-vector sourcing only after provenance is documented in docs/NOTICE.",
    ),
    ProjectFit(
        name="FOSSology / GNU Licenseutils",
        fsf_entry="https://directory.fsf.org/wiki/FOSSology",
        license_summary="LGPL/GPL-with-exception / GPL-family entries in FSF Directory",
        boundary="Process-boundary or clean-room gate only; no GPL source copy.",
        budlum_modules=("xtask/gates", ".github/workflows", "supply-chain policy"),
        adaptation=(
            "Budlum already has cargo-vet, deny, OSV, grype and license gates. The useful adaptation is a curated "
            "import-boundary matrix so GPL/AGPL projects cannot be silently vendored."
        ),
        next_step="This file is that clean-room adaptation; wire it to CI only after PR #79 stabilizes.",
    ),
    ProjectFit(
        name="Monero Core",
        fsf_entry="https://directory.fsf.org/wiki/Monero_Core",
        license_summary="BSD-3-Clause in the FSF Directory entry",
        boundary="Permissive, but privacy-crypto code still needs independent cryptographic review before reuse.",
        budlum_modules=("note-packing", "wallet privacy", "settlement privacy research"),
        adaptation=(
            "Use as research reference for decoy/amount privacy threat models. Do not introduce ring-signature code without a bar like BPQS."
        ),
        next_step="Add to privacy research backlog, not current PR code.",
    ),
    ProjectFit(
        name="Tor / I2P / Ricochet family",
        fsf_entry="https://directory.fsf.org/wiki/Tor",
        license_summary="Mixed/varies across entries; Ricochet listed BSD-3-Clause",
        boundary="Prefer sidecar/proxy compatibility and SOCKS tests over vendored anonymity-network code.",
        budlum_modules=("src/network", "devnet", "operator privacy", "RPC exposure"),
        adaptation=(
            "Define network egress/proxy seams so nodes and operator tools can run behind Tor/I2P without browser-style leaks."
        ),
        next_step="Add proxy-seam tests only when network PR scope opens; avoid expanding PR #79 further.",
    ),
)


def render() -> str:
    rows = []
    for p in PROJECTS:
        rows.append(
            "| {name} | {risk} | {modules} | {adaptation} | {next_step} |".format(
                name=f"[{p.name}]({p.fsf_entry})",
                risk=p.risk,
                modules="<br>".join(p.budlum_modules),
                adaptation=p.adaptation.replace("|", "\\|"),
                next_step=p.next_step.replace("|", "\\|"),
            )
        )
    return "\n".join(
        [
            "# FSF high-priority project fit for Budlum",
            "",
            "This document is generated by `tools/fsf_project_fit.py`. It is **phase 0**:",
            "a clean-room curation of FSF/Free Software Directory project ideas against",
            "Budlum modules, not a completed implementation and not a claim that the FSF",
            "work has been fully adapted. It does **not** copy upstream project code.",
            "Budlum is currently licensed under PolyForm Shield, so GPL/AGPL source",
            "imports are treated as design-only unless a separate legal/provenance",
            "decision creates an explicit boundary.",
            "",
            "Sources inspected:",
            *[f"- {url}" for url in SOURCE_PAGES],
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
            *rows,
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
    )


def check_policy() -> list[str]:
    errors: list[str] = []
    seen = set()
    for p in PROJECTS:
        if p.name in seen:
            errors.append(f"duplicate project: {p.name}")
        seen.add(p.name)
        if p.risk == "permissive-ok" and any(x in p.license_summary.lower() for x in ("gpl", "agpl")):
            errors.append(f"copyleft marked permissive: {p.name}")
        if p.risk == "design-only" and "do not" not in p.boundary.lower() and "design-only" not in p.boundary.lower():
            errors.append(f"design-only project lacks hard boundary wording: {p.name}")
        if not p.budlum_modules:
            errors.append(f"no module mapping: {p.name}")
    return errors


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="write docs/FSF_PROJECT_FIT.md")
    parser.add_argument("--check", action="store_true", help="verify generated doc and policy")
    parser.add_argument("--self-test", action="store_true", help="run policy canaries")
    args = parser.parse_args(argv)

    errors = check_policy()
    if args.self_test:
        if errors:
            print("\n".join(errors), file=sys.stderr)
            return 1
        print(f"fsf project fit self-test ok: {len(PROJECTS)} projects")
        return 0

    content = render()
    if args.write:
        DOC.write_text(content, encoding="utf-8")
        print(f"wrote {DOC.relative_to(ROOT)}")
        return 0

    if args.check:
        if errors:
            print("\n".join(errors), file=sys.stderr)
            return 1
        if not DOC.exists():
            print(f"missing {DOC.relative_to(ROOT)}", file=sys.stderr)
            return 1
        actual = DOC.read_text(encoding="utf-8")
        if actual != content:
            print(f"{DOC.relative_to(ROOT)} is not generated from tools/fsf_project_fit.py", file=sys.stderr)
            return 1
        print("fsf project fit doc ok")
        return 0

    print(content)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
