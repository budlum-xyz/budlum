# Skills installation — 2026-11-16

Cloned shallow to `budlum-work/skills/` (outside repo, not committed to Budlum):
- mattpocock/skills (1.7 MB) — "Skills For Real Engineers". Install via Claude Code / Codex / Copilot plugin marketplaces (CLIs not present in sandbox). Read as: small composable engineering skills, not process-owning frameworks. Working principle adopted: small, adaptable skills, keep control, avoid vibe-coding.
- obra/superpowers (3.0 MB) — complete SDLC methodology on composable skills. Install per harness (Claude Code marketplace, Codex, Cursor, etc. — none present). Working principle adopted: spec -> plan -> TDD red/green -> subagent-driven implementation, YAGNI/DRY, junior-engineer-readable plans.
- affaan-m/ECC (105 MB) — agent harness OS, commands/agents/skills. Install via npm ecc-universal / GitHub App (not installed). Working principle adopted: harness commands, agent definitions, quick-ref.
- usestrix/strix (15 MB) — open-source AI pentesting tool, Python (uv/pip, `strix-agent` on PyPI). Not installed as binary in this pass (needs LLM API key + docker for dynamic pentest). Method imitated manually: attack surface -> trace code path end-to-end -> test/prove each claim. See strix-ledger.md.

No skill files are committed to Budlum repo (repo is English-only, tree_is_english gate; skills are agent-local). Installation is clone + read; plugin marketplace install requires Claude Code/Codex/Copilot CLI which are absent in sandbox — documented as environment limit, not skipped silently.
