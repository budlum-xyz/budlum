#!/usr/bin/env python3
"""Inventory the storage migration surface without removing or rewriting it.

Run from the repository root: python3 docs/audit/live/storage_inventory.py
Counts are literal identifier mentions in tracked UTF-8 files, not evidence
that a feature is live or safe to remove. Re-run on the branch being audited.
"""
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]

# The table separates node persistence from content storage even though both
# currently live under src/storage. Keep the full paths explicit.
PATHS = {
    "Move node persistence": """src/storage/db.rs src/storage/traits.rs src/storage/merkle_trie.rs src/storage/pruning.rs src/storage/witness_retention.rs""",
    "Migrate content storage": """src/storage/content_id.rs src/storage/three_recipe.rs src/storage/qr_recipe.rs src/storage/qr_payload.rs src/storage/qr_reemit.rs src/storage/qr_carousel.rs src/storage/qr_frame.rs src/storage/qr_encode.rs src/storage/qr_matrix.rs src/storage/qr_png.rs src/storage/qr_codec.rs src/storage/qr_receive.rs src/storage/qr_verify.rs src/storage/qr_verify_indep.rs src/storage/qr_video.rs src/storage/emit.rs src/storage/three_pipe.rs src/storage/three_nft.rs src/storage/three_reveal.rs src/storage/three_rpc.rs src/storage/reveal_gateway.rs src/storage/three_gate.rs src/storage/three_hooks.rs src/storage/three_meter.rs src/storage/three_visibility.rs src/storage/assignment.rs src/storage/dictionary.rs src/storage/derived.rs src/storage/transformed.rs src/storage/living_threshold.rs src/storage/key_package.rs src/storage/payload_crypt.rs src/storage/view_grant.rs src/storage/social_delete.rs src/domain/storage_tx.rs src/gateway/service.rs bud/ docs/BUD_STORAGE_ROADMAP.md docs/BUD_CONTENT_ENCRYPTION.md""",
    "Remove after replacement": """src/storage/manifest.rs src/storage/erasure.rs src/storage/lrc.rs src/storage/msr.rs src/storage/column_commitment.rs src/storage/provider.rs src/storage/lifecycle.rs src/storage/one_share.rs src/storage/one_view.rs src/storage/mobile_self.rs src/storage/server_admission.rs src/storage/generated.rs src/storage/render.rs src/storage/fixed_point.rs src/storage/pact_binding.rs src/storage/three_regime.rs src/domain/storage_deal.rs src/domain/storage_params.rs src/domain/deal_open.rs src/chain/storage_economics_tests.rs src/chain/storage_maintenance.rs budzero/bud-node/""",
    "Move state recovery": """src/domain/regeneration_stage.rs src/domain/regen_health.rs src/domain/regen_mempool.rs src/network/regen_health_tick.rs""",
}

IDENTIFIERS = """ContentManifest ErasureScheme ReedSolomon EncodedObject LrcLayout MsrError StorageRegistry StorageDealOpen OpenDeal AnswerCodingAudit AcceptReallocation OpenChallenge AnswerChallenge StorageProvider InMemoryStorageProvider BudStorageEdition GeneratedSpec MobileSelfProfile MobileSelfContentPolicy CustodyLedger ServerAdmission OneShareRegistry SingleScreenView PactBinding BudBitswap MemoryContentStore ContentDiscovery VideoRecipe ThreeRecipePublic bud_storageOpenDeal bud_storageRegisterManifest bud_storageQrFeedPreview""".split()
TRANSACTIONS = """RegisterManifest DeclareOperatorClass DeclareSelfHostPolicy OpenDeal AnswerCodingAudit AcceptReallocation OpenChallenge AnswerChallenge CommitConfidentialBody IssueViewGrant RevokeViewGrant SocialDelete""".split()
RPCS = """bud_storageAcceptReallocation bud_storageActiveOperators bud_storageAnswerChallenge bud_storageGetChallenges bud_storageGetConfidentialCommit bud_storageGetDealsByManifest bud_storageGetDealsByShard bud_storageGetEconomicsEvents bud_storageGetEconomicsSummary bud_storageGetManifest bud_storageGetOperatorEconomics bud_storageGetOutcome bud_storageOpenChallenge bud_storageOpenDeal bud_storageRegisterConfidentialCommit bud_storageRegisterManifest bud_storageRepairBand bud_storageVerifyEncoding bud_storageQrFeedFrames bud_storageQrFeedPreview""".split()


def tracked_files(root):
    output = subprocess.check_output(["git", "ls-files", "-z"], cwd=root)
    return [Path(p.decode()) for p in output.split(b"\0") if p]


def count_mentions(root, files, names):
    """Return whole-token mentions and distinct tracked files per name."""
    patterns = {n: re.compile(r"(?<![A-Za-z0-9_])" + re.escape(n) + r"(?![A-Za-z0-9_])") for n in names}
    counts = {n: [0, 0] for n in names}
    for path in files:
        try:
            text = (root / path).read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        for name, pattern in patterns.items():
            matches = len(pattern.findall(text))
            if matches:
                counts[name][0] += 1
                counts[name][1] += matches
    return counts


def main():
    files = tracked_files(ROOT)
    names = set(IDENTIFIERS + TRANSACTIONS + RPCS)
    counts = count_mentions(ROOT, files, names)
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    print("# Storage migration inventory\n")
    print(f"Snapshot: `{sha}`. Counts cover the working copies of tracked UTF-8 files, including tests, docs, configuration and CI. Untracked files are excluded. Literal mentions are not proof of live callers or deletion safety.\n")
    print("The target B.U.D. 3.0 implementation and each caller must be verified before any deletion. This inventory authorizes no deletion. The storage module also contains `mod.rs` and `README.md`, which are not individual rows in the migration table; review them during migration.\n")
    for group, paths in PATHS.items():
        print(f"## {group}\n\n| Path | Present |\n|---|---|")
        for path in paths.split():
            print(f"| `{path}` | {'yes' if (ROOT / path).exists() else 'no'} |")
        print()
    for title, entries in [("Forbidden identifiers", IDENTIFIERS), ("Legacy transaction variants", TRANSACTIONS), ("Legacy RPC names", RPCS)]:
        print(f"## {title}\n\n| Identifier | Files | Mentions |\n|---|---:|---:|")
        for name in entries:
            print(f"| `{name}` | {counts[name][0]} | {counts[name][1]} |")
        print()
    print("## Limitations\n\nA token count can include comments, tests and unrelated names. It does not find aliases, dynamic dispatch, generated code or external consumers. The `three_meter.rs` row is absent on this snapshot; do not infer that its function is unnecessary. Inspect callers and replacement paths separately before each migration.")


if __name__ == "__main__":
    main()
