#!/usr/bin/env bash
# Task 0.414 / MAINNET_READINESS §2.7 (Ayaz Karar = Seçenek A: İsteğe Bağlı Kabuk Betiği):
# Generate/refresh synthetic binary seed corpus files for BudZero ZKVM and STARK AIR fuzzing.
#
# Usage:
#   bash scripts/generate_zkvm_seed_corpus.sh [output_dir]
#
# If [output_dir] is omitted, defaults to ./fuzz/corpus/zkvm

set -euo pipefail

OUT_DIR="${1:-./fuzz/corpus/zkvm}"
mkdir -p "$OUT_DIR"

echo "🚀 Generating synthetic binary seed corpus files for BudZero ZKVM fuzzing in: $OUT_DIR"

# 1. Simple arithmetic & halt seed (Opcode::Add = 0x01, Opcode::Halt = 0x00)
printf "\x01\x01\x02\x03\x00\x00\x00\x00" > "$OUT_DIR/01_simple_add.bud"
echo "  [+] $OUT_DIR/01_simple_add.bud (Simple Add + Halt)"

# 2. Branching & control flow loop seed (Opcode::Jmp = 0x0A, Opcode::Add = 0x01)
printf "\x0a\x01\x02\x03\x05\x00\x00\x00\x12\x00\x00\x00\x00\x00\x00\x00" > "$OUT_DIR/02_branch_loop.bud"
echo "  [+] $OUT_DIR/02_branch_loop.bud (Branching Loop)"

# 3. VerifyMerkle (0x1E) path verification seed (Task 0.36 Z-B Commit 3.5 / Task 0.31 selector check)
printf "\x1e\x01\x02\x03\x00\x01\x00\x00" > "$OUT_DIR/03_verify_merkle_0x1E.bud"
echo "  [+] $OUT_DIR/03_verify_merkle_0x1E.bud (VerifyMerkle 0x1E Opcode)"

# 4. Poseidon4 hash round seed (Opcode::Poseidon = 0x1D)
printf "\x1d\x01\x02\x03\x0a\x00\x00\x00" > "$OUT_DIR/04_poseidon_hash.bud"
echo "  [+] $OUT_DIR/04_poseidon_hash.bud (Poseidon4 Hash)"

# 5. Memory load/store seed (Opcode::SRead = 0x10, Opcode::SWrite = 0x11)
printf "\x10\x01\x02\x00\x11\x01\x02\x00" > "$OUT_DIR/05_memory_ops.bud"
echo "  [+] $OUT_DIR/05_memory_ops.bud (Memory Operations)"

echo "✅ Synthetic ZKVM seed corpus generation complete. Total seeds: $(ls -1 "$OUT_DIR"/*.bud | wc -l)"
