#!/bin/bash
# Budlum Pre-push Check Script
# Kalıcı çözüm: push öncesi cargo fmt ve clippy kontrollerini zorunlu kılar.
# ADIM 5 §5.4 / Hedef 3 (ARENA3 görevi, ARENA2 tarafından uygulandı)

set -e

echo "Running Budlum Pre-push Checks..."

# 1. Format Check
echo "Checking code formatting..."
cargo fmt --all -- --check

# 2. Clippy Check (Strict)
echo "Running Clippy (Strict mode)..."
cargo clippy --all-targets --all-features -- -D warnings

# 3. Quick Test (Optional but recommended)
# echo "Running unit tests..."
# cargo test --lib

echo "✅ All checks passed! Safe to push."
