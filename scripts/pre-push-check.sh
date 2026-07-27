#!/bin/bash
# Budlum Pre-push Check Script
# Kalıcı çözüm: push öncesi cargo fmt ve clippy kontrollerini zorunlu kılar.
# Push öncesi yerel doğrulama.

set -e

echo "Running Budlum Pre-push Checks..."

# 1. Format Check
echo "Checking code formatting..."
cargo fmt --all -- --check

# 2. Clippy Check (Strict)
echo "Running Clippy (Strict mode)..."
cargo clippy --all-targets --all-features -- -D warnings

# 3. Quick Test (Optional but recommended)
# Echo "Running unit tests..."
# Cargo test --lib

echo "✅ All checks passed! Safe to push."
