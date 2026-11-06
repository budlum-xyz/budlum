#!/usr/bin/env bash
# WP-46 drill T-6 (TLG-14): ecosystem tooling, code unchanged.
# Foundry, Hardhat, viem, CosmJS, Anchor, aptos CLI scenarios; one EVM contract
# calls a CW20 transfer in the SAME transaction and the result is atomic.
# Evidence: docs/rehearsal/T-6.md.
set -euo pipefail
echo "T-6: Foundry/Hardhat/viem/CosmJS/Anchor/aptos CLI + atomic EVM->CW20 call"
echo "PASS requires: all tool scenarios pass AND uel_evm_calls_wasm_atomically"
