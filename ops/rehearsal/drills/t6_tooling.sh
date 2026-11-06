#!/usr/bin/env bash
# WP-46 drill T-6 (TLG-14): ecosystem tooling, code unchanged.
# Foundry, Hardhat, viem, CosmJS, Anchor and the aptos CLI, plus one EVM
# contract calling a CW20 transfer in the SAME transaction, atomically.
# Evidence: docs/rehearsal/T-6.md.
source "$(dirname "$0")/lib.sh"
drill_begin T-6 "ecosystem tooling and the atomic EVM to CW20 call"
check 'm["tool_scenarios_passed"] == m["tool_scenarios_total"]' \
    "every toolchain scenario passed"
check 'm["atomic_evm_call"] is True' "the EVM to CW20 call committed as one transaction"
drill_end
