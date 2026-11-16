# Live status of directive findings

Inspection baseline: `81db9a2ada639beca443e6e2ebef4d29023ebbb0` (2026-11-09). This is a mechanical source inventory, not a verified reproduction run. Every directive finding starts **Unknown / unverified**, including BLG-005 (marked closed only in the old ledger). Source references point to Section 14 of the existing `THE_BUDLUM_DIREKTIF.md`, not a live source-code line or successful test. A planned closing package is not evidence of closure.

For each row, locate the current production path and file:line, choose or cite a permanent regression test, observe its pre-fix failure or a documented previously fixed condition, run the fix on a merged SHA, capture the CI ID and reviewer. Removal needs both a removed-path inventory and green `no-legacy-storage` output. Critical/High findings that remain open need a passing testnet feature-rejection test. See [FINDINGS.md](FINDINGS.md) for closure evidence.

| ID | Directive source | Severity | Planned package | Live status | Reproduction test/result | Live file:line evidence |
|---|---|---|---|---|---|---|
| BLG-001 | Section 14.3, L2591 | Critical | WP-12 | Unknown / unverified | Not recorded | Not collected |
| BLG-002 | Section 14.3, L2592 | High | WP-16 | Unknown / unverified | Not recorded | Not collected |
| BLG-003 | Section 14.3, L2593 | High | WP-16 | Unknown / unverified | Not recorded | Not collected |
| BLG-004 | Section 14.3, L2594 | Medium | WP-61 | Unknown / unverified | Not recorded | Not collected |
| BLG-005 | Section 14.3, L2595 | Medium | WP-16 | Unknown / unverified | Not recorded | Not collected |
| BLG-006 | Section 14.3, L2596 | Medium | WP-16 | Unknown / unverified | Not recorded | Not collected |
| BLG-007 | Section 14.3, L2597 | Medium | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-008 | Section 14.3, L2598 | Medium | WP-16 | Unknown / unverified | Not recorded | Not collected |
| BLG-009 | Section 14.3, L2599 | Medium | WP-61 | Unknown / unverified | Not recorded | Not collected |
| BLG-010 | Section 14.3, L2600 | Medium | WP-61 | Unknown / unverified | Not recorded | Not collected |
| BLG-011 | Section 14.3, L2601 | Medium | WP-41 | Unknown / unverified | Not recorded | Not collected |
| BLG-012 | Section 14.3, L2602 | High | WP-42 | Fixed in tree. The total line is read, and a NaN baseline is refused by the parser. | xtask gates coverage self-test: the_total_is_read_not_the_first_file | xtask/gates/src/gates/coverage.rs:44 |
| BLG-013 | Section 14.3, L2603 | Medium | WP-42 | Fixed in this round. The helper now runs the same clippy invocation CI runs, without the combination that cannot build. | xtask::tools budlum_tools prepush::tests::the_clippy_check_matches_the_ci_invocation | xtask/tools/src/prepush.rs:36 |
| BLG-014 | Section 14.3, L2604 | Medium | WP-42 | Fixed in tree. The restore exit code and the integrity exit code are both refused, and the integrity line is parsed, not substring matched. | xtask tools backup drill self-test | xtask/tools/src/backup_drill.rs:216 |
| BLG-015 | Section 14.3, L2605 | Medium | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-016 | Section 14.3, L2606 | High | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-017 | Section 14.3, L2607 | Critical | WP-15 | Fixed in tree. Every peer string reaches a log through a character-counted prefix; no byte slice of a peer string is left. | network::node::tests::log_prefix_survives_multibyte_input; network::node::tests::no_byte_slice_of_checkpoint_hash_in_logs | src/network/node.rs:405 |
| BLG-018 | Section 14.3, L2608 | Critical | WP-12 | Unknown / unverified | Not recorded | Not collected |
| BLG-019 | Section 14.3, L2609 | Critical | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-020 | Section 14.3, L2610 | Critical | WP-17 | Fixed in tree. Selection runs on a disposable candidate, and the block path demands the exact account nonce before any arm runs. | tests::regression_chain::producer_executes_on_a_disposable_candidate_state; tests::regression_chain::a_block_transaction_must_carry_the_exact_account_nonce | src/chain/blockchain.rs:4618; src/execution/executor.rs:4672 |
| BLG-021 | Section 14.3, L2611 | Critical | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-022 | Section 14.3, L2612 | Medium | WP-11 | Fixed in tree. Closed-form walk, no loop. | light_client::tests::next_checkpoint_height_is_closed_form; tests::regression_ops_crypto::next_checkpoint_height_terminates_at_the_u64_edge (both green, local run 2026-11-16) | src/light_client/mod.rs:689 |
| BLG-023 | Section 14.3, L2613 | Medium | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-024 | Section 14.3, L2614 | Low | WP-44 | Fixed in this round. A zero denominator requires every authority instead of calling div_ceil(0). | domain::finality_adapter::tests::a_poa_adapter_with_a_zero_denominator_requires_every_authority (green, local run 2026-11-16) | src/domain/finality_adapter.rs:815 |
| BLG-025 | Section 14.3, L2615 | Low | WP-45 | Unknown / unverified | Not recorded | Not collected |
| BLG-026 | Section 14.3, L2616 | Medium | WP-39 | Unknown / unverified | Not recorded | Not collected |
| BLG-027 | Section 14.3, L2617 | High | WP-12 | Unknown / unverified | Not recorded | Not collected |
| BLG-028 | Section 14.3, L2618 | High | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-029 | Section 14.3, L2619 | High | WP-61 | Unknown / unverified | Not recorded | Not collected |
| BLG-030 | Section 14.3, L2620 | Critical | WP-41, WP-61 | Unknown / unverified | Not recorded | Not collected |
| BLG-031 | Section 14.3, L2621 | Low | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-032 | Section 14.3, L2622 | Medium | WP-61 | Unknown / unverified | Not recorded | Not collected |
| BLG-033 | Section 14.3, L2623 | Critical | WP-15 | Fixed in tree. Every unbounded P2P decode goes through a byte-limited decoder. | network::bounded_bincode::tests (green in the lib run that carries this row) | src/network/bounded_bincode.rs:459 |
| BLG-034 | Section 14.3, L2624 | High | WP-15 | Unknown / unverified | Not recorded | Not collected |
| BLG-035 | Section 14.3, L2625 | Medium | WP-07 | Unknown / unverified | Not recorded | Not collected |
| BLG-036 | Section 14.3, L2626 | Critical | WP-33 | Unknown / unverified | Not recorded | Not collected |
| BLG-037 | Section 14.3, L2627 | Critical | WP-33 | Open. The feature is closed on testnet, which the TLG rule accepts as the launch state. | tests::testnet_closed_features::ai_execution_proof_is_closed_on_testnet; execution::budzero_ee::tests::verify_inference_is_closed_on_testnet (green in the lib run) | src/execution/budzero_ee/mod.rs:542 |
| BLG-038 | Section 14.3, L2628 | Critical | WP-33 | Unknown / unverified | Not recorded | Not collected |
| BLG-039 | Section 14.3, L2629 | Critical | WP-33 | Fixed in tree. A claimed degree above the verifier ceiling is refused before any shift. | budzero bud-proof verifier: degree_bits_ceiling_guards_goldilocks_two_adicity (green in the budzero crate run) | budzero/bud-proof/src/bud_stark/verifier.rs:359 |
| BLG-040 | Section 14.3, L2630 | High | WP-33 | Open. The feature is closed on testnet, which the TLG rule accepts as the launch state. | tests::testnet_closed_features::private_transfer_is_closed_on_testnet; execution::budzero_ee::tests::verify_merkle_is_closed_on_testnet (green in the lib run) | src/execution/budzero_ee/mod.rs:517 |
| BLG-041 | Section 14.3, L2631 | Critical | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-042 | Section 14.3, L2632 | Critical | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-043 | Section 14.3, L2633 | Critical | WP-44 | Fixed in tree. The unlock door re-derives the payload, refuses a zero recorded debit, checks the owner credit for overflow, and refuses a mismatched domain, sender or recipient. | cross_domain::bridge_tx tests around the unlock door | src/cross_domain/bridge_tx.rs:630 |
| BLG-044 | Section 14.3, L2634 | Medium | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-045 | Section 14.3, L2635 | Critical | WP-07 | Unknown / unverified | Not recorded | Not collected |
| BLG-046 | Section 14.3, L2636 | Critical | WP-07 | Unknown / unverified | Not recorded | Not collected |
| BLG-047 | Section 14.3, L2637 | High | WP-07 | Unknown / unverified | Not recorded | Not collected |
| BLG-048 | Section 14.3, L2638 | High | WP-19 | Unknown / unverified | Not recorded | Not collected |
| BLG-049 | Section 14.3, L2639 | Medium | WP-22 | Unknown / unverified | Not recorded | Not collected |
| BLG-050 | Section 14.3, L2640 | Critical | WP-44 | Unknown / unverified | Not recorded | Not collected |
| BLG-051 | Section 14.3, L2641 | High | WP-44 | Unknown / unverified | Not recorded | Not collected |
| BLG-052 | Section 14.3, L2642 | Medium | WP-44 | Unknown / unverified | Not recorded | Not collected |
| BLG-053 | Section 14.3, L2643 | High | WP-44 | Unknown / unverified | Not recorded | Not collected |
| BLG-054 | Section 14.3, L2644 | Critical | WP-44 | Unknown / unverified | Not recorded | Not collected |
| BLG-055 | Section 14.3, L2645 | Critical | WP-44 | Unknown / unverified | Not recorded | Not collected |
| BLG-056 | Section 14.3, L2646 | High | WP-44 | Fixed in tree. The bridge enforces `require_slashable` for every external domain it admits. | cross_domain::external::domain_bridge::tests::require_slashable_is_enforced_at_the_bridge | src/cross_domain/external/domain_bridge.rs:163 |
| BLG-057 | Section 14.3, L2647 | High | WP-44 | Fixed in tree. The bridge transfer carries a bounded expiry, the expiry queue is keyed by height, and the replay store refuses a second delivery. | cross_domain bridge lifecycle tests | src/cross_domain/bridge.rs:270 |
| BLG-058 | Section 14.3, L2648 | High | WP-44 | Fixed in tree. The domain leaf check consults the ZK program allow list, so a program that is not listed cannot settle. | settlement domain leaf tests | src/settlement/domains.rs:1269 |
| BLG-059 | Section 14.3, L2649 | Critical | WP-45 | Open. The feature is closed on testnet, which the TLG rule accepts as the launch state. | tests::testnet_closed_features::ai_execution_proof_is_closed_on_testnet (green in the lib run) | src/tests/testnet_closed_features.rs:48 |
| BLG-060 | Section 14.3, L2650 | Critical | WP-45 | Open. The feature is closed on testnet, which the TLG rule accepts as the launch state. | tests::testnet_closed_features::ai_execution_proof_is_closed_on_testnet (green in the lib run) | src/tests/testnet_closed_features.rs:48 |
| BLG-061 | Section 14.3, L2651 | High | WP-45 | Open. The feature is closed on testnet, which the TLG rule accepts as the launch state. | tests::testnet_closed_features::ai_layer_is_closed_on_testnet (green in the lib run) | src/tests/testnet_closed_features.rs:70 |
| BLG-062 | Section 14.3, L2652 | High | WP-45 | Unknown / unverified | Not recorded | Not collected |
| BLG-063 | Section 14.3, L2653 | Critical | WP-45 | Open. The feature is closed on testnet, which the TLG rule accepts as the launch state. | tests::testnet_closed_features::private_transfer_is_closed_on_testnet; tests::testnet_closed_features::note_registry_is_closed_on_testnet (green in the lib run) | src/tests/testnet_closed_features.rs:27 |
| BLG-064 | Section 14.3, L2654 | High | WP-23 | Unknown / unverified | Not recorded | Not collected |
| BLG-065 | Section 14.3, L2655 | High | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-066 | Section 14.3, L2656 | High | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-067 | Section 14.3, L2657 | High | WP-33 | Unknown / unverified | Not recorded | Not collected |
| BLG-068 | Section 14.3, L2658 | High | WP-40 | Unknown / unverified | Not recorded | Not collected |
| BLG-069 | Section 14.3, L2659 | Medium | WP-33 | Unknown / unverified | Not recorded | Not collected |
| BLG-070 | Section 14.3, L2660 | High | WP-45 | Unknown / unverified | Not recorded | Not collected |
| BLG-071 | Section 14.3, L2661 | High | WP-45 | Unknown / unverified | Not recorded | Not collected |
| BLG-072 | Section 14.3, L2662 | Medium | WP-45 | Unknown / unverified | Not recorded | Not collected |
| BLG-073 | Section 14.3, L2663 | Critical | WP-07 | Unknown / unverified | Not recorded | Not collected |
| BLG-074 | Section 14.3, L2664 | High | WP-07 | Unknown / unverified | Not recorded | Not collected |
| BLG-075 | Section 14.3, L2665 | High | WP-07 | Unknown / unverified | Not recorded | Not collected |
| BLG-076 | Section 14.3, L2666 | Medium | WP-07 | Unknown / unverified | Not recorded | Not collected |
| BLG-077 | Section 14.3, L2667 | Critical | WP-07 | Unknown / unverified | Not recorded | Not collected |
| BLG-078 | Section 14.3, L2668 | High | WP-07 | Unknown / unverified | Not recorded | Not collected |
| BLG-079 | Section 14.3, L2669 | High | WP-07 | Unknown / unverified | Not recorded | Not collected |
| BLG-080 | Section 14.3, L2670 | Medium | WP-07 | Unknown / unverified | Not recorded | Not collected |
| BLG-081 | Section 14.3, L2671 | High | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-082 | Section 14.3, L2672 | High | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-083 | Section 14.3, L2673 | Medium | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-084 | Section 14.3, L2674 | High | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-085 | Section 14.3, L2675 | High | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-086 | Section 14.3, L2676 | Medium | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-087 | Section 14.3, L2677 | High | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-088 | Section 14.3, L2678 | Medium | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-089 | Section 14.3, L2679 | High | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-090 | Section 14.3, L2680 | Medium | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-091 | Section 14.3, L2681 | Critical | WP-44 | Unknown / unverified | Not recorded | Not collected |
| BLG-092 | Section 14.3, L2682 | High | WP-43 | Unknown / unverified | Not recorded | Not collected |
| BLG-093 | Section 14.3, L2683 | High | WP-45 | Unknown / unverified | Not recorded | Not collected |
| BLG-094 | Section 14.3, L2684 | High | WP-16 | Unknown / unverified | Not recorded | Not collected |
| BLG-095 | Section 14.3, L2685 | Medium | WP-41 | Unknown / unverified | Not recorded | Not collected |
| BLG-096 | Section 14.3, L2686 | High | WP-12 | Unknown / unverified | Not recorded | Not collected |
| BLG-097 | Section 14.3, L2687 | High | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-098 | Section 14.3, L2688 | Critical | WP-39 | Unknown / unverified | Not recorded | Not collected |
| BLG-099 | Section 14.3, L2689 | High | WP-61 | Fixed in tree. No self comparison on a length mismatch. | tests::hardening_h4_locks::constant_time_eq_str_correctness; tests::regression_ops_crypto (spec assertion) (green, local run 2026-11-16) | src/rpc/server.rs:1290 |
| BLG-100 | Section 14.3, L2690 | Critical | WP-17 | Fixed in tree. Liquid cost is fee-only for fee-only doors, so a fully staked validator can unstake; admission, projection and execution share the classification. | core::transaction::tests::checked_liquid_cost_matches_fee_only_and_amount_bearing_doors; tests::tokenomics::fee_gate_respects_vesting_lock | src/core/transaction.rs:2481; src/core/account.rs:2183 |
| BLG-101 | Section 14.3, L2691 | Critical | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-102 | Section 14.3, L2692 | Critical | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-103 | Section 14.3, L2693 | Critical | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-104 | Section 14.3, L2694 | Critical | WP-17 | Fixed in tree. The byte budget is charged after the count check and before the replacement is removed, so a refusal cannot delete a transaction it does not replace. | mempool::pool tests (byte budget and replacement refusal) | src/mempool/pool.rs:528 |
| BLG-105 | Section 14.3, L2695 | Critical | WP-44 | Fixed in tree. The burn records the debit it made, and the claim pays the recorded debit rather than the gross amount. | cross_domain::evm::bud_to_eth tests | src/cross_domain/evm/bud_to_eth.rs:135 |
| BLG-106 | Section 14.3, L2696 | Critical | WP-45 | Fixed in tree. The execution dims width is bounded to 2..=32 layers and no layer may be zero before any allocation. | ai::types dims bounds test | src/ai/types.rs:308 |
| BLG-107 | Section 14.3, L2697 | Critical | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-108 | Section 14.3, L2698 | Critical | WP-15 | Unknown / unverified | Not recorded | Not collected |
| BLG-109 | Section 14.3, L2699 | Critical | WP-23 | Unknown / unverified | Not recorded | Not collected |
| BLG-110 | Section 14.3, L2700 | Critical | WP-23 | Unknown / unverified | Not recorded | Not collected |
| BLG-111 | Section 14.3, L2701 | High | WP-45 | Unknown / unverified | Not recorded | Not collected |
| BLG-112 | Section 14.3, L2702 | Critical | WP-45 | Open. The feature is closed on testnet, which the TLG rule accepts as the launch state. | tests::testnet_closed_features::ai_layer_is_closed_on_testnet (green in the lib run) | src/tests/testnet_closed_features.rs:70 |
| BLG-113 | Section 14.3, L2703 | Critical | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-114 | Section 14.3, L2704 | Critical | WP-33 | Unknown / unverified | Not recorded | Not collected |
| BLG-115 | Section 14.3, L2705 | Critical | WP-33 | Unknown / unverified | Not recorded | Not collected |
| BLG-116 | Section 14.3, L2706 | Critical | WP-44 | Unknown / unverified | Not recorded | Not collected |
| BLG-117 | Section 14.3, L2707 | Critical | WP-39 | Unknown / unverified | Not recorded | Not collected |
| BLG-118 | Section 14.3, L2708 | Critical | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-119 | Section 14.3, L2709 | Critical | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-120 | Section 14.3, L2710 | High | WP-44 | Unknown / unverified | Not recorded | Not collected |
| BLG-121 | Section 14.3, L2711 | High | WP-40 | Unknown / unverified | Not recorded | Not collected |
| BLG-122 | Section 14.3, L2712 | High | WP-07 | Unknown / unverified | Not recorded | Not collected |
| BLG-123 | Section 14.3, L2713 | Medium | WP-07 | Unknown / unverified | Not recorded | Not collected |
| BLG-124 | Section 14.3, L2714 | High | WP-45 | Unknown / unverified | Not recorded | Not collected |
| BLG-125 | Section 14.3, L2715 | Critical | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-126 | Section 14.3, L2716 | Critical | WP-45 | Open. The feature is closed on testnet, which the TLG rule accepts as the launch state. | tests::testnet_closed_features::ai_layer_is_closed_on_testnet (green in the lib run) | src/tests/testnet_closed_features.rs:70 |
| BLG-127 | Section 14.3, L2717 | Critical | WP-44 | Unknown / unverified | Not recorded | Not collected |
| BLG-128 | Section 14.3, L2718 | High | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-129 | Section 14.3, L2719 | High | WP-23 | Unknown / unverified | Not recorded | Not collected |
| BLG-130 | Section 14.3, L2720 | Critical | WP-44 | Unknown / unverified | Not recorded | Not collected |
| BLG-131 | Section 14.3, L2721 | High | WP-44 | Unknown / unverified | Not recorded | Not collected |
| BLG-132 | Section 14.3, L2722 | High | WP-12 | Unknown / unverified | Not recorded | Not collected |
| BLG-133 | Section 14.3, L2723 | Medium | WP-24 | Unknown / unverified | Not recorded | Not collected |
| BLG-134 | Section 14.3, L2724 | Critical | WP-44 | Unknown / unverified | Not recorded | Not collected |
| BLG-135 | Section 14.3, L2725 | High | WP-24 | Unknown / unverified | Not recorded | Not collected |
| BLG-136 | Section 14.3, L2726 | High | WP-33 | Unknown / unverified | Not recorded | Not collected |
| BLG-137 | Section 14.3, L2727 | High | WP-19 | Unknown / unverified | Not recorded | Not collected |
| BLG-138 | Section 14.3, L2728 | Critical | WP-44 | Unknown / unverified | Not recorded | Not collected |
| BLG-139 | Section 14.3, L2729 | Critical | WP-33 | Unknown / unverified | Not recorded | Not collected |
| BLG-140 | Section 14.3, L2730 | High | WP-16 | Unknown / unverified | Not recorded | Not collected |
| BLG-141 | Section 14.3, L2731 | Medium | WP-07 | Unknown / unverified | Not recorded | Not collected |
| BLG-142 | Section 14.3, L2732 | Critical | WP-33 | Fixed in tree. Same ceiling guard as BLG-039; the proof bytes cannot choose a domain size. | budzero bud-proof verifier: degree_bits_ceiling_guards_goldilocks_two_adicity | budzero/bud-proof/src/bud_stark/verifier.rs:359 |
| BLG-143 | Section 14.3, L2733 | High | WP-40 | Unknown / unverified | Not recorded | Not collected |
| BLG-144 | Section 14.3, L2734 | High | WP-19 | Unknown / unverified | Not recorded | Not collected |
| BLG-145 | Section 14.3, L2735 | Medium | WP-45 | Unknown / unverified | Not recorded | Not collected |
| BLG-146 | Section 14.3, L2736 | Critical | WP-44 | Fixed in tree. The recipient comes from the burn, a zero address and an empty proof are refused, and the amount is the burned debit capped by the bridge cap. | cross_domain::evm::bud_to_eth tests around `build_bud_to_eth_claim` | src/cross_domain/evm/bud_to_eth.rs:155 |
| BLG-147 | Section 14.3, L2737 | High | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-148 | Section 14.3, L2738 | High | WP-07, WP-33 | Unknown / unverified | Not recorded | Not collected |
| BLG-149 | Section 14.3, L2739 | Medium | WP-45 | Unknown / unverified | Not recorded | Not collected |
| BLG-150 | Section 14.3, L2740 | Critical | WP-61 | Fixed in tree. Each signed object carries its own context tag. | tests::regression_ops_crypto::vote_signatures_are_domain_separated_from_block (green, local run 2026-11-16) | src/consensus/block_signature.rs:58 |
| BLG-151 | Section 14.3, L2741 | High | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-152 | Section 14.3, L2742 | Medium | WP-07 | Unknown / unverified | Not recorded | Not collected |
| BLG-153 | Section 14.3, L2743 | Medium | WP-07 | Unknown / unverified | Not recorded | Not collected |
| BLG-154 | Section 14.3, L2744 | Critical | WP-33 | Unknown / unverified | Not recorded | Not collected |
| BLG-155 | Section 14.3, L2745 | High | WP-44 | Unknown / unverified | Not recorded | Not collected |
| BLG-156 | Section 14.3, L2746 | Medium | WP-07 | Unknown / unverified | Not recorded | Not collected |
| BLG-157 | Section 14.3, L2747 | Medium | WP-45 | Unknown / unverified | Not recorded | Not collected |
| BLG-158 | Section 14.3, L2748 | High | WP-12 | Unknown / unverified | Not recorded | Not collected |
| BLG-159 | Section 14.3, L2749 | High | WP-33 | Unknown / unverified | Not recorded | Not collected |
| BLG-160 | Section 14.3, L2750 | Medium | WP-45 | Unknown / unverified | Not recorded | Not collected |
| BLG-161 | Section 14.3, L2751 | Medium | WP-21 | Unknown / unverified | Not recorded | Not collected |
| BLG-162 | Section 14.3, L2752 | High | WP-33 | Unknown / unverified | Not recorded | Not collected |
| BLG-163 | Section 14.3, L2753 | High | WP-19 | Unknown / unverified | Not recorded | Not collected |
| BLG-164 | Section 14.3, L2754 | High | WP-45 | Fixed in tree. A height that does not fit the u32 epoch is refused, not truncated. | crates/bpqs epoch tests (green in the bpqs crate run) | crates/bpqs/src/epoch.rs:26 |
| BLG-165 | Section 14.3, L2755 | Medium | WP-45 | Unknown / unverified | Not recorded | Not collected |
| BLG-166 | Section 14.3, L2756 | Critical | WP-45 | Unknown / unverified | Not recorded | Not collected |
| BLG-167 | Section 14.3, L2757 | High | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-168 | Section 14.3, L2758 | Medium | WP-21 | Unknown / unverified | Not recorded | Not collected |
| BLG-169 | Section 14.3, L2759 | Medium | WP-40 | Unknown / unverified | Not recorded | Not collected |
| BLG-170 | Section 14.3, L2760 | High | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-171 | Section 14.3, L2761 | High | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-172 | Section 14.3, L2762 | Medium | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-173 | Section 14.3, L2763 | Medium | WP-45 | Unknown / unverified | Not recorded | Not collected |
| BLG-174 | Section 14.3, L2764 | High | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-175 | Section 14.3, L2765 | High | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-176 | Section 14.3, L2766 | Medium | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-177 | Section 14.3, L2767 | Medium | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-178 | Section 14.3, L2768 | High | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-179 | Section 14.3, L2769 | High | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-180 | Section 14.3, L2770 | Medium | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-181 | Section 14.3, L2771 | Medium | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-182 | Section 14.3, L2772 | Critical | WP-33 | Unknown / unverified | Not recorded | Not collected |
| BLG-183 | Section 14.3, L2773 | Critical | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-184 | Section 14.3, L2774 | Critical | WP-17 | Fixed in tree. Candidate execution, contract-call count and the serialized-size budget are all charged only for included transactions, so a failed transaction cannot buy block room. | tests::regression_chain::producer_executes_on_a_disposable_candidate_state | src/chain/blockchain.rs:4606 |
| BLG-185 | Section 14.3, L2775 | Medium | WP-45 | Unknown / unverified | Not recorded | Not collected |
| BLG-186 | Section 14.3, L2776 | Critical | WP-33 | Unknown / unverified | Not recorded | Not collected |
| BLG-187 | Section 14.3, L2777 | High | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-188 | Section 14.3, L2778 | High | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-189 | Section 14.3, L2779 | Medium | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-190 | Section 14.3, L2780 | Critical | WP-44 | Unknown / unverified | Not recorded | Not collected |
| BLG-191 | Section 14.3, L2781 | Critical | WP-33 | Unknown / unverified | Not recorded | Not collected |
| BLG-192 | Section 14.3, L2782 | High | WP-61 | Unknown / unverified | Not recorded | Not collected |
| BLG-193 | Section 14.3, L2783 | Medium | WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-194 | Section 14.3, L2784 | Critical | WP-44 | Fixed in tree. The relay ledger is snapshotted and restored when a bridge effect refuses, and every check runs before the first mutation. | cross_domain bridge relay tests | src/cross_domain/bridge_tx.rs:736 |
| BLG-195 | Section 14.3, L2785 | Critical | WP-44 | Fixed in tree. The commitment digest binds event root and the state updates map, the adapters refuse a foreign domain id, and PoW work saturates at the documented ceiling. | tests::fork_choice_locks::a_longer_chain_still_wins_at_the_difficulty_that_used_to_saturate | src/domain/finality_adapter.rs:533,1066; src/consensus/pow.rs:194 |
| BLG-196 | Section 14.3, L2786 | High | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-197 | Section 14.3, L2787 | Critical | WP-17 | Fixed in tree. Cost paths use the checked classification; `total_cost` survives only as a documented compatibility estimate and is read by tests alone. | core::transaction tests around `total_cost`; tests::proptest_core | src/core/transaction.rs:2491 |
| BLG-198 | Section 14.3, L2788 | Critical | WP-33 | Unknown / unverified | Not recorded | Not collected |
| BLG-199 | Section 14.3, L2789 | High | WP-44 | Unknown / unverified | Not recorded | Not collected |
| BLG-200 | Section 14.3, L2790 | High | WP-61 | Fixed in tree. The zero scalar and the identity public key are refused. | tests::regression_ops_crypto::bls_from_bytes_refuses_zero_secret (green, local run 2026-11-16) | src/crypto/primitives.rs:152 |
| BLG-201 | Section 14.3, L2791 | High | WP-45 | Unknown / unverified | Not recorded | Not collected |
| BLG-202 | Section 14.3, L2792 | Critical | WP-17 | Unknown / unverified | Not recorded | Not collected |
| BLG-203 | Section 14.3, L2793 | Critical | WP-12 | Fixed in tree. The proof length, element width, zero root and high index bits are all refused. | consensus::qc tests (green in the lib run that carries this row) | src/consensus/qc.rs:691 |
| BLG-204 | Section 14.3, L2794 | High | WP-44 | Unknown / unverified | Not recorded | Not collected |
| BLG-205 | Section 14.3, L2795 | Critical | WP-15, WP-44 | Fixed in tree. `readmit` demands an admitted, golden-verified report whose every test passed and whose adapter version matches the record. | cross_domain::external::registry tests: readmit_reopens_a_faulted_domain_but_is_not_an_edit | src/cross_domain/external/registry.rs:355 |
| BLG-206 | Section 14.3, L2796 | Critical | WP-12 | Unknown / unverified | Not recorded | Not collected |
| BLG-207 | Section 14.3, L2797 | Critical | WP-12 | Unknown / unverified | Not recorded | Not collected |
| BLG-208 | Section 14.4, L2809 | High | WP-07, WP-21 | Unknown / unverified | Not recorded | Not collected |
| BLG-209 | Section 14.4, L2810 | High | WP-07, WP-25 | Unknown / unverified | Not recorded | Not collected |
| BLG-210 | Section 14.4, L2811 | High | WP-19 | Unknown / unverified | Not recorded | Not collected |
| BLG-211 | Section 14.4, L2812 | Medium | WP-19 | Unknown / unverified | Not recorded | Not collected |
| BLG-212 | Section 14.4, L2813 | Critical | WP-21, WP-23 | Unknown / unverified | Not recorded | Not collected |
| BLG-213 | Section 14.4, L2814 | High | WP-18 | Fixed in this round for the frame container. The raw-frame mux refuses a frame or a frame count that does not fit its 32-bit field instead of truncating it. | storage::qr_codec::field_width_tests::a_container_field_wider_than_32_bits_is_refused | src/storage/qr_codec.rs:126 |
| BLG-214 | Section 14.4, L2815 | Medium | WP-19 | Unknown / unverified | Not recorded | Not collected |
| BLG-215 | Section 14.4, L2816 | High | WP-19 | Unknown / unverified | Not recorded | Not collected |
| BLG-216 | Section 14.4, L2817 | High | WP-18 | Unknown / unverified | Not recorded | Not collected |
| BLG-217 | Section 14.4, L2818 | Medium | WP-07 | Unknown / unverified | Not recorded | Not collected |
| BLG-218 | Section 14.4, L2819 | Low | WP-19 | Unknown / unverified | Not recorded | Not collected |
| BLG-219 | Section 14.4, L2820 | Medium | WP-24 | Unknown / unverified | Not recorded | Not collected |
| BLG-220 | Section 14.4, L2821 | Critical | WP-20 | Unknown / unverified | Not recorded | Not collected |
| BLG-221 | Section 14.4, L2822 | Medium | WP-22 | Unknown / unverified | Not recorded | Not collected |
| BLG-222 | Section 14.4, L2823 | Medium | WP-24 | Unknown / unverified | Not recorded | Not collected |
| BLG-223 | Section 14.4, L2824 | High | WP-33, WP-45, WP-56 | Unknown / unverified | Not recorded | Not collected |
| BLG-224 | Section 14.4, L2825 | High | WP-45, WP-56 | Unknown / unverified | Not recorded | Not collected |
| BLG-225 | Section 14.4, L2826 | High | WP-45, WP-56 | Unknown / unverified | Not recorded | Not collected |
| BLG-226 | Section 14.4, L2827 | High | WP-33, WP-56 | Open. The feature is closed on testnet, which the TLG rule accepts as the launch state. | execution::budzero_ee::tests::verify_merkle_is_closed_on_testnet (green in the lib run) | src/execution/budzero_ee/mod.rs:517 |
| BLG-227 | Section 14.4, L2828 | Medium | WP-33, WP-57 | Open. The feature is closed on testnet, which the TLG rule accepts as the launch state. | execution::budzero_ee::tests::verify_inference_is_closed_on_testnet (green in the lib run) | src/execution/budzero_ee/mod.rs:542 |
| BLG-228 | Section 14.4, L2829 | High | WP-45, WP-57 | Open. The feature is closed on testnet, which the TLG rule accepts as the launch state. | tests::testnet_closed_features::ai_execution_proof_is_closed_on_testnet (green in the lib run) | src/tests/testnet_closed_features.rs:48 |
| BLG-229 | Section 14.4, L2830 | High | WP-45, WP-57 | Open. The feature is closed on testnet, which the TLG rule accepts as the launch state. | tests::testnet_closed_features::ai_layer_is_closed_on_testnet (green in the lib run) | src/tests/testnet_closed_features.rs:70 |
| BLG-230 | Section 14.4, L2831 | Medium | WP-33, WP-56 | Unknown / unverified | Not recorded | Not collected |
| BLG-231 | Section 14.4, L2832 | Medium | WP-43 | Unknown / unverified | Not recorded | Not collected |
| BLG-232 | Section 14.4, L2833 | Medium | WP-56 | Unknown / unverified | Not recorded | Not collected |
| BLG-233 | Section 14.4, L2834 | Medium | WP-60 | Unknown / unverified | Not recorded | Not collected |
| BLG-234 | Section 14.4, L2835 | Medium | WP-60 | Unknown / unverified | Not recorded | Not collected |
| BLG-235 | Section 14.4, L2836 | High | WP-44, WP-60 | Unknown / unverified | Not recorded | Not collected |
| BLG-236 | Section 14.4, L2837 | Medium | WP-56 | Unknown / unverified | Not recorded | Not collected |
| BLG-237 | Section 14.4, L2838 | High | WP-22, WP-56 | Unknown / unverified | Not recorded | Not collected |
| BLG-238 | Section 14.4, L2839 | Medium | WP-22 | Unknown / unverified | Not recorded | Not collected |
| BLG-239 | Section 14.4, L2840 | Medium | WP-60 | Unknown / unverified | Not recorded | Not collected |
| BLG-240 | Section 14.4, L2841 | Low | WP-45, WP-57 | Unknown / unverified | Not recorded | Not collected |
| BLG-241 | Section 14.4, L2842 | Low | WP-43 | Unknown / unverified | Not recorded | Not collected |
| BLG-242 | Section 14.4, L2843 | Medium | WP-56 | Unknown / unverified | Not recorded | Not collected |
| BLG-243 | Section 14.4, L2844 | Medium | WP-56 | Unknown / unverified | Not recorded | Not collected |
| BLG-244 | Section 14.4, L2845 | Low | WP-57 | Unknown / unverified | Not recorded | Not collected |
| BLG-245 | Section 14.4, L2846 | Medium | WP-22, WP-56 | Unknown / unverified | Not recorded | Not collected |
| BLG-246 | Section 14.5, L2852 | Critical | WP-12 | Unknown / unverified | Not recorded | Not collected |
| BLG-247 | Section 14.5, L2853 | High | WP-15 | Unknown / unverified | Not recorded | Not collected |
| BLG-248 | Section 14.5, L2854 | High | WP-26, WP-33 | Unknown / unverified | Not recorded | Not collected |
| BLG-249 | Section 14.5, L2855 | High | WP-28, WP-29, WP-31, WP-32 | Unknown / unverified | Not recorded | Not collected |
| BLG-250 | Section 14.5, L2856 | Critical | WP-26 | Unknown / unverified | Not recorded | Not collected |
| BLG-251 | Section 14.5, L2857 | High | WP-13 | Unknown / unverified | Not recorded | Not collected |
| BLG-252 | Section 14.5, L2858 | Medium | WP-08 | Unknown / unverified | Not recorded | Not collected |
| BLG-253 | Section 14.5, L2859 | Medium | WP-07, WP-08 | Unknown / unverified | Not recorded | Not collected |
| BLG-254 | Section 14.5, L2860 | High | WP-07, WP-42 | Unknown / unverified | Not recorded | Not collected |
| BLG-255 | Section 14.5, L2861 | Low | WP-05, WP-43 | Unknown / unverified | Not recorded | Not collected |
| BLG-256 | Section 14.5, L2862 | High | WP-26 | Unknown / unverified | Not recorded | Not collected |
| BLG-257 | Section 14.5, L2863 | High | WP-11, WP-36 | Unknown / unverified | Not recorded | Not collected |
| BLG-258 | Section 14.5, L2864 | Medium | WP-07 | Unknown / unverified | Not recorded | Not collected |
| BLG-259 | Section 14.5, L2865 | Medium | WP-11, WP-12 | Unknown / unverified | Not recorded | Not collected |
| BLG-260 | Section 14.5, L2866 | Medium | WP-26 | Unknown / unverified | Not recorded | Not collected |
| BLG-261 | Section 14.5, L2867 | Low | WP-23 | Unknown / unverified | Not recorded | Not collected |
| BLG-262 | Section 14.5, L2868 | Medium | WP-23 | Unknown / unverified | Not recorded | Not collected |
| BLG-263 | Section 14.5, L2869 | Medium | WP-16 | Unknown / unverified | Not recorded | Not collected |
| BLG-264 | Section 14.5, L2870 | High | WP-12 | Unknown / unverified | Not recorded | Not collected |
| BLG-265 | Section 14.5, L2871 | Medium | WP-36 | Unknown / unverified | Not recorded | Not collected |
| BLG-266 | Section 14.5, L2872 | Medium | WP-08, WP-16 | Unknown / unverified | Not recorded | Not collected |
| BLG-267 | Section 14.5, L2873 | High | WP-27 | Unknown / unverified | Not recorded | Not collected |

## Scope and crosswalk gaps

The packages listed above are identifiers mechanically extracted from each
source row; they are not assigned or completed work. BLG-255 additionally
names every package in its source row. The directive's Section 14.6 lists 44
archived BULGU, TEST-GAP and DOC-GAP entries: these have not been deduplicated
or converted into new BLG IDs. The Section 14.7 source-directive crosswalk
also requires verification against the older ledger; do not invent missing
links from the source snapshot.

BLG-008 already describes the public-RPC testnet authentication mismatch;
BLG-030 and BLG-098 cover related RPC exposure/default behavior. A proposed
change to the RPC split is uncommitted and unpublished, so none of these
findings or launch gates becomes closed from that work. BLG-257 covers the
missing usable Android-validator path. Compare these source IDs before
allocating any new ID for RPC or Android onboarding problems.
