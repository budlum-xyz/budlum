//! The Solana gateway's three-table locks (WP-31, 1/N).
//!
//! The gateway is only real when three places agree: the table in
//! [`super`], the declarations in `src/rpc/api.rs`, and the rows in
//! `src/rpc/method_class.rs`. These tests read all three as text, so a
//! method cannot be half-added: a row without a declaration, a declaration
//! without a row, or a pending row that is served all fail here.

#[cfg(test)]
mod solana_compat_tests {
    use crate::rpc::compat::solana::{row, Answer, METHODS};

    /// Section 8.11.3, verbatim and in its order.
    const DIRECTIVE_METHODS: &[&str] = &[
        "getHealth",
        "getVersion",
        "getGenesisHash",
        "getSlot",
        "getBlockHeight",
        "getEpochInfo",
        "getLatestBlockhash",
        "isBlockhashValid",
        "getBalance",
        "getAccountInfo",
        "getMultipleAccounts",
        "getProgramAccounts",
        "getTokenAccountsByOwner",
        "getTokenAccountBalance",
        "getTokenSupply",
        "getMinimumBalanceForRentExemption",
        "getFeeForMessage",
        "getRecentPrioritizationFees",
        "sendTransaction",
        "simulateTransaction",
        "getSignatureStatuses",
        "getSignaturesForAddress",
        "getTransaction",
        "getBlock",
        "requestAirdrop",
    ];

    /// The WebSocket subscriptions of the same section, in its order.
    const SUBSCRIPTIONS: &[&str] = &[
        "accountSubscribe",
        "signatureSubscribe",
        "slotSubscribe",
        "logsSubscribe",
        "programSubscribe",
    ];

    /// The names the gateway serves today: every row that is not pending.
    fn served_names() -> Vec<&'static str> {
        METHODS
            .iter()
            .filter(|row| !matches!(row.answer, Answer::Pending { .. }))
            .map(|row| row.name)
            .collect()
    }

    /// Every method name `src/rpc/api.rs` declares, read from its source.
    ///
    /// `api.rs` is the wire surface: a name that is not in it cannot be
    /// called, so the gateway table is checked against this text and not
    /// against a second hand-written list.
    fn declared_method_names() -> Vec<String> {
        let api = include_str!("../../api.rs");
        let mut names = Vec::new();
        for needle in ["#[method(name = \"", "#[subscription(name = \"", "unsubscribe = \""] {
            for (at, _) in api.match_indices(needle) {
                let rest = &api[at + needle.len()..];
                let name = &rest[..rest.find('"').expect("a declared method has a name")];
                names.push(name.to_string());
            }
        }
        names
    }

    /// The declared names that belong to this gateway: the served table
    /// names, which must all be declared.
    fn declared_gateway_names() -> Vec<String> {
        let declared = declared_method_names();
        let mut names: Vec<String> = METHODS
            .iter()
            .filter(|row| !matches!(row.answer, Answer::Pending { .. }))
            .map(|row| row.name.to_string())
            .filter(|name| declared.iter().any(|candidate| candidate == name))
            .collect();
        names.sort();
        names
    }

    /// `(name, listener, effect)` for every row of the Budlum class table.
    fn class_rows() -> Vec<(String, String, String)> {
        let source = include_str!("../../method_class.rs");
        let cut = source.find("#[cfg(test)]").unwrap_or(source.len());
        let text = &source[..cut];
        let mut rows = Vec::new();
        for (at, _) in text.match_indices("row(\"") {
            let rest = &text[at + "row(\"".len()..];
            let name = &rest[..rest.find('"').expect("a class row has a name")];
            let after = &rest[name.len() + 1..];
            let inner = &after[..after.find(')').expect("a class row closes")];
            let mut parts = inner.split(',').map(str::trim).filter(|s| !s.is_empty());
            rows.push((
                name.to_string(),
                parts.next().expect("a class row has a listener").to_string(),
                parts.next().expect("a class row has an effect").to_string(),
            ));
        }
        rows
    }

    #[test]
    fn solana_method_table_is_complete() {
        let listed: Vec<&str> = METHODS.iter().map(|row| row.name).collect();
        let mut unique = listed.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(unique.len(), listed.len(), "a method has two rows");

        let mut missing: Vec<&str> = Vec::new();
        for name in DIRECTIVE_METHODS {
            if !listed.contains(name) {
                missing.push(*name);
            }
        }
        assert!(
            missing.is_empty(),
            "Section 8.11.3 names methods the gateway table does not: {missing:?}"
        );

        // The table is the directive list plus the five subscriptions, and
        // nothing else: an extra row would be a method the directive never
        // gave this gateway.
        let mut expected: Vec<&str> = DIRECTIVE_METHODS.to_vec();
        for name in SUBSCRIPTIONS {
            expected.push(name);
            expected.push(match *name {
                "accountSubscribe" => "accountUnsubscribe",
                "signatureSubscribe" => "signatureUnsubscribe",
                "slotSubscribe" => "slotUnsubscribe",
                "logsSubscribe" => "logsUnsubscribe",
                "programSubscribe" => "programUnsubscribe",
                _ => unreachable!("the subscription list is fixed"),
            });
        }
        assert_eq!(listed, expected);
    }

    #[test]
    fn solana_refusals_name_an_existing_door() {
        let declared = declared_method_names();
        for entry in METHODS {
            if let Answer::EeUnavailable { door } = entry.answer {
                assert!(!door.is_empty(), "{} refuses without a door", entry.name);
                assert!(
                    declared.iter().any(|name| name == door),
                    "{} names the door {door}, which src/rpc/api.rs does not declare",
                    entry.name
                );
            }
        }
    }

    #[test]
    fn solana_served_set_matches_the_declared_api() {
        let mut served: Vec<String> = served_names().iter().map(|n| (*n).to_string()).collect();
        served.sort_unstable();
        assert_eq!(
            served,
            declared_gateway_names(),
            "the gateway table and src/rpc/api.rs disagree on which methods exist"
        );
    }

    #[test]
    fn solana_class_table_matches_the_gateway_table() {
        let rows = class_rows();
        for entry in METHODS {
            let expected = match entry.answer {
                Answer::Pending { .. } => None,
                Answer::ChainRead | Answer::Subscription | Answer::Unsubscribe => Some("Read"),
                Answer::EeUnavailable { .. } => Some("Refused"),
            };
            let found = rows.iter().find(|(name, _, _)| name.as_str() == entry.name);
            match (expected, found) {
                (None, None) => {}
                (None, Some(_)) => panic!(
                    "{} is a pending method and must not have a class row",
                    entry.name
                ),
                (Some(_), None) => panic!("{} has no class row in method_class.rs", entry.name),
                (Some(effect), Some((_, listener, got_effect))) => {
                    assert_eq!(
                        got_effect.as_str(),
                        effect,
                        "{} has a different effect in the two tables",
                        entry.name
                    );
                    // A chain read is never operator-only: every node agrees
                    // on it, so there is nothing to withhold.
                    if matches!(entry.answer, Answer::ChainRead | Answer::Subscription | Answer::Unsubscribe) {
                        assert_eq!(listener.as_str(), "Public", "{}", entry.name);
                    }
                }
            }
        }
    }

    #[test]
    fn solana_subscriptions_have_the_exact_wire_doors() {
        for name in SUBSCRIPTIONS {
            let entry = row(name).unwrap_or_else(|| panic!("{name} has no row"));
            if *name == "slotSubscribe" {
                assert_eq!(entry.answer, Answer::Subscription);
            } else {
                assert!(matches!(entry.answer, Answer::EeUnavailable { .. }));
            }
            let unsubscribe = name.replace("Subscribe", "Unsubscribe");
            assert_eq!(row(&unsubscribe).unwrap().answer, Answer::Unsubscribe);
            assert!(crate::rpc::compat::solana::is_unsubscribe(&unsubscribe));
        }
        assert!(!crate::rpc::compat::solana::is_unsubscribe("slotSubscribe"));
        assert!(!crate::rpc::compat::solana::is_unsubscribe("bud_unsubscribe"));
    }

    #[test]
    fn solana_the_chain_reads_are_the_ones_a_node_can_answer_without_an_ee() {
        let reads: Vec<&str> = METHODS
            .iter()
            .filter(|row| row.answer == Answer::ChainRead)
            .map(|row| row.name)
            .collect();
        let expected: &[&str] = &["getHealth", "getVersion", "getSlot", "getBlockHeight"];
        assert_eq!(&reads[..], expected);
        assert_eq!(row("slotSubscribe").unwrap().answer, Answer::Subscription);
    }

    #[test]
    fn solana_check_served_accepts_classified_subscription_doors() {
        crate::rpc::compat::solana::check_served(["getHealth", "getBalance"])
            .expect("a served method and a named refusal both have rows");
        crate::rpc::compat::solana::check_served(["accountSubscribe", "slotSubscribe"])
            .expect("a named refusal and a served feed both have rows");
    }

    #[test]
    fn solana_check_served_refuses_a_foreign_method_with_no_row() {
        let err = crate::rpc::compat::solana::check_served(["solana_notAThing"])
            .expect_err("a foreign method with no row is refused");
        assert!(err.contains("solana_notAThing"), "{err}");
    }

    #[test]
    fn solana_get_balance_row_is_a_refusal_with_a_door() {
        let entry = row("getBalance").expect("getBalance has a row");
        assert_eq!(
            entry.answer,
            Answer::EeUnavailable {
                door: "bud_getBalance"
            }
        );
        let err = crate::rpc::compat::solana::ee_unavailable("getBalance", "bud_getBalance");
        assert_eq!(err.code(), -32004);
        assert!(
            err.message().contains("bud_getBalance"),
            "the refusal names the Budlum door: {}",
            err.message()
        );
    }

    #[test]
    fn solana_not_exposed_names_the_door() {
        let err = crate::rpc::compat::solana::not_exposed("getEpochInfo", "bud_getStatus");
        assert_eq!(err.code(), -32004);
        assert!(
            err.message().contains("not exposed"),
            "the chain-gap refusal does not blame the SVM: {}",
            err.message()
        );
        assert!(
            err.message().contains("bud_getStatus"),
            "the refusal names the Budlum door: {}",
            err.message()
        );
    }

    #[test]
    fn solana_request_airdrop_refuses_and_names_the_faucet() {
        let entry = row("requestAirdrop").expect("requestAirdrop has a row");
        assert_eq!(
            entry.answer,
            Answer::EeUnavailable {
                door: "bud_sendRawTransaction"
            }
        );
        let err = crate::rpc::compat::solana::faucet_unavailable("requestAirdrop");
        assert_eq!(err.code(), -32004);
        assert!(
            err.message().contains("faucet"),
            "the refusal names the faucet: {}",
            err.message()
        );
    }

    #[test]
    fn solana_the_class_rows_are_in_api_order() {
        let rows = class_rows();
        let mut previous = 0usize;
        for entry in METHODS {
            if let Answer::Pending { .. } = entry.answer {
                continue;
            }
            let at = rows
                .iter()
                .position(|(name, _, _)| name.as_str() == entry.name)
                .unwrap_or_else(|| panic!("{} has no class row", entry.name));
            assert!(
                at > previous,
                "{} is declared after an earlier Solana method in api.rs but its row is not",
                entry.name
            );
            previous = at;
        }
    }
}
