#[cfg(test)]
mod ethereum_compat_tests {
    use crate::rpc::compat::ethereum::opening::{proof_is_not_an_mpt_proof, row, Answer, METHODS};

 /// Section 8.11.2, verbatim and in its order, without `eth_getProof`
 /// (which Section 8.10.6 adds to this gateway on purpose).
    const DIRECTIVE_METHODS: &[&str] = &[
        "web3_clientVersion",
        "net_version",
        "net_listening",
        "eth_chainId",
        "eth_syncing",
        "eth_blockNumber",
        "eth_getBalance",
        "eth_getCode",
        "eth_getStorageAt",
        "eth_getTransactionCount",
        "eth_call",
        "eth_estimateGas",
        "eth_createAccessList",
        "eth_gasPrice",
        "eth_maxPriorityFeePerGas",
        "eth_feeHistory",
        "eth_sendRawTransaction",
        "eth_getBlockByNumber",
        "eth_getBlockByHash",
        "eth_getBlockTransactionCountByNumber",
        "eth_getBlockTransactionCountByHash",
        "eth_getTransactionByHash",
        "eth_getTransactionByBlockNumberAndIndex",
        "eth_getTransactionReceipt",
        "eth_getBlockReceipts",
        "eth_getLogs",
        "eth_newFilter",
        "eth_newBlockFilter",
        "eth_getFilterChanges",
        "eth_getFilterLogs",
        "eth_uninstallFilter",
        "eth_subscribe",
        "eth_unsubscribe",
        "eth_accounts",
        "debug_traceTransaction",
        "debug_traceCall",
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
        let api = include_str!("../../../api.rs");
        let mut names = Vec::new();
        for needle in ["#[method(name = \"", "#[subscription(name = \""] {
            for (at, _) in api.match_indices(needle) {
                let rest = &api[at + needle.len()..];
                let name = &rest[..rest.find('"').expect("a declared method has a name")];
                names.push(name.to_string());
            }
        }
        names
    }

 /// The declared names that belong to a compatibility namespace.
    fn declared_gateway_names() -> Vec<String> {
        let mut names: Vec<String> = declared_method_names()
            .into_iter()
            .filter(|name| {
                name.starts_with("eth_")
                    || name.starts_with("net_")
                    || name.starts_with("web3_")
                    || name.starts_with("debug_")
            })
            .collect();
        names.sort();
        names
    }

 /// `(name, listener, effect)` for every row of the Budlum class table.
    fn class_rows() -> Vec<(String, String, String)> {
        let source = include_str!("../../../method_class.rs");
        let start = source
            .find("const METHOD_CLASSES")
            .expect("the production class table exists");
        let text = &source[start..];
        let cut = text.find("#[cfg(test)]").unwrap_or(text.len());
        let text = &text[..cut];
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
    fn eth_rpc_method_table_is_complete() {
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
            "Section 8.11.2 names methods the gateway table does not: {missing:?}"
        );

 // The table is the directive list plus `eth_getProof`, and nothing
 // else: an extra row would be a method the directive never gave this
 // gateway.
        assert_eq!(listed.len(), DIRECTIVE_METHODS.len() + 1);
        assert_eq!(listed.last().copied(), Some("eth_getProof"));

 // The directive names these in this order, so a reader can walk both
 // side by side.
        assert_eq!(&listed[..DIRECTIVE_METHODS.len()], DIRECTIVE_METHODS);
    }

    #[test]
    fn eth_get_proof_returns_method_not_found() {
        let entry = row("eth_getProof").expect("eth_getProof has a row");
        assert_eq!(entry.answer, Answer::MethodNotFound);
        let err = proof_is_not_an_mpt_proof();
        assert_eq!(err.code(), -32601);
        assert!(
            err.message().contains("bud_getAccountProof"),
            "the refusal names the Budlum door: {}",
            err.message()
        );
    }

    #[test]
    fn eth_refusals_name_an_existing_door() {
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
    fn eth_served_set_matches_the_declared_api() {
        let mut served: Vec<String> = served_names().iter().map(|n| (*n).to_string()).collect();
        served.sort_unstable();
        assert_eq!(
            served,
            declared_gateway_names(),
            "the gateway table and src/rpc/api.rs disagree on which methods exist"
        );
    }

    #[test]
    fn eth_class_table_matches_the_gateway_table() {
        let rows = class_rows();
        for entry in METHODS {
            let expected = match entry.answer {
                Answer::Pending { .. } => None,
                Answer::ChainRead => Some("Read"),
                Answer::MethodNotFound | Answer::EeUnavailable { .. } => Some("Refused"),
                Answer::BoundedFilter => Some("LocalAdmin"),
                Answer::BoundedFilterRead => Some("Refused"),
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
                    if entry.answer == Answer::ChainRead {
                        assert_eq!(listener.as_str(), "Public", "{}", entry.name);
                    }
                }
            }
        }
    }

    #[test]
    fn eth_debug_methods_are_operator_only() {
        let rows = class_rows();
        for name in ["debug_traceTransaction", "debug_traceCall"] {
            let row = rows
                .iter()
                .find(|(candidate, _, _)| candidate == name)
                .expect("the operator method has a class row");
            assert_eq!(row.1, "Operator", "{name} must not be on the public listener");
        }
    }

    #[test]
    fn eth_pending_rows_name_a_package_and_are_not_served() {
        let served = served_names();
        let mut pending = 0usize;
        for entry in METHODS {
            if let Answer::Pending { package } = entry.answer {
                pending += 1;
                assert!(!package.is_empty(), "{} pends without a package", entry.name);
                assert!(
                    !served.contains(&entry.name),
                    "{} pends and is served at the same time",
                    entry.name
                );
            }
        }
        assert_eq!(
            pending, 2,
            "eth_subscribe and eth_unsubscribe are the pending pair"
        );
    }

    #[test]
    fn eth_the_chain_reads_are_the_ones_a_node_can_answer_without_an_ee() {
        let reads: Vec<&str> = METHODS
            .iter()
            .filter(|row| row.answer == Answer::ChainRead)
            .map(|row| row.name)
            .collect();
        let expected: &[&str] = &[
            "web3_clientVersion",
            "net_version",
            "net_listening",
            "eth_chainId",
            "eth_syncing",
            "eth_blockNumber",
            "eth_gasPrice",
            "eth_maxPriorityFeePerGas",
            "eth_accounts",
        ];
        assert_eq!(&reads[..], expected);
    }

    #[test]
    fn eth_filter_rows_use_the_bounded_pool() {
        let expected = [
            "eth_newFilter",
            "eth_newBlockFilter",
            "eth_getFilterChanges",
            "eth_getFilterLogs",
            "eth_uninstallFilter",
        ];
        let rows = class_rows();
        for name in expected {
            let entry = row(name).expect("a filter method has a gateway row");
            let reads = matches!(name, "eth_getFilterChanges" | "eth_getFilterLogs");
            let expected_answer = if reads {
                Answer::BoundedFilterRead
            } else {
                Answer::BoundedFilter
            };
            let expected_effect = if reads { "Refused" } else { "LocalAdmin" };
            assert_eq!(entry.answer, expected_answer, "{name}");
            let class = rows
                .iter()
                .find(|(candidate, _, _)| candidate == name)
                .expect("a filter method has a class row");
            assert_eq!(class.2, expected_effect, "{name}");
        }
    }

    #[test]
    fn eth_check_served_refuses_a_foreign_method_with_no_row() {
        let served: Vec<&str> = served_names();
        super::super::check_served(served.iter().copied())
            .expect("every served gateway method has a row");
        let err = super::super::check_served(["eth_getBalance", "eth_notAThing"])
            .expect_err("a foreign method with no row is refused");
        assert!(err.contains("eth_notAThing"), "{err}");
        let err = super::super::check_served(["eth_subscribe"])
            .expect_err("a pending row cannot be served");
        assert!(err.contains("the Ethereum compatibility gateway"), "{err}");
    }
}
