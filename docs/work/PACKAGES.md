# Work-package ledger

One row per work package of the directive (section 15.7). A row is written only
from evidence: a path in the tree, a live open pull request, or a command quoted
in the row (section 0.4). This file is the claim record until the issue tracker
is available (section 15.3 items 1-2; GitHub issues are disabled on this
repository), and it is the status record required by section 15.5 item 7.

`WP-NN` here and the directive's own package id are the same package (section
15.3 item 1). Status vocabulary: `not started`, `in progress`, `in review`,
`merged`, `blocked`. "In review" means at least one open pull request claims
the package; it does not mean the package's closing condition is believed to
hold anywhere. `main` is `cccf1da` ("Add files via upload"); no package has
merged to `main`.

This first edition is written from the WP-31 delivery. The other open pull
requests carry their own rows; the merge of the queue will consolidate them.
Rows are not copied from a pull request that has not been read.

| Package | Title | Lane | Layer | Status | Pull requests | Evidence |
|---|---|---|---|---|---|---|
| WP-31 | SVM and Solana RPC subset | C | T-Launch | in review | this PR | `src/rpc/compat/solana/` (namespace, class table, chain reads, named refusals); `docs/SOLANA_RPC.md`; the dedicated listener, subscriptions and SVM worker are 2/N |

## WP-31: SVM and Solana RPC subset

Delivery 1/N of the card. What is in the tree and what it proves:

| Card item | State | Evidence |
|---|---|---|
| Method table, in the `method_class.rs` pattern | delivered | `src/rpc/compat/solana/mod.rs`, `solana_method_table_is_complete` |
| Every Section 8.11.3 method present in the table | delivered | `solana_method_table_is_complete` compares the table to the directive list |
| The table, `api.rs` and `method_class.rs` agree | delivered | `solana_served_set_matches_the_declared_api`, `solana_class_table_matches_the_gateway_table`, and the startup check `method_class::check_served_methods` |
| Every refusal names a door that exists | delivered | `solana_refusals_name_an_existing_door` |
| `requestAirdrop` names the faucet | delivered | `solana_request_airdrop_refuses_and_names_the_faucet` |
| The five subscriptions are pending and not served | delivered | `solana_pending_rows_name_a_package_and_are_not_served` |
| Dedicated listener on `127.0.0.1:18548` (HTTP and WebSocket) | 2/N | not in this delivery |
| SVM worker, `Foreign::Solana` envelope, built-in programs | 2/N | not in this delivery |
| web3.js, Anchor and Solana CLI tool tests | 2/N | they cannot pass before the SVM worker; no green claim is made |

The read side is honest about the dependency: WP-31 depends on WP-26 in
Section 15.7, and the Execution Coordinator is not merged. Serving account
state before it would be the `getBalance`-returns-a-Budlum-balance mistake,
which is why those answers are refusals with a named door rather than
numbers.
