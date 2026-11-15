# B-0003: Both domain clients panic on every submission ("No provider set")

- **Identifier:** B-0003
- **Severity:** high (the tool cannot submit at all; it is a crash, not a wrong answer)
- **Status:** fixed and green locally on `testnet-quantum` as `f4619898` (rebased onto `10dea2c2`), not pushed at the time of writing, no CI result. The failure was observed on the tree before the fix (see "Observed evidence"), and observed again after an insufficient first attempt (see "The first attempt did not work"). No passing run is captured yet.
- **Related:** PR #110 adds these two binaries; they do not exist on captured `main`.

## Location

`src/bin/budlum-domain-producer.rs:297` and `src/bin/budlum-domain-reporter.rs:120`:

```rust
let client = reqwest::Client::new();
```

`Cargo.toml:150`:

```toml
# The TLS provider is installed by `crypto::tls` (aws-lc-rs, X25519MLKEM768 only),
# so reqwest takes the provider-less rustls feature.
reqwest = { version = "0.12", features = ["json", "rustls-tls-webpki-roots-no-provider"], default-features = false }
```

`src/crypto/tls.rs:31` supplies `install_default_provider()`, and the three older HTTP binaries call it from `main`: `src/bin/budlum-faucet.rs:688`, `src/bin/budlum-indexer.rs:746`, `src/bin/budlum-relayer.rs:1070`. Neither domain client does.

## What is wrong

The workspace deliberately builds reqwest against `rustls-tls-webpki-roots-no-provider`, so no process-wide `rustls::crypto::CryptoProvider` exists until someone installs one. `reqwest::Client::new()` needs that provider at construction time, so it panics:

```
thread 'tests::submission_checks_the_network_before_signing_or_sending' panicked at
.../reqwest-0.12.28/src/async_impl/client.rs:767:29:
No provider set
```

## Why it is wrong

The panic happens before any network call and independently of the URL scheme — the failing test in each binary talks to a plain `http://` mock. The producer and reporter therefore abort on every run that submits, which is their entire purpose. Only the offline `--write-payload` producer mode survives, because it never builds a client. The `1` exit code comes from a panic, not from the `Result` error path the CLI's `main` is written to report, so an operator sees a backtrace instead of "RPC chain id differs…".

## What it leads to

1. No operator can submit a domain commitment or a proof-market receipt with these clients; testnet onboarding of an external domain cannot start.
2. The chain-ID binding added in the same PR — the check that the RPC's `bud_chainId` matches the operator-named network — never runs, so the fix that is supposed to make clients network-safe is unreachable in practice.
3. Because the panic is in client construction, `--rpc-url` is not even contacted: the failure looks like a broken binary rather than a configuration error.

## How to fix it

The install cannot live only at the top of `main`. Both binaries build the client in `run`, and the HTTP regression tests call `run` directly, so a `main`-only install leaves the test path — and any future caller that reuses `run` — unprotected. The fix puts it where the client is built, in both files:

```rust
/// A client whose TLS stack is ready to use.
///
/// reqwest is built against `rustls-tls-webpki-roots-no-provider`, so
/// `Client::new()` panics unless a process-wide provider is installed first.
/// The install is idempotent and keeps an existing default, and doing it here
/// rather than only in `main` covers every entry point - including a test that
/// calls `run` directly, which is exactly how the missing install went unnoticed.
fn http_client() -> reqwest::Client {
    budlum_core::crypto::tls::install_default_provider();
    reqwest::Client::new()
}
```

`src/bin/budlum-domain-producer.rs:84` and `src/bin/budlum-domain-reporter.rs:71`; the single call site in each `run` now reads `let client = http_client();` (`producer:309`, `reporter:132`). `install_default_provider` is idempotent and keeps an existing default, so a process that already installed one is unaffected. The alternative — dropping `rustls-tls-webpki-roots-no-provider` from the crate-wide reqwest feature — would change the TLS policy of every HTTP binary and is not warranted.

## The first attempt did not work

Installing the provider at the top of `main` (the shape the faucet, indexer and relayer use) was tried first and the producer test still failed with the same panic at the same line. The reason is visible in the test: it calls `run(Cli::…).await` directly, so `main`'s install never executes; the binary rebuilt at 14:51:02 against the patched source and the failure reproduced at 14:52:08 (`/var/tmp/budlum-producer-fixed.log`). Copying the older binaries' pattern would therefore have shipped a "fix" whose only test still failed for a different reason than the one it was meant to cover. This is why the final shape installs at the client construction site instead.

## Observed evidence

Command: `cargo test --bin budlum-domain-producer --locked` with `CARGO_TARGET_DIR=/var/tmp/budlum-target`, on the working tree without the install line:

```
running 4 tests
test tests::signing_refuses_a_different_rpc_network ... ok
test tests::strix_110_submission_requires_an_independent_network ... ok
test tests::submitting_requires_the_operators_network_chain_id ... ok
test tests::submission_checks_the_network_before_signing_or_sending ... FAILED
test result: FAILED. 3 passed; 1 failed
```

The reporter binary failed identically in the same stage run (`tests::submission_checks_the_network_before_signing_or_sending ... FAILED`, 4 passed, 1 failed). Both failures were observed before any install line existed. After the fix: `cargo test --bin budlum-domain-producer` 2 passed, `cargo test --bin budlum-domain-reporter` 2 passed, each including `submission_checks_the_network_before_signing_or_sending`.

## Note on why the unit tests missed it

`Cli::try_parse_from` tests and `chain_id_binding` tests never construct a client, so a parse-and-bind-only test suite stays green while the binary cannot run. The failing test is the only one that crosses into `run`. This is the general shape to watch in the other binaries: install coverage, not parsing coverage.
