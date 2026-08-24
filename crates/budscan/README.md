# Budscan

Budlum's decentralised browser. It opens Web3 extensions and decentralised
storage; wallet addresses, NFTs and sites are all searched from the same box.

```
budscan/
  src/          browser core (Rust, its own workspace)
  browser/      Gecko patch layer (patches, settings, localisation)
```

## What it does

The user types `ayaz.bud` into the address bar:

1. **Classification** (`query.rs`): is the typed thing a name, an address, an
   NFT, or a scheme.
2. **Name rule** (`name_rule.rs`): a name that does not pass is not opened, and
   the reason is stated.
3. **Resolution**: `.bud` through BNS (`bns_proof.rs`), `.eth` through ENS
   (`ens.rs`).
4. **Fetching** (`fetch.rs`): four fetchers, each declaring its own strength.
5. **Verification**: it is **measured** that the fetched bytes are the
   requested bytes.
6. **Badge** (`resolve.rs`): the weakest link is shown in the address bar.

The fifth step is this browser's reason to exist. On today's web a browser does
not know that the bytes the server sent are the right bytes: TLS says only
**who** sent them, not **what** was sent. On a content-addressed network
`manifest_id` is the hash of the bytes, so verification is a comparison and the
browser never has to decide whom to trust.

## Verification strength: four values

| value | what it means | example |
|---|---|---|
| `verified` | the digest of the bytes equals the expected identity | B.U.D. manifest, IPFS raw CID, Arweave `data_root` |
| `transport only` | TLS is present, the content was not verified | ordinary HTTPS |
| `claim only` | a node answered, no proof was verified | BNS resolution without a proof |
| `refused` | it was measured and did not hold; the content is not shown | hash mismatch, name-rule refusal |

The badge shows the **weakest link**. A page whose bytes match their hash still
reads `claim only` when its resolution carries no proof: the bytes are
consistent with themselves, and nobody proved they belong to this name.

Content that cannot be verified is **labelled, not banned**. Banning makes the
browser unusable and sends the user to another browser that verifies nothing.
`refused` is the exception: there a measurement was made and it did not hold.

## What is not verified is written down too

Part of this crate is a record of **what cannot be done**. None of it is
quietly labelled `verified`:

* **BNS resolution cannot be proven per name today.** `BnsRegistry::root()`
  (`src/bns/registry.rs:299`) writes the whole registry into a single SHA-256
  stream, not into a Merkle tree. There is no structure that could produce a
  proof for one name; `AccountState::calculate_state_root` folds it into the
  state root under the `bns_v1` tag, and verifying it needs the entire
  registry. Changing the proof format is a **consensus surface change**, and
  not a decision this browser takes unilaterally (`bns_proof.rs`).
* **Header finality is not verified in the browser.** There are seven
  `DomainFinalityAdapter` shapes (PoW header chain, PoS, PoA, BFT, ZK, storage
  attestation, AI inference) and none is implemented client-side
  (`light_client.rs`).
* **IPFS `dag-pb` multi-block content is not verified.** Walking a UnixFS DAG
  is a separate job; `CidVerdict::UnsupportedMultiblock` says so (`cid.rs`).
* **There is no fetcher for IPNS or Swarm.** Falling back to HTTPS would mean
  presenting unverified content as if it were verified (`resolve.rs`).
* **Key distribution for encrypted content is unsolved.**
  `ContentEncryption::ClientSide` exists; how the key reaches the browser is
  the access-permission layer's job and is not here.
* **The sandbox boundary is not measured.** Verified content is not safe
  content; a page whose hash matches can still be malicious. Gecko's sandbox
  does that job, and how to show that the patches do not weaken it has not been
  measured.

## No shell

Nothing is shell, the patch tooling included. The reason was measured: a
misspelt variable is not an error in a shell but an empty string, so a check
can inspect nothing and report OK. The concrete example is inside
`browser/README.md`.

In `patchset.rs`, "I could inspect nothing" is a separate outcome
(`Verdict::Vacuous`) and `is_ok()` returns false.

## Duplicates, and the gate that holds them together

Budscan does **not** depend on `budlum-core`: doing so would pull in libp2p,
tokio, jsonrpsee and sled, and that graph is unwanted at a browser's trust
boundary. The price is two copies, and the price is measured:

| copy | browser | chain |
|---|---|---|
| name rule | `src/name_rule.rs` | `xtask/gates/.../bns_names_are_safe_in_an_address_bar.rs` |
| `ContentId` | `src/content_id.rs` | `src/storage/content_id.rs` |
| size limit | `src/fetch.rs` | `src/gateway/service.rs` |
| `EPOCH_LENGTH` | `src/light_client.rs` | `src/chain/blockchain.rs` |

The `budscan-name-rule-parity` gate measures all four in CI. Divergence would
be silent: the browser accepts a name the chain does not, or the browser says
a byte is verified while the chain computes a different identity.

## The gap between the document and the measurement

The architecture note says `xn--yaz-hlc.bud` for `аyaz.bud`, whose first letter
is Cyrillic U+0430. **That is wrong.** The RFC 3492 algorithm and Python's
`str.encode("idna")` reference both produce `xn--yaz-5cd.bud`. The code carries
the computed value, not the one copied out of the document (`punycode.rs`, the
`one_cyrillic_letter_in_a_latin_word` test).

## Running it

```
cargo test  --manifest-path budscan/Cargo.toml
cargo clippy --manifest-path budscan/Cargo.toml --all-targets -- -D warnings
cargo run   --manifest-path budscan/Cargo.toml --bin budscan -- self-test
cargo run   --manifest-path budscan/Cargo.toml --bin budscan -- classify ayaz.bud
cargo run   --manifest-path budscan/Cargo.toml --bin budscan -- name-rule "javascript:alert(1)"

cargo run --release --manifest-path xtask/gates/Cargo.toml -- budscan-name-rule-parity
cargo run --release --manifest-path xtask/gates/Cargo.toml -- budscan-patchset
```

107 tests, all passing. There is no engine source under `browser/` and there
will not be: it is downloaded at build time, the patches are applied, and the
result is compiled.
