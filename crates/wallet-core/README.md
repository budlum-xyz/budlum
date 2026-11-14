# Budlum Wallet Core

BIP39 mnemonic + FIPS 204 ML-DSA-87 key derivation and transaction signing for Budlum. <!-- claim:L-WALLET-01 -->

ML-DSA-87 (NIST Category 5, formerly CRYSTALS-Dilithium5) replaces the retired
Ed25519 scheme: ML-DSA rests on module lattices, not on factoring or discrete
logarithms, so Shor's algorithm does not apply to the wallet key. <!-- claim:L-WALLET-01 --> Public keys are 2592 bytes; signatures are 4627 bytes (FIPS 204
final). The 32-byte seed is expanded through FIPS 204 `KeyGen_internal` after a
domain-separated SHA3-256 of the BIP39 entropy.

## Permissionless Relayer

This is a **wallet**, not a relayer. The wallet signs transactions; the user
submits them to any permissionless relayer (stake + slashing). Wallet-core
contains **no** relayer registration/stake/whitelist code.

## Usage

```rust
use budlum_wallet_core::{Wallet, WalletPrivacyConfig, ML_DSA_87_SIGNATURE_LEN};

let wallet = Wallet::generate(12).unwrap();
println!("Mnemonic: {}", wallet.mnemonic());
println!("Address: {}", wallet.address_hex());

let sig = wallet.sign(b"message");
assert_eq!(sig.len(), ML_DSA_87_SIGNATURE_LEN);
```

## Features

- BIP39 mnemonic (12/24 word)
- FIPS 204 ML-DSA-87 key derivation (Category 5, hardened seed-only)
- Address = ML-DSA-87 pubkey → domain-separated SHA3-256 (32 byte)
- Transaction signing (ML-DSA-87)
- M-of-N multisig (up to 16 owners, independent signatures)
- Guardian-based social recovery
- V5 transfer signing the node accepts (`transfer::signed_transfer_json`;
  the signing hash is pinned by the same vector in the node's tests)
- JSON-RPC bodies and answers for the node's public listener (`rpc`
  feature; transport-free)
- Browser: `wasm` feature exports `BrowserWallet` (24-word mnemonic, address,
  V5 transfer signing) and the RPC helpers; `web/index.html` is a test page
  that signs and sends. Built for `wasm32-unknown-unknown` in CI.
- Planned: UniFFI (Kotlin/Swift). Not built yet; the binding descriptor's
  `bindings_are_wired` stays false until it is.
