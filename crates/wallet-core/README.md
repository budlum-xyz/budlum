# Budlum Wallet Core

BIP39 mnemonic + FIPS 204 ML-DSA-87 post-quantum key derivation and transaction signing for Budlum.

ML-DSA-87 (NIST Category 5, formerly CRYSTALS-Dilithium5) replaces the retired
Ed25519 scheme so a Shor-capable adversary cannot recover a wallet key from a
public key. Public keys are 2592 bytes; signatures are 4627 bytes (FIPS 204
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
- Planned: UniFFI (Kotlin/Swift), wasm-bindgen (JS)
