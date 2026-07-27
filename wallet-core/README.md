# Budlum Wallet Core

BIP39 mnemonic + SLIP-0010 Ed25519 key derivation + transaction signing for Budlum.

## Permissionless Relayer

This is a **wallet**, not a relayer. The wallet signs transactions; the user
submits them to any permissionless relayer (stake + slashing). Wallet-core
contains **no** relayer registration/stake/whitelist code.

## Usage

```rust
use budlum_wallet_core::Wallet;

let wallet = Wallet::generate(12).unwrap();
println!("Mnemonic: {}", wallet.mnemonic());
println!("Address: {}", wallet.address_hex());

let sig = wallet.sign(b"message");
```

## Features

- BIP39 mnemonic (12/24 word)
- SLIP-0010 Ed25519 HD derivation (hardened-only per RFC 8032)
- Address = Ed25519 pubkey → SHA3-256 (32 byte)
- Transaction signing (Ed25519)
- Planned: UniFFI (Kotlin/Swift), wasm-bindgen (JS)
