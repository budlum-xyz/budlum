# Wallet Ecosystem Spec (Mobile + Browser + Multisig)

> **Yazar:** ARENA1, 2026-07-20. **Durum:** Erken tasarım.
> **Bağımlılık:** `wallet-core/` crate (BIP39 + SLIP-0010 + Ed25519 — shipped).

## 1. Mobile (UniFFI → Kotlin/Swift)

### Mimarisi
```
wallet-core (Rust)
  ├── lib.rs (Wallet struct, sign, verify)
  └── uniffi.toml (binding config)
       ↓
  Kotlin (budlum-wallet.kt) / Swift (budlum-wallet.swift)
       ↓
  Android / iOS app
```

### Binding Plan
- `wallet-core/src/lib.rs`'e `#[uniffi::export]` attribute ekle
- `uniffi-bindgen` → Kotlin header + Swift module
- Functions: `generate_wallet`, `from_mnemonic`, `sign_transaction`, `get_address`

### Eksik
- UniFFI dependency + build pipeline
- Transaction serialization (wallet → JSON-RPC tx format)
- Mobile key storage (Keystore/Keychain)

## 2. Browser Extension (wasm-bindgen → JS/TS)

### Mimarisi
```
wallet-core (Rust → wasm32)
  ├── wasm.rs (#[wasm_bindgen] exports)
  └── wallet-core.wasm
       ↓
  JS/TS wrapper (budlum-wallet.js)
       ↓
  Chrome/Firefox extension
```

### Binding Plan
- `wallet-core/src/wasm.rs`: `#[wasm_bindgen]` functions
- `wasm-pack build --target web`
- JS API: `BudlumWallet.generate()`, `.sign()`, `.address`

### Eksik
- wasm-bindgen dependency (Cargo.toml feature flag ready)
- `getrandom` js feature (entropy)
- Chrome extension manifest + UI

## 3. Multisig / Social Recovery

### Mevcut
- **Yok** — hesap bazlı tek-imza (Ed25519)

### Tasarım Seçenekleri

| Model | Açıklama | Karmaşıklık |
|-------|----------|-------------|
| **Smart contract multisig** | BudZKVM kontratı (m-of-n) | Orta |
| **Native multisig** | AccountState'e multisig alanı | Düşük-Orta |
| **Social recovery** | Guardian set (k-of-n recovery) | Orta-Yüksek |
| **Threshold (FROST)** | Threshold Ed25519 (DKG) | Yüksek |

### Öneri
- **Görev 1:** Native multisig (AccountState'e `multisig_config` alanı)
- **Görev 2:** Social recovery (guardian set + recovery flow)
- **Görev 3:** Threshold Ed25519 (SLIP-0010 + FROST)

### Permissionless Kural
- Multisig hesaplar permissionless — herkes oluşturabilir
- Recovery flow on-chain governance değil → wallet-level

## 4. Gap Analizi

- **Transaction serialization:** Wallet → chain tx format (V29 V4 signing)
- **Key storage:** OS-level secure storage (Keystore/Keychain/SecureRandom)
- **UX:** Mnemonic backup flow, address verification, fee estimation
- **Hardware wallet:** Ledger/Trezor support (future)

---

*Co-authored-by: ARENA1 <arena1@budlum.ai>*
