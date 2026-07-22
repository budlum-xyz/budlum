# BLS/PQ HSM Policy (Task 2 §1.1)

**Tarih:** 2026-07-15
**Durum:** PKCS#11 Ed25519 yolu + BLS/PQ mock backend main kod tabanında mevcut; mainnet disk-key yasağı fail-closed kalır. Vendor-native non-extractable BLS/Dilithium HSM mekanizmaları hâlâ ayrı audit/entegrasyon maddesidir.
**Kod:** `src/crypto/pkcs11.rs`, `src/crypto/mainnet_policy.rs` (H4 pure admission), `src/main.rs`, `src/cli/commands.rs`

> **Not (2026-07-20):** `hsm_mock` crate path may be absent; mainnet admission
> explicitly rejects `hsm_mock`/`mock` backends via `MainnetKeyPolicyViolation::HsmMockBackend`.
> Vendor-native non-extractable BLS/PQ remains **out of scope for mainnet v1** (K3).

> Bu belge mainnet için sahte-yeşil iddia üretmez. Mock backend geliştirici ve
> CI doğrulaması içindir; mainnet validator profili `hsm_mock` ile çalışmaz.

## Politika özeti

| Ortam | İzinli validator key yolu | BLS/PQ davranışı |
|-------|---------------------------|------------------|
| Devnet/testnet | `ValidatorKeys`, `pkcs11` veya `hsm_mock` | Geliştirici doğrulaması için BLS/PQ mock imza yolu kullanılabilir. |
| Mainnet validator | Sadece `validator.signer.backend = "pkcs11"` | Disk `ValidatorKeys` ve `hsm_mock` fail-closed reddedilir. |
| Mainnet validator + disk `ValidatorKeys` | Yasak | Dosya BLS + Dilithium secret içerdiği için process çıkar. |
| Mainnet validator + vendor-native BLS/PQ HSM | Hedef | Donanım/vendor entegrasyonu ve harici audit gerektirir. |

## Mevcut kod sınırları

### PKCS#11 backend

`src/crypto/pkcs11.rs` Ed25519 consensus signer adapter’ını sağlar. Ayrıca
`BUD_BLS_KEY` ve `BUD_PQ_KEY` label’lı private data object’lerden BLS/PQ
materyali okuyabilen destek kodu vardır. Bu, disk `ValidatorKeys` kullanımını
azaltmak için bir inventory/signing yoludur; her vendor için native
non-extractable BLS/Dilithium mekanizması iddia edilmez.

### HSM mock backend

`src/crypto/hsm_mock.rs` ve `--signer-backend=hsm_mock`:

- in-process UNIX socket thread başlatır,
- BLS ve Dilithium/PQ imzalama akışını geliştirici ortamında test eder,
- mainnet validator strict rules tarafından reddedilir.

Bu backend production secret saklama çözümü değildir.

### Runtime fail-closed kuralları

`src/cli/commands.rs` mainnet validator başlatırken:

1. `validator.signer.backend = "pkcs11"` zorunlu kılar,
2. PKCS#11 `module_path` ve `token_pin_env` ister,
3. PIN env yok/boş ise çıkar,
4. disk-backed `ValidatorKeys` dosyasını reddeder.

## Operatör yapılandırması

`config/mainnet.toml` örneği:

```toml
[validator]
backend = "pkcs11"

[validator.signer]
backend = "pkcs11"

[validator.signer.pkcs11]
module_path = "/path/to/vendor-pkcs11.so"
slot_id = 0
token_pin_env = "BUDLUM_PKCS11_TOKEN_PIN"
```

PIN değeri repo, CLI argümanı veya log’a yazılmaz; yalnızca environment/secret
manager üzerinden verilir.

## Doğrulama

```bash
cargo test --lib test_hsm_mock_backend
cargo clippy --lib --tests -- -D warnings
cargo fmt --all -- --check
```

Bu Arena sandbox’ında `cargo`/`rustc` yoksa PR CI zorunlu kanıt kabul edilir.

## Kabul kriteri

- [x] Disk-backed `ValidatorKeys` mainnet validator için reddedilir.
- [x] Mainnet validator `hsm_mock` ile başlatılamaz; yalnız `pkcs11` kabul edilir.
- [x] BLS/PQ mock backend geliştirici/CI amaçlı geri gelir.
- [x] Mock backend production HSM olarak dokümante edilmez.
- [ ] Vendor-native non-extractable BLS/Dilithium PKCS#11 mekanizma entegrasyonu ayrıca yapılacak.

## Sınırlar / yapılmayanlar

- Harici audit yapılmadı.
- BLS/Dilithium için vendor-specific native PKCS#11 mechanism desteği iddia edilmez.
- B.U.D. Proof-of-Storage Görev 3 ile ilişkili değildir.
- Bu policy, `VerifyMerkle` Z-B gate’ini açmaz.
