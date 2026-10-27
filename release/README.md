# Release signing

Every release carries two extra files: `RELEASE.manifest` (one line per release
file, `<SHA3-256 hex>  <path>`) and `RELEASE.manifest.sig` (an SLH-DSA-SHAKE-256s
signature over the manifest, FIPS 205 context `BDLM/RELEASE/V1`).

`RELEASE_PUBKEY.hex` is the pinned release public key (64 bytes, hex). It is all
zero until the release key ceremony has run; `verify-release` refuses an all-zero
key, so nothing verifies before the ceremony.

```text
cargo run --release --manifest-path xtask/release/Cargo.toml -- keygen <seed-file> <public-key-file>
cargo run --release --manifest-path xtask/release/Cargo.toml -- sign-release <seed-file> <base-dir> <out-dir> <file>...
cargo run --release --manifest-path xtask/release/Cargo.toml -- verify-release release/RELEASE_PUBKEY.hex RELEASE.manifest RELEASE.manifest.sig
```

The seed stays offline. The check runs in `.github/workflows/release-signature.yml`.
Model checkpoint manifests use the same format and context; see
`docs/pq/LUBOT_CHECKPOINTS.md`.
