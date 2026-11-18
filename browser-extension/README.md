# Budlum BNS Browser Extension (Manifest V3)

Gateway-free cryptographic resolver for `.bud` and `*.budlum.xyz` names.

## Architecture

- **Host interception (`rules.json`)**: Uses Manifest V3 `declarativeNetRequest` to route `*.bud` and non-reserved `*.budlum.xyz` main-frame navigations to `resolver.html`. Every label in `src/registry/params.rs::RESERVED_LABELS` is explicitly excluded so core Budlum endpoints (`api`, `rpc`, `docs`, `explorer`, `gateway`, etc.) are never hijacked.
- **Local proof verification (`resolver.js`)**: Queries configured Budlum RPC endpoints via `bud_bnsGetProof` and verifies Merkle inclusion/absence proofs inside the browser using `crates/wallet-core` compiled to WebAssembly (`BrowserHeaderBook`, `verify_bns_proof`, `resolve_bns`).
- **Fail-closed boundary**: Unverified RPC answers are never rendered. If no trusted light-client header root is pinned or no proof matches a trusted root, resolution refuses cleanly.
- **Sealed content sovereignty**: Decryption keys for Sealed B.U.D. 3.0 objects stay strictly inside browser memory and are never sent to any gateway or RPC server.

## Building the local WASM bundle

```bash
wasm-pack build crates/wallet-core \
  --target web \
  --out-dir ../../browser-extension/wasm \
  -- --features wasm
```

Then load `browser-extension/` as an unpacked Manifest V3 extension in Chromium or Firefox.

## License

Licensed under the **PolyForm Shield License 1.0.0** (see [`LICENSE.md`](../LICENSE.md)).
Required Notice: Copyright budlum-xyz (https://github.com/budlum-xyz)
