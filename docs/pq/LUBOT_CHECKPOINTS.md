# Model checkpoint manifests (Lubot interface)

Lubot model checkpoints are signed with the same format as Budlum releases
.

- The manifest lists every checkpoint file: `<SHA3-256 hex>  <path>`, paths
  relative to the checkpoint directory, sorted, unique, one per line, with a
  final newline.
- The signature is SLH-DSA-SHAKE-256s (FIPS 205) over the manifest bytes with
  the context string `BDLM/RELEASE/V1`.
- The checkpoint public key is pinned in the Lubot repository next to the
  manifest, the same way `release/RELEASE_PUBKEY.hex` is pinned here. A key of
  all zero bytes means the ceremony has not happened and verification refuses
  it.
- Verification order: signature over the manifest first, then every file hash.
  A file the manifest does not list is not part of the checkpoint.

The Lubot repository implements this interface by calling
`cargo run --release --manifest-path xtask/release/Cargo.toml -- verify-release`
from a pinned checkout of this repository, or by linking the same two crates
(`slh-dsa` and `sha3`, exact versions in `xtask/release/Cargo.toml`). The
example check is `--self-test`, which signs a manifest, verifies it, and
proves that a changed file, a changed manifest, another key, an unsafe path and
the unset key are each refused.
