# Bridge asset identifiers

Public bridge-asset registrations use a domain namespace.

For a domain id `d` and domain-local asset bytes `local_asset`, tooling computes
`AssetId::for_domain(d, local_asset)`:

1. bytes `0..4` are `d` as little-endian `u32`;
2. bytes `4..32` are the first 28 bytes of
   `H("BDLM_BRIDGE_ASSET_LOCAL_V1", d_le, local_asset)`.

`BridgeTx::RegisterAsset` refuses an id whose first four bytes do not name the
declaring domain. Consequently, two domain operators cannot register the same
global key, even when they choose identical local asset bytes.

## Migration rule

The rule applies to new registrations through the signed transaction door.
Existing bridge-state rows keep their 32-byte ids and remain usable for lock,
mint, burn, unlock, query, and snapshot restore; no state rewrite silently
renames an in-flight asset. Operators migrating a legacy asset register its
namespaced successor before opening new transfers and allow existing transfers
under the legacy id to settle. Genesis and test harness insertion remains able
to restore legacy rows, but public mempool registration cannot create another
one.
