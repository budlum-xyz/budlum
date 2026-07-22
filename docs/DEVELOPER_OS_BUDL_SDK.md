# Budlum Developer OS / BudL SDK — Task 12 Skeleton

> **TR Özet:** Bu belge P12-12 Developer OS / BudL SDK ilk iskeletini tarif eder. Amaç; lokal devnet, BudL paket fixture'ı, proof fixture'ları, Pollen grant akışı ve relayer policy fixture'larını tek deterministik manifest altında toplamak. Bu belge mainnet-ready veya external SDK release iddiası değildir.

## Scope

The first Task 12 Developer OS step is a pure manifest/fixture layer in `src/developer_os.rs`.
It does not start a network, call external APIs, or depend on `budlumdevnet`.

The manifest binds:

- local devnet topology,
- BudL package source hash and compiler profile,
- proof fixture commitments,
- Pollen asset/grant fixtures,
- relayer policy fixture hash,
- SDK feature flags.

## Guardrails

- Local templates are offline by default (`external_network_access = false`).
- BudL source is represented by a hash, not arbitrary host paths.
- Verified proof fixtures cannot claim `Verified` with a zero proof hash.
- Pollen fixtures cannot model AI grant bypass; `ai_read_requires_grant` must stay true.
- Project/package labels reject path traversal.

## ARENA2 coordination note

ARENA2's `origin/arena2/budl-hardening-v2` branch was inspected before this step.
It contains BudL compiler hardening work and remains a reference for future compiler-layer hardening; it was not merged into main in this ADIM.

## Future CLI shape

A later CLI/SDK layer can consume the manifest and materialize:

```text
budlum dev new <project>
budlum dev fixture proof
budlum dev fixture pollen
budlum dev run --topology single-node
```

Those commands are intentionally out of scope for this first primitive step.
