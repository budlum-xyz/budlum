# B-0047: the dead-public-API ratchet cannot see common names, so dead plugin methods read as live

- **Location:** `xtask/gates/src/gates/dead_pub_api.rs:239-264` on `budlum-consensus-of-consensuses` head `7533b71b`; baseline `.github/dead-pub-api-baseline.txt` (183 entries).
- **Severity:** low to medium for audit tooling. No runtime impact. It matters because this gate is one of the few that is supposed to keep "tested" and "wired" different words, and B-0046 is exactly the case it cannot see.

## The rule, as implemented

```rust
// xtask/gates/src/gates/dead_pub_api.rs:244-252
let counted = surface.references.get(name).copied().unwrap_or(0);
let declared = own.get(name).copied().unwrap_or(0);
if counted > declared {
    continue;   // "referenced somewhere in the corpus" - no further question asked
}
```

`surface.references` counts every identifier-shaped token of that name anywhere in the corpus, with `#[cfg(test)]` modules stripped (`:216-218`). `if counted > declared` is a **name** test, not a call test, and it is not receiver-aware.

## The demonstration

The plugin registry of B-0046 exports four read methods with no production caller. Two of them are measured dead, two are measured live, purely by the collision count of their names:

| method (`src/domain/plugin_registry.rs`) | token occurrences in `src/**/*.rs` | declarations in that file | gate verdict |
|---|---|---|---|
| `domain_ids` (`:138`) | 1 | 1 | dead → listed in `.github/dead-pub-api-baseline.txt` |
| `get` (`:133`) | 2,816 | 1 | "referenced" → invisible |
| `len` (`:142`) | 5,394 | 1 | "referenced" → invisible |
| `is_empty` (`:147`) | 1,742 | 1 | "referenced" → invisible |

The single reference that keeps `get` alive is in its own file: `replace()` calls `self.plugins.get(&domain_id)` (`:110`), a `BTreeMap::get`. One `BTreeMap` accessor of the same name makes the registry accessor unmeasurable, and `domain_ids`, whose name nothing else uses, is the one the ratchet caught.

## Why this is worth recording

- A dead `pub fn` whose name collides with a common method name (`get`, `len`, `is_empty`, `new`, `insert`, `hash`) is permanently exempt without anyone writing an exemption. The gate's own documentation names two limits (a function taken as a value, and cross-directory references); name collision is a third and it is the one that hides wiring gaps in the layer this audit cares most about.
- The `WIRING:` / `Convenience:` / `exposed for` doc-line exemption (`:22-24`, `:254-258`) is the honest way out, and it is visible in a diff. Collision is not: nothing in the tree says "this method is dead", so a reviewer reading `plugin_registry.rs` sees four normal accessors.
- A ratchet that under-reports is worse than no ratchet at all in one specific way: the baseline's 183 entries read as a complete inventory of unwired public API, and they are not.

## Repair plan

1. Make the reference test receiver-aware for method names: count a name as referenced only when it appears as `.name(` or `::name(`, not as a bare token, and prefer matching `Type::name` / `receiver.name(` shapes for the module's own types.
2. Keep a short, explicit list of generic names (`get`, `len`, `is_empty`, `new`, `insert`) that are never counted as references; a method with one of those names then needs a `WIRING:` doc line to pass, which is exactly the signal the gate exists to produce.
3. Regenerate the baseline after the rule change and treat the delta as the real inventory.
4. Add a self-test: a two-file fixture where file A declares `pub fn get` and file B contains `map.get(x)`, and assert the gate reports the declaration dead.

## Status

open. The table's numbers are reproducible with `git grep -o -w <name>` over `src/**/*.rs` at head `7533b71b`; the gate's comparison is quoted above. Neither the gate nor the baseline was modified by this audit.
