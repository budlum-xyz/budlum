# Mobile field log analyzer

Run from the repository root with the pinned Rust toolchain:

```text
cargo run --manifest-path mobile/tools/log-analyzer/Cargo.toml -- mobile/tools/log-analyzer/fixtures/samples.jsonl
```

Pass a UTF-8 JSONL file as the sole argument. On success the tool prints a JSON
summary; malformed input, an empty file, or a policy violation produces a
message on stderr and a nonzero exit code. The sample and report fixtures are
synthetic, not device results.

Each line is a `MobileFieldSample` described in `docs/MOBILE_DEVICE_MATRIX.md`.
Device count is the number of distinct IDs. Audit and reward fields are summed
as per-interval deltas, not cumulative counters: exporting overlapping intervals
or cumulative values would double-count them. RSS and battery are maxima.

The summary does not establish 24-hour service uptime, timeout absence, battery
measurement methodology, or NAT connectivity. Real-device logs and independent
review remain required for the device matrix and release decision.
