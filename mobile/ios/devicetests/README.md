# iOS device tests (WP-38)

The unit tests in `Tests/BudlumValidatorKitTests` run on a macOS runner on every
push. The three tests below need a simulator or a device, because the thing
under test is the platform's behaviour rather than the kit's arithmetic.

They are listed here with their pass criteria so they can be run by hand before
the WP-38 2/N simulator harness automates them. Nothing here is measured yet:
the numbers in the criteria are the directive's, and the measured values belong
in `docs/MOBILE_DEVICE_MATRIX.md` once a run exists (directive 0.5).

## `ios_bg_task_answers_audit`

**Unit form.** Exists and passes in CI: see
`Tests/BudlumValidatorKitTests/BackgroundDutyTests.swift`. It asserts that one
duty pass answers every outstanding audit and then signs presence, in that
order.

**Device form.** With the app backgrounded on a charging device and one audit
outstanding, the log at `Application Support/bud3/duty.log` gains one
`AUDIT pass` line and one `RUN` line within the audit window.

Steps:

1. Install a TestFlight build on a physical iPhone (the simulator does not run
   `BGProcessingTask`).
2. Register the device with a 1 GiB quota so at least one share is assigned
   quickly.
3. Wait for a share, then background the app and connect the charger.
4. Force the task:
   ```
   e -l objc -- (void)[[BGTaskScheduler sharedScheduler] _simulateLaunchForTaskWithIdentifier:@"dev.budlum.validator.duty"]
   ```
5. Pull the container and check the log with `mobile/tools/log-analyzer`.

**Pass criterion.** One `AUDIT pass` line appears within the 48-hour window,
and `audits.pass_rate` in the analyzer output is `1.0000`.

## `ios_quota_cap_is_8_gib`

**Unit form.** In CI: the consensus ceiling of the opportunistic class is
8 GiB, and the app's own range ends there.

**Device form.** The quota slider in Settings cannot be moved above 8 GiB, and
`RegisterValidator` with a declared quota of 8 GiB + 1 byte is refused by the
node with `quotaAboveClassCeiling`.

**Pass criterion.** The slider's maximum reads 8 GB on the device, and the
refusal is visible in the node log.

## `ios_class_is_opportunistic`

**Unit form.** In CI: the tag of the class is 2, it holds no seat, and the
per-class windows match the Rust definition.

**Device form.** The registration request the device sends carries class tag
`2`, and the explorer page of the validator shows the opportunistic class, a
48-hour audit window and a seven-day suspension threshold.

**Pass criterion.** The three values on the explorer page agree with
`crates/budlum-types/src/class.rs`.
