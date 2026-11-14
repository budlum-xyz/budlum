package xyz.budlum.validator.devicetests

/**
 * 24-hour device field-test telemetry emitter for  (`docs/MOBILE_DEVICE_MATRIX.md`).
 *
 * Emits newline-delimited JSON (`JSONL`) records consumed by
 * `budlum_core::registry::rehearsal::analyze_mobile_field_logs` covering:
 * - `android_specialuse_service_runs_24h` (zero `onTimeout` callbacks),
 * - `android_battery_budget` (`<= 500 bps` = 5.00% / 24h unplugged),
 * - `mobile_nat_matrix` (QUIC direct, DCUtR hole-punch, and circuit relay v2).
 */
object DeviceFieldTelemetry {
    fun formatSampleJsonl(
        deviceId: String,
        tier: String,
        peakRssMib: Int,
        dailyBatteryBps: Int,
        meteredBytesServed: Long,
        allowCellularOptIn: Boolean,
        auditsAnswered: Long,
        auditsMissed: Long,
        rewardsCreditedAtoms: Long,
    ): String =
        """{"device_id":"$deviceId","tier":"$tier","peak_rss_mib":$peakRssMib,"daily_battery_bps":$dailyBatteryBps,"metered_bytes_served":$meteredBytesServed,"allow_cellular_opt_in":$allowCellularOptIn,"audits_answered":$auditsAnswered,"audits_missed":$auditsMissed,"rewards_credited_atoms":$rewardsCreditedAtoms}"""
}
