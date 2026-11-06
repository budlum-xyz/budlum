package dev.budlum.validator.policy

/**
 * Working policy of the mobile validator. Directive 7.9.4.
 *
 * The thermal rule is NOT part of the user-editable policy: pausing at
 * THERMAL_STATUS_MODERATE or above is not changeable (risk R-35). It is
 * applied by [PolicyEngine] from the device state alone.
 */
data class NetworkPolicy(
    /** Default: unmetered (Wi-Fi) only. Risk R-33. */
    val wifiOnly: Boolean = true,
    /** Daily mobile-data ceiling in MB. Only consulted when [wifiOnly] is false. */
    val dailyMobileCapMb: Int? = null,
)

data class PowerPolicy(
    val mode: PowerMode = PowerMode.ANY,
)

enum class PowerMode {
    /** Charging, or battery above 50% with power saver off. */
    ANY,

    /** Charging only. */
    CHARGING_ONLY,
}

data class QuotaPolicy(
    val quotaBytes: Long = DEFAULT_QUOTA_BYTES,
) {
    init {
        require(quotaBytes in MIN_QUOTA_BYTES..MAX_QUOTA_BYTES) {
            "quota must be within 1 GiB..64 GiB (directive 7.9.4)"
        }
    }
}

data class SymbolPolicy(
    /** Default: serve symbols on unmetered networks. Turning it off halves the storage reward. */
    val serveSymbols: Boolean = true,
)

data class AppPolicy(
    val network: NetworkPolicy = NetworkPolicy(),
    val power: PowerPolicy = PowerPolicy(),
    val quota: QuotaPolicy = QuotaPolicy(),
    val symbol: SymbolPolicy = SymbolPolicy(),
)

/** Snapshot of the device state the policy engine decides on. */
data class DeviceState(
    val isMetered: Boolean,
    val mobileUsedMbToday: Long = 0,
    val isCharging: Boolean,
    val batteryPercent: Int,
    val powerSaveOn: Boolean,
    /** PowerManager.getCurrentThermalStatus() value. */
    val thermalStatus: Int,
)

enum class RunDecision {
    RUN,

    /** Thermal status at or above MODERATE. Not changeable (R-35). */
    PAUSED_THERMAL,

    PAUSED_NETWORK,
    PAUSED_POWER,
}

object PolicyEngine {
    const val MIN_QUOTA_BYTES = 1L * 1024 * 1024 * 1024
    const val MAX_QUOTA_BYTES = 64L * 1024 * 1024 * 1024
    const val DEFAULT_QUOTA_BYTES = 4L * 1024 * 1024 * 1024

    /** PowerManager.THERMAL_STATUS_MODERATE */
    const val THERMAL_STATUS_MODERATE = 2

    const val BATTERY_PERCENT_THRESHOLD = 50

    /** Storage reward multiplier: symbol serving off halves the reward (7.9.4). */
    fun rewardMultiplier(policy: AppPolicy): Double =
        if (policy.symbol.serveSymbols) 1.0 else 0.5

    fun clampQuota(bytes: Long): Long = bytes.coerceIn(MIN_QUOTA_BYTES, MAX_QUOTA_BYTES)

    /**
     * Decision order is binding: thermal first (immutable), then network,
     * then power.
     */
    fun decision(policy: AppPolicy, state: DeviceState): RunDecision {
        if (state.thermalStatus >= THERMAL_STATUS_MODERATE) return RunDecision.PAUSED_THERMAL
        if (!networkAllowed(policy.network, state)) return RunDecision.PAUSED_NETWORK
        if (!powerAllowed(policy.power, state)) return RunDecision.PAUSED_POWER
        return RunDecision.RUN
    }

    fun networkAllowed(network: NetworkPolicy, state: DeviceState): Boolean {
        if (!state.isMetered) return true
        if (network.wifiOnly) return false
        val cap = network.dailyMobileCapMb ?: return true
        return state.mobileUsedMbToday < cap
    }

    fun powerAllowed(power: PowerPolicy, state: DeviceState): Boolean = when (power.mode) {
        PowerMode.ANY ->
            state.isCharging || (state.batteryPercent > BATTERY_PERCENT_THRESHOLD && !state.powerSaveOn)

        PowerMode.CHARGING_ONLY -> state.isCharging
    }
}
