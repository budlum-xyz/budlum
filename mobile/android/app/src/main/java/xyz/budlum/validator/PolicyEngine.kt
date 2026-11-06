package xyz.budlum.validator

import android.os.PowerManager

/**
 * Runtime policy engine for the Android Mobile validator (Section 7.9.4, R-33, R-35).
 *
 * - Default network mode is strictly unmetered Wi-Fi (`wifiOnly = true`).
 * - Thermal pause at [PowerManager.THERMAL_STATUS_MODERATE] or higher is immutable (`R-35`).
 * - Custody quota is bounded to `[1 GiB, 64 GiB]` (default `4 GiB`).
 */
data class ValidatorPolicy(
    val wifiOnly: Boolean = true,
    val dailyCellularCapMib: Int = 0,
    val chargingOnly: Boolean = false,
    val minBatteryPercent: Int = 50,
    val quotaBytes: Long = DEFAULT_QUOTA_BYTES,
    val serveSymbolsEnabled: Boolean = true,
) {
    val thermalPauseEnabled: Boolean = true

    init {
        require(wifiOnly || dailyCellularCapMib > 0) {
            "Cellular mode requires a positive daily MiB cap (R-33)"
        }
        require(quotaBytes in MIN_QUOTA_BYTES..MAX_QUOTA_BYTES) {
            "Quota must stay within 1 GiB..64 GiB"
        }
    }

    fun setThermalPause(enabled: Boolean): ValidatorPolicy {
        if (!enabled) {
            throw IllegalArgumentException("Thermal pause cannot be disabled (R-35)")
        }
        return this
    }

    fun permitsDuty(
        isUnmeteredWifi: Boolean,
        isCharging: Boolean,
        batteryPercent: Int,
        batterySaverEnabled: Boolean,
        thermalStatus: Int,
    ): Boolean {
        if (thermalStatus >= PowerManager.THERMAL_STATUS_MODERATE) {
            return false
        }
        if (wifiOnly && !isUnmeteredWifi) {
            return false
        }
        if (chargingOnly) {
            return isCharging
        }
        return isCharging || (batteryPercent > minBatteryPercent && !batterySaverEnabled)
    }

    fun custodyRewardMultiplierBps(): Int = if (serveSymbolsEnabled) 10_000 else 5_000

    companion object {
        const val GIB: Long = 1L shl 30
        const val MIN_QUOTA_BYTES: Long = 1L * GIB
        const val DEFAULT_QUOTA_BYTES: Long = 4L * GIB
        const val MAX_QUOTA_BYTES: Long = 64L * GIB
        const val LOW_FREE_SPACE_THRESHOLD_BYTES: Long = 2L * GIB
    }
}
