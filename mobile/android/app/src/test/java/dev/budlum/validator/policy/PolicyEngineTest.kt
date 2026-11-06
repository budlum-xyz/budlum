package dev.budlum.validator.policy

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit tests named after the WP-36 acceptance tests that do not need an
 * emulator: policy defaults and immutability (directive 7.9.4, R-33, R-35).
 */
class PolicyEngineTest {

    private fun state(
        metered: Boolean = false,
        charging: Boolean = true,
        battery: Int = 80,
        powerSave: Boolean = false,
        thermal: Int = 0,
    ) = DeviceState(
        isMetered = metered,
        isCharging = charging,
        batteryPercent = battery,
        powerSaveOn = powerSave,
        thermalStatus = thermal,
    )

    @Test
    fun `android_policy_wifi_only_by_default`() {
        val policy = AppPolicy()
        assertTrue(policy.network.wifiOnly)
        // Metered network with the default policy pauses the validator.
        assertEquals(
            RunDecision.PAUSED_NETWORK,
            PolicyEngine.decision(policy, state(metered = true))
        )
        // Unmetered network runs.
        assertEquals(RunDecision.RUN, PolicyEngine.decision(policy, state(metered = false)))
    }

    @Test
    fun `android_thermal_pause_cannot_be_disabled`() {
        // There is no policy field that can turn the thermal pause off: the
        // decision depends only on the device thermal status.
        val policy = AppPolicy()
        for (thermal in PolicyEngine.THERMAL_STATUS_MODERATE..6) {
            assertEquals(
                RunDecision.PAUSED_THERMAL,
                PolicyEngine.decision(policy, state(thermal = thermal))
            )
        }
        assertEquals(
            RunDecision.RUN,
            PolicyEngine.decision(policy, state(thermal = PolicyEngine.THERMAL_STATUS_MODERATE - 1))
        )
    }

    @Test
    fun `daily_mobile_cap_pauses_when_exhausted`() {
        val policy = AppPolicy(
            network = NetworkPolicy(wifiOnly = false, dailyMobileCapMb = 100)
        )
        val under = state(metered = true).copy(mobileUsedMbToday = 99)
        val over = state(metered = true).copy(mobileUsedMbToday = 100)
        assertEquals(RunDecision.RUN, PolicyEngine.decision(policy, under))
        assertEquals(RunDecision.PAUSED_NETWORK, PolicyEngine.decision(policy, over))
    }

    @Test
    fun `power_default_requires_charging_or_battery_above_50_without_powersave`() {
        val policy = AppPolicy()
        assertEquals(RunDecision.RUN, PolicyEngine.decision(policy, state(charging = true)))
        assertEquals(RunDecision.RUN, PolicyEngine.decision(policy, state(charging = false, battery = 60)))
        assertEquals(RunDecision.PAUSED_POWER, PolicyEngine.decision(policy, state(charging = false, battery = 50)))
        assertEquals(RunDecision.PAUSED_POWER, PolicyEngine.decision(policy, state(charging = false, battery = 60, powerSave = true)))

        val chargingOnly = AppPolicy(power = PowerPolicy(PowerMode.CHARGING_ONLY))
        assertEquals(RunDecision.PAUSED_POWER, PolicyEngine.decision(chargingOnly, state(charging = false, battery = 90)))
        assertEquals(RunDecision.RUN, PolicyEngine.decision(chargingOnly, state(charging = true)))
    }

    @Test
    fun `quota_defaults_to_4gib_and_is_clamped_to_1_64_gib`() {
        assertEquals(4L * 1024 * 1024 * 1024, AppPolicy().quota.quotaBytes)
        assertEquals(PolicyEngine.MIN_QUOTA_BYTES, PolicyEngine.clampQuota(1))
        assertEquals(PolicyEngine.MAX_QUOTA_BYTES, PolicyEngine.clampQuota(Long.MAX_VALUE))
    }

    @Test
    fun `symbol_serving_off_halves_the_reward`() {
        assertEquals(1.0, PolicyEngine.rewardMultiplier(AppPolicy()), 0.0)
        assertEquals(0.5, PolicyEngine.rewardMultiplier(AppPolicy(symbol = SymbolPolicy(serveSymbols = false))), 0.0)
    }

    @Test
    fun `quota_policy_rejects_out_of_range_values`() {
        assertFalse(runCatching { QuotaPolicy(quotaBytes = 1) }.isSuccess)
        assertFalse(runCatching { QuotaPolicy(quotaBytes = 65L * 1024 * 1024 * 1024) }.isSuccess)
    }
}
