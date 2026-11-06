package dev.budlum.validator.work

import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.os.BatteryManager
import android.os.PowerManager
import dev.budlum.validator.policy.DeviceState

/** Reads the current [DeviceState] from system services for the policy engine. */
fun currentDeviceState(context: Context): DeviceState {
    val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    val isMetered = cm.isActiveNetworkMetered

    val battery = context.registerReceiver(
        null,
        IntentFilter(Intent.ACTION_BATTERY_CHANGED)
    )
    val level = battery?.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) ?: -1
    val scale = battery?.getIntExtra(BatteryManager.EXTRA_SCALE, -1) ?: -1
    val batteryPercent = if (level >= 0 && scale > 0) (level * 100 / scale) else 0
    val status = battery?.getIntExtra(BatteryManager.EXTRA_STATUS, -1)
    val isCharging =
        status == BatteryManager.BATTERY_STATUS_CHARGING ||
            status == BatteryManager.BATTERY_STATUS_FULL

    val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
    val powerSaveOn = pm.isPowerSaveMode
    val thermalStatus = if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.Q) {
        pm.currentThermalStatus
    } else {
        0
    }

    return DeviceState(
        isMetered = isMetered,
        mobileUsedMbToday = 0, // in-app meter lands with the mobile core binding
        isCharging = isCharging,
        batteryPercent = batteryPercent,
        powerSaveOn = powerSaveOn,
        thermalStatus = thermalStatus,
    )
}
