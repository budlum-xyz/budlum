package network.budlum.validator.garden

import android.Manifest
import android.app.ActivityManager
import android.app.NotificationManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.content.ContextCompat
import network.budlum.validator.core.OemBatteryGuide

/**
 * What this phone still needs before it can hold a seat.
 *
 * A validator is a promise to be there. The phone cannot keep that promise
 * on good intentions: Android has to be told to let the work run, and the
 * person has to be the one who says yes. This is the list of those asks,
 * in the order they make sense, with the reason for each - the same way a
 * VPN explains itself before it takes over the connection.
 *
 * Nothing here is a trick. Only two runtime permissions are ever asked
 * for, and battery is not a permission at all: Android gives no way to
 * request it that this app is allowed to use (section 7.9.11 forbids
 * REQUEST_IGNORE_BATTERY_OPTIMIZATIONS), so the person is walked to the
 * setting instead of being asked for something the app must not ask.
 */
data class Readiness(
    val notifications: Boolean,
    val batteryUnrestricted: Boolean,
    val camera: Boolean,
    /** The path through this phone's own settings app, by manufacturer. */
    val batteryPath: String,
    val batteryFamily: String,
) {
    /**
     * Whether the phone can take a seat now.
     *
     * Battery is not in this gate. It cannot be read reliably on every
     * manufacturer and the person may reasonably decline it, so it is
     * advice that stays visible rather than a door that stays shut.
     */
    val canValidate: Boolean get() = notifications
}

object GardenReadiness {

    /** Notifications are the only thing the validator truly cannot do without. */
    fun notificationPermission(): String? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            Manifest.permission.POST_NOTIFICATIONS
        } else {
            null
        }

    fun read(context: Context): Readiness {
        val guide = OemBatteryGuide.forManufacturer(Build.MANUFACTURER ?: "")
        return Readiness(
            notifications = notificationsAllowed(context),
            batteryUnrestricted = batteryUnrestricted(context),
            camera = granted(context, Manifest.permission.CAMERA),
            batteryPath = guide.settingsPath,
            batteryFamily = guide.manufacturerFamily,
        )
    }

    /**
     * Both halves of it: the runtime permission on Android 13 and later,
     * and the channel-level switch that a person can turn off at any time
     * on every version. A validator with its notification switched off is
     * a foreground service nobody can see, which is not honest.
     */
    private fun notificationsAllowed(context: Context): Boolean {
        val permission = notificationPermission()
        if (permission != null && !granted(context, permission)) return false
        val manager = context.getSystemService(NotificationManager::class.java) ?: return false
        return manager.areNotificationsEnabled()
    }

    /**
     * Whether the system is leaving this app's background work alone.
     *
     * `isBackgroundRestricted` is the one signal Android gives without a
     * permission. It answers the worst case - the app was explicitly
     * restricted - and not every manufacturer's extra layer, which is why
     * the written path stays on screen either way.
     */
    private fun batteryUnrestricted(context: Context): Boolean {
        val manager = context.getSystemService(ActivityManager::class.java) ?: return true
        return !manager.isBackgroundRestricted
    }

    private fun granted(context: Context, permission: String): Boolean =
        ContextCompat.checkSelfPermission(context, permission) == PackageManager.PERMISSION_GRANTED

    /** The page of the system settings where the battery choice is made. */
    fun batterySettings(context: Context): Intent =
        Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
            data = Uri.fromParts("package", context.packageName, null)
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        }

    /** The page where this app's notifications are switched on. */
    fun notificationSettings(context: Context): Intent =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply {
                putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName)
                addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            }
        } else {
            batterySettings(context)
        }
}
