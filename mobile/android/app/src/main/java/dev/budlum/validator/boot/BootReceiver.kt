package dev.budlum.validator.boot

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.os.Build
import dev.budlum.validator.BudlumApp
import dev.budlum.validator.notify.Notifications
import dev.budlum.validator.service.ValidatorService

/**
 * Device reboot handling. Directive 7.9.3.5.
 *
 * Verified against the official Android docs on 2026-11-06: apps targeting
 * API 31+ may not start a foreground service from the background, and since
 * Android 15 (API 35) BOOT_COMPLETED receivers may no longer launch certain
 * foreground-service types. `specialUse` is not on the blocked list, but the
 * start is still attempted only inside a try/catch: if the system refuses
 * (ForegroundServiceStartNotAllowedException / SecurityException), the app
 * posts a notification telling the user to reopen it, and the WorkManager
 * periodic audit work keeps running regardless (it is re-enqueued here).
 */
class BootReceiver : BroadcastReceiver() {

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return

        // WorkManager work persists across reboots; re-enqueue defensively.
        (context.applicationContext as BudlumApp).enqueueAuditWork()

        try {
            val service = Intent(context, ValidatorService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(service)
            } else {
                context.startService(service)
            }
        } catch (e: Exception) {
            // Background start refused at this target API level: fall back to
            // a notification; WorkManager covers audits meanwhile.
            Notifications.bootFallback(context)
        }
    }
}
