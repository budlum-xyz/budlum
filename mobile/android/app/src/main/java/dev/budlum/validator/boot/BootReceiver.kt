package dev.budlum.validator.boot

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import dev.budlum.validator.BudlumApp
import dev.budlum.validator.notify.Notifications

/**
 * Re-enqueue periodic work after reboot, without starting a foreground service
 * from the background. A user-visible notice asks the user to reopen the app
 * when notification permission is available (directive 7.9.3.4-5).
 *
 * The current worker evaluates policy only; it does not yet answer audits.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED) return

        (context.applicationContext as BudlumApp).enqueueAuditWork()
        Notifications.bootFallback(context)
    }
}
