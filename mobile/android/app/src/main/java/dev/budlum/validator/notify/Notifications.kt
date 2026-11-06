package dev.budlum.validator.notify

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import androidx.core.app.NotificationCompat
import dev.budlum.validator.MainActivity
import dev.budlum.validator.R

/**
 * Notification channels and the persistent validator notification.
 * Directive 7.9.3.7: the persistent notification shows stored bytes,
 * last audit result and connection state.
 */
object Notifications {
    const val CHANNEL_SERVICE = "validator_service"
    const val CHANNEL_ALERTS = "validator_alerts"
    const val ID_SERVICE = 1001
    const val ID_BOOT_FALLBACK = 1002

    fun ensureChannels(context: Context) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = context.getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_SERVICE,
                    context.getString(R.string.channel_service_name),
                    NotificationManager.IMPORTANCE_LOW
                )
            )
            nm.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ALERTS,
                    context.getString(R.string.channel_alerts_name),
                    NotificationManager.IMPORTANCE_DEFAULT
                )
            )
        }
    }

    /**
     * Persistent foreground-service notification (7.9.3.7): stored bytes,
     * last audit result, connection state.
     */
    fun serviceNotification(
        context: Context,
        storedBytes: Long,
        lastAuditResult: String,
        connected: Boolean,
    ): Notification {
        ensureChannels(context)
        val openApp = PendingIntent.getActivity(
            context,
            0,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        return NotificationCompat.Builder(context, CHANNEL_SERVICE)
            .setSmallIcon(android.R.drawable.ic_menu_save)
            .setContentTitle(context.getString(R.string.notification_service_title))
            .setContentText(
                context.getString(
                    R.string.notification_service_text,
                    storedBytes,
                    lastAuditResult,
                    if (connected) {
                        context.getString(R.string.state_connected)
                    } else {
                        context.getString(R.string.state_disconnected)
                    }
                )
            )
            .setOngoing(true)
            .setContentIntent(openApp)
            .setOnlyAlertOnce(true)
            .build()
    }

    /**
     * Shown when the device rebooted and the specialUse foreground service
     * could not be restarted from BOOT_COMPLETED (directive 7.9.3.5):
     * the user reopens the app; WorkManager keeps answering audits meanwhile.
     */
    fun bootFallback(context: Context) {
        ensureChannels(context)
        val openApp = PendingIntent.getActivity(
            context,
            1,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val nm = context.getSystemService(NotificationManager::class.java)
        nm.notify(
            ID_BOOT_FALLBACK,
            NotificationCompat.Builder(context, CHANNEL_ALERTS)
                .setSmallIcon(android.R.drawable.ic_menu_revert)
                .setContentTitle(context.getString(R.string.notification_boot_title))
                .setContentText(context.getString(R.string.notification_boot_text))
                .setContentIntent(openApp)
                .setAutoCancel(true)
                .build()
        )
    }
}
