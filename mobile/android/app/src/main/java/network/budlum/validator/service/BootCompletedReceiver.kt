package network.budlum.validator.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import androidx.core.content.ContextCompat
import network.budlum.validator.R
import network.budlum.validator.ui.MainActivity
import network.budlum.validator.worker.DutyPeriodicWorker

/**
 * Android 15+ (API 35/36) prohibits launching a `specialUse` foreground service
 * from `ACTION_BOOT_COMPLETED`. Per Section 7.9.3 item 5 & 6, this receiver
 * never calls `startForegroundService()`; it schedules the 15-minute unmetered
 * `WorkManager` periodic job and posts a user notification to reopen the app.
 */
class BootCompletedReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent?) {
        if (intent?.action != Intent.ACTION_BOOT_COMPLETED) {
            return
        }
        DutyPeriodicWorker.enqueuePeriodic(context)

        val nm = context.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channel = NotificationChannel(
            ValidatorService.CHANNEL_ID,
            context.getString(R.string.notif_channel_name),
            NotificationManager.IMPORTANCE_DEFAULT,
        )
        nm.createNotificationChannel(channel)
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(context, android.Manifest.permission.POST_NOTIFICATIONS) !=
            PackageManager.PERMISSION_GRANTED
        ) {
            return
        }
        if (!nm.areNotificationsEnabled()) return

        val openApp = PendingIntent.getActivity(
            context,
            1,
            Intent(context, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val resumeNotice = Notification.Builder(context, ValidatorService.CHANNEL_ID)
            .setContentTitle(context.getString(R.string.notif_boot_resume_title))
            .setContentText(context.getString(R.string.notif_boot_resume_body))
            .setSmallIcon(android.R.drawable.stat_notify_sync_noanim)
            .setContentIntent(openApp)
            .setAutoCancel(true)
            .build()
        try {
            nm.notify(BOOT_RESUME_NOTIFICATION_ID, resumeNotice)
        } catch (_: SecurityException) {
            // Notification permission may have been revoked after the check.
        }
    }

    companion object {
        const val BOOT_RESUME_NOTIFICATION_ID: Int = 45262
    }
}
