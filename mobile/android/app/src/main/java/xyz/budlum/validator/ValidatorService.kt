package xyz.budlum.validator

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder

/**
 * Persistent `specialUse` foreground service for the Android Mobile validator
 * (Section 7.9.3).
 *
 * Started strictly from foreground user interaction (or permitted boot receiver),
 * displaying stored bytes, last custody audit outcome, and QUIC/relay connection state.
 */
class ValidatorService : Service() {

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        ensureNotificationChannel()
        val storedMib = intent?.getLongExtra(EXTRA_STORED_MIB, 0L) ?: 0L
        val lastAudit = intent?.getStringExtra(EXTRA_LAST_AUDIT) ?: "Ready"
        val connState = intent?.getStringExtra(EXTRA_CONN_STATE) ?: "QUIC + Relay Standby"

        val notification = buildStatusNotification(storedMib, lastAudit, connState)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE,
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
        return START_STICKY
    }

    override fun onTimeout(startId: Int, fgsType: Int) {
        ValidatorAuditWorker.schedulePeriodic(applicationContext)
        stopSelf(startId)
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun ensureNotificationChannel() {
        val mgr = getSystemService(NotificationManager::class.java) ?: return
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notification_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        )
        mgr.createNotificationChannel(channel)
    }

    private fun buildStatusNotification(
        storedMib: Long,
        lastAudit: String,
        connState: String,
    ): Notification =
        Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText("Custody: ${storedMib} MiB | Audit: $lastAudit | Net: $connState")
            .setSmallIcon(android.R.drawable.stat_notify_sync_noanim)
            .setOngoing(true)
            .build()

    companion object {
        const val CHANNEL_ID = "budlum_validator_status"
        const val NOTIFICATION_ID = 4526
        const val EXTRA_STORED_MIB = "stored_mib"
        const val EXTRA_LAST_AUDIT = "last_audit"
        const val EXTRA_CONN_STATE = "conn_state"
    }
}
