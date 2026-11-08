package network.budlum.validator.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import android.os.PowerManager
import network.budlum.validator.R
import network.budlum.validator.core.Connection
import network.budlum.validator.core.CoreStatus

/**
 * `specialUse` foreground service keeping QUIC/TCP relay sessions open to serve
 * B.U.D. 3.0 custody shares and answer storage audits (Section 7.9.3).
 */
class ValidatorService : Service() {
    private var timeoutObserved: Boolean = false

    override fun onCreate() {
        super.onCreate()
        ensureChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val storedLabel = intent?.getStringExtra(EXTRA_STORED_LABEL) ?: "0 B"
        val auditLabel = intent?.getStringExtra(EXTRA_AUDIT_LABEL) ?: "None"
        val netLabel = intent?.getStringExtra(EXTRA_NET_LABEL) ?: "Connecting"
        val notification = buildStatusNotification(storedLabel, auditLabel, netLabel)
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
        timeoutObserved = true
        stopSelf(startId)
    }

    override fun onBind(intent: Intent?): IBinder? = null

    private fun ensureChannel() {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        val channel = NotificationChannel(
            CHANNEL_ID,
            getString(R.string.notif_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        )
        nm.createNotificationChannel(channel)
    }

    private fun buildStatusNotification(
        storedLabel: String,
        auditLabel: String,
        netLabel: String,
    ): Notification {
        val summary = getString(R.string.notif_status_template, storedLabel, auditLabel, netLabel)
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(summary)
            .setSmallIcon(android.R.drawable.stat_notify_sync)
            .setOngoing(true)
            .build()
    }

    companion object {
        const val CHANNEL_ID: String = "budlum_validator_custody"
        const val NOTIFICATION_ID: Int = 45261
        const val EXTRA_STORED_LABEL: String = "stored_label"
        const val EXTRA_AUDIT_LABEL: String = "audit_label"
        const val EXTRA_NET_LABEL: String = "net_label"

        fun currentThermalStatus(context: Context): Int {
            val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
            return pm.currentThermalStatus
        }

        fun formatStatusExtras(status: CoreStatus): Triple<String, String, String> {
            val stored = "${status.storedBytes} B"
            val audit = status.lastAudit.name
            val net = when (val c = status.connection) {
                is Connection.Down -> "Down"
                is Connection.Relay -> "Relay (${c.offer.multiaddr})"
            }
            return Triple(stored, audit, net)
        }
    }
}
