package dev.budlum.validator.service

import android.app.Service
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import androidx.core.app.ServiceCompat
import dev.budlum.validator.R
import dev.budlum.validator.notify.Notifications
import dev.budlum.validator.storage.ShareStore

/**
 * Long-lived validator foreground service. Directive 7.9.3.
 *
 * Type is `specialUse` (declared in the manifest with the
 * PROPERTY_SPECIAL_USE_FGS_SUBTYPE property). dataSync/mediaProcessing are
 * limited to 6h/24h on Android 15+ and would be stopped via onTimeout, so they
 * are deliberately not used (BLG-265).
 *
 * The service is only started while the user has the app in the foreground
 * (7.9.3.4); background start restrictions are respected and caught.
 *
 * The persistent notification carries stored bytes, last audit result and
 * connection state (7.9.3.7).
 */
class ValidatorService : Service() {

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        Notifications.ensureChannels(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        startForegroundWithType()
        return START_STICKY
    }

    private fun startForegroundWithType() {
        val type = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
        } else {
            0
        }
        val store = ShareStore(noBackupFilesDir)
        val notification = Notifications.serviceNotification(
            context = this,
            storedBytes = store.storedBytes(),
            lastAuditResult = getString(R.string.audit_result_none_yet),
            connected = false,
        )
        ServiceCompat.startForeground(this, Notifications.ID_SERVICE, notification, type)
    }

    override fun onDestroy() {
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        super.onDestroy()
    }
}
