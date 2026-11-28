package network.budlum.validator.garden

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.IBinder
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject

/**
 * The Garden validator, running whether or not anybody is looking at it.
 *
 * A validator is not a screen. It holds connections, answers rounds and
 * serves the parts of the Garden's content that it keeps, and the phone
 * spends most of its day in a pocket. Before this, the validator lived
 * inside the activity: closing the app took the Garden down, and the
 * other validators watched this one go absent. It lives here now, and
 * the notification says plainly what it is doing.
 *
 * Android is told the honest subtype in the manifest: this is a
 * peer-to-peer duty with no other foreground type that fits.
 */
class GardenValidatorService : Service() {

    private var watch: Job? = null
    private val scope = CoroutineScope(Dispatchers.IO)

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        channel()
        startForeground(NOTE_ID, note("Garden", "Starting the validator"))
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (watch == null) {
            watch = scope.launch { keep() }
        }
        // The seat is on disk, so the system may restart this service and
        // the validator picks up where it was.
        return START_STICKY
    }

    /**
     * Take the seat if it is not taken, then say what the Garden is doing.
     *
     * Returning is tried once on the way up: a phone that was in a Garden
     * when it was last switched off is in that Garden again without being
     * asked. A phone with no seat has nothing to return to, and the
     * service stops rather than sitting in the status bar for nothing.
     */
    private suspend fun keep() {
        val phone = GardenHolder.phone(this)
        if (!GardenHolder.hasGarden(this)) {
            stopSelf()
            return
        }
        if (GardenHolder.isAway(this)) {
            runCatching { phone.rejoin() }
                .onFailure { update("Garden", "Could not return yet: " + (it.message ?: "")) }
        }
        while (scope.isActive) {
            val status = runCatching { phone.status().json }.getOrNull()
            if (status == null) {
                update("Garden", "The validator is not answering")
            } else {
                update(title(status), detail(status))
            }
            delay(REFRESH_MS)
        }
    }

    private fun title(status: String): String =
        garden(status)?.optString("title").orEmpty().ifBlank { "Garden" }

    /** The one line worth putting in a status bar. */
    private fun detail(status: String): String {
        val garden = garden(status) ?: return "Not in a Garden"
        return when (garden.optString("status")) {
            "Away" -> "Stepped out. Tap to return."
            "" -> "Not in a Garden"
            else -> {
                val height = garden.optLong("height", 0)
                val validators = garden.optInt("active_validators", 0)
                val parts = garden.optJSONObject("work")?.optLong("parts_held", 0) ?: 0
                "Validating - block $height, $validators validators, $parts parts held"
            }
        }
    }

    private fun garden(status: String): JSONObject? = runCatching {
        JSONObject(status).optJSONObject("garden")
    }.getOrNull()

    private fun update(title: String, text: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager?.notify(NOTE_ID, note(title, text))
    }

    private fun note(title: String, text: String): Notification {
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, GardenActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle(title)
            .setContentText(text)
            .setSmallIcon(android.R.drawable.ic_menu_compass)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
    }

    private fun channel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(NotificationManager::class.java) ?: return
        manager.createNotificationChannel(
            NotificationChannel(
                CHANNEL,
                "Garden validator",
                NotificationManager.IMPORTANCE_LOW,
            ).apply {
                description = "Shown while this phone is validating a Garden."
            },
        )
    }

    override fun onDestroy() {
        watch?.cancel()
        watch = null
        super.onDestroy()
    }

    companion object {
        private const val CHANNEL = "garden-validator"
        private const val NOTE_ID = 0x6761
        private const val REFRESH_MS = 5_000L

        /** Start validating, or do nothing if there is no seat to take. */
        fun start(context: Context) {
            val intent = Intent(context, GardenValidatorService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }
        }

        /** Stop validating. Called where the Garden was given up. */
        fun stop(context: Context) {
            context.stopService(Intent(context, GardenValidatorService::class.java))
        }
    }
}
