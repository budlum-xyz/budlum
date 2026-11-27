package network.budlum.validator.garden

import android.app.Activity
import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import uniffi.budlum_garden_ffi.GardenPhone
import uniffi.budlum_garden_ffi.SelfTestStep
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/** Everything the three screens read. */
data class GardenState(
    val record: String = "",
    val recordQr: String = "",
    val expiry: String = "",
    val uses: Int = 0,
    val status: String = "This phone is in no Garden.",
    val preview: String = "",
    /** The record the preview describes, so confirming joins that record. */
    val previewRecord: String = "",
    val message: String = "",
    val busy: Boolean = false,
    val selfTest: List<SelfTestStep> = emptyList(),
    val selfTestMs: Long = 0,
    /** What Android still has to be told to allow. */
    val readiness: Readiness = Readiness(
        notifications = false,
        batteryUnrestricted = true,
        camera = false,
        batteryPath = "",
        batteryFamily = "",
    ),
)

/**
 * The bridge between the three screens and the Garden the phone runs.
 *
 * Every call goes to `budlum-core`'s own Garden through UniFFI. This class
 * holds no Garden rules of its own: it moves text between a screen and the
 * core, and it keeps the one rule section 4 puts on the app, which is that
 * nothing is created or joined until the self test has passed.
 */
class GardenModel(
    context: Context,
    private val scope: CoroutineScope,
) {
    private val app: Context = context.applicationContext

    // One validator per process, shared with the service that keeps it
    // running while no screen is up.
    private val phone: GardenPhone = GardenHolder.phone(context)
    private val name: String = android.os.Build.MODEL ?: "phone"

    var state by mutableStateOf(GardenState())
        private set

    /** The share text of section 5.7: where to get the app, then the invite. */
    fun shareText(): String =
        "Budlum Garden: " + APK_SOURCE + "\n" + state.record

    /**
     * Section 4: run the self test at first open, before anything else is
     * offered. A Garden is not created or joined while it fails.
     */
    fun runSelfTest() = background {
        val report = phone.selfTest()
        state = state.copy(
            selfTest = report.steps,
            selfTestMs = report.elapsedMs.toLong(),
            message = if (report.passed) {
                ""
            } else {
                "This phone did not pass its own check, so it will not join a Garden."
            },
        )
    }

    fun create(title: String) = background {
        if (!selfTestPassed()) return@background
        val answer = phone.create(title, name)
        readInvite(phone.invite())
        state = state.copy(status = answer.json)
        // From here the phone owes the Garden its presence, so the duty
        // leaves the screen and goes to the service that outlives it.
        startValidating()
    }

    fun refreshInvite() = background {
        readInvite(phone.invite())
    }

    /** Show who is inviting before anybody agrees to anything. */
    fun preview(record: String) {
        if (record.isBlank()) {
            state = state.copy(preview = "", previewRecord = "")
            return
        }
        scope.launch {
            val shown = withContext(Dispatchers.IO) {
                runCatching {
                    val json = JSONObject(phone.readRecord(record.trim()).json)
                    val owner = json.optString("owner").take(16)
                    val until = stamp(json.optLong("expires_at_ms"))
                    "validator " + owner + ", good until " + until
                }.getOrElse { "" }
            }
            state = state.copy(
                preview = shown,
                previewRecord = if (shown.isEmpty()) "" else record.trim(),
            )
        }
    }

    fun join(record: String) = background {
        if (!selfTestPassed()) return@background
        val answer = phone.join(record.trim(), name)
        state = state.copy(status = answer.json, preview = "", previewRecord = "")
        readInvite(phone.invite())
        startValidating()
    }

    fun refreshStatus() = background {
        state = state.copy(status = phone.status().json)
    }

    /**
     * Return to the Garden this phone stepped out of.
     *
     * Leaving keeps the seat unless it was the second leave, and the answer
     * says so in can_return. Without this the only way back was the invite
     * again, which the person who left may no longer have.
     */
    fun returnToGarden() = background {
        val answer = phone.rejoin()
        state = state.copy(status = answer.json, preview = "", previewRecord = "")
        readInvite(phone.invite())
        startValidating()
    }

    fun leave() = background {
        val answer = phone.leave()
        // Stepping out keeps the seat and the way back; retiring gives the
        // Garden up. Only the second ends the duty, so only the second
        // takes the notification away.
        if (!GardenSeat.canReturn(answer.json)) {
            GardenValidatorService.stop(app)
        }
        state = GardenState(
            status = answer.json,
            selfTest = state.selfTest,
            selfTestMs = state.selfTestMs,
        )
    }

    /**
     * Pick up a Garden this phone already belongs to.
     *
     * The seat survives the process, so opening the app after it was
     * closed - or after the phone was switched off - finds the Garden
     * still there and puts the validator back on the network without
     * asking for the invite again.
     */
    fun resumeIfSeated() = background {
        if (!GardenHolder.hasGarden(app)) return@background
        startValidating()
        state = state.copy(status = phone.status().json)
        runCatching { readInvite(phone.invite()) }
    }

    /** Hand the scan off to the activity, which owns the camera. */
    fun scan() {
        (scanner ?: return).invoke()
    }

    /** Set by the activity so the model does not reach for an Activity. */
    var scanner: (() -> Unit)? = null

    /**
     * Set by the activity, which owns the permission dialog.
     *
     * The model asks; the activity is the only thing Android will show a
     * permission prompt for.
     */
    var permissionAsker: ((String) -> Unit)? = null

    /** Ask Android for the one permission the background work needs. */
    fun askForNotifications() {
        val permission = GardenReadiness.notificationPermission()
        if (permission == null) {
            // Before Android 13 there is nothing to ask for; the switch in
            // settings is the only thing that can be off.
            readPermissions()
            return
        }
        permissionAsker?.invoke(permission)
    }

    /** Read what Android currently allows. Cheap, so it runs on every resume. */
    fun readPermissions() {
        state = state.copy(readiness = GardenReadiness.read(app))
    }

    /**
     * Hand the duty to the service that outlives the screen.
     *
     * Android refuses to start a foreground service in more cases every
     * release. A refusal here does not undo the Garden this phone just
     * joined, so it is reported as what it is - the validator is seated
     * but not running in the background - instead of being thrown over
     * the join itself or, worse, swallowed.
     */
    private fun startValidating() {
        val failure = runCatching { GardenValidatorService.start(app) }.exceptionOrNull()
            ?: return
        state = state.copy(
            message = "In the Garden, but Android would not let the background " +
                "validator start: " + (failure.message ?: failure.toString()) +
                " - check notifications and battery in setup.",
        )
    }

    /** Section 5.12: a scanned invite joins without a second detour. */
    fun scanned(record: String) {
        preview(record)
        join(record)
    }

    private fun selfTestPassed(): Boolean {
        val passed = state.selfTest.isNotEmpty() && state.selfTest.all { it.passed }
        if (!passed) {
            state = state.copy(
                message = "The self test has to pass before this phone joins a Garden.",
            )
        }
        return passed
    }

    private fun readInvite(answer: uniffi.budlum_garden_ffi.GardenAnswer) {
        val json = JSONObject(answer.json)
        val record = json.optString("record")
        state = state.copy(
            record = if (record == "null") "" else record,
            recordQr = json.optString("record_qr"),
            expiry = stamp(json.optLong("expires_at_ms")),
            uses = json.optInt("uses"),
            message = json.optString("record_refused"),
        )
    }

    private fun stamp(millis: Long): String =
        if (millis <= 0) {
            "unknown"
        } else {
            SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US).format(Date(millis))
        }

    private fun background(work: suspend () -> Unit) {
        scope.launch {
            state = state.copy(busy = true, message = "")
            val failure = withContext(Dispatchers.IO) {
                runCatching { work() }.exceptionOrNull()
            }
            state = state.copy(
                busy = false,
                message = failure?.message ?: state.message,
            )
        }
    }

    private companion object {
        /** Section 5.7 asks the share text to say where the app comes from. */
        const val APK_SOURCE = "https://github.com/budlum-xyz/budlum/releases"
    }
}

/** Convenience for an Activity that owns a scope. */
fun Activity.gardenModel(scope: CoroutineScope): GardenModel = GardenModel(this, scope)
