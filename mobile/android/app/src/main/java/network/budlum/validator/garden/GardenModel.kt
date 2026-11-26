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
/**
 * One line of the conversation, as the chain holds it.
 *
 * `height` is the block the line landed in, which is the only order the
 * group agrees on - a phone's own clock is its own opinion.
 */
data class ChatLine(
    val id: String,
    val author: String,
    val who: String,
    val text: String?,
    val caption: String,
    val mime: String,
    val size: Int,
    val height: Long,
    val heldHere: Boolean,
) {
    /** True when this line is a file rather than something typed. */
    val isFile: Boolean get() = text == null
}

/** Hex, because that is the binary encoding the core's publish takes. */
internal fun ByteArray.toHex(): String {
    val digits = "0123456789abcdef"
    val out = StringBuilder(size * 2)
    for (byte in this) {
        val value = byte.toInt() and 0xff
        out.append(digits[value shr 4]).append(digits[value and 0x0f])
    }
    return out.toString()
}

data class GardenState(
    val record: String = "",
    val recordQr: String = "",
    val expiry: String = "",
    val uses: Int = 0,
    val status: String = "This phone is in no Garden.",
    val preview: String = "",
    val message: String = "",
    val busy: Boolean = false,
    val selfTest: List<SelfTestStep> = emptyList(),
    /** The conversation, oldest first. */
    val messages: List<ChatLine> = emptyList(),
    /** This phone's validator key, so its own lines can be told apart. */
    val myKey: String = "",
    /** True while this phone is the only validator of its network. */
    val aloneHere: Boolean = false,
    /** What the group has sent, as the core reports it. */
    val feed: String = "",
    /** One piece of data pulled back out and checked. */
    val fetched: String = "",
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
        val answer = phone.create(title, name, null)
        readInvite(phone.invite())
        state = state.copy(status = answer.json)
        // The network exists the moment the core says so. Whether Android
        // also allows the ongoing notice is a separate question, and a
        // refusal there must not be reported as a network that failed to
        // start - it is a network running without its notice.
        val refused = runCatching { startValidating() }.exceptionOrNull()
        state = state.copy(
            message = if (refused == null) {
                "Your network is running. Invite someone from this screen."
            } else {
                "Your network is running, but Android refused the ongoing " +
                    "notice: " + (refused.message ?: "no reason given") +
                    ". The Garden keeps working while this screen is open."
            },
        )
    }

    /**
     * Say something in the Garden.
     *
     * There is no token and nothing to pay. The line is signed by this
     * phone, coded into parts by B.U.D. 3.0 and spread over the group,
     * and it comes back out of the chain verified rather than trusted.
     */
    fun say(text: String) = background {
        if (text.isBlank()) return@background
        phone.send(text, "")
        readChat()
    }

    /**
     * Send the contents of a file the person picked.
     *
     * Read here rather than in the screen because the screen does not
     * outlive a rotation and a large file does.
     */
    fun sendFile(uri: android.net.Uri) = background {
        val resolver = app.contentResolver
        val mime = resolver.getType(uri) ?: "application/octet-stream"
        val name = fileName(uri)
        val bytes = resolver.openInputStream(uri)?.use { it.readBytes() }
        if (bytes == null) {
            state = state.copy(message = "That file could not be opened.")
            return@background
        }
        if (bytes.size > MAX_FILE_BYTES) {
            state = state.copy(
                message = "That file is " + (bytes.size / 1024 / 1024) +
                    " MB. A Garden carries up to 4 MB in one piece.",
            )
            return@background
        }
        phone.sendFile(bytes.toHex(), mime, name)
        readChat()
    }

    /** The name the picker knows the file by, for the caption. */
    private fun fileName(uri: android.net.Uri): String {
        val cursor = app.contentResolver.query(uri, null, null, null, null) ?: return "file"
        return cursor.use {
            val column = it.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (column >= 0 && it.moveToFirst()) it.getString(column) ?: "file" else "file"
        }
    }

    /**
     * The conversation, rebuilt from the chain.
     *
     * The feed names what was published; the bytes of each line live in
     * the parts the validators hold, so each one is fetched and checked
     * against its content id. Already-seen lines are kept, because the
     * chain does not change its mind about them.
     */
    fun readChat() = background {
        val status = runCatching { phone.status().json }.getOrNull() ?: return@background
        val garden = JSONObject(status).optJSONObject("garden")
        val me = garden?.optJSONObject("me")?.optString("key").orEmpty()
        val alone = (garden?.optInt("active_validators", 0) ?: 0) <= 1
        val feed = phone.feed(FEED_LIMIT).json
        val items = runCatching {
            JSONObject(feed).optJSONArray("items") ?: org.json.JSONArray()
        }.getOrElse { org.json.JSONArray() }

        val known = state.messages.associateBy { it.id }
        val lines = mutableListOf<ChatLine>()
        for (index in 0 until items.length()) {
            val item = items.optJSONObject(index) ?: continue
            val id = item.optString("content_id")
            val seen = known[id]
            if (seen != null) {
                lines.add(seen)
                continue
            }
            val mime = item.optString("mime")
            val text = if (mime.startsWith("text/")) {
                runCatching {
                    JSONObject(phone.fetch(id).json).optString("text").takeIf {
                        it.isNotEmpty() && it != "null"
                    }
                }.getOrNull()
            } else {
                null
            }
            lines.add(
                ChatLine(
                    id = id,
                    author = item.optString("author"),
                    who = item.optString("author_name").ifBlank { "someone" },
                    text = text,
                    caption = item.optString("caption"),
                    mime = mime,
                    size = item.optInt("size", 0),
                    height = item.optLong("height", 0),
                    heldHere = item.optBoolean("held_here"),
                ),
            )
        }
        // The feed is newest first; a conversation reads the other way.
        state = state.copy(
            messages = lines.sortedWith(compareBy({ it.height }, { it.id })),
            myKey = me,
            aloneHere = alone,
            feed = feed,
        )
    }

    /** Pull one piece of data back out and check it against the chain. */
    fun fetch(contentId: String) = background {
        if (contentId.isBlank()) return@background
        state = state.copy(fetched = phone.fetch(contentId.trim()).json)
    }

    fun refreshInvite() = background {
        readInvite(phone.invite())
    }

    /** Show who is inviting before anybody agrees to anything. */
    fun preview(record: String) {
        if (record.isBlank()) {
            state = state.copy(preview = "")
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
            state = state.copy(preview = shown)
        }
    }

    fun join(record: String) = background {
        if (!selfTestPassed()) return@background
        val answer = phone.join(record.trim(), name)
        state = state.copy(status = answer.json, preview = "")
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
        state = state.copy(status = answer.json, preview = "")
        readInvite(phone.invite())
        startValidating()
    }

    fun leave() = background {
        val answer = phone.leave()
        // Stepping out keeps the seat and the way back; retiring gives the
        // Garden up. Only the second ends the duty, so only the second
        // takes the notification away.
        if (!answer.json.contains("\"can_return\":true")) {
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
        // A seat is a way back into a Garden that still exists. The one
        // case where it is not is a network this phone founded alone: the
        // chain lives in the running app, so nobody kept it while the app
        // was gone. Saying "no Garden" there reads as a fault; it is not.
        if (!state.status.contains("\"chain_id\"")) {
            state = state.copy(
                message = "The network you started is not running any more. " +
                    "A network lives in the phones that are in it, so one " +
                    "with only this phone in it ends when the app closes. " +
                    "Start it again, and invite someone before you close it.",
            )
        }
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
        /** Enough of the feed to see what the group has sent. */
        const val FEED_LIMIT = 100u

        /** One Garden object, from the limits the chain was founded with. */
        const val MAX_FILE_BYTES = 4 * 1024 * 1024

        const val APK_SOURCE = "https://github.com/budlum-xyz/budlum/releases"
    }
}

/** Convenience for an Activity that owns a scope. */
fun Activity.gardenModel(scope: CoroutineScope): GardenModel = GardenModel(this, scope)
