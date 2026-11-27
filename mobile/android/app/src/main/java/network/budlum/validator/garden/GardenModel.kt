package network.budlum.validator.garden

import android.app.Activity
import android.content.Context
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import network.budlum.validator.R
import org.json.JSONObject
import uniffi.budlum_garden_ffi.GardenPhone
import uniffi.budlum_garden_ffi.SelfTestStep

/** Everything the three screens read. */
/**
 * One line of the conversation, as the chain holds it.
 *
 * `height` is the block the line landed in, which is the only order the
 * group agrees on - a phone's own clock is its own opinion.
 */
/**
 * Somebody the chain knows about.
 *
 * `waiting` is the whole point of the people screen: a key that holds an
 * invite is in the record but not in the group, and somebody has to say
 * yes. Nothing about a person here is self-reported - the name travels
 * with the join, the key is what signs, and the state is the chain's.
 */
data class Person(
    val key: String,
    val name: String,
    val state: String,
    val isMe: Boolean,
) {
    val waiting: Boolean get() = state == "Waiting"
    val active: Boolean get() = state == "Active"
    /** The short form a person reads, like the design shows addresses. */
    val shortKey: String
        get() = if (key.length > 16) key.take(7) + "..." + key.takeLast(7) else key
}

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
    val verified: Boolean = false,
    /** Decoded once, when the line is a picture the chain handed back. */
    val picture: androidx.compose.ui.graphics.ImageBitmap? = null,
    /** True while a line is published but no block carries it yet. */
    val sending: Boolean = false,
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
    /** Everyone the chain knows about, seated or waiting. */
    val people: List<Person> = emptyList(),
    /** The six digits this phone is answering, while they last. */
    val code: String = "",
    /** Seconds before the code stops working. */
    val codeSecondsLeft: Long = 0,
    /** True when this phone is waiting for somebody else's answer. */
    val waitingForHost: Boolean = false,
    /** True when this phone started the network. */
    val iAmHost: Boolean = false,
    /** True once this phone holds a wallet. One phone holds one. */
    val walletExists: Boolean = false,
    /** The address of that wallet, readable without the password. */
    val walletAddress: String = "",
    /**
     * The twenty-four words, held only between making a wallet and the
     * person saying they have written them down. Never read back off
     * disk: the sealed file does not hold them in the clear.
     */
    val mnemonic: List<String> = emptyList(),
    /** True once the password has been shown to open the wallet. */
    val walletUnlocked: Boolean = false,
    /** The record behind the preview, kept so one tap can act on it. */
    val previewRecord: String = "",
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
            state = state.copy(message = app.getString(R.string.g_file_unreadable))
            return@background
        }
        if (bytes.size > MAX_FILE_BYTES) {
            state = state.copy(message = app.getString(R.string.g_file_too_big))
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
    fun readChat() = background(quiet = true) {
        val status = runCatching { phone.status().json }.getOrNull() ?: return@background
        val garden = JSONObject(status).optJSONObject("garden")
        val mine = garden?.optJSONObject("me")
        val me = mine?.optString("key").orEmpty()
        val alone = (garden?.optInt("active_validators", 0) ?: 0) <= 1
        val folk = readPeople(garden, me)
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
            // The words are fetched rather than remembered: the core
            // hands the bytes back checked against the content id, and
            // says so. What the Room shows is what the chain holds.
            var verified = false
            var picture: androidx.compose.ui.graphics.ImageBitmap? = null
            var text: String? = null
            if (mime.startsWith("text/") || mime.startsWith("image/")) {
                runCatching {
                    val got = JSONObject(phone.fetch(id).json)
                    verified = got.optBoolean("verified")
                    if (mime.startsWith("image/")) {
                        // A picture is worth fetching whole: the chain
                        // hands the bytes back checked, and a thumbnail
                        // nobody can see is not a message.
                        picture = pictureFrom(got.optString("hex"))
                    } else {
                        text = got.optString("text").takeIf {
                            it.isNotEmpty() && it != "null"
                        }
                    }
                }.getOrNull()
            }
            lines.add(
                ChatLine(
                    id = id,
                    author = item.optString("author"),
                    who = item.optString("author_name")
                        .ifBlank { app.getString(R.string.g_unnamed) },
                    text = text,
                    caption = item.optString("caption"),
                    mime = mime,
                    size = item.optInt("size", 0),
                    height = item.optLong("height", 0),
                    heldHere = item.optBoolean("held_here"),
                    verified = verified,
                    picture = picture,
                ),
            )
        }
        // The feed is newest first, already in the order the chain put
        // things in - by block, and within a block by where the
        // transaction sits in it. Two lines often share a block, so
        // sorting by height alone would reorder them and sorting by
        // content id would scramble them outright. Reversing the feed
        // keeps the order the group agreed on.
        state = state.copy(
            messages = lines.asReversed(),
            myKey = me,
            aloneHere = alone,
            people = folk,
            waitingForHost = mine?.optString("member") == "Waiting",
            iAmHost = mine?.optBoolean("host") == true,
            feed = feed,
        )
    }

    /** Everyone in the chain's identity record, me first, waiting next. */
    private fun readPeople(garden: JSONObject?, me: String): List<Person> {
        val list = garden?.optJSONArray("validators") ?: return emptyList()
        val folk = mutableListOf<Person>()
        for (index in 0 until list.length()) {
            val entry = list.optJSONObject(index) ?: continue
            val key = entry.optString("key")
            folk.add(
                Person(
                    key = key,
                    name = entry.optString("name")
                        .ifBlank { app.getString(R.string.g_unnamed) },
                    state = entry.optString("status"),
                    isMe = key == me && me.isNotEmpty(),
                ),
            )
        }
        // Me at the top, then whoever is waiting on an answer, then the
        // rest. The people waiting are the only ones needing anything.
        return folk.sortedWith(
            compareByDescending<Person> { it.isMe }
                .thenByDescending { it.waiting }
                .thenBy { it.name },
        )
    }

    /**
     * Which of the three floors is showing.
     *
     * The sheets put this switch in the corner of every page, so it
     * lives on the model rather than inside one screen - the floor is
     * under all of them.
     */
    var skin by mutableStateOf(Skin.Page)

    /** Let somebody in, or turn them away. Only the host may. */
    fun answerRequest(key: String, accept: Boolean) = background {
        phone.admit(key, accept)
        readChat()
    }

    /** Open six digits that stand for this Garden's invite for an hour. */
    /**
     * What this phone knows about its own wallet without being told a
     * password: whether there is one, and which address it is.
     */
    fun readWallet() = background(quiet = true) {
        val here = phone.walletExists()
        val address = if (here) runCatching { phone.walletAddress() }.getOrNull() ?: "" else ""
        state = state.copy(walletExists = here, walletAddress = address)
    }

    /**
     * Make this phone's wallet.
     *
     * The words come back once and are held in state only until the
     * person says they have written them down, because the sealed file
     * keeps no clear copy to show them again.
     */
    fun createWallet(password: String) = background {
        val seed = phone.walletCreate(password)
        state = state.copy(
            walletExists = true,
            walletAddress = seed.address,
            mnemonic = seed.mnemonic.trim().split(" ").filter { it.isNotEmpty() },
            walletUnlocked = true,
        )
    }

    /** Put back a wallet from words the person already had. */
    fun restoreWallet(words: String, password: String) = background {
        val address = phone.walletRestore(words.trim().lowercase(), password)
        state = state.copy(
            walletExists = true,
            walletAddress = address,
            mnemonic = emptyList(),
            walletUnlocked = true,
        )
    }

    /** Show that the password opens this phone's wallet. */
    fun unlockWallet(password: String) = background {
        val address = phone.walletOpen(password)
        state = state.copy(walletUnlocked = true, walletAddress = address)
    }

    /**
     * Drop the words from memory once they have been written down.
     *
     * Called by the screen that showed them, so they are not sitting in
     * state behind every later screen.
     */
    fun forgetMnemonic() {
        state = state.copy(mnemonic = emptyList())
    }

    /** How many words a phrase has, asked of the core rather than assumed. */
    fun wordCount(): Int = phone.walletWordCount().toInt()

    fun openCode() = background {
        val opened = phone.openCode()
        state = state.copy(code = opened.code, codeSecondsLeft = opened.secondsLeft.toLong())
    }

    /** Join the network six digits point at. */
    fun joinWithCode(code: String) = background {
        phone.joinWithCode(code.trim(), name)
        readChat()
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

    fun refreshStatus() = background(quiet = true) {
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
                message = app.getString(R.string.g_network_ended),
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
            message = app.getString(R.string.g_background_refused) +
                " " + (failure.message ?: failure.toString()),
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
                message = app.getString(R.string.g_self_test_first),
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

    /**
     * Run something off the main thread.
     *
     * `quiet` is for work nobody asked for - the timer that re-reads the
     * chain. Letting that work raise the busy flag was a real bug: the
     * Room polls every three seconds, the poll takes a moment, and the
     * send and attach buttons are disabled while it runs, so for most of
     * any given second they could not be tapped at all. Quiet work also
     * leaves the message alone, because wiping it every three seconds
     * meant an error was gone before it could be read.
     */
    private fun background(quiet: Boolean = false, work: suspend () -> Unit) {
        scope.launch {
            if (!quiet) {
                state = state.copy(busy = true, message = "")
            }
            val failure = withContext(Dispatchers.IO) {
                runCatching { work() }.exceptionOrNull()
            }
            if (failure != null) {
                state = state.copy(message = failure.message ?: "that did not work")
            }
            if (!quiet) {
                state = state.copy(busy = false)
            }
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
