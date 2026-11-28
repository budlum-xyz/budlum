package network.budlum.validator.garden

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
import network.budlum.validator.core.DeviceWalletSeal
import org.json.JSONArray
import org.json.JSONObject
import uniffi.budlum_garden_ffi.GardenAnswer
import uniffi.budlum_garden_ffi.GardenPhone
import uniffi.budlum_garden_ffi.SelfTestStep

/** Somebody the chain knows about in the active Garden. */
data class Person(
    val key: String,
    val name: String,
    val state: String,
    val isMe: Boolean,
) {
    val waiting: Boolean get() = state == "Waiting"
    val active: Boolean get() = state == "Active"

    /** The short form shown in lists, matching the Figma account rows. */
    val shortKey: String
        get() = if (key.length > 16) key.take(7) + "..." + key.takeLast(7) else key
}

/** One line of the conversation, as verified from the chain or optimistically pending. */
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
    val picture: androidx.compose.ui.graphics.ImageBitmap? = null,
    val sending: Boolean = false,
) {
    val isFile: Boolean get() = !mime.startsWith("text/") || picture != null
}

/** Complete observable UI state for Budlum Garden screens. */
data class GardenState(
    val status: String = "",
    val record: String = "",
    val preview: String = "",
    val previewRecord: String = "",
    val feed: String = "",
    val fetched: String = "",
    val busy: Boolean = false,
    val message: String = "",
    val selfTest: List<SelfTestStep> = emptyList(),
    val selfTestMs: Long = 0,
    val readiness: Readiness = Readiness(
        notifications = false,
        batteryUnrestricted = true,
        camera = false,
        batteryPath = "",
        batteryFamily = "",
    ),
    val messages: List<ChatLine> = emptyList(),
    val myKey: String = "",
    val aloneHere: Boolean = true,
    val people: List<Person> = emptyList(),
    val waitingForHost: Boolean = false,
    val iAmHost: Boolean = false,
    val code: String = "",
    val codeSecondsLeft: Long = 0,
    val walletExists: Boolean = false,
    val walletAddress: String = "",
    val mnemonic: List<String> = emptyList(),
    val walletUnlocked: Boolean = false,
    val walletLoaded: Boolean = false,
    val resumeChecked: Boolean = false,
    val canReturn: Boolean = false,
    val pendingJoinLink: String = "",
    val clipboardInvite: String = "",
    val dismissedClipboardInvite: String = "",
    /** The place on the floor this phone took, and with it its coordinate. */
    val seat: Cell? = null,
) {
    val waitingCount: Int get() = people.count { it.waiting }
    val seated: Boolean get() = GardenLogic.isGardenSeated(status)
}

/**
 * Coordinates the native Budlum Garden validator core with the Compose UI.
 *
 * Every FFI call runs off the main thread on `Dispatchers.IO`, failures stay
 * visible to the user, and wallet / readiness state is never wiped when
 * stepping out of a Garden.
 */
class GardenModel(
    context: Context,
    private val scope: CoroutineScope,
) {
    private val app = context.applicationContext
    private val prefs = app.getSharedPreferences(UI_PREFS, Context.MODE_PRIVATE)

    private val phone: GardenPhone by lazy { GardenHolder.phone(app) }

    /**
     * The wallet's sealing passphrase, held by the Keystore rather than typed.
     *
     * The design file has no passphrase control on the wallet screens, so the
     * phone supplies one: thirty-two random bytes wrapped by a non-exportable
     * Keystore key. See [DeviceWalletSeal] for why this is not a weaker seal.
     */
    private val seal by lazy { DeviceWalletSeal(app) }

    var state by mutableStateOf(GardenState(seat = storedSeat()))
        private set

    /** The active floor skin, persisted as a non-secret UI preference. */
    var skin by mutableStateOf(Skin.fromName(prefs.getString(PREF_SKIN, null)))
        private set

    /**
     * Take a place on the floor.
     *
     * The coordinate is the wallet's address on the floor rather than a label:
     * two people whose places are neighbours in the lattice are standing beside
     * each other, and the Garden only shows someone else's block when they are
     * standing beside you.
     */
    fun settle(cell: Cell) {
        if (state.seat == cell) return
        state = state.copy(seat = cell)
        prefs.edit().putInt(PREF_SEAT_X, cell.x).putInt(PREF_SEAT_Y, cell.y).apply()
    }

    /** The place this phone took in an earlier run, if it took one. */
    private fun storedSeat(): Cell? {
        if (!prefs.contains(PREF_SEAT_X)) return null
        return Cell(prefs.getInt(PREF_SEAT_X, 0), prefs.getInt(PREF_SEAT_Y, 0))
    }

    fun selectSkin(next: Skin) {
        if (skin == next) return
        skin = next
        prefs.edit().putString(PREF_SKIN, next.name).apply()
    }

    /** Name this phone announces when founding or joining a Garden. */
    private val name: String
        get() = listOf(android.os.Build.MANUFACTURER, android.os.Build.MODEL)
            .filter { !it.isNullOrBlank() }
            .joinToString(" ")
            .ifBlank { "phone" }

    var scanner: (() -> Unit)? = null
    var permissionAsker: ((String) -> Unit)? = null

    fun clearMessage() {
        if (state.message.isNotEmpty()) {
            state = state.copy(message = "")
        }
    }

    fun runSelfTest() = background {
        val report = phone.selfTest()
        state = state.copy(
            selfTest = report.steps,
            selfTestMs = report.elapsedMs.toLong(),
        )
    }

    fun create(title: String, onSuccess: () -> Unit = {}) {
        val clean = title.trim()
        if (clean.isEmpty()) {
            state = state.copy(message = app.getString(R.string.g_err_create_title))
            return
        }
        if (!selfTestPassed()) return
        background(onSuccess = onSuccess) {
            val answer = phone.create(clean, name, null)
            state = state.copy(
                status = answer.json,
                canReturn = false,
            )
            runCatching { readInvite(phone.invite()) }
            startValidating()
            refreshChatLocked()
            syncCodeLocked()
        }
    }

    fun say(text: String) {
        val clean = text.trim()
        if (clean.isEmpty()) return
        val pendingId = "pending-" + System.nanoTime().toString()
        val lastHeight = state.messages.lastOrNull()?.height ?: 0L
        val optimistic = ChatLine(
            id = pendingId,
            author = state.myKey,
            who = app.getString(R.string.g_you),
            text = clean,
            caption = "",
            mime = "text/plain",
            size = clean.toByteArray().size,
            height = lastHeight,
            heldHere = true,
            verified = false,
            sending = true,
        )
        state = state.copy(
            messages = state.messages + optimistic,
            message = "",
        )
        background(
            quiet = true,
            onFailure = {
                state = state.copy(messages = state.messages.filterNot { it.id == pendingId })
            },
        ) {
            phone.send(clean, "")
            refreshChatLocked()
        }
    }

    fun sendFile(uri: android.net.Uri) = background {
        val resolver = app.contentResolver
        val mime = resolver.getType(uri) ?: "application/octet-stream"
        val caption = fileName(uri)
        val bytes = resolver.openInputStream(uri)?.use { it.readBytes() }
        if (bytes == null) {
            state = state.copy(message = app.getString(R.string.g_file_unreadable))
            return@background
        }
        // No file-size ceiling is offered here. The screen has no control for
        // one in the design file, and a number invented on this side would be a
        // second source of truth next to the chain parameter: what the Garden
        // accepts is the Garden's answer, and the core refuses what it refuses.
        phone.sendFile(bytes.toHex(), mime, caption)
        refreshChatLocked()
    }

    private fun fileName(uri: android.net.Uri): String {
        val cursor = app.contentResolver.query(uri, null, null, null, null) ?: return "file"
        return cursor.use {
            val column = it.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (column >= 0 && it.moveToFirst()) it.getString(column) ?: "file" else "file"
        }
    }

    fun readChat() = background(quiet = true) {
        refreshChatLocked()
    }

    private suspend fun refreshChatLocked() {
        val status = runCatching { phone.status().json }.getOrNull() ?: return
        val garden = runCatching { JSONObject(status).optJSONObject("garden") }.getOrNull()
        val mine = garden?.optJSONObject("me")
        val me = mine?.optString("key").orEmpty()
        val alone = (garden?.optInt("active_validators", 0) ?: 0) <= 1
        val folk = readPeople(garden, me)
        val feed = runCatching { phone.feed(FEED_LIMIT).json }.getOrElse { "" }
        val items = runCatching {
            JSONObject(feed).optJSONArray("items") ?: JSONArray()
        }.getOrElse { JSONArray() }

        val known = state.messages.filterNot { it.sending }.associateBy { it.id }
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
            var verified = false
            var picture: androidx.compose.ui.graphics.ImageBitmap? = null
            var text: String? = null
            if (mime.startsWith("text/") || mime.startsWith("image/")) {
                runCatching {
                    val got = JSONObject(phone.fetch(id).json)
                    verified = got.optBoolean("verified")
                    if (mime.startsWith("image/")) {
                        picture = pictureFrom(got.optString("hex"))
                    } else {
                        text = got.optString("text").takeIf {
                            it.isNotEmpty() && it != "null"
                        }
                    }
                }
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
        val activeCode = runCatching { phone.codeNow() }.getOrNull()
        state = state.copy(
            status = status,
            canReturn = GardenLogic.canReturnToGarden(status),
            messages = lines.asReversed(),
            myKey = me,
            aloneHere = alone,
            people = folk,
            waitingForHost = mine?.optString("member") == "Waiting",
            iAmHost = mine?.optBoolean("host") == true,
            feed = feed,
            code = activeCode?.code ?: state.code.takeIf { state.codeSecondsLeft > 0 }.orEmpty(),
            codeSecondsLeft = activeCode?.secondsLeft?.toLong() ?: 0L,
        )
    }

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
        return folk.sortedWith(
            compareByDescending<Person> { it.isMe }
                .thenByDescending { it.waiting }
                .thenBy { it.name },
        )
    }

    fun answerRequest(key: String, accept: Boolean) = background {
        phone.admit(key, accept)
        refreshChatLocked()
    }

    fun readWallet() = background(quiet = true) {
        val here = runCatching { phone.walletExists() }.getOrDefault(false)
        val address = if (here) runCatching { phone.walletAddress() }.getOrNull().orEmpty() else ""
        // The passphrase is the phone's, not a person's, so "is the wallet
        // open" is a question this process can answer: ask the core to open
        // the file with the Keystore secret. A file this phone cannot open -
        // a Keystore reset, say - is a real state and the person has to hear
        // it rather than watch every action fail one by one.
        var unreadable: String? = null
        val opens = if (here) {
            runCatching { phone.walletOpen(seal.secret()) }
                .onFailure { unreadable = it.message }
                .isSuccess
        } else {
            false
        }
        state = state.copy(
            walletExists = here,
            walletAddress = address,
            walletLoaded = true,
            walletUnlocked = here && opens,
            message = unreadable ?: state.message,
        )
    }

    fun createWallet() = background {
        val seed = phone.walletCreate(seal.secret())
        state = state.copy(
            walletExists = true,
            walletAddress = seed.address,
            mnemonic = GardenLogic.normalizeMnemonicWords(seed.mnemonic),
            walletUnlocked = true,
            walletLoaded = true,
        )
    }

    fun restoreWallet(words: String) = background {
        val normalized = GardenLogic.normalizeMnemonicWords(words).joinToString(" ")
        val address = phone.walletRestore(normalized, seal.secret())
        state = state.copy(
            walletExists = true,
            walletAddress = address,
            mnemonic = emptyList(),
            walletUnlocked = true,
            walletLoaded = true,
        )
    }

    fun forgetMnemonic() {
        state = state.copy(mnemonic = emptyList())
    }

    fun wordCount(): Int = runCatching { phone.walletWordCount().toInt() }.getOrDefault(24)

    /** What the next code is for: a Garden to join, or one person to talk to. */
    var invitePurpose by mutableStateOf(GardenLogic.InvitePurpose.Garden)
        private set

    fun selectInvitePurpose(next: GardenLogic.InvitePurpose) {
        invitePurpose = next
    }

    /**
     * Ask for a new code, burning the one that was live.
     *
     * The screen calls this when a person presses "new code": the old digits
     * stop being answered before the new ones exist, so nothing is ever live
     * twice.
     */
    fun newCode() = background {
        val opened = phone.newCode()
        state = state.copy(
            code = opened.code,
            codeSecondsLeft = opened.secondsLeft.toLong(),
            record = opened.record.ifBlank { state.record },
        )
    }

    fun openCode() = background {
        val opened = phone.openCode()
        state = state.copy(
            code = opened.code,
            codeSecondsLeft = opened.secondsLeft.toLong(),
            record = opened.record.ifBlank { state.record },
        )
    }

    fun syncCode() = background(quiet = true) {
        syncCodeLocked()
    }

    private fun syncCodeLocked() {
        val current = runCatching { phone.codeNow() }.getOrNull()
        if (current != null) {
            state = state.copy(
                code = current.code,
                codeSecondsLeft = current.secondsLeft.toLong(),
                record = current.record.ifBlank { state.record },
            )
        } else if (state.code.isNotEmpty()) {
            state = state.copy(code = "", codeSecondsLeft = 0L)
        }
    }

    /** Tick down the visible code counter locally between core syncs. */
    fun tickCode() {
        val remaining = state.codeSecondsLeft
        if (remaining > 1L) {
            state = state.copy(codeSecondsLeft = remaining - 1L)
        } else if (remaining == 1L) {
            state = state.copy(code = "", codeSecondsLeft = 0L)
        }
    }

    fun joinWithCode(code: String, onSuccess: () -> Unit = {}) {
        if (!selfTestPassed()) return
        background(onSuccess = onSuccess) {
            val answer = phone.joinWithCode(code.trim(), name)
            state = state.copy(
                status = answer.json,
                preview = "",
                previewRecord = "",
                canReturn = false,
            )
            runCatching { readInvite(phone.invite()) }
            startValidating()
            refreshChatLocked()
        }
    }

    fun fetch(contentId: String) = background {
        if (contentId.isBlank()) return@background
        state = state.copy(fetched = phone.fetch(contentId.trim()).json)
    }

    fun refreshInvite() = background(quiet = true) {
        runCatching { readInvite(phone.invite()) }
    }

    /** Handle an incoming invite deep-link and signal the navigator to open Join. */
    fun receiveInviteLink(link: String) {
        val clean = link.trim()
        if (clean.isEmpty()) return
        state = state.copy(pendingJoinLink = clean)
        preview(clean)
    }

    fun consumePendingJoinLink() {
        if (state.pendingJoinLink.isNotEmpty()) {
            state = state.copy(pendingJoinLink = "")
        }
    }

    /**
     * Section 5.9: inspect clipboard strictly for a Garden invite prefix.
     * Any other clipboard content is ignored and never stored.
     */
    fun checkClipboardInvite(rawClipboard: String?) {
        val invite = GardenLogic.extractClipboardInvite(rawClipboard) ?: return
        if (invite == state.dismissedClipboardInvite || invite == state.record) return
        if (state.seated) return
        state = state.copy(clipboardInvite = invite)
    }

    fun dismissClipboardInvite() {
        state = state.copy(
            dismissedClipboardInvite = state.clipboardInvite,
            clipboardInvite = "",
        )
    }

    /** Preview who is inviting and when the record expires before joining. */
    fun preview(record: String) {
        val trimmed = record.trim()
        if (trimmed.isEmpty()) {
            state = state.copy(preview = "", previewRecord = "")
            return
        }
        scope.launch {
            val shown = withContext(Dispatchers.IO) {
                runCatching {
                    val json = JSONObject(phone.readRecord(trimmed).json)
                    val owner = json.optString("owner").take(16)
                    val until = stamp(json.optLong("expires_at_ms"))
                    app.getString(R.string.g_preview_invited, owner, until)
                }.getOrElse { "" }
            }
            state = state.copy(
                preview = shown,
                previewRecord = if (shown.isEmpty()) "" else trimmed,
                message = if (shown.isEmpty()) app.getString(R.string.g_preview_invalid) else "",
            )
        }
    }

    fun join(record: String, onSuccess: () -> Unit = {}) {
        if (!selfTestPassed()) return
        background(onSuccess = onSuccess) {
            val answer = phone.join(record.trim(), name)
            state = state.copy(
                status = answer.json,
                preview = "",
                previewRecord = "",
                clipboardInvite = "",
                canReturn = false,
            )
            runCatching { readInvite(phone.invite()) }
            startValidating()
            refreshChatLocked()
        }
    }

    fun refreshStatus() = background(quiet = true) {
        val status = phone.status().json
        state = state.copy(
            status = status,
            canReturn = GardenLogic.canReturnToGarden(status),
        )
    }

    fun returnToGarden(onSuccess: () -> Unit = {}) = background(onSuccess = onSuccess) {
        val answer = phone.rejoin()
        state = state.copy(
            status = answer.json,
            preview = "",
            canReturn = false,
        )
        runCatching { readInvite(phone.invite()) }
        startValidating()
        refreshChatLocked()
    }

    fun leave() = background {
        val answer = phone.leave()
        val canReturn = GardenLogic.canReturnToGarden(answer.json)
        if (!canReturn) {
            GardenValidatorService.stop(app)
        }
        // Preserve wallet, readiness and self-test state across stepping out or retiring.
        state = state.copy(
            status = answer.json,
            record = "",
            preview = "",
            previewRecord = "",
            feed = "",
            fetched = "",
            messages = emptyList(),
            myKey = "",
            aloneHere = true,
            people = emptyList(),
            waitingForHost = false,
            iAmHost = false,
            code = "",
            codeSecondsLeft = 0L,
            canReturn = canReturn,
            message = "",
        )
    }

    fun resumeIfSeated() = background(quiet = true) {
        if (!GardenHolder.hasGarden(app)) {
            state = state.copy(resumeChecked = true)
            return@background
        }
        startValidating()
        val status = runCatching { phone.status().json }.getOrDefault("")
        state = state.copy(
            status = status,
            canReturn = GardenLogic.canReturnToGarden(status),
            resumeChecked = true,
        )
        runCatching { readInvite(phone.invite()) }
        refreshChatLocked()
        if (!GardenLogic.hasGardenSeat(state.status)) {
            state = state.copy(message = app.getString(R.string.g_network_ended))
        }
    }

    fun scan() {
        (scanner ?: return).invoke()
    }

    fun askForNotifications() {
        val permission = GardenReadiness.notificationPermission()
        if (permission == null) {
            readPermissions()
            return
        }
        permissionAsker?.invoke(permission)
    }

    fun readPermissions() {
        state = state.copy(readiness = GardenReadiness.read(app))
    }

    private fun startValidating() {
        val failure = runCatching { GardenValidatorService.start(app) }.exceptionOrNull()
            ?: return
        state = state.copy(
            message = app.getString(R.string.g_background_refused) +
                " " + (failure.message ?: failure.toString()),
        )
    }

    /**
     * Fail-closed QR confirmation: preview the scanned invite in Join so the
     * owner sees host and expiry and explicitly confirms with one tap.
     */
    fun scanned(record: String) {
        receiveInviteLink(record)
    }

    private fun selfTestPassed(): Boolean {
        val passed = state.selfTest.isNotEmpty() && state.selfTest.all { it.passed }
        if (!passed) {
            state = state.copy(message = app.getString(R.string.g_self_test_first))
        }
        return passed
    }

    private fun readInvite(answer: GardenAnswer) {
        val json = runCatching { JSONObject(answer.json) }.getOrNull() ?: return
        val record = json.optString("record").ifBlank { json.optString("invite") }
        if (record.isNotEmpty()) {
            state = state.copy(record = record)
        }
    }

    private fun stamp(millis: Long): String {
        if (millis <= 0L) return ""
        return SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault()).format(Date(millis))
    }

    private fun background(
        quiet: Boolean = false,
        onSuccess: (() -> Unit)? = null,
        onFailure: (() -> Unit)? = null,
        work: suspend () -> Unit,
    ) {
        scope.launch {
            if (!quiet) {
                state = state.copy(busy = true, message = "")
            }
            val err = withContext(Dispatchers.IO) {
                runCatching { work() }.exceptionOrNull()
            }
            if (err != null) {
                onFailure?.invoke()
                state = state.copy(
                    busy = false,
                    message = err.message ?: err.toString(),
                )
            } else {
                if (!quiet) {
                    state = state.copy(busy = false)
                }
                onSuccess?.invoke()
            }
        }
    }

    private fun ByteArray.toHex(): String = buildString(size * 2) {
        for (byte in this@toHex) {
            val v = byte.toInt() and 0xFF
            append(HEX[v ushr 4])
            append(HEX[v and 0x0F])
        }
    }

    companion object {
        private const val UI_PREFS = "budlum_garden_ui"
        private const val PREF_SKIN = "skin"

        /** The floor coordinate this phone took. A place, not a secret. */
        private const val PREF_SEAT_X = "seat_x"
        private const val PREF_SEAT_Y = "seat_y"
        private const val FEED_LIMIT = 100u
        private val HEX = "0123456789abcdef".toCharArray()
    }
}
