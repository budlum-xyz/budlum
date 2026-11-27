package network.budlum.validator.garden

import android.app.Application
import android.content.ClipboardManager
import android.content.Context
import android.net.Uri
import android.os.Build
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject
import uniffi.budlum_garden_ffi.SelfTestStep
import java.net.InetAddress

/**
 * The screen state for the Garden flow.
 *
 * Every mutation happens strictly on the Main dispatcher after FFI work on
 * `Dispatchers.IO` completes, and state-changing core calls are serialized
 * through `opMutex` in `GardenModel`.
 */
data class GardenState(
    val readiness: Readiness,
    val setupDone: Boolean = false,
    val selfTest: List<SelfTestStep> = emptyList(),
    val selfTestMs: ULong = 0uL,
    val selectedTab: Int = 0,
    val record: String = "",
    val recordQr: String = "",
    val expiry: String = "",
    val uses: Int = 0,
    val localShareUrl: String = "",
    val pendingJoinRecord: String = "",
    val clipboardSuggestion: String? = null,
    val nearbyInvites: List<Pair<String, String>> = emptyList(),
    val preview: String = "",
    val status: String = "",
    val feed: String = "",
    val fetched: String = "",
    val message: String = "",
    val busy: Boolean = false,
) {
    /** True once the phone can honestly hold a validator seat. */
    val readyForGarden: Boolean
        get() = readiness.canValidate && selfTest.isNotEmpty() && selfTest.all { it.passed }

    /** True when the validator stepped out and can come back without a fresh invite. */
    val canReturn: Boolean
        get() = GardenModel.parseStatusFlags(status).canReturn

    /** True when the phone currently sits in a Garden (running or away). */
    val hasSeat: Boolean
        get() = GardenModel.parseStatusFlags(status).hasSeat

    /** True when the phone is actively sitting in a Garden right now. */
    val inGarden: Boolean
        get() = GardenModel.parseStatusFlags(status).let { it.hasSeat && !it.isAway }
}

internal data class GardenStatusFlags(
    val hasSeat: Boolean = false,
    val hasChainId: Boolean = false,
    val canReturn: Boolean = false,
    val isAway: Boolean = false,
)

private data class ParsedInvite(
    val record: String = "",
    val recordQr: String = "",
    val expiry: String = "",
    val uses: Int = 0,
    val title: String = "",
)

/**
 * Coordinates the Garden validator FFI, foreground service, QR scanner, and LAN sharing.
 */
class GardenModel(
    private val app: Application,
    private val askNotifications: () -> Unit,
    private val openScanner: () -> Unit,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private val opMutex = Mutex()
    private val localShare = GardenLocalShare(app)

    var state by mutableStateOf(GardenState(readiness = GardenReadiness.read(app)))
        private set

    private var inviteScreenVisible = false
    private var currentTitle = ""

    /** Run the core self-test that proves this phone can validate. */
    fun runSelfTest() {
        scope.launch {
            opMutex.withLock {
                state = state.copy(busy = true, message = "")
                val result = runCatching {
                    withContext(Dispatchers.IO) {
                        GardenHolder.phone(app).selfTest()
                    }
                }
                result.fold(
                    onSuccess = { report ->
                        state = state.copy(
                            selfTest = report.steps,
                            selfTestMs = report.elapsedMs,
                            setupDone = state.setupDone || (report.passed && state.readiness.canValidate),
                            message = if (report.passed) {
                                ""
                            } else {
                                "This phone did not pass its own check, so it will not join a Garden."
                            },
                            busy = false,
                        )
                    },
                    onFailure = { err ->
                        state = state.copy(
                            selfTest = listOf(
                                SelfTestStep(
                                    name = "Self test",
                                    passed = false,
                                    detail = err.message ?: "failed",
                                ),
                            ),
                            busy = false,
                        )
                    },
                )
            }
        }
    }

    /** Re-read Android permissions when returning from system settings. */
    fun readPermissions() {
        val current = GardenReadiness.read(app)
        val selfOk = state.selfTest.isNotEmpty() && state.selfTest.all { it.passed }
        state = state.copy(
            readiness = current,
            setupDone = state.setupDone || (current.canValidate && selfOk),
        )
    }

    /** Ask Android for notification permission (required for the honest FGS notification). */
    fun askForNotifications() {
        askNotifications()
    }

    /** Launch the camera QR scanner activity. */
    fun scan() {
        openScanner()
    }

    /** Select an active tab on the Garden screen (`0 = Data`, `1 = Invite`, `2 = Status`). */
    fun selectTab(index: Int) {
        val clamped = index.coerceIn(0, 2)
        state = state.copy(selectedTab = clamped)
    }

    /** Update the pending join invite input field and preview it when shaped like an invite. */
    fun updatePendingInvite(raw: String) {
        state = state.copy(pendingJoinRecord = raw)
        val trimmed = raw.trim()
        if (trimmed.startsWith("budlum://") || trimmed.startsWith("http://") || trimmed.startsWith("budlum-garden:")) {
            preview(trimmed)
        } else if (trimmed.isEmpty()) {
            state = state.copy(preview = "")
        }
    }

    /** Resume any persisted seat across app restarts or process kills. */
    fun resumeIfSeated() {
        scope.launch {
            opMutex.withLock {
                val res = runCatching {
                    withContext(Dispatchers.IO) {
                        val phone = GardenHolder.phone(app)
                        val st = phone.status().json
                        val stFlags = parseStatusFlags(st)
                        val active = if (stFlags.canReturn) {
                            runCatching { phone.rejoin().json }.getOrDefault(st)
                        } else {
                            st
                        }
                        val activeFlags = parseStatusFlags(active)
                        val inv = if (activeFlags.hasChainId && !activeFlags.isAway) {
                            runCatching { phone.invite().json }.getOrNull()
                        } else {
                            null
                        }
                        active to inv
                    }
                }
                res.onSuccess { (active, inv) ->
                    val flags = parseStatusFlags(active)
                    val hasSeat = flags.hasChainId
                    val isActive = hasSeat && !flags.isAway
                    val fgsError = if (isActive) {
                        runCatching { GardenValidatorService.start(app) }.exceptionOrNull()
                    } else {
                        if (!hasSeat) {
                            runCatching { GardenValidatorService.stop(app) }
                        }
                        null
                    }
                    val parsed = parseInviteJson(inv)
                    if (parsed.title.isNotEmpty()) {
                        currentTitle = parsed.title
                    }
                    state = state.copy(
                        setupDone = state.setupDone || hasSeat,
                        status = active,
                        record = parsed.record.ifEmpty { state.record },
                        recordQr = parsed.recordQr.ifEmpty { parsed.record.ifEmpty { state.recordQr } },
                        expiry = parsed.expiry.ifEmpty { state.expiry },
                        uses = if (parsed.uses > 0) parsed.uses else state.uses,
                        message = fgsError?.let { foregroundNoticeWarning(it) } ?: state.message,
                    )
                }
            }
        }
    }

    /** Start a new Garden with this device's label and keep the validator service running. */
    fun create(title: String) {
        val cleanTitle = title.trim()
        if (cleanTitle.isEmpty()) return
        scope.launch {
            opMutex.withLock {
                if (!ensureSelfTestPassed()) return@withLock
                state = state.copy(busy = true, message = "")
                val res = runCatching {
                    withContext(Dispatchers.IO) {
                        val phone = GardenHolder.phone(app)
                        val st = phone.create(cleanTitle, deviceValidatorName(), null).json
                        val inv = runCatching { phone.invite().json }.getOrNull()
                        st to inv
                    }
                }
                res.fold(
                    onSuccess = { (st, inv) ->
                        val fgsError = runCatching { GardenValidatorService.start(app) }.exceptionOrNull()
                        val parsed = parseInviteJson(inv)
                        currentTitle = parsed.title.ifEmpty { cleanTitle }
                        state = state.copy(
                            status = st,
                            record = parsed.record,
                            recordQr = parsed.recordQr.ifEmpty { parsed.record },
                            expiry = parsed.expiry,
                            uses = parsed.uses,
                            selectedTab = 1,
                            message = fgsError?.let { foregroundNoticeWarning(it) }
                                ?: "Your network is running. Invite someone from this screen.",
                            busy = false,
                        )
                        if (inviteScreenVisible) {
                            syncInviteShareLocked()
                        }
                    },
                    onFailure = { err ->
                        state = state.copy(
                            message = err.message ?: "could not start Garden",
                            busy = false,
                        )
                    },
                )
            }
        }
    }

    /**
     * Send data into the Garden and refresh the feed cleanly inside the serialized lock.
     *
     * Calls [onSent] on the Main dispatcher only after the publication succeeds so
     * form drafts are preserved if publishing fails.
     */
    fun send(text: String, caption: String, onSent: () -> Unit = {}) {
        val trimmedText = text.trim()
        val trimmedCaption = caption.trim()
        if (trimmedText.isEmpty()) {
            state = state.copy(message = "There is nothing to send yet.")
            return
        }
        scope.launch {
            opMutex.withLock {
                state = state.copy(busy = true, message = "")
                val res = runCatching {
                    withContext(Dispatchers.IO) {
                        val phone = GardenHolder.phone(app)
                        val answer = phone.send(trimmedText, trimmedCaption).json
                        val updatedFeed = runCatching { phone.feed(FEED_LIMIT).json }.getOrNull()
                        answer to updatedFeed
                    }
                }
                res.fold(
                    onSuccess = { (answer, updatedFeed) ->
                        state = state.copy(
                            feed = updatedFeed ?: state.feed,
                            message = "Sent. $answer",
                            busy = false,
                        )
                        onSent()
                    },
                    onFailure = { err ->
                        state = state.copy(
                            message = err.message ?: "could not send data",
                            busy = false,
                        )
                    },
                )
            }
        }
    }

    /** Load what the Garden has sent through B.U.D. 3.0. */
    fun refreshFeed() {
        scope.launch {
            opMutex.withLock {
                state = state.copy(busy = true, message = "")
                val res = runCatching {
                    withContext(Dispatchers.IO) {
                        GardenHolder.phone(app).feed(FEED_LIMIT).json
                    }
                }
                res.fold(
                    onSuccess = { feedJson ->
                        state = state.copy(feed = feedJson, busy = false)
                    },
                    onFailure = { err ->
                        state = state.copy(
                            message = err.message ?: "could not load feed",
                            busy = false,
                        )
                    },
                )
            }
        }
    }

    /** Pull one piece of data back out by content id and verify it against the chain. */
    fun fetch(contentId: String) {
        val trimmed = contentId.trim()
        if (trimmed.isEmpty()) return
        scope.launch {
            opMutex.withLock {
                state = state.copy(busy = true, message = "")
                val res = runCatching {
                    withContext(Dispatchers.IO) {
                        GardenHolder.phone(app).fetch(trimmed).json
                    }
                }
                res.fold(
                    onSuccess = { fetchedJson ->
                        state = state.copy(fetched = fetchedJson, busy = false)
                    },
                    onFailure = { err ->
                        state = state.copy(
                            message = err.message ?: "could not fetch item",
                            busy = false,
                        )
                    },
                )
            }
        }
    }

    /** Read an invite record without joining it so the Join screen can preview it first. */
    fun preview(raw: String) {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return
        scope.launch {
            opMutex.withLock {
                runPreviewLocked(trimmed)
            }
        }
    }

    /** Handle a QR scan result by staging it into Join and previewing safely. */
    fun scanned(raw: String) {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return
        scope.launch {
            opMutex.withLock {
                state = state.copy(
                    pendingJoinRecord = trimmed,
                    message = "",
                )
                runPreviewLocked(trimmed)
            }
        }
    }

    /** Stage an incoming deep link invite onto the Join screen for explicit one-tap confirmation. */
    fun stageIncomingInvite(raw: String) {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return
        scope.launch {
            opMutex.withLock {
                state = state.copy(
                    pendingJoinRecord = trimmed,
                    message = "",
                )
                runPreviewLocked(trimmed)
            }
        }
    }

    /** Use an explicit clipboard or LAN discovery invite by filling and previewing it. */
    fun acceptSuggestedInvite(raw: String) {
        stageIncomingInvite(raw)
        state = state.copy(clipboardSuggestion = null)
    }

    /** Join a Garden using an invite record (requires user confirmation tap). */
    fun join(raw: String) {
        val trimmed = raw.trim()
        if (trimmed.isEmpty()) return
        scope.launch {
            opMutex.withLock {
                if (!ensureSelfTestPassed()) return@withLock
                state = state.copy(busy = true, message = "")
                val res = runCatching {
                    withContext(Dispatchers.IO) {
                        val phone = GardenHolder.phone(app)
                        val st = phone.join(trimmed, deviceValidatorName()).json
                        val inv = runCatching { phone.invite().json }.getOrNull()
                        st to inv
                    }
                }
                res.fold(
                    onSuccess = { (st, inv) ->
                        val fgsError = runCatching { GardenValidatorService.start(app) }.exceptionOrNull()
                        val parsed = parseInviteJson(inv)
                        if (parsed.title.isNotEmpty()) {
                            currentTitle = parsed.title
                        }
                        state = state.copy(
                            status = st,
                            record = parsed.record,
                            recordQr = parsed.recordQr.ifEmpty { parsed.record },
                            expiry = parsed.expiry,
                            uses = parsed.uses,
                            pendingJoinRecord = "",
                            clipboardSuggestion = null,
                            preview = "",
                            selectedTab = 0,
                            message = fgsError?.let { foregroundNoticeWarning(it) } ?: "Joined Garden.",
                            busy = false,
                        )
                    },
                    onFailure = { err ->
                        state = state.copy(
                            message = err.message ?: "could not join Garden",
                            busy = false,
                        )
                    },
                )
            }
        }
    }

    /** Refresh the current invite record and local-HTTP share link. */
    fun refreshInvite() {
        scope.launch {
            opMutex.withLock {
                state = state.copy(busy = true, message = "")
                syncInviteShareLocked()
                state = state.copy(busy = false)
            }
        }
    }

    /** Format share text cleanly for external messaging apps. */
    fun shareText(): String {
        val title = currentTitle.ifBlank { "this Garden" }
        val link = state.record
        return if (link.isBlank()) {
            ""
        } else {
            "Budlum Garden ($title): $APK_SOURCE\n$link"
        }
    }

    /** Refresh validator status from the core. */
    fun refreshStatus() {
        scope.launch {
            opMutex.withLock {
                val res = runCatching {
                    withContext(Dispatchers.IO) { GardenHolder.phone(app).status().json }
                }
                res.fold(
                    onSuccess = { st -> state = state.copy(status = st) },
                    onFailure = { err -> state = state.copy(message = err.message ?: "status failed") },
                )
            }
        }
    }

    /** Step back into a Garden after stepping out (`Away -> Active`). */
    fun returnToGarden() {
        scope.launch {
            opMutex.withLock {
                state = state.copy(busy = true, message = "")
                val res = runCatching {
                    withContext(Dispatchers.IO) {
                        val phone = GardenHolder.phone(app)
                        val st = phone.rejoin().json
                        val inv = runCatching { phone.invite().json }.getOrNull()
                        st to inv
                    }
                }
                res.fold(
                    onSuccess = { (st, inv) ->
                        val fgsError = runCatching { GardenValidatorService.start(app) }.exceptionOrNull()
                        val parsed = parseInviteJson(inv)
                        if (parsed.title.isNotEmpty()) {
                            currentTitle = parsed.title
                        }
                        state = state.copy(
                            status = st,
                            record = parsed.record,
                            recordQr = parsed.recordQr.ifEmpty { parsed.record },
                            expiry = parsed.expiry,
                            uses = parsed.uses,
                            message = fgsError?.let { foregroundNoticeWarning(it) } ?: "Back in the Garden.",
                            busy = false,
                        )
                        if (inviteScreenVisible) {
                            syncInviteShareLocked()
                        }
                    },
                    onFailure = { err ->
                        state = state.copy(
                            message = err.message ?: "could not return",
                            busy = false,
                        )
                    },
                )
            }
        }
    }

    /**
     * Step out (`Active -> Away`) on first tap, or retire (`Away -> None`) on second tap.
     *
     * Preserves readiness/permission state so leaving a Garden never drops the
     * user back onto the first-run permissions screen.
     */
    fun leave() {
        scope.launch {
            opMutex.withLock {
                state = state.copy(busy = true, message = "")
                val res = runCatching {
                    withContext(Dispatchers.IO) { GardenHolder.phone(app).leave().json }
                }
                val currentReadiness = GardenReadiness.read(app)
                res.fold(
                    onSuccess = { st ->
                        val obj = runCatching { JSONObject(st) }.getOrNull()
                        val retired = obj?.optBoolean("retired", true) ?: true
                        val canReturn = obj?.optBoolean("can_return", false) ?: false
                        val stillSeated = !retired && canReturn
                        if (!stillSeated) {
                            GardenValidatorService.stop(app)
                            withContext(Dispatchers.IO) {
                                localShare.stopShare()
                                runCatching { GardenHolder.phone(app).setLocalHttpAddress(null) }
                            }
                            currentTitle = ""
                        }
                        val chainId = obj?.optString("chain_id").orEmpty()
                        val awayStatusJson = if (stillSeated) {
                            JSONObject().put(
                                "garden",
                                JSONObject()
                                    .put("chain_id", chainId)
                                    .put("status", "Away")
                                    .put("can_return", true),
                            ).put("can_return", true).toString()
                        } else {
                            ""
                        }
                        state = state.copy(
                            readiness = currentReadiness,
                            status = awayStatusJson,
                            record = if (stillSeated) state.record else "",
                            recordQr = if (stillSeated) state.recordQr else "",
                            expiry = if (stillSeated) state.expiry else "",
                            uses = if (stillSeated) state.uses else 0,
                            localShareUrl = if (stillSeated) state.localShareUrl else "",
                            feed = if (stillSeated) state.feed else "",
                            fetched = if (stillSeated) state.fetched else "",
                            message = if (stillSeated) {
                                "Stepped away from the Garden. Tap Leave again to retire permanently."
                            } else {
                                "Left the Garden."
                            },
                            busy = false,
                        )
                    },
                    onFailure = { err ->
                        state = state.copy(
                            readiness = currentReadiness,
                            message = err.message ?: "could not leave",
                            busy = false,
                        )
                    },
                )
            }
        }
    }

    /** Toggle the temporary local-HTTP + mDNS share server when the Invite screen opens or closes. */
    fun setInviteVisible(visible: Boolean) {
        inviteScreenVisible = visible
        scope.launch {
            opMutex.withLock {
                if (visible && state.inGarden) {
                    syncInviteShareLocked()
                } else {
                    withContext(Dispatchers.IO) {
                        localShare.stopShare()
                        runCatching { GardenHolder.phone(app).setLocalHttpAddress(null) }
                    }
                    state = state.copy(localShareUrl = "")
                }
            }
        }
    }

    /** Start LAN invite discovery and check clipboard when entering foreground. */
    fun onForeground() {
        localShare.startDiscovery { label, discoveredRecord ->
            scope.launch {
                val existing = state.nearbyInvites
                if (existing.none { it.second == discoveredRecord }) {
                    state = state.copy(nearbyInvites = existing + (label to discoveredRecord))
                }
            }
        }
        checkClipboardInvite()
    }

    /** Stop LAN discovery and temporary invite HTTP sharing when backgrounded. */
    fun onBackground() {
        localShare.stopDiscovery()
        if (!inviteScreenVisible) return
        scope.launch {
            withContext(Dispatchers.IO) {
                localShare.stopShare()
                runCatching { GardenHolder.phone(app).setLocalHttpAddress(null) }
            }
            state = state.copy(localShareUrl = "")
        }
    }

    /** Clean up background discovery, HTTP sharing, and coroutines on destroy. */
    fun shutdown() {
        inviteScreenVisible = false
        localShare.stopDiscovery()
        localShare.stopShare()
        scope.cancel()
    }

    private fun ensureSelfTestPassed(): Boolean {
        val passed = state.selfTest.isNotEmpty() && state.selfTest.all { it.passed }
        if (!passed) {
            state = state.copy(
                message = "The self test has to pass before this phone joins a Garden.",
            )
        }
        return passed
    }

    private fun foregroundNoticeWarning(failure: Throwable): String =
        "Your network is running, but Android refused the ongoing notice: " +
            (failure.message ?: "no reason given") +
            ". The Garden keeps working while this screen is open."

    private suspend fun runPreviewLocked(trimmed: String) {
        state = state.copy(busy = true, message = "")
        val res = runCatching {
            withContext(Dispatchers.IO) {
                val json = GardenHolder.phone(app).readRecord(trimmed).json
                formatPreviewSummary(json)
            }
        }
        res.fold(
            onSuccess = { summary ->
                state = state.copy(preview = summary, busy = false)
            },
            onFailure = { err ->
                state = state.copy(
                    preview = "",
                    message = err.message ?: "unreadable invite",
                    busy = false,
                )
            },
        )
    }

    private suspend fun syncInviteShareLocked() {
        val res = runCatching {
            withContext(Dispatchers.IO) {
                val phone = GardenHolder.phone(app)
                val baseJson = phone.inviteFor(null).json
                val baseParsed = parseInviteJson(baseJson)
                val hostPort = if (inviteScreenVisible && baseParsed.record.isNotBlank()) {
                    localShare.startShare(baseParsed.record)
                } else {
                    localShare.stopShare()
                    null
                }
                phone.setLocalHttpAddress(hostPort)
                val activeJson = if (hostPort != null) phone.inviteFor(hostPort).json else baseJson
                Triple(activeJson, baseParsed, hostPort)
            }
        }
        res.fold(
            onSuccess = { (activeJson, baseParsed, hostPort) ->
                val activeParsed = parseInviteJson(activeJson)
                val canonical = activeParsed.record.ifEmpty { baseParsed.record }
                val qr = activeParsed.recordQr.ifEmpty { canonical }
                if (activeParsed.title.isNotEmpty()) {
                    currentTitle = activeParsed.title
                }
                val shareHttp = hostPort?.let { "http://$it/g" }.orEmpty()
                state = state.copy(
                    record = canonical,
                    recordQr = qr,
                    expiry = activeParsed.expiry.ifEmpty { baseParsed.expiry },
                    uses = if (activeParsed.uses > 0) activeParsed.uses else baseParsed.uses,
                    localShareUrl = shareHttp,
                )
            },
            onFailure = { err ->
                state = state.copy(message = err.message ?: "could not load invite")
            },
        )
    }

    private fun checkClipboardInvite() {
        val suggestion = runCatching {
            val cm = app.getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                ?: return@runCatching null
            val clip = cm.primaryClip ?: return@runCatching null
            if (clip.itemCount == 0) return@runCatching null
            val raw = clip.getItemAt(0).coerceToText(app)?.toString()?.trim()
            extractCandidateFromClipboard(raw)
        }.getOrNull()
        if (suggestion != null && suggestion != state.pendingJoinRecord && suggestion != state.record) {
            state = state.copy(clipboardSuggestion = suggestion)
        }
    }

    private fun deviceValidatorName(): String =
        Build.MODEL?.trim()?.takeIf { it.isNotEmpty() } ?: "Phone"

    companion object {
        private const val FEED_LIMIT = 50u
        private const val APK_SOURCE = "https://github.com/budlum-xyz/budlum/releases"

        internal fun parseStatusFlags(statusJson: String?): GardenStatusFlags {
            if (statusJson.isNullOrBlank()) return GardenStatusFlags()
            return runCatching {
                val root = JSONObject(statusJson)
                val garden = root.optJSONObject("garden")
                val hasSeat = garden != null
                val hasChainId = garden != null && garden.optString("chain_id").isNotBlank()
                val isAway = garden?.optString("status") == "Away" ||
                    root.optString("status") == "Away"
                val canReturn = root.optBoolean("can_return", false) ||
                    (garden?.optBoolean("can_return", false) == true) ||
                    (hasSeat && isAway)
                GardenStatusFlags(
                    hasSeat = hasSeat,
                    hasChainId = hasChainId,
                    canReturn = canReturn,
                    isAway = isAway,
                )
            }.getOrDefault(GardenStatusFlags())
        }

        private fun formatExpiryMs(ms: Long): String {
            if (ms <= 0L) return ""
            return java.text.SimpleDateFormat("yyyy-MM-dd HH:mm", java.util.Locale.US)
                .format(java.util.Date(ms))
        }

        private fun parseInviteJson(json: String?): ParsedInvite {
            if (json.isNullOrBlank()) return ParsedInvite()
            return runCatching {
                val obj = JSONObject(json)
                val record = obj.optString("record").ifBlank { obj.optString("invite") }
                val qr = obj.optString("record_qr")
                    .ifBlank { record }
                    .ifBlank { obj.optString("qr") }
                val expiry = formatExpiryMs(obj.optLong("expires_at_ms", 0L))
                val uses = obj.optInt("uses", 0)
                val title = obj.optString("title")
                ParsedInvite(
                    record = record,
                    recordQr = qr,
                    expiry = expiry,
                    uses = uses,
                    title = title,
                )
            }.getOrDefault(ParsedInvite())
        }

        private fun formatPreviewSummary(json: String): String =
            runCatching {
                val obj = JSONObject(json)
                val chainId = obj.optString("chain_id").take(12)
                val owner = obj.optString("owner").take(12)
                val uses = obj.optInt("uses", 0)
                val peers = obj.optJSONArray("peers")?.length() ?: 0
                val expires = formatExpiryMs(obj.optLong("expires_at_ms", 0L))
                buildString {
                    append("Garden ")
                    append(if (chainId.isNotEmpty()) chainId else "invite")
                    if (owner.isNotEmpty()) append(" from $owner")
                    if (peers > 0) append(", $peers peer(s)")
                    if (uses > 0) append(", $uses seat(s) left")
                    if (expires.isNotEmpty()) append(" (good until $expires)")
                }
            }.getOrDefault(json)

        fun extractAllowedInviteFromUri(uri: Uri?): String? {
            if (uri == null) return null
            val scheme = uri.scheme?.lowercase() ?: return null
            val fragment = uri.fragment?.trim().orEmpty()
            if (fragment.isEmpty()) return null
            return when (scheme) {
                "budlum" -> {
                    if (uri.host?.lowercase() == "garden" &&
                        uri.path.orEmpty().trimEnd('/') == "/join"
                    ) {
                        uri.toString()
                    } else {
                        null
                    }
                }
                "http" -> {
                    val host = uri.host?.trim().orEmpty()
                    val path = uri.path.orEmpty()
                    if (isLocalIpLiteral(host) && (path == "/g" || path == "/g/")) {
                        uri.toString()
                    } else {
                        null
                    }
                }
                else -> null
            }
        }

        fun extractCandidateFromClipboard(text: String?): String? {
            val trimmed = text?.trim().orEmpty()
            if (trimmed.isEmpty()) return null
            if (trimmed.startsWith("budlum://garden/join#") && trimmed.length > "budlum://garden/join#".length) {
                return trimmed
            }
            if (trimmed.startsWith("http://")) {
                val parsed = runCatching { Uri.parse(trimmed) }.getOrNull()
                return extractAllowedInviteFromUri(parsed)
            }
            return null
        }

        /**
         * Pure lexical IPv4/IPv6 private/CGNAT/loopback literal check without DNS lookup.
         */
        fun isLocalIpLiteral(rawHost: String?): Boolean {
            val host = rawHost?.trim()?.removePrefix("[")?.removeSuffix("]") ?: return false
            if (host.isEmpty()) return false
            val isIpv4 = host.count { it == '.' } == 3 && host.all { it.isDigit() || it == '.' }
            val isIpv6 = host.contains(':') && host.all { it.isDigit() || it in 'a'..'f' || it in 'A'..'F' || it == ':' }
            if (!isIpv4 && !isIpv6) return false
            val addr = runCatching { InetAddress.getByName(host) }.getOrNull() ?: return false
            if (addr.isAnyLocalAddress || addr.isMulticastAddress) return false
            if (addr.isSiteLocalAddress || addr.isLinkLocalAddress || addr.isLoopbackAddress) return true
            val raw = addr.address
            if (raw.size == 4) {
                val b0 = raw[0].toInt() and 0xFF
                val b1 = raw[1].toInt() and 0xFF
                if (b0 == 100 && b1 in 64..127) return true
            }
            return false
        }
    }
}
