package network.budlum.validator.garden

import org.json.JSONObject

/**
 * Pure state, parsing and navigation rules for Budlum Garden.
 *
 * Kept free of Android framework calls so every decision here can be tested
 * deterministically on the host JVM as well as inside the app.
 */
object GardenLogic {

    /** Normalize pasted or typed recovery words across spaces, tabs and newlines. */
    fun normalizeMnemonicWords(raw: String): List<String> =
        raw.trim()
            .lowercase()
            .split(Regex("\\s+"))
            .filter { it.isNotEmpty() }

    /** Format a six-digit local code with a readable center gap (`482 910`). */
    fun formatCode(code: String): String {
        val digits = code.filter { it.isDigit() }
        return if (digits.length == 6) {
            digits.substring(0, 3) + " " + digits.substring(3, 6)
        } else {
            code
        }
    }

    /**
     * Extract a Budlum Garden invite only when clipboard text clearly carries one.
     *
     * Section 5.9: ordinary clipboard text is never processed or retained.
     * Fail closed on anything that does not match a recognized Garden invite shape.
     */
    fun extractClipboardInvite(raw: String?): String? {
        val text = raw?.trim() ?: return null
        if (text.isEmpty() || text.length > MAX_INVITE_CHARS) return null
        if (text.any { it.code < 0x20 || it.code == 0x7F }) return null
        val lower = text.lowercase()
        val isBudlumLink = lower.startsWith("budlum://garden/") && text.length > "budlum://garden/".length
        val isSignedRecord =
            lower.startsWith("budlum-garden-invite:") && text.length > "budlum-garden-invite:".length
        val isHttpGardenQr =
            (lower.startsWith("http://") || lower.startsWith("https://")) &&
                lower.contains("/g#") &&
                text.substringAfter("/g#", "").isNotBlank()
        return if (isBudlumLink || isSignedRecord || isHttpGardenQr) text else null
    }

    /**
     * True when the phone stepped out once and can still return without re-inviting.
     *
     * Parses JSON fail-closed so nested fields (such as `budlum.status`) or an
     * ended-chain summary never forge a live seat.
     */
    fun canReturnToGarden(statusJson: String): Boolean {
        val root = parseObject(statusJson) ?: return false
        if (root.optBoolean("can_return", false)) return true
        val garden = root.optJSONObject("garden") ?: return false
        return garden.optBoolean("can_return", false) ||
            garden.optString("status") == "Away"
    }

    /**
     * True when the `garden` object itself names an active (non-Away) chain seat.
     *
     * An ended response (`{"garden":null,"ended":{"chain_id":...}}`) fails closed.
     */
    fun isGardenSeated(statusJson: String): Boolean {
        val root = parseObject(statusJson) ?: return false
        val garden = root.optJSONObject("garden") ?: return false
        val chainId = garden.optString("chain_id").trim()
        if (chainId.isEmpty()) return false
        return !canReturnToGarden(statusJson)
    }

    /** True when the phone holds a live or stepped-out seat in the `garden` object. */
    fun hasGardenSeat(statusJson: String): Boolean {
        val root = parseObject(statusJson) ?: return false
        if (root.optBoolean("can_return", false)) return true
        val garden = root.optJSONObject("garden") ?: return false
        return garden.optString("chain_id").trim().isNotEmpty() ||
            garden.optBoolean("can_return", false) ||
            garden.optString("status") == "Away"
    }

    private fun parseObject(raw: String): JSONObject? {
        val trimmed = raw.trim()
        if (!trimmed.startsWith("{")) return null
        return runCatching { JSONObject(trimmed) }.getOrNull()
    }

    /**
     * Choose the landing step once initial readiness, wallet and seat checks settle.
     *
     * Opens on the interactive field of blocks by default, jumping straight to
     * Join on an incoming invite link or directly into an active Garden seat.
     */
    fun resolveInitialStep(
        hasPendingLink: Boolean,
        seated: Boolean,
        walletExists: Boolean,
        canValidate: Boolean,
    ): Step = when {
        hasPendingLink -> Step.Join
        seated -> Step.Garden
        else -> Step.Blocks
    }

    /** Shorten a 32-byte hex address the way the Figma sheets display addresses. */
    fun shortAddress(address: String): String = when {
        address.isEmpty() -> ""
        address.length <= 18 -> address
        else -> address.take(10) + "..." + address.takeLast(6)
    }

    /** Human-readable byte size for B.U.D. 3.0 storage counters. */
    fun formatBytes(bytes: Long): String = when {
        bytes <= 0L -> "0 B"
        bytes < 1024L -> "$bytes B"
        bytes < 1024L * 1024L -> "${bytes / 1024L} KB"
        else -> String.format(java.util.Locale.US, "%.1f MB", bytes.toDouble() / (1024.0 * 1024.0))
    }

    /** Format remaining seconds of an active six-digit code (`59:42`). */
    fun formatCountdown(secondsLeft: Long): String {
        val clamped = secondsLeft.coerceAtLeast(0L)
        val minutes = clamped / 60L
        val seconds = clamped % 60L
        return String.format(java.util.Locale.US, "%d:%02d", minutes, seconds)
    }

    private const val MAX_INVITE_CHARS = 2048
}
