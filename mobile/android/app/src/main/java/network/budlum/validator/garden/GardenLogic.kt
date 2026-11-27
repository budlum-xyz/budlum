package network.budlum.validator.garden

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

    /** True when the phone stepped out once and can still return without re-inviting. */
    fun canReturnToGarden(statusJson: String): Boolean =
        statusJson.contains("\"can_return\":true") || statusJson.contains("\"status\":\"Away\"")

    /** True when the Garden status JSON names an active (non-Away) chain seat. */
    fun isGardenSeated(statusJson: String): Boolean =
        statusJson.contains("\"chain_id\"") && !canReturnToGarden(statusJson)

    /** True when the user holds a seat (either currently seated or stepped out). */
    fun hasGardenSeat(statusJson: String): Boolean =
        statusJson.contains("\"chain_id\"") || canReturnToGarden(statusJson)

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
