package xyz.budlum.validator

import java.io.File

/**
 * Cloud-excluded B.U.D. 3.0 share storage rooted at `context.noBackupFilesDir/bud3/`
 * (Section 7.9.5, R-34).
 *
 * One file per segment share named after the lowercase hex segment identifier.
 * Enforces `quotaBytes`. Shares must not be deleted until the network has
 * accepted a release and repair can be scheduled. That flow is not yet wired.
 */
class CustodyShareStore(
    noBackupRoot: File,
    private var quotaBytes: Long,
) {
    val shareDir: File = File(noBackupRoot, "bud3").apply { mkdirs() }

    fun usedBytes(): Long =
        shareDir.listFiles()?.sumOf { if (it.isFile) it.length() else 0L } ?: 0L

    fun writeSegmentShare(segmentHex: String, payload: ByteArray) {
        require(segmentHex.matches(Regex("^[0-9a-f]{64}$"))) { "Invalid hex segment id" }
        val nextBytes = usedBytes() + payload.size
        require(nextBytes <= quotaBytes) { "Share write exceeds declared custody quota" }
        File(shareDir, segmentHex).writeBytes(payload)
    }

    // Retain local shares until a confirmed network release is available.
    fun releaseForLowSpace(initialFreeBytes: Long): List<String> {
        if (initialFreeBytes >= ValidatorPolicy.LOW_FREE_SPACE_THRESHOLD_BYTES) {
            return emptyList()
        }
        return emptyList()
    }

    // Leaving also requires an on-chain release and unbond; neither is wired yet.
    fun releaseAllForLeave(): List<String> = emptyList()

}
