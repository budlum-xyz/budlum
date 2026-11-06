package xyz.budlum.validator

import java.io.File

/**
 * Cloud-excluded B.U.D. 3.0 share storage rooted at `context.noBackupFilesDir/bud3/`
 * (Section 7.9.5, R-34).
 *
 * One file per segment share named after the lowercase hex segment identifier.
 * Enforces `quotaBytes` and releases shares via `ReleaseShares` whenever free
 * storage drops below `2 GiB` (`R-34`) or the user taps `Leave`.
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

    fun releaseForLowSpace(initialFreeBytes: Long): List<String> {
        var free = initialFreeBytes
        val released = mutableListOf<String>()
        val files = shareDir.listFiles()?.sortedBy { it.lastModified() }?.toMutableList()
            ?: return emptyList()
        while (free < ValidatorPolicy.LOW_FREE_SPACE_THRESHOLD_BYTES && files.isNotEmpty()) {
            val victim = files.removeAt(0)
            val len = victim.length()
            if (victim.delete()) {
                free += len
                released.add(victim.name)
            }
        }
        return released
    }

    fun releaseAllForLeave(): List<String> {
        val released = mutableListOf<String>()
        shareDir.listFiles()?.forEach { file ->
            if (file.isFile && file.delete()) {
                released.add(file.name)
            }
        }
        return released
    }
}
