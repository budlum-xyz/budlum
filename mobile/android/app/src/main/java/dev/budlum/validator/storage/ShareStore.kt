package dev.budlum.validator.storage

import java.io.File

/**
 * Share storage. Directive 7.9.5.
 *
 * - Shares live in app-private storage: `noBackupFilesDir/bud3/`. They never
 *   enter a cloud backup (allowBackup=false in the manifest as well).
 * - One file per segment; the file name is the hex form of the segment id.
 * - The quota is never exceeded: lowering the quota releases the overflow with
 *   StorageTx::ReleaseShares and triggers repair. Release is not a penalty.
 * - When free space drops below 2 GiB the store reports that shares must be
 *   released (R-34, card item 6).
 *
 * The embedded-database choice (redb vs plain file vs WAL; never sled) is
 * measured inside WP-11; this 1/N delivery uses the plain-file candidate.
 */
class ShareStore(
    /** The app's noBackupFilesDir. */
    private val noBackupFilesDir: File,
    private val freeSpaceProvider: () -> Long = { noBackupFilesDir.usableSpace },
) {
    val bud3Dir: File get() = File(noBackupFilesDir, "bud3")

    fun shareFileName(segmentId: ByteArray): String =
        segmentId.joinToString("") { "%02x".format(it) }

    fun shareFile(segmentId: ByteArray): File = File(bud3Dir, shareFileName(segmentId))

    fun storedBytes(): Long =
        bud3Dir.listFiles()?.sumOf { it.length() } ?: 0L

    /**
     * Write one share. Returns false (and writes nothing) when the write would
     * exceed [quotaBytes].
     */
    fun writeShare(segmentId: ByteArray, bytes: ByteArray, quotaBytes: Long): Boolean {
        if (storedBytes() + bytes.size > quotaBytes) return false
        bud3Dir.mkdirs()
        shareFile(segmentId).writeBytes(bytes)
        return true
    }

    /**
     * Release [segmentIds]: delete the files and return the ids that were
     * actually released. The caller turns them into a StorageTx::ReleaseShares.
     */
    fun releaseShares(segmentIds: Collection<ByteArray>): List<ByteArray> {
        val released = mutableListOf<ByteArray>()
        for (id in segmentIds) {
            if (shareFile(id).delete()) released.add(id)
        }
        return released
    }

    /**
     * Enforce the quota: release the oldest shares first until the stored bytes
     * fit. Returns the released segment ids (hex names, oldest first).
     */
    fun enforceQuota(quotaBytes: Long): List<ByteArray> {
        val files = bud3Dir.listFiles()?.sortedBy { it.lastModified() } ?: return emptyList()
        val released = mutableListOf<ByteArray>()
        var total = files.sumOf { it.length() }
        for (file in files) {
            if (total <= quotaBytes) break
            // Read the size before deleting: after File.delete() length() is 0,
            // so subtracting it afterwards would never reduce `total` and the
            // loop would delete every share instead of the overflow.
            val size = file.length()
            val id = file.name.hexToByteArray()
            if (file.delete()) {
                total -= size
                released.add(id)
            }
        }
        return released
    }

    /** Free space below this triggers ReleaseShares (R-34). */
    fun needsReleaseDueToLowSpace(): Boolean = freeSpaceProvider() < LOW_SPACE_BYTES

    companion object {
        const val LOW_SPACE_BYTES = 2L * 1024 * 1024 * 1024 // 2 GiB
    }
}

private fun String.hexToByteArray(): ByteArray {
    require(length % 2 == 0) { "hex segment id must have even length" }
    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
