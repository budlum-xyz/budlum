package dev.budlum.validator.storage

import java.io.File
import java.io.FileOutputStream
import java.nio.file.FileAlreadyExistsException
import java.nio.file.Files
import java.nio.file.LinkOption

/**
 * Local share files under `noBackupFilesDir/bud3/` (directive 7.9.5).
 *
 * This is an interim store, not the mobile core's durable share database.
 * Release methods return local segment ids; the caller must still submit and
 * durably track the corresponding StorageTx::ReleaseShares and repair. The
 * app has no such network binding yet, so this class alone does not implement
 * the low-space or quota-change protocol.
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

    /** A listing or arithmetic failure must not understate the space in use. */
    fun storedBytes(): Long = synchronized(STORE_LOCK) {
        val files = listFiles() ?: return@synchronized Long.MAX_VALUE
        totalBytes(files) ?: Long.MAX_VALUE
    }

    /**
     * Admit a new share only if its id is unused, the quota will not be
     * exceeded, and the write will leave at least 2 GiB of free space.
     * A duplicate, including a dangling symlink, is never overwritten.
     *
     * A complete, synced temporary file is linked into place without replacing
     * an existing name. This prevents a failed write from publishing a partial
     * share. It does not replace the durable release protocol or database.
     */
    fun writeShare(segmentId: ByteArray, bytes: ByteArray, quotaBytes: Long): Boolean =
        synchronized(STORE_LOCK) {
            if (segmentId.isEmpty() || quotaBytes < 0) return@synchronized false

            val target = shareFile(segmentId)
            if (Files.exists(target.toPath(), LinkOption.NOFOLLOW_LINKS)) return@synchronized false

            val files = listFiles() ?: return@synchronized false
            val used = totalBytes(files) ?: return@synchronized false
            val size = bytes.size.toLong()
            if (used > quotaBytes || size > quotaBytes - used) return@synchronized false

            val free = freeSpaceProvider()
            if (free < LOW_SPACE_BYTES || size > free - LOW_SPACE_BYTES) return@synchronized false

            val dir = bud3Dir
            if (!dir.isDirectory && !dir.mkdirs()) return@synchronized false
            val temporary = File.createTempFile(".share-", ".tmp", dir)
            try {
                FileOutputStream(temporary).use { output ->
                    output.write(bytes)
                    output.fd.sync()
                }
                try {
                    // Both paths are on the same filesystem. createLink fails
                    // atomically if any entry already occupies the target.
                    Files.createLink(target.toPath(), temporary.toPath())
                } catch (e: FileAlreadyExistsException) {
                    return@synchronized false
                }
                true
            } finally {
                temporary.delete()
            }
        }

    /**
     * Delete explicitly selected local shares and return their segment ids.
     * This is not a network acknowledgement or a durable release intent.
     */
    fun releaseShares(segmentIds: Collection<ByteArray>): List<ByteArray> =
        synchronized(STORE_LOCK) {
            val released = mutableListOf<ByteArray>()
            for (id in segmentIds) {
                if (id.isEmpty()) continue
                val file = shareFile(id)
                if (file.isFile && file.delete()) released.add(id)
            }
            released
        }

    /**
     * Delete the oldest local shares until they fit [quotaBytes]. Return the
     * deleted segment ids. An unrecognized file makes the operation fail closed
     * so metadata or a recovered temporary file is never silently deleted.
     */
    fun enforceQuota(quotaBytes: Long): List<ByteArray> = synchronized(STORE_LOCK) {
        require(quotaBytes >= 0) { "quota must not be negative" }
        val files = listFiles() ?: return@synchronized emptyList()
        var total = totalBytes(files) ?: return@synchronized emptyList()
        val candidates = files.map { file ->
            val id = file.name.hexToByteArrayOrNull()
            if (!file.isFile || id == null) return@synchronized emptyList()
            file to id
        }.sortedWith(compareBy<Pair<File, ByteArray>> { it.first.lastModified() }.thenBy { it.first.name })
        val released = mutableListOf<ByteArray>()
        for ((file, id) in candidates) {
            if (total <= quotaBytes) break
            // A deleted file's length is zero, so capture it first.
            val size = file.length()
            if (file.delete()) {
                total -= size
                released.add(id)
            }
        }
        released
    }

    /** Free space below this triggers the release protocol (R-34). */
    fun needsReleaseDueToLowSpace(): Boolean = freeSpaceProvider() < LOW_SPACE_BYTES

    private fun listFiles(): Array<File>? {
        val dir = bud3Dir
        return if (!dir.exists()) emptyArray() else dir.listFiles()
    }

    private fun totalBytes(files: Array<File>): Long? {
        var total = 0L
        for (file in files) {
            val size = file.length()
            if (size > Long.MAX_VALUE - total) return null
            total += size
        }
        return total
    }

    companion object {
        const val LOW_SPACE_BYTES = 2L * 1024 * 1024 * 1024 // 2 GiB

        // ShareStore instances in the app process must make admission and
        // deletion decisions against the same snapshot of the directory.
        private val STORE_LOCK = Any()
    }
}

private fun String.hexToByteArrayOrNull(): ByteArray? {
    if (isEmpty() || length % 2 != 0 || any { it !in '0'..'9' && it !in 'a'..'f' }) return null
    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
