package dev.budlum.validator.storage

import java.io.File
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * Unit tests for share storage: hex naming, quota enforcement, and the
 * low-space release rule (directive 7.9.5, R-34). Covers the WP-36 test
 * `android_low_space_releases_shares`.
 */
class ShareStoreTest {

    @get:Rule
    val tmp = TemporaryFolder()

    private lateinit var store: ShareStore
    private val segmentA = byteArrayOf(0x01, 0x0a, 0xff.toByte())
    private val segmentB = byteArrayOf(0x02, 0x0b)

    @Before
    fun setUp() {
        store = ShareStore(noBackupFilesDir = tmp.root, freeSpaceProvider = { Long.MAX_VALUE })
    }

    @Test
    fun `share file name is the hex form of the segment id`() {
        assertEquals("010aff", store.shareFileName(segmentA))
        assertEquals("020b", store.shareFileName(segmentB))
        assertTrue(store.shareFile(segmentA).parentFile == store.bud3Dir)
        assertEquals("bud3", store.bud3Dir.name)
    }

    @Test
    fun `write respects the quota`() {
        val quota = 8L
        assertTrue(store.writeShare(segmentA, ByteArray(6), quota))
        // 6 + 4 > 8: refused, nothing written.
        assertFalse(store.writeShare(segmentB, ByteArray(4), quota))
        assertFalse(store.shareFile(segmentB).exists())
        assertEquals(6L, store.storedBytes())
    }

    @Test
    fun `enforceQuota releases oldest first until within quota`() {
        val quota = 6L
        assertTrue(store.writeShare(segmentA, ByteArray(4), quotaBytes = 100))
        assertTrue(store.writeShare(segmentB, ByteArray(4), quotaBytes = 100))
        // Do not depend on filesystem timestamp resolution or thread sleeps.
        assertTrue(store.shareFile(segmentA).setLastModified(1_000))
        assertTrue(store.shareFile(segmentB).setLastModified(2_000))

        val released = store.enforceQuota(quota)
        // ByteArray equality is reference equality; compare hex forms.
        assertEquals(listOf("010aff"), released.map { store.shareFileName(it) })
        assertEquals(4L, store.storedBytes())
        assertFalse(store.shareFile(segmentA).exists())
        assertTrue(store.shareFile(segmentB).exists())
    }

    @Test
    fun `duplicate segment never overwrites an existing share`() {
        val original = byteArrayOf(1, 2, 3, 4)
        assertTrue(store.writeShare(segmentA, original, quotaBytes = 100))
        assertFalse(store.writeShare(segmentA, byteArrayOf(9, 9, 9), quotaBytes = 100))
        assertArrayEquals(original, store.shareFile(segmentA).readBytes())
        assertEquals(4L, store.storedBytes())
        assertEquals(listOf("010aff"), store.bud3Dir.listFiles()!!.map { it.name })
    }

    @Test
    fun `an existing dangling link cannot redirect a share write`() {
        assertTrue(store.bud3Dir.mkdirs())
        val outside = File(tmp.root, "outside")
        Files.createSymbolicLink(store.shareFile(segmentA).toPath(), outside.toPath())
        assertFalse(store.writeShare(segmentA, ByteArray(4), quotaBytes = 100))
        assertFalse(outside.exists())
    }

    @Test
    fun `admission refuses to cross the low space floor`() {
        val almostFull = ShareStore(
            noBackupFilesDir = tmp.root,
            freeSpaceProvider = { ShareStore.LOW_SPACE_BYTES + 3 }
        )
        assertFalse(almostFull.writeShare(segmentA, ByteArray(4), quotaBytes = 100))
        assertFalse(almostFull.shareFile(segmentA).exists())

        val exactlyEnough = ShareStore(
            noBackupFilesDir = tmp.root,
            freeSpaceProvider = { ShareStore.LOW_SPACE_BYTES + 4 }
        )
        assertTrue(exactlyEnough.writeShare(segmentA, ByteArray(4), quotaBytes = 100))
    }

    @Test
    fun `negative quota cannot delete stored shares`() {
        assertTrue(store.writeShare(segmentA, ByteArray(4), quotaBytes = 100))
        assertTrue(runCatching { store.enforceQuota(-1) }.isFailure)
        assertTrue(store.shareFile(segmentA).exists())
        assertEquals(4L, store.storedBytes())
    }

    @Test
    fun `empty segment id cannot delete the store directory`() {
        assertTrue(store.bud3Dir.mkdirs())
        assertTrue(store.releaseShares(listOf(byteArrayOf())).isEmpty())
        assertTrue(store.bud3Dir.isDirectory)
        assertFalse(store.writeShare(byteArrayOf(), ByteArray(1), quotaBytes = 100))
    }

    @Test
    fun `quota enforcement preserves files with unrecognized names`() {
        assertTrue(store.writeShare(segmentA, byteArrayOf(1, 2), quotaBytes = 100))
        val unknown = File(store.bud3Dir, "not-a-segment")
        unknown.writeBytes(byteArrayOf(7, 8, 9))
        val released = store.enforceQuota(0)
        assertTrue(released.isEmpty())
        assertArrayEquals(byteArrayOf(7, 8, 9), unknown.readBytes())
        assertArrayEquals(byteArrayOf(1, 2), store.shareFile(segmentA).readBytes())
    }

    @Test
    fun `concurrent stores cannot admit more than the quota`() {
        val workers = 16
        val bytesPerShare = 16_384
        val ready = CountDownLatch(workers)
        val start = CountDownLatch(1)
        val executor = Executors.newFixedThreadPool(workers)
        try {
            val writes = (0 until workers).map { index ->
                executor.submit<Boolean> {
                    val concurrentStore = ShareStore(tmp.root) { Long.MAX_VALUE }
                    ready.countDown()
                    start.await()
                    concurrentStore.writeShare(
                        byteArrayOf(index.toByte()),
                        ByteArray(bytesPerShare),
                        quotaBytes = bytesPerShare.toLong(),
                    )
                }
            }
            assertTrue(ready.await(10, TimeUnit.SECONDS))
            start.countDown()
            assertEquals(1, writes.count { it.get(10, TimeUnit.SECONDS) })
            assertEquals(bytesPerShare.toLong(), store.storedBytes())
        } finally {
            executor.shutdownNow()
        }
    }

    @Test
    fun `low space is detected and explicit local release reports ids`() {
        assertTrue(store.writeShare(segmentA, ByteArray(4), quotaBytes = 100))
        val lowSpace = ShareStore(
            noBackupFilesDir = tmp.root,
            freeSpaceProvider = { ShareStore.LOW_SPACE_BYTES - 1 }
        )
        assertTrue(lowSpace.needsReleaseDueToLowSpace())
        assertFalse(lowSpace.writeShare(segmentB, ByteArray(4), quotaBytes = 100))

        val plenty = ShareStore(
            noBackupFilesDir = tmp.root,
            freeSpaceProvider = { ShareStore.LOW_SPACE_BYTES + 1 }
        )
        assertFalse(plenty.needsReleaseDueToLowSpace())

        // This tests only local deletion. The durable chain release and repair
        // protocol is not wired into this Android scaffold yet.
        val released = lowSpace.releaseShares(listOf(segmentA))
        assertEquals(listOf(segmentA), released)
        assertEquals(0L, lowSpace.storedBytes())
    }
}
