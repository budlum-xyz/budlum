package dev.budlum.validator.storage

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
    fun `android_low_space_releases_shares`() {
        val lowSpace = ShareStore(
            noBackupFilesDir = tmp.root,
            freeSpaceProvider = { ShareStore.LOW_SPACE_BYTES - 1 }
        )
        assertTrue(lowSpace.needsReleaseDueToLowSpace())

        val plenty = ShareStore(
            noBackupFilesDir = tmp.root,
            freeSpaceProvider = { ShareStore.LOW_SPACE_BYTES + 1 }
        )
        assertFalse(plenty.needsReleaseDueToLowSpace())

        // The release path itself deletes the files and reports the ids.
        assertTrue(lowSpace.writeShare(segmentA, ByteArray(4), quotaBytes = 100))
        val released = lowSpace.releaseShares(listOf(segmentA))
        assertEquals(listOf(segmentA), released)
        assertEquals(0L, lowSpace.storedBytes())
    }
}
