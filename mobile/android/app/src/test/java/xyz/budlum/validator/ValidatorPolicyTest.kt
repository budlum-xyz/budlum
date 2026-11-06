package xyz.budlum.validator

import android.os.PowerManager
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.nio.file.Files

class ValidatorPolicyTest {

    @Test
    fun android_policy_wifi_only_by_default() {
        val policy = ValidatorPolicy()
        assertTrue(policy.wifiOnly)
        assertFalse(
            policy.permitsDuty(
                isUnmeteredWifi = false,
                isCharging = true,
                batteryPercent = 95,
                batterySaverEnabled = false,
                thermalStatus = PowerManager.THERMAL_STATUS_NONE,
            ),
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun android_thermal_pause_cannot_be_disabled() {
        ValidatorPolicy().setThermalPause(false)
    }

    @Test
    fun android_keys_are_keystore_wrapped() {
        val mgr = KeystoreKeyManager(hasStrongBox = true)
        val blob = mgr.wrapDutyKeyInMemoryOrKeystore(
            alias = KeystoreKeyManager.OPERATOR_KEY_ALIAS,
            plaintextKeyMaterial = ByteArray(32) { 0x5A },
            useAndroidKeystore = false,
        )
        assertEquals(12, blob.iv.size)
        assertTrue(blob.ciphertext.size > 32)
        assertTrue(blob.strongBoxBacked)
    }

    @Test
    fun android_low_space_releases_shares() {
        val dir = Files.createTempDirectory("bud3_low_space").toFile()
        val store = CustodyShareStore(dir, ValidatorPolicy.DEFAULT_QUOTA_BYTES)
        val segHex = "a".repeat(64)
        store.writeSegmentShare(segHex, ByteArray(4096) { 1 })
        val released = store.releaseForLowSpace(1024L)
        assertEquals(listOf(segHex), released)
        dir.deleteRecursively()
    }

    @Test
    fun android_leave_releases_shares_and_unbonds() {
        val dir = Files.createTempDirectory("bud3_leave").toFile()
        val store = CustodyShareStore(dir, ValidatorPolicy.DEFAULT_QUOTA_BYTES)
        val segHex = "b".repeat(64)
        store.writeSegmentShare(segHex, ByteArray(2048) { 2 })
        val released = store.releaseAllForLeave()
        assertEquals(listOf(segHex), released)
        assertEquals(0L, store.usedBytes())
        dir.deleteRecursively()
    }
}
