package dev.budlum.validator.keys

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Runs against the device's Android Keystore, not a JVM-generated AES key. */
@RunWith(AndroidJUnit4::class)
class KeyVaultInstrumentedTest {
    @Test
    fun android_keys_are_keystore_wrapped() {
        val key = KeyVault.keystoreWrapKey()
        assertEquals("AES", key.algorithm)
        assertNull(key.encoded) // The wrapping key cannot be exported from the Keystore.

        val plaintext = ByteArray(64).also { SecureRandom().nextBytes(it) }
        val wrapped = KeyVault.wrapForStorage(plaintext)
        assertEquals(12 + plaintext.size + 16, wrapped.size)
        assertArrayEquals(plaintext, KeyVault.unwrapFromStorage(wrapped))

        val tampered = wrapped.copyOf()
        tampered[tampered.lastIndex] = (tampered.last().toInt() xor 1).toByte()
        assertTrue(runCatching { KeyVault.unwrapFromStorage(tampered) }.isFailure)
    }

    @Test
    fun concurrent_keystore_lookups_use_the_same_wrapping_key() {
        val count = 8
        val ready = CountDownLatch(count)
        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(count)
        try {
            val keys = (0 until count).map {
                pool.submit<javax.crypto.SecretKey> {
                    ready.countDown()
                    start.await()
                    KeyVault.keystoreWrapKey()
                }
            }
            assertTrue(ready.await(30, TimeUnit.SECONDS))
            start.countDown()
            val resolved = keys.map { it.get(60, TimeUnit.SECONDS) }
            val plaintext = byteArrayOf(1, 2, 3, 4)
            val wrapped = KeyVault.wrap(resolved.first(), plaintext)
            for (key in resolved) assertArrayEquals(plaintext, KeyVault.unwrap(key, wrapped))
        } finally {
            pool.shutdownNow()
        }
    }
}
