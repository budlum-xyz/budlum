package network.budlum.validator.core

import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.SecureRandom
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** Runs against Android Keystore, not the JVM in-memory provider. */
@RunWith(AndroidJUnit4::class)
class AndroidKeystoreWrappingKeyProviderInstrumentedTest {
    @Test
    fun wrapping_key_is_non_exportable_and_round_trips() {
        val provider = AndroidKeystoreWrappingKeyProvider()
        val alias = "budlum.instrumented.roundtrip"
        val key = provider.getOrCreateAes256Key(alias, false)
        assertEquals("AES", key.algorithm)
        assertNull(key.encoded)
        assertNull(provider.getExistingAes256Key("budlum.instrumented.absent", false))

        // The provider never calls setRandomizedEncryptionRequired(false), so
        // the Keystore generates the IV and refuses one from the caller. That
        // refusal is the invariant, not an obstacle: measured on an emulator
        // (run 44983814725, job 137089901345), handing the cipher a
        // caller-generated IV in ENCRYPT_MODE threw
        // InvalidAlgorithmParameterException: Caller-provided IV not permitted.
        val callerIv = ByteArray(12).also { SecureRandom().nextBytes(it) }
        assertTrue(
            "a Keystore key that accepts a caller IV would allow GCM nonce reuse",
            runCatching {
                Cipher.getInstance("AES/GCM/NoPadding")
                    .init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(128, callerIv))
            }.isFailure,
        )

        val plaintext = ByteArray(64).also { SecureRandom().nextBytes(it) }
        val encrypting = Cipher.getInstance("AES/GCM/NoPadding")
        encrypting.init(Cipher.ENCRYPT_MODE, key)
        val wrapped = encrypting.doFinal(plaintext)
        val iv = encrypting.iv
        assertEquals("the Keystore must hand back a fresh 12-byte GCM IV", 12, iv.size)
        val existing = provider.getExistingAes256Key(alias, false)
        val unwrapped = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, existing, GCMParameterSpec(128, iv))
            doFinal(wrapped)
        }
        assertArrayEquals(plaintext, unwrapped)

        val tampered = wrapped.copyOf()
        tampered[tampered.lastIndex] = (tampered.last().toInt() xor 1).toByte()
        assertTrue(runCatching {
            Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, existing, GCMParameterSpec(128, iv))
                doFinal(tampered)
            }
        }.isFailure)
    }

    @Test
    fun concurrent_lookups_use_the_same_wrapping_key() {
        val provider = AndroidKeystoreWrappingKeyProvider()
        val alias = "budlum.instrumented.concurrent"
        val count = 8
        val ready = CountDownLatch(count)
        val start = CountDownLatch(1)
        val pool = Executors.newFixedThreadPool(count)
        try {
            val keys = (0 until count).map {
                pool.submit<javax.crypto.SecretKey> {
                    ready.countDown()
                    start.await()
                    provider.getOrCreateAes256Key(alias, false)
                }
            }
            assertTrue(ready.await(30, TimeUnit.SECONDS))
            start.countDown()
            val resolved = keys.map { it.get(60, TimeUnit.SECONDS) }
            val plaintext = byteArrayOf(1, 2, 3, 4)
            // Same Keystore contract as above: no caller IV on encrypt. The IV
            // is read back off the cipher and reused for every unwrap, which is
            // what proves all eight concurrent lookups resolved the same key.
            val encrypting = Cipher.getInstance("AES/GCM/NoPadding")
            encrypting.init(Cipher.ENCRYPT_MODE, resolved.first())
            val wrapped = encrypting.doFinal(plaintext)
            val iv = encrypting.iv
            for (key in resolved) {
                val unwrapped = Cipher.getInstance("AES/GCM/NoPadding").run {
                    init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv))
                    doFinal(wrapped)
                }
                assertArrayEquals(plaintext, unwrapped)
            }
        } finally {
            pool.shutdownNow()
        }
    }
}
