package dev.budlum.validator.keys

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * Unit tests for key wrapping (directive 7.9.6). Uses a locally generated AES
 * key so the wrap/unwrap logic is tested on the JVM without the Android
 * Keystore; the Keystore lookup itself is exercised on-device/emulator.
 * Android Keystore itself is covered by the instrumentation test, not here.
 */
class KeyVaultTest {

    private fun localAesKey(): SecretKey =
        KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()

    @Test
    fun `aes_gcm_wrap_round_trips_and_rejects_wrong_key`() {
        val key = localAesKey()
        val raw = ByteArray(64) { (it * 7).toByte() } // stand-in for a serialized ML-DSA-65 key

        val wrapped = KeyVault.wrap(key, raw)

        // Wrapped form is IV || ciphertext+tag: longer than the raw key and
        // does not contain it.
        assertTrue(wrapped.size > raw.size)
        assertFalse(wrapped.toList().windowed(raw.size, 1).any { it == raw.toList() })

        // Round trip restores the exact bytes.
        assertArrayEquals(raw, KeyVault.unwrap(key, wrapped))

        // A different key cannot unwrap it.
        val other = localAesKey()
        assertTrue(runCatching { KeyVault.unwrap(other, wrapped) }.isFailure)
    }

    @Test
    fun `unwrap rejects truncated blobs`() {
        val key = localAesKey()
        assertTrue(runCatching { KeyVault.unwrap(key, ByteArray(4)) }.isFailure)
    }
}
