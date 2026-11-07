package dev.budlum.validator.keys

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class StrongBoxFallbackTest {
    private class Unavailable : Exception()

    @Test
    fun `android_keystore_retries_without_strongbox_only_when_unavailable`() {
        val attempts = mutableListOf<Boolean>()
        val result = generatePreferStrongBox(
            generate = { strongBox ->
                attempts.add(strongBox)
                if (strongBox) throw Unavailable()
                "ordinary keystore key"
            },
            isUnavailable = { it is Unavailable },
        )
        assertEquals("ordinary keystore key", result)
        assertEquals(listOf(true, false), attempts)
    }

    @Test
    fun `strongbox_success_is_not_replaced_with_a_non_strongbox_key`() {
        val attempts = mutableListOf<Boolean>()
        val result = generatePreferStrongBox(
            generate = { strongBox ->
                attempts.add(strongBox)
                "strongbox key"
            },
            isUnavailable = { it is Unavailable },
        )
        assertEquals("strongbox key", result)
        assertEquals(listOf(true), attempts)
    }

    @Test
    fun `unexpected_keystore_errors_do_not_trigger_fallback`() {
        val attempts = mutableListOf<Boolean>()
        val failure = IllegalStateException("unexpected failure")
        val result = runCatching {
            generatePreferStrongBox(
                generate = { strongBox ->
                    attempts.add(strongBox)
                    throw failure
                },
                isUnavailable = { it is Unavailable },
            )
        }
        assertTrue(result.exceptionOrNull() === failure)
        assertEquals(listOf(true), attempts)
    }

    @Test
    fun `ordinary_keystore_failure_is_propagated`() {
        val attempts = mutableListOf<Boolean>()
        val failure = IllegalStateException("ordinary keystore failed")
        val result = runCatching {
            generatePreferStrongBox(
                generate = { strongBox ->
                    attempts.add(strongBox)
                    if (strongBox) throw Unavailable()
                    throw failure
                },
                isUnavailable = { it is Unavailable },
            )
        }
        assertTrue(result.exceptionOrNull() === failure)
        assertEquals(listOf(true, false), attempts)
    }
}
