package dev.budlum.validator.keys

import java.security.KeyStoreException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class KeyLookupTest {
    @Test
    fun `an_absent_alias_is_available_for_first_key_generation`() {
        assertEquals(null, checkedExistingKey<String>(null, aliasOccupied = false))
    }

    @Test
    fun `a_non_key_alias_is_not_replaced`() {
        val error = runCatching {
            checkedExistingKey<String>(null, aliasOccupied = true)
        }.exceptionOrNull()
        assertTrue(error is KeyStoreException)
    }

    @Test
    fun `existing_keys_are_reused`() {
        val key = Any()
        assertTrue(checkedExistingKey(key, aliasOccupied = true) === key)
        assertTrue(requireExistingKey(key) === key)
    }

    @Test
    fun `missing_key_is_an_error_when_unwrapping`() {
        val error = runCatching { requireExistingKey<String>(null) }.exceptionOrNull()
        assertTrue(error is KeyStoreException)
    }
}
