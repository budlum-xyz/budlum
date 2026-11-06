package dev.budlum.validator.keys

import java.security.KeyStoreException

/** An occupied alias must not be silently overwritten with a new key. */
internal fun <T : Any> checkedExistingKey(key: T?, aliasOccupied: Boolean): T? {
    if (key == null && aliasOccupied) {
        throw KeyStoreException("wrapping key alias is occupied by a different entry")
    }
    return key
}

/** Decrypting a saved blob never creates a new, unrelated wrapping key. */
internal fun <T : Any> requireExistingKey(key: T?): T =
    key ?: throw KeyStoreException("wrapping key is missing; recovery is required")
