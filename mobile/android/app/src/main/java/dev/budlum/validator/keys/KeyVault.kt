package dev.budlum.validator.keys

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Device key wrapping. Directive 7.9.6.
 *
 * - The owner key (ML-DSA-87, 24 words) lives in the wallet and is NOT here.
 * - The operator key (ML-DSA-65) and the BLS asset key are generated on the
 *   device and wrapped with an AES-256-GCM key held in the Android Keystore.
 *   StrongBox is used when available.
 * - The operator key is used in the background, so its Keystore entry uses
 *   setUserAuthenticationRequired(false) and setUnlockedDeviceRequired(false).
 *   Trade-off (documented on the in-app Security page, 7.9.6.3): someone who
 *   seizes the unlocked device can sign duty transactions but cannot spend the
 *   stake. Device loss is handled with RotateOperatorKey from the owner wallet
 *   on another device (R-16).
 */
object KeyVault {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val AES_KEY_ALIAS = "budlum_keywrap_v1"
    const val OPERATOR_KEY_ALIAS = "budlum_operator_key_v1"
    const val BLS_KEY_ALIAS = "budlum_bls_asset_key_v1"

    private const val GCM_TAG_BITS = 128
    private const val GCM_IV_BYTES = 12

    /** AES-256-GCM wrapping key from the Android Keystore, StrongBox preferred. */
    @Synchronized
    fun keystoreWrapKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        findWrapKey(ks)?.let { return it }

        return generatePreferStrongBox(
            generate = { strongBox ->
                val builder = KeyGenParameterSpec.Builder(
                    AES_KEY_ALIAS,
                    KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
                )
                    .setKeySize(256)
                    .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                    // The operator key must be usable by background duties.
                    .setUserAuthenticationRequired(false)
                    .setUnlockedDeviceRequired(false)
                if (strongBox && android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.P) {
                    builder.setIsStrongBoxBacked(true)
                }
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
                    .apply { init(builder.build()) }
                    .generateKey()
            },
            isUnavailable = { it is StrongBoxUnavailableException },
        )
    }

    /**
     * Wrap [plaintext] with [key]. Output layout: 12-byte IV || ciphertext+GCM tag.
     * Kept separate from the Keystore lookup so it is unit-testable with a
     * locally generated key.
     */
    fun wrap(key: SecretKey, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, key)
        val iv = cipher.iv
        val body = cipher.doFinal(plaintext)
        return iv + body
    }

    fun unwrap(key: SecretKey, wrapped: ByteArray): ByteArray {
        require(wrapped.size > GCM_IV_BYTES) { "wrapped blob too short" }
        val iv = wrapped.copyOfRange(0, GCM_IV_BYTES)
        val body = wrapped.copyOfRange(GCM_IV_BYTES, wrapped.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        return cipher.doFinal(body)
    }

    fun wrapForStorage(plaintext: ByteArray): ByteArray = wrap(keystoreWrapKey(), plaintext)

    fun unwrapFromStorage(wrapped: ByteArray): ByteArray = unwrap(existingWrapKey(), wrapped)

    @Synchronized
    private fun existingWrapKey(): SecretKey {
        val ks = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        return requireExistingKey(findWrapKey(ks))
    }

    private fun findWrapKey(ks: KeyStore): SecretKey? {
        val entry = ks.getEntry(AES_KEY_ALIAS, null)
        val key = (entry as? KeyStore.SecretKeyEntry)?.secretKey
        return checkedExistingKey(key, aliasOccupied = entry != null || ks.containsAlias(AES_KEY_ALIAS))
    }
}
