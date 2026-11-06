package xyz.budlum.validator

import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Android Keystore AES-256-GCM key wrapper for Mobile validator keys (Section 7.9.6).
 *
 * - Owner wallet (ML-DSA-87, 24 words) requires Biometric / PIN authentication to spend.
 * - Operator duty key (ML-DSA-65) and BLS12-381 presence key are wrapped under an
 *   Android Keystore AES-256-GCM key (`StrongBox` when supported) with
 *   `setUserAuthenticationRequired(false)` and `setUnlockedDeviceRequired(false)`
 *   so background audits and presence signals work while the screen is locked.
 */
class KeystoreKeyManager(private val hasStrongBox: Boolean) {

    data class WrappedKeyBlob(
        val iv: ByteArray,
        val ciphertext: ByteArray,
        val strongBoxBacked: Boolean,
    )

    fun wrapDutyKeyInMemoryOrKeystore(
        alias: String,
        plaintextKeyMaterial: ByteArray,
        useAndroidKeystore: Boolean = true,
    ): WrappedKeyBlob {
        require(plaintextKeyMaterial.isNotEmpty()) { "Key material cannot be empty" }
        val secretKey: SecretKey = if (useAndroidKeystore) {
            getOrCreateKeystoreAesKey(alias, requireUserAuth = false)
        } else {
            val gen = KeyGenerator.getInstance("AES")
            gen.init(256)
            gen.generateKey()
        }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey)
        val ct = cipher.doFinal(plaintextKeyMaterial)
        return WrappedKeyBlob(cipher.iv, ct, hasStrongBox)
    }

    private fun getOrCreateKeystoreAesKey(alias: String, requireUserAuth: Boolean): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val existing = ks.getKey(alias, null) as? SecretKey
        if (existing != null) {
            return existing
        }
        val specBuilder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setUserAuthenticationRequired(requireUserAuth)
            .setUnlockedDeviceRequired(false)

        if (hasStrongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            specBuilder.setIsStrongBoxBacked(true)
        }
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(specBuilder.build())
        return generator.generateKey()
    }

    companion object {
        const val OPERATOR_KEY_ALIAS = "budlum_operator_mldsa65_aes_gcm"
        const val BLS_PRESENCE_KEY_ALIAS = "budlum_presence_bls_aes_gcm"
        const val OWNER_WALLET_KEY_ALIAS = "budlum_owner_mldsa87_spend_auth"

        fun deviceSupportsStrongBox(pm: PackageManager): Boolean =
            Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
                pm.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
    }
}
