package network.budlum.validator.core

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.security.KeyStore
import java.security.KeyStoreException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/** Android Keystore AES-256-GCM wrapping keys, with a narrow StrongBox fallback. */
class AndroidKeystoreWrappingKeyProvider : AesWrappingKeyProvider {
    // Conservative for restored keys whose backing cannot be inferred here.
    @Volatile
    override var strongBoxAvailable: Boolean = false
        private set

    @Synchronized
    override fun getOrCreateAes256Key(alias: String, requireUserAuth: Boolean): SecretKey {
        require(alias.isNotBlank()) { "wrapping key alias cannot be blank" }
        val keyStore = loadKeyStore()
        findExistingKey(keyStore, alias)?.let { return it }

        var usedStrongBox = true
        val key = generatePreferStrongBox(
            generate = { strongBox ->
                usedStrongBox = strongBox
                generateKey(alias, requireUserAuth, strongBox)
            },
            isUnavailable = { it is StrongBoxUnavailableException },
        )
        strongBoxAvailable = usedStrongBox
        return key
    }

    @Synchronized
    override fun getExistingAes256Key(alias: String, requireUserAuth: Boolean): SecretKey? {
        require(alias.isNotBlank()) { "wrapping key alias cannot be blank" }
        return findExistingKey(loadKeyStore(), alias)
    }

    private fun loadKeyStore(): KeyStore =
        KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun findExistingKey(keyStore: KeyStore, alias: String): SecretKey? {
        val entry = keyStore.getEntry(alias, null)
        val key = (entry as? KeyStore.SecretKeyEntry)?.secretKey
        if (key == null && (entry != null || keyStore.containsAlias(alias))) {
            throw KeyStoreException("wrapping key alias is occupied by a different entry")
        }
        return key
    }

    private fun generateKey(alias: String, requireUserAuth: Boolean, strongBox: Boolean): SecretKey {
        val builder = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setUserAuthenticationRequired(requireUserAuth)
            .setUnlockedDeviceRequired(requireUserAuth)
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        return KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .apply { init(builder.build()) }
            .generateKey()
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
}
