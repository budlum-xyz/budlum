package network.budlum.validator.core

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * The secret that seals this phone's wallet, held by the Android Keystore.
 *
 * The core seals a wallet under a passphrase (PBKDF2 plus XChaCha20-Poly1305).
 * Asking a person to invent that passphrase on the screen that also shows the
 * twenty-four words is a second thing to remember at the worst moment, and the
 * design file has no such control: the wallet is opened by the phone, not by a
 * typed string.
 *
 * So the passphrase is generated here, once, as thirty-two random bytes, and
 * stored wrapped by a non-exportable AES-256 key inside the Android Keystore.
 * The wrapped copy lives in app-private preferences (excluded from backup by
 * `data_extraction_rules.xml`); the key itself never leaves the Keystore, so a
 * copy of the preferences alone opens nothing.
 *
 * This is not a weaker seal than a typed passphrase: the passphrase it replaces
 * was eight characters of a person's invention, reused across apps and shown on
 * a screen next to the words it protects. What it does give up is portability -
 * the wallet file cannot be opened off this phone. The words are the way back,
 * which is what they are for.
 */
class DeviceWalletSeal(context: Context) {

    private val prefs = context.applicationContext
        .getSharedPreferences(PREFS, Context.MODE_PRIVATE)

    /** The sealing passphrase, made on first ask and returned as lowercase hex. */
    fun secret(): String {
        val stored = prefs.getString(KEY, null)
        if (stored != null) return toHex(unwrap(stored))
        val fresh = ByteArray(SECRET_BYTES).also { SecureRandom().nextBytes(it) }
        prefs.edit().putString(KEY, wrap(fresh)).apply()
        return toHex(fresh)
    }

    /** Whether this phone already holds a sealing secret. */
    fun exists(): Boolean = prefs.getString(KEY, null) != null

    private fun wrap(plain: ByteArray): String {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key())
        val sealed = cipher.iv + cipher.doFinal(plain)
        return Base64.encodeToString(sealed, Base64.NO_WRAP)
    }

    private fun unwrap(stored: String): ByteArray {
        val sealed = Base64.decode(stored, Base64.NO_WRAP)
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            Cipher.DECRYPT_MODE,
            key(),
            GCMParameterSpec(TAG_BITS, sealed, 0, IV_BYTES),
        )
        return cipher.doFinal(sealed, IV_BYTES, sealed.size - IV_BYTES)
    }

    private fun key(): SecretKey {
        val store = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        val existing = store.getEntry(ALIAS, null) as? KeyStore.SecretKeyEntry
        if (existing != null) return existing.secretKey
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(false)
                .build(),
        )
        return generator.generateKey()
    }

    private fun toHex(bytes: ByteArray): String {
        val out = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            out.append(HEX[v ushr 4]).append(HEX[v and 0x0F])
        }
        return out.toString()
    }

    private companion object {
        const val PREFS = "budlum_garden_seal"
        const val KEY = "wallet_seal_v1"
        const val ALIAS = "budlum.garden.wallet.seal"
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val SECRET_BYTES = 32
        const val IV_BYTES = 12
        const val TAG_BITS = 128
        const val HEX = "0123456789abcdef"
    }
}
