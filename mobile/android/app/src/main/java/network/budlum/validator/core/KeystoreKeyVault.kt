package network.budlum.validator.core

import java.security.KeyStoreException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Key wrapping model per Directive Section 7.9.6:
 * 1. Owner spend/stake/rotation/unbonding is REFUSED in this build. The planned
 *    ML-DSA-87 owner wallet and Keystore-bound biometric/PIN authorization are
 *    not connected. No caller-controlled string may bypass this refusal.
 * 2. Operator (`ML-DSA-65`) and BLS wrapping is a local key-storage model;
 *    its non-authenticated AES key is not an owner authorization or a working
 *    background duty transport. The app never claims these keys can validate.
 */
enum class KeyPurpose(val aadLabel: String, val requiresBiometricOrPin: Boolean) {
    OwnerSpendMlDsa87("BDLM_ANDROID_OWNER_MLDSA87_V1", true),
    OperatorDutyMlDsa65("BDLM_ANDROID_OPERATOR_MLDSA65_V1", false),
    PresenceBls12381("BDLM_ANDROID_PRESENCE_BLS_V1", false),
}

data class WrappedKeyEnvelope(
    val purpose: KeyPurpose,
    val keystoreAlias: String,
    val strongBoxBacked: Boolean,
    val userAuthenticationRequired: Boolean,
    val unlockedDeviceRequired: Boolean,
    val iv: ByteArray,
    val ciphertextWithTag: ByteArray,
)

interface AesWrappingKeyProvider {
    val strongBoxAvailable: Boolean
    fun getOrCreateAes256Key(alias: String, requireUserAuth: Boolean): SecretKey

    /** Return an existing wrapping key without creating replacement key material. */
    fun getExistingAes256Key(alias: String, requireUserAuth: Boolean): SecretKey?
}

/** Retry without StrongBox only for the platform's explicit unavailable error. */
internal fun <T> generatePreferStrongBox(
    generate: (strongBox: Boolean) -> T,
    isUnavailable: (Exception) -> Boolean,
): T = try {
    generate(true)
} catch (error: Exception) {
    if (!isUnavailable(error)) throw error
    generate(false)
}

class KeystoreKeyVault(private val provider: AesWrappingKeyProvider) {
    private val rng = SecureRandom()

    /**
     * No bearer string proves biometric/PIN authentication. Refuse every
     * owner-key, stake, rotation and unbond request until a Keystore-backed,
     * operation-scoped authorization and real ML-DSA wallet signer are wired.
     * Accepting a well-known token here would silently authorize anyone.
     */
    fun requireOwnerSpendAuthorization(@Suppress("UNUSED_PARAMETER") presentedToken: String): Nothing {
        throw SecurityException("owner authorization is unavailable without a verified Keystore operation")
    }

    fun wrapKey(
        purpose: KeyPurpose,
        plaintextKeyMaterial: ByteArray,
        biometricAuthToken: String? = null,
    ): WrappedKeyEnvelope {
        require(plaintextKeyMaterial.isNotEmpty()) { "key material cannot be empty" }
        if (purpose.requiresBiometricOrPin) {
            requireOwnerSpendAuthorization(biometricAuthToken ?: "")
        }
        val alias = "budlum.${purpose.name.lowercase()}"
        val secretKey = provider.getOrCreateAes256Key(alias, purpose.requiresBiometricOrPin)
        val iv = ByteArray(12).also { rng.nextBytes(it) }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
        cipher.updateAAD(purpose.aadLabel.toByteArray(Charsets.UTF_8))
        val sealed = cipher.doFinal(plaintextKeyMaterial)

        return WrappedKeyEnvelope(
            purpose = purpose,
            keystoreAlias = alias,
            strongBoxBacked = provider.strongBoxAvailable,
            userAuthenticationRequired = purpose.requiresBiometricOrPin,
            unlockedDeviceRequired = purpose.requiresBiometricOrPin,
            iv = iv,
            ciphertextWithTag = sealed,
        )
    }

    fun unwrapKey(envelope: WrappedKeyEnvelope, biometricAuthToken: String? = null): ByteArray {
        if (envelope.purpose.requiresBiometricOrPin) {
            requireOwnerSpendAuthorization(biometricAuthToken ?: "")
        }
        val secretKey = provider.getExistingAes256Key(
            envelope.keystoreAlias,
            envelope.purpose.requiresBiometricOrPin,
        ) ?: throw KeyStoreException("wrapping key is missing; recovery is required")
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, envelope.iv))
        cipher.updateAAD(envelope.purpose.aadLabel.toByteArray(Charsets.UTF_8))
        return cipher.doFinal(envelope.ciphertextWithTag)
    }
}
