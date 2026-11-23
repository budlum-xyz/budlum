package network.budlum.validator.core

import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/** JVM-only fixture. Never ship a non-authenticating owner provider in an APK. */
class JvmMemoryWrappingKeyProvider(override val strongBoxAvailable: Boolean = true) : AesWrappingKeyProvider {
    private val keys = mutableMapOf<String, SecretKey>()

    @Synchronized
    override fun getOrCreateAes256Key(alias: String, requireUserAuth: Boolean): SecretKey {
        return keys.getOrPut(alias) {
            val kg = KeyGenerator.getInstance("AES")
            kg.init(256)
            kg.generateKey()
        }
    }

    @Synchronized
    override fun getExistingAes256Key(alias: String, requireUserAuth: Boolean): SecretKey? = keys[alias]
}
