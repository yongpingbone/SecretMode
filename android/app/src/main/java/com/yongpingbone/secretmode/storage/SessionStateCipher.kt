package com.yongpingbone.secretmode.storage

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.KeyStore
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * M0 storage primitive for proving cryptographic erasure on Android.
 *
 * Session state is encrypted with a non-exportable Android Keystore AES key.
 * Destroying the key removes app decryptability even if an encrypted blob remains.
 * This does not claim physical overwriting of flash cells.
 */
object SessionStateCipher {
    private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    private const val CIPHER = "AES/GCM/NoPadding"
    private const val KEY_ALIAS_PREFIX = "secretmode.session.v1."
    private const val AAD_PREFIX = "secretmode/session-state/v1\u0000"
    private const val TAG_BITS = 128

    data class EncryptedState(
        val version: Int,
        val iv: ByteArray,
        val ciphertext: ByteArray,
    )

    class MissingSessionKeyException(sessionId: String) :
        GeneralSecurityException("No decrypt key exists for destroyed/missing session: ${fingerprint(sessionId)}")

    @Synchronized
    fun encrypt(sessionId: String, plaintext: ByteArray): EncryptedState {
        require(sessionId.isNotBlank()) { "sessionId must not be blank" }
        require(plaintext.isNotEmpty()) { "session state must not be empty" }

        val key = getOrCreateKey(sessionId)
        val cipher = Cipher.getInstance(CIPHER)
        cipher.init(Cipher.ENCRYPT_MODE, key)
        cipher.updateAAD(aad(sessionId))
        val ciphertext = cipher.doFinal(plaintext)

        return EncryptedState(
            version = 1,
            iv = cipher.iv.clone(),
            ciphertext = ciphertext,
        )
    }

    @Synchronized
    fun decrypt(sessionId: String, state: EncryptedState): ByteArray {
        require(sessionId.isNotBlank()) { "sessionId must not be blank" }
        require(state.version == 1) { "Unsupported encrypted session-state version: ${state.version}" }
        require(state.iv.isNotEmpty()) { "GCM IV must not be empty" }
        require(state.ciphertext.isNotEmpty()) { "ciphertext must not be empty" }

        val key = loadKey(sessionId) ?: throw MissingSessionKeyException(sessionId)
        val cipher = Cipher.getInstance(CIPHER)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BITS, state.iv))
        cipher.updateAAD(aad(sessionId))
        return cipher.doFinal(state.ciphertext)
    }

    @Synchronized
    fun destroy(sessionId: String): Boolean {
        require(sessionId.isNotBlank()) { "sessionId must not be blank" }
        val store = keyStore()
        val alias = alias(sessionId)
        if (store.containsAlias(alias)) {
            store.deleteEntry(alias)
        }
        return !store.containsAlias(alias)
    }

    @Synchronized
    fun hasKey(sessionId: String): Boolean = keyStore().containsAlias(alias(sessionId))

    private fun getOrCreateKey(sessionId: String): SecretKey {
        loadKey(sessionId)?.let { return it }

        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
        generator.init(
            KeyGenParameterSpec.Builder(
                alias(sessionId),
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setKeySize(256)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build(),
        )
        return generator.generateKey()
    }

    private fun loadKey(sessionId: String): SecretKey? =
        keyStore().getKey(alias(sessionId), null) as? SecretKey

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    private fun aad(sessionId: String): ByteArray =
        (AAD_PREFIX + sessionId).toByteArray(StandardCharsets.UTF_8)

    private fun alias(sessionId: String): String = KEY_ALIAS_PREFIX + fingerprint(sessionId)

    private fun fingerprint(sessionId: String): String =
        MessageDigest.getInstance("SHA-256")
            .digest(sessionId.toByteArray(StandardCharsets.UTF_8))
            .joinToString(separator = "") { byte ->
                (byte.toInt() and 0xff).toString(16).padStart(2, '0')
            }
}
