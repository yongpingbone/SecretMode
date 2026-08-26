package com.yongpingbone.secretmode.crypto

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.GeneralSecurityException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.security.spec.X509EncodedKeySpec

class DeviceIdentitySigner(
    private val alias: String = DEFAULT_ALIAS,
) {
    fun publicKeySpki(): ByteArray = ensurePublicKey().encoded.copyOf()

    fun sign(payload: ByteArray): ByteArray {
        ensurePublicKey()
        val keyStore = loadKeyStore()
        val privateKey = keyStore.getKey(alias, null) as? PrivateKey
            ?: error("AndroidKeyStore identity private key is missing or has the wrong type")
        return Signature.getInstance(SIGNATURE_ALGORITHM).run {
            initSign(privateKey)
            update(payload)
            sign()
        }
    }

    private fun ensurePublicKey(): PublicKey {
        val keyStore = loadKeyStore()
        keyStore.getCertificate(alias)?.publicKey?.let { return it }

        val generator = KeyPairGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_EC,
            ANDROID_KEY_STORE,
        )
        generator.initialize(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
                .setAlgorithmParameterSpec(ECGenParameterSpec(EC_CURVE))
                .setDigests(KeyProperties.DIGEST_SHA256)
                .build(),
        )
        return generator.generateKeyPair().public
    }

    companion object {
        const val DEFAULT_ALIAS = "secretmode.device-identity-signing.v1"
        private const val ANDROID_KEY_STORE = "AndroidKeyStore"
        private const val EC_CURVE = "secp256r1"
        private const val SIGNATURE_ALGORITHM = "SHA256withECDSA"

        fun verify(
            publicKeySpki: ByteArray,
            payload: ByteArray,
            signatureBytes: ByteArray,
        ): Boolean = try {
            val publicKey = KeyFactory.getInstance(KeyProperties.KEY_ALGORITHM_EC)
                .generatePublic(X509EncodedKeySpec(publicKeySpki))
            Signature.getInstance(SIGNATURE_ALGORITHM).run {
                initVerify(publicKey)
                update(payload)
                verify(signatureBytes)
            }
        } catch (_: GeneralSecurityException) {
            false
        }

        private fun loadKeyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEY_STORE).apply {
            load(null)
        }
    }
}
