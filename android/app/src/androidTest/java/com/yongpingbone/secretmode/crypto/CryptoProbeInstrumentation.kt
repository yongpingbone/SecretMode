package com.yongpingbone.secretmode.crypto

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle
import com.yongpingbone.secretmode.storage.SessionStateCipher
import java.security.GeneralSecurityException

class CryptoProbeInstrumentation : Instrumentation() {
    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        start()
    }

    override fun onStart() {
        val result = Bundle()
        try {
            val probe = CryptoBridge.loadForM0Probe()
            check(probe == "vodozemac-0.10.0") { "Unexpected crypto probe result: $probe" }

            verifyKeystoreCryptographicErasure()
            val restoredSessionId = verifyRealOlmSessionCryptographicErasure()

            result.putString("secretmode_result", "ok")
            result.putString("probe", probe)
            result.putString("keystore_destroy_result", "ok")
            result.putString("olm_pickle_destroy_result", "ok")
            result.putString("restored_olm_session_id", restoredSessionId)
            finish(Activity.RESULT_OK, result)
        } catch (t: Throwable) {
            result.putString("secretmode_result", "failure")
            result.putString("error_type", t.javaClass.name)
            result.putString("error_message", t.message ?: "unknown")
            finish(Activity.RESULT_CANCELED, result)
        }
    }

    private fun verifyKeystoreCryptographicErasure() {
        val sessionId = "m0-keystore-destruction-probe-session"
        val oldPlaintext = "serialized-olm-pickle-that-must-become-unrecoverable".toByteArray()
        val replacementPlaintext = "replacement-session-state".toByteArray()

        check(SessionStateCipher.destroy(sessionId))
        check(!SessionStateCipher.hasKey(sessionId))

        val oldState = SessionStateCipher.encrypt(sessionId, oldPlaintext)
        check(SessionStateCipher.hasKey(sessionId))
        check(SessionStateCipher.decrypt(sessionId, oldState).contentEquals(oldPlaintext))

        check(SessionStateCipher.destroy(sessionId))
        check(!SessionStateCipher.hasKey(sessionId))

        var missingKeyRejected = false
        try {
            SessionStateCipher.decrypt(sessionId, oldState)
        } catch (_: SessionStateCipher.MissingSessionKeyException) {
            missingKeyRejected = true
        }
        check(missingKeyRejected) { "Old state decrypted after its Keystore key was deleted" }

        val replacementState = SessionStateCipher.encrypt(sessionId, replacementPlaintext)
        check(SessionStateCipher.decrypt(sessionId, replacementState).contentEquals(replacementPlaintext))

        var oldCiphertextRejectedByReplacementKey = false
        try {
            SessionStateCipher.decrypt(sessionId, oldState)
        } catch (_: GeneralSecurityException) {
            oldCiphertextRejectedByReplacementKey = true
        }
        check(oldCiphertextRejectedByReplacementKey) { "Old state unexpectedly decrypted with a replacement Keystore key" }

        oldPlaintext.fill(0)
        replacementPlaintext.fill(0)
        check(SessionStateCipher.destroy(sessionId))
        check(!SessionStateCipher.hasKey(sessionId))
    }

    private fun verifyRealOlmSessionCryptographicErasure(): String {
        val storageSessionId = "m0-real-olm-pickle-destruction-probe"
        var plaintextForCleanup: ByteArray? = null
        var recoveredForCleanup: ByteArray? = null
        var replacementForCleanup: ByteArray? = null

        check(SessionStateCipher.destroy(storageSessionId))
        check(!SessionStateCipher.hasKey(storageSessionId))

        try {
            val createdBundle = CryptoBridge.createM0OlmPickleBundle()
            plaintextForCleanup = createdBundle
            check(createdBundle.isNotEmpty()) { "Rust returned an empty Olm SessionPickle bundle" }

            val originalSessionId = CryptoBridge.validateM0OlmPickleBundle(createdBundle)
            check(originalSessionId.isNotBlank()) { "Restored Olm session ID must not be blank" }

            val encryptedState = SessionStateCipher.encrypt(storageSessionId, createdBundle)
            check(SessionStateCipher.hasKey(storageSessionId))

            val recoveredBundle = SessionStateCipher.decrypt(storageSessionId, encryptedState)
            recoveredForCleanup = recoveredBundle
            val recoveredSessionId = CryptoBridge.validateM0OlmPickleBundle(recoveredBundle)
            check(recoveredSessionId == originalSessionId) { "Keystore roundtrip changed the restored Olm session identity" }

            createdBundle.fill(0)
            plaintextForCleanup = null
            recoveredBundle.fill(0)
            recoveredForCleanup = null

            check(SessionStateCipher.destroy(storageSessionId))
            check(!SessionStateCipher.hasKey(storageSessionId))

            var missingKeyRejected = false
            try {
                SessionStateCipher.decrypt(storageSessionId, encryptedState)
            } catch (_: SessionStateCipher.MissingSessionKeyException) {
                missingKeyRejected = true
            }
            check(missingKeyRejected) { "Destroyed Keystore key still decrypted a real Olm SessionPickle bundle" }

            val replacementPlaintext = "replacement-state-must-not-open-old-olm-pickle".toByteArray()
            replacementForCleanup = replacementPlaintext
            val replacementState = SessionStateCipher.encrypt(storageSessionId, replacementPlaintext)
            check(SessionStateCipher.decrypt(storageSessionId, replacementState).contentEquals(replacementPlaintext))

            var oldCiphertextRejectedByReplacementKey = false
            try {
                SessionStateCipher.decrypt(storageSessionId, encryptedState)
            } catch (_: GeneralSecurityException) {
                oldCiphertextRejectedByReplacementKey = true
            }
            check(oldCiphertextRejectedByReplacementKey) { "Replacement key unexpectedly authenticated ciphertext containing the old Olm SessionPickle" }

            replacementPlaintext.fill(0)
            replacementForCleanup = null
            return originalSessionId
        } finally {
            plaintextForCleanup?.fill(0)
            recoveredForCleanup?.fill(0)
            replacementForCleanup?.fill(0)
            SessionStateCipher.destroy(storageSessionId)
        }
    }
}
