package com.yongpingbone.secretmode.crypto

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle
import com.yongpingbone.secretmode.storage.SessionStateCipher
import java.security.GeneralSecurityException

/**
 * M0-only instrumentation entrypoint.
 *
 * This does not test product messaging. It proves that an Android process can
 * load the packaged Rust library, resolve the JNI symbol, enter Rust code, and
 * exercise Android Keystore cryptographic-erasure behavior before real session
 * persistence is allowed.
 */
class CryptoProbeInstrumentation : Instrumentation() {
    override fun onCreate(arguments: Bundle?) {
        super.onCreate(arguments)
        start()
    }

    override fun onStart() {
        val result = Bundle()
        try {
            val probe = CryptoBridge.loadForM0Probe()
            check(probe == "vodozemac-0.10.0") {
                "Unexpected crypto probe result: $probe"
            }

            verifyKeystoreCryptographicErasure()

            result.putString("secretmode_result", "ok")
            result.putString("probe", probe)
            result.putString("keystore_destroy_result", "ok")
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

        // Make the probe deterministic across emulator snapshots/retries.
        check(SessionStateCipher.destroy(sessionId))
        check(!SessionStateCipher.hasKey(sessionId))

        val oldState = SessionStateCipher.encrypt(sessionId, oldPlaintext)
        check(SessionStateCipher.hasKey(sessionId))
        check(SessionStateCipher.decrypt(sessionId, oldState).contentEquals(oldPlaintext))

        // Destruction removes the only app-usable key for the old encrypted state.
        check(SessionStateCipher.destroy(sessionId))
        check(!SessionStateCipher.hasKey(sessionId))

        var missingKeyRejected = false
        try {
            SessionStateCipher.decrypt(sessionId, oldState)
        } catch (_: SessionStateCipher.MissingSessionKeyException) {
            missingKeyRejected = true
        }
        check(missingKeyRejected) { "Old state decrypted after its Keystore key was deleted" }

        // Even if a fresh key is later created under the same alias, AES-GCM must reject
        // ciphertext authenticated by the destroyed key.
        val replacementState = SessionStateCipher.encrypt(sessionId, replacementPlaintext)
        check(SessionStateCipher.decrypt(sessionId, replacementState).contentEquals(replacementPlaintext))

        var oldCiphertextRejectedByReplacementKey = false
        try {
            SessionStateCipher.decrypt(sessionId, oldState)
        } catch (_: GeneralSecurityException) {
            oldCiphertextRejectedByReplacementKey = true
        }
        check(oldCiphertextRejectedByReplacementKey) {
            "Old state unexpectedly decrypted with a replacement Keystore key"
        }

        check(SessionStateCipher.destroy(sessionId))
        check(!SessionStateCipher.hasKey(sessionId))
    }
}
