package com.yongpingbone.secretmode.crypto

/**
 * JNI boundary for the M0 crypto spike.
 *
 * No product messaging path may depend on this until the M0 crypto gate passes.
 */
object CryptoBridge {
    private const val LIBRARY_NAME = "secretmode_crypto_spike"

    @Volatile
    private var loaded = false

    @Synchronized
    private fun ensureLoaded() {
        if (!loaded) {
            System.loadLibrary(LIBRARY_NAME)
            loaded = true
        }
    }

    fun loadForM0Probe(): String {
        ensureLoaded()
        return nativeProbe()
    }

    fun createM0OlmPickleBundle(): ByteArray {
        ensureLoaded()
        return nativeCreateOlmPickleBundle()
    }

    fun validateM0OlmPickleBundle(bundle: ByteArray): String {
        ensureLoaded()
        return nativeValidateOlmPickleBundle(bundle)
    }

    private external fun nativeProbe(): String
    private external fun nativeCreateOlmPickleBundle(): ByteArray
    private external fun nativeValidateOlmPickleBundle(bundle: ByteArray): String
}
