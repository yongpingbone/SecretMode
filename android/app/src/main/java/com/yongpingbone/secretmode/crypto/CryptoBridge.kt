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
    fun loadForM0Probe(): String {
        if (!loaded) {
            System.loadLibrary(LIBRARY_NAME)
            loaded = true
        }
        return nativeProbe()
    }

    private external fun nativeProbe(): String
}
