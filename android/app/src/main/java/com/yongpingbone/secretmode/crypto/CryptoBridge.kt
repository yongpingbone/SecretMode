package com.yongpingbone.secretmode.crypto

/**
 * JNI boundary for the M0 crypto spike.
 *
 * The Android app does not load or call this library in production paths yet.
 * Native packaging is enabled only after the host-side vodozemac tests and
 * Android ABI build checks pass.
 */
object CryptoBridge {
    external fun nativeProbe(): String
}
