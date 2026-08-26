package com.yongpingbone.secretmode.crypto

import android.app.Activity
import android.app.Instrumentation
import android.os.Bundle

/**
 * M0-only instrumentation entrypoint.
 *
 * This does not test product messaging. It proves that an Android process can
 * load the packaged Rust library, resolve the JNI symbol, enter Rust code, and
 * return the pinned vodozemac version to Kotlin.
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
            result.putString("secretmode_result", "ok")
            result.putString("probe", probe)
            finish(Activity.RESULT_OK, result)
        } catch (t: Throwable) {
            result.putString("secretmode_result", "failure")
            result.putString("error_type", t.javaClass.name)
            result.putString("error_message", t.message ?: "unknown")
            finish(Activity.RESULT_CANCELED, result)
        }
    }
}
