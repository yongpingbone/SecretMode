package com.yongpingbone.secretmode.verification

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Gravity
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.google.android.gms.mlkit.barcode.GmsBarcodeScannerOptions
import com.google.android.gms.mlkit.barcode.GmsBarcodeScanning
import com.google.mlkit.vision.barcode.common.Barcode
import com.yongpingbone.secretmode.crypto.HumanVerificationMethod

class FinalVerificationActivity : Activity() {
    private val handler = Handler(Looper.getMainLooper())
    private var token: String? = null
    private var entry: FinalVerificationSessionRegistry.Entry? = null
    private var statusLabel: TextView? = null
    private var scanButton: Button? = null
    private var confirmButton: Button? = null
    private var transientMessage: String? = null

    private val refreshRunnable = object : Runnable {
        override fun run() {
            refreshStatus()
            handler.postDelayed(this, STATUS_REFRESH_MS)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)

        token = intent.getStringExtra(EXTRA_SESSION_TOKEN)
        entry = token?.takeIf { it.isNotBlank() }?.let(FinalVerificationSessionRegistry::get)
        if (entry == null) {
            renderExpiredSession()
            return
        }
        renderVerification()
    }

    override fun onStart() {
        super.onStart()
        if (entry != null) {
            handler.post(refreshRunnable)
        }
    }

    override fun onStop() {
        handler.removeCallbacks(refreshRunnable)
        super.onStop()
    }

    private fun renderVerification() {
        val verificationEntry = checkNotNull(entry)
        val session = verificationEntry.session
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(24), dp(30), dp(24), dp(30))
            setBackgroundColor(Color.rgb(17, 19, 24))
        }

        content.addView(label("Final pairing verification", 26, true))
        content.addView(label(
            "Verify in person before this pairing can become VERIFIED.",
            14,
            false,
        ).apply {
            setTextColor(Color.rgb(182, 188, 205))
            setPadding(0, dp(8), 0, dp(18))
        })

        content.addView(label("Show this QR to your peer", 17, true).apply {
            setPadding(0, 0, 0, dp(10))
        })

        val qrSize = minOf(dp(280), resources.displayMetrics.widthPixels - dp(56))
        val qrImage = ImageView(this).apply {
            setImageBitmap(FinalVerificationQrRenderer.render(session.qrPayload(), qrSize))
            contentDescription = "Final pairing verification QR code"
            adjustViewBounds = true
            layoutParams = LinearLayout.LayoutParams(qrSize, qrSize)
            setBackgroundColor(Color.WHITE)
        }
        content.addView(qrImage)

        content.addView(label(
            "The QR binds the pairing ID to the final transcript digest. It does not contain private message text.",
            12,
            false,
        ).apply {
            setTextColor(Color.rgb(160, 168, 190))
            setPadding(0, dp(12), 0, dp(18))
        })

        scanButton = button("Scan peer verification QR") {
            startQrScan()
        }.also(content::addView)

        confirmButton = button("Confirm peer in person") {
            confirmPeer()
        }.also(content::addView)

        statusLabel = label("", 14, true).apply {
            setPadding(0, dp(22), 0, 0)
        }.also(content::addView)

        content.addView(label(
            "VERIFIED requires two different pairing roles: one valid QR-scan acknowledgment and one valid in-person peer confirmation. Closing or losing this process-local session fails closed.",
            12,
            false,
        ).apply {
            setTextColor(Color.rgb(160, 168, 190))
            setPadding(0, dp(18), 0, 0)
        })

        setContentView(ScrollView(this).apply {
            isFillViewport = true
            addView(content, ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT,
            ))
        })
        refreshStatus()
    }

    private fun startQrScan() {
        val verificationEntry = entry ?: return
        scanButton?.isEnabled = false
        transientMessage = "Opening secure QR scanner..."
        refreshStatus()

        val options = GmsBarcodeScannerOptions.Builder()
            .setBarcodeFormats(Barcode.FORMAT_QR_CODE)
            .build()
        GmsBarcodeScanning.getClient(this, options)
            .startScan()
            .addOnSuccessListener { barcode ->
                val raw = barcode.rawValue
                if (raw.isNullOrEmpty()) {
                    transientMessage = "That QR did not contain a readable verification payload."
                } else {
                    processScannedPayload(verificationEntry, raw)
                }
                refreshStatus()
            }
            .addOnCanceledListener {
                transientMessage = "QR scan canceled."
                refreshStatus()
            }
            .addOnFailureListener {
                transientMessage = "QR scanner unavailable. Check Google Play services and try again."
                refreshStatus()
            }
    }

    private fun processScannedPayload(
        verificationEntry: FinalVerificationSessionRegistry.Entry,
        rawValue: String,
    ) {
        try {
            val acknowledgment = verificationEntry.session.acknowledgeScannedQr(
                encodedQr = rawValue,
                verifiedAtMs = System.currentTimeMillis(),
            )
            verificationEntry.publishLocalAcknowledgment(acknowledgment)
            transientMessage = "Peer QR matched the final transcript. Signed acknowledgment queued."
        } catch (_: IllegalArgumentException) {
            transientMessage = "Verification failed: this QR does not match the active pairing."
        } catch (_: IllegalStateException) {
            transientMessage = "Verification acknowledgment could not be queued. Try again."
        }
    }

    private fun confirmPeer() {
        val verificationEntry = entry ?: return
        try {
            val acknowledgment = verificationEntry.session.confirmPeerInPerson(System.currentTimeMillis())
            verificationEntry.publishLocalAcknowledgment(acknowledgment)
            transientMessage = "In-person peer confirmation signed and queued."
        } catch (_: IllegalArgumentException) {
            transientMessage = "This pairing is no longer active. Return to pairing and start again."
        } catch (_: IllegalStateException) {
            transientMessage = "Verification acknowledgment could not be queued. Try again."
        }
        refreshStatus()
    }

    private fun refreshStatus() {
        val session = entry?.session ?: return
        val verified = session.isVerified()
        scanButton?.isEnabled = !verified
        confirmButton?.isEnabled = !verified

        val state = if (verified) {
            "VERIFIED ✓\nBoth role-separated human acknowledgments are valid."
        } else {
            buildString {
                append("Waiting for role-separated acknowledgments")
                append("\nLocal QR scan: ")
                append(if (session.hasLocalAcknowledgment(HumanVerificationMethod.IN_PERSON_QR_SCAN)) "✓" else "pending")
                append(" · Local peer confirm: ")
                append(if (session.hasLocalAcknowledgment(HumanVerificationMethod.IN_PERSON_PEER_CONFIRM)) "✓" else "pending")
                append("\nRemote QR scan: ")
                append(if (session.hasRemoteAcknowledgment(HumanVerificationMethod.IN_PERSON_QR_SCAN)) "✓" else "pending")
                append(" · Remote peer confirm: ")
                append(if (session.hasRemoteAcknowledgment(HumanVerificationMethod.IN_PERSON_PEER_CONFIRM)) "✓" else "pending")
            }
        }
        val message = transientMessage
        statusLabel?.text = if (message.isNullOrBlank()) state else "$state\n\n$message"
        statusLabel?.setTextColor(
            if (verified) Color.rgb(119, 221, 151) else Color.WHITE,
        )
    }

    private fun renderExpiredSession() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(24), dp(48), dp(24), dp(24))
            setBackgroundColor(Color.rgb(17, 19, 24))
        }
        root.addView(label("Verification session unavailable", 24, true))
        root.addView(label(
            "SecretMode does not restore final verification material from saved state. Return to pairing and create a fresh verification session.",
            14,
            false,
        ).apply {
            setTextColor(Color.rgb(182, 188, 205))
            setPadding(0, dp(14), 0, dp(20))
        })
        root.addView(button("Close") { finish() })
        setContentView(root)
    }

    private fun button(text: String, action: () -> Unit): Button = Button(this).apply {
        this.text = text
        isAllCaps = false
        textSize = 16f
        setOnClickListener { action() }
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(54),
        ).apply { topMargin = dp(10) }
    }

    private fun label(value: String, size: Int, bold: Boolean): TextView = TextView(this).apply {
        text = value
        textSize = size.toFloat()
        setTextColor(Color.WHITE)
        if (bold) setTypeface(typeface, android.graphics.Typeface.BOLD)
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    companion object {
        private const val EXTRA_SESSION_TOKEN = "final_verification_session_token"
        private const val STATUS_REFRESH_MS = 750L

        fun createIntent(context: Context, sessionToken: String): Intent {
            require(sessionToken.isNotBlank()) { "final verification session token must not be blank" }
            return Intent(context, FinalVerificationActivity::class.java)
                .putExtra(EXTRA_SESSION_TOKEN, sessionToken)
        }
    }
}
