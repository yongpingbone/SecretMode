package com.yongpingbone.secretmode

import android.app.Activity
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView

class BubbleActivity : Activity() {
    private lateinit var composer: EditText
    private lateinit var privateContent: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        // Deliberately do not restore Android hierarchy/SavedState for private surfaces.
        super.onCreate(null)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        setContentView(buildSecureUi())
    }

    override fun onSaveInstanceState(outState: Bundle) {
        // Deliberately skip super: private plaintext must never enter the hierarchy state Bundle.
        outState.clear()
    }

    override fun onStop() {
        clearSensitiveUi()
        super.onStop()
    }

    override fun onDestroy() {
        clearSensitiveUi()
        super.onDestroy()
    }

    private fun buildSecureUi(): View {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(18), dp(18), dp(18), dp(14))
            setBackgroundColor(Color.rgb(17, 19, 24))
            isSaveEnabled = false
            isSaveFromParentEnabled = false
            importantForContentCapture = View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
            if (Build.VERSION.SDK_INT >= 35) {
                setContentSensitivity(View.CONTENT_SENSITIVITY_SENSITIVE)
            }
        }

        root.addView(text("🔐 SecretMode", 18, true))
        root.addView(text("M0 private surface · no real messages yet", 12, false).apply {
            setTextColor(Color.rgb(170, 177, 197))
            setPadding(0, dp(4), 0, dp(14))
        })

        privateContent = text(
            "Crypto is intentionally gated. This surface exists to validate Bubble lifecycle and secure UI behavior before real plaintext is allowed.",
            15,
            false
        ).apply {
            isSaveEnabled = false
            isSaveFromParentEnabled = false
            setPadding(0, dp(16), 0, dp(16))
        }
        root.addView(privateContent, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            0,
            1f
        ))

        composer = EditText(this).apply {
            hint = "Private draft (M0 only)"
            setTextColor(Color.WHITE)
            setHintTextColor(Color.rgb(130, 137, 157))
            setBackgroundColor(Color.rgb(31, 35, 44))
            setPadding(dp(12), dp(8), dp(12), dp(8))
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
            imeOptions = EditorInfo.IME_ACTION_SEND or EditorInfo.IME_FLAG_NO_EXTRACT_UI
            maxLines = 4
            isSaveEnabled = false
            isSaveFromParentEnabled = false
            importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO
            importantForContentCapture = View.IMPORTANT_FOR_CONTENT_CAPTURE_NO
        }
        root.addView(composer, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(54)
        ))

        root.addView(Button(this).apply {
            text = "Crypto gate not passed"
            isAllCaps = false
            isEnabled = false
            gravity = Gravity.CENTER
            isSaveEnabled = false
        }, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(52)
        ).apply { topMargin = dp(8) })

        return root
    }

    private fun clearSensitiveUi() {
        if (::composer.isInitialized) composer.text?.clear()
        if (::privateContent.isInitialized) privateContent.text = "Private content hidden"
    }

    private fun text(value: String, size: Int, bold: Boolean): TextView = TextView(this).apply {
        text = value
        textSize = size.toFloat()
        setTextColor(Color.WHITE)
        if (bold) setTypeface(typeface, android.graphics.Typeface.BOLD)
        isSaveEnabled = false
        isSaveFromParentEnabled = false
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
}
