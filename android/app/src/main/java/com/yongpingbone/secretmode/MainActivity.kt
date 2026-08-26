package com.yongpingbone.secretmode

import android.Manifest
import android.app.Activity
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.Gravity
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView

class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        BubbleController.ensureChannel(this)
        requestNotificationsIfNeeded()
        render()
    }

    override fun onResume() {
        super.onResume()
        render()
    }

    private fun render() {
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER_HORIZONTAL
            setPadding(dp(24), dp(36), dp(24), dp(24))
            setBackgroundColor(Color.rgb(17, 19, 24))
        }

        root.addView(label("SecretMode", 28, true))
        root.addView(label("M0 · Foundation / Crypto Spike", 14, false).apply {
            setTextColor(Color.rgb(170, 177, 197))
            setPadding(0, dp(8), 0, dp(28))
        })

        val capability = BubbleController.capability(this)
        val status = when {
            !capability.notificationsEnabled -> "Notifications disabled · Bubble unavailable"
            capability.usable -> "Bubble ready"
            else -> "Bubble supported · user/OEM setting may still block floating display"
        }
        root.addView(label(status, 16, true).apply {
            setPadding(0, 0, 0, dp(18))
        })

        root.addView(button("Open private session") {
            BubbleController.launchOrFallback(this)
        })

        root.addView(button("Notification / Bubble settings") {
            openNotificationSettings()
        })

        root.addView(label(
            "Security baseline: no AccessibilityService, no SYSTEM_ALERT_WINDOW, no plaintext notification payloads, and no private plaintext in Android saved state.",
            13,
            false
        ).apply {
            setTextColor(Color.rgb(170, 177, 197))
            setPadding(0, dp(28), 0, 0)
        })

        setContentView(root)
    }

    private fun requestNotificationsIfNeeded() {
        if (Build.VERSION.SDK_INT >= 33 &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 700)
        }
    }

    private fun openNotificationSettings() {
        val intent = Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).apply {
            putExtra(Settings.EXTRA_APP_PACKAGE, packageName)
            data = Uri.parse("package:$packageName")
        }
        startActivity(intent)
    }

    private fun button(text: String, action: () -> Unit): Button = Button(this).apply {
        this.text = text
        isAllCaps = false
        textSize = 16f
        setOnClickListener { action() }
        layoutParams = LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            dp(54)
        ).apply { topMargin = dp(10) }
    }

    private fun label(value: String, size: Int, bold: Boolean): TextView = TextView(this).apply {
        text = value
        textSize = size.toFloat()
        setTextColor(Color.WHITE)
        if (bold) setTypeface(typeface, android.graphics.Typeface.BOLD)
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()
}
