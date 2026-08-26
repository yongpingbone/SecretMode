package com.yongpingbone.secretmode

import android.app.Activity
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Person
import android.content.Context
import android.content.Intent
import android.content.pm.ShortcutInfo
import android.content.pm.ShortcutManager
import android.graphics.drawable.Icon
import android.os.Build

object BubbleController {
    const val CHANNEL_ID = "secretmode_private_sessions"
    private const val NOTIFICATION_ID = 1001
    private const val SHORTCUT_ID = "secretmode_private_session_demo"

    data class Capability(
        val notificationsEnabled: Boolean,
        val channelCanBubble: Boolean,
        val appCanBubble: Boolean
    ) {
        val usable: Boolean
            get() = notificationsEnabled && channelCanBubble && appCanBubble
    }

    fun ensureChannel(context: Context) {
        val manager = context.getSystemService(NotificationManager::class.java)
        val existing = manager.getNotificationChannel(CHANNEL_ID)
        if (existing != null) return

        val channel = NotificationChannel(
            CHANNEL_ID,
            "Private sessions",
            NotificationManager.IMPORTANCE_DEFAULT
        ).apply {
            description = "Opaque private-session notifications. Message plaintext is never placed here."
            setAllowBubbles(true)
        }
        manager.createNotificationChannel(channel)
    }

    fun capability(context: Context): Capability {
        ensureChannel(context)
        val manager = context.getSystemService(NotificationManager::class.java)
        val channel = manager.getNotificationChannel(CHANNEL_ID)
        val appCanBubble = if (Build.VERSION.SDK_INT >= 31) manager.areBubblesAllowed() else true
        return Capability(
            notificationsEnabled = manager.areNotificationsEnabled(),
            channelCanBubble = channel?.canBubble() == true,
            appCanBubble = appCanBubble
        )
    }

    fun launchOrFallback(activity: Activity) {
        if (!postBubble(activity, autoExpand = true)) {
            activity.startActivity(Intent(activity, BubbleActivity::class.java))
        }
    }

    fun postBubble(context: Context, autoExpand: Boolean): Boolean {
        ensureChannel(context)
        if (!capability(context).notificationsEnabled) return false

        val person = Person.Builder()
            .setKey("private-peer-demo")
            .setName("Private session")
            .setImportant(true)
            .build()

        publishConversationShortcut(context, person)

        val bubbleIntent = PendingIntent.getActivity(
            context,
            41,
            Intent(context, BubbleActivity::class.java).apply {
                action = Intent.ACTION_VIEW
                putExtra("session_id", "m0-demo")
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
        )

        val contentIntent = PendingIntent.getActivity(
            context,
            42,
            Intent(context, BubbleActivity::class.java).apply {
                action = Intent.ACTION_VIEW
                putExtra("session_id", "m0-demo")
            },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val bubble = Notification.BubbleMetadata.Builder(
            bubbleIntent,
            Icon.createWithResource(context, R.drawable.ic_secretmode)
        )
            .setDesiredHeight(640)
            .setAutoExpandBubble(autoExpand)
            .setSuppressNotification(autoExpand)
            .build()

        val notification = Notification.Builder(context, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_secretmode)
            .setContentTitle("SecretMode")
            .setContentText("Private session available")
            .setCategory(Notification.CATEGORY_MESSAGE)
            .setOnlyAlertOnce(true)
            .setContentIntent(contentIntent)
            .setShortcutId(SHORTCUT_ID)
            .addPerson(person)
            .setBubbleMetadata(bubble)
            .build()

        context.getSystemService(NotificationManager::class.java)
            .notify(NOTIFICATION_ID, notification)

        // Posting can succeed even when the user has chosen not to float bubbles.
        // In that case Android intentionally presents a normal notification instead.
        return true
    }

    private fun publishConversationShortcut(context: Context, person: Person) {
        val shortcutManager = context.getSystemService(ShortcutManager::class.java)
        val shortcut = ShortcutInfo.Builder(context, SHORTCUT_ID)
            .setShortLabel("Private session")
            .setLongLabel("Open private SecretMode session")
            .setLongLived(true)
            .setIcon(Icon.createWithResource(context, R.drawable.ic_secretmode))
            .setPersons(arrayOf(person))
            .setIntent(Intent(context, BubbleActivity::class.java).apply {
                action = Intent.ACTION_VIEW
                putExtra("session_id", "m0-demo")
            })
            .build()
        shortcutManager.addDynamicShortcuts(listOf(shortcut))
    }
}
