// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 The TokTok team.

package chat.tox.toxxi

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Person
import android.content.Context

/**
 * Shows notifications of the messages toxxi tells us about while the app isn't in front: one per
 * chat, with its messages since it was last seen.
 */
class Messages(private val context: Context) {
    private val notifications = context.getSystemService(NotificationManager::class.java)
    private val unseen = mutableMapOf<String, MutableList<Pair<String, Long>>>()

    /** Whether the user is looking at toxxi, so needs no notifications. */
    @Volatile
    var seen = false
        set(value) {
            field = value
            if (value) clear()
        }

    init {
        notifications.createNotificationChannel(
            NotificationChannel(CHANNEL, context.getString(R.string.messages_channel),
                NotificationManager.IMPORTANCE_HIGH))
    }

    @Synchronized
    fun add(chat: String, title: String, text: String) {
        if (seen) {
            return
        }

        val messages = unseen.getOrPut(chat, ::mutableListOf)
        messages += text to System.currentTimeMillis()
        val sender = Person.Builder().setName(title).build()
        val style = Notification.MessagingStyle(Person.Builder().setName("").build())

        for ((message, time) in messages.takeLast(MAX_LINES)) {
            style.addMessage(message, time, sender)
        }

        val notification = Notification.Builder(context, CHANNEL)
            .setSmallIcon(R.drawable.ic_notification)
            .setStyle(style)
            .setContentIntent(MainActivity.opening(context, chat))
            .setAutoCancel(true)
            .setCategory(Notification.CATEGORY_MESSAGE)
            .build()
        notifications.notify(chat, NOTIFICATION, notification)
    }

    @Synchronized
    private fun clear() {
        for (chat in unseen.keys) {
            notifications.cancel(chat, NOTIFICATION)
        }

        unseen.clear()
    }

    private companion object {
        const val CHANNEL = "messages"
        const val NOTIFICATION = 2
        const val MAX_LINES = 8
    }
}
