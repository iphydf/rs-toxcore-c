// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 The TokTok team.

package chat.tox.toxxi

import android.app.Application
import android.content.Intent
import kotlin.system.exitProcess

/** Connects toxxi to what outlives the activity: notifications and the service. */
class ToxxiApp : Application() {
    lateinit var messages: Messages
        private set

    override fun onCreate() {
        super.onCreate()
        messages = Messages(this)
        Toxxi.messageListener = messages::add
        Toxxi.exitListener = {
            // toxxi saved everything; nothing else in the process needs to end cleanly.
            stopService(Intent(this, ToxxiService::class.java))
            exitProcess(0)
        }
    }
}
