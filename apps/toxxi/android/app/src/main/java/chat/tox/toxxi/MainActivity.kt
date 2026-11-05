// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 The TokTok team.

package chat.tox.toxxi

import android.Manifest
import android.app.Activity
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.util.TypedValue
import android.view.Gravity
import android.view.KeyEvent
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.LinearLayout.LayoutParams.MATCH_PARENT
import android.widget.LinearLayout.LayoutParams.WRAP_CONTENT

/** Shows toxxi with a row of keys that phone keyboards don't have. */
class MainActivity : Activity() {
    private lateinit var terminal: TerminalView
    private var ctrlLatched = false

    private val messages get() = (application as ToxxiApp).messages

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        terminal = TerminalView(this)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(0xff000000.toInt())
            addView(terminal, LinearLayout.LayoutParams(MATCH_PARENT, 0, 1f))
            addView(extraKeys(), LinearLayout.LayoutParams(MATCH_PARENT, WRAP_CONTENT))
        }
        setContentView(root)
        root.keepClearOfBars()

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            requestPermissions(arrayOf(Manifest.permission.POST_NOTIFICATIONS), 0)
        }

        startForegroundService(Intent(this, ToxxiService::class.java))
        showChat(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        showChat(intent)
    }

    private fun showChat(intent: Intent) = intent.getStringExtra(CHAT)?.let(Toxxi::show)

    override fun onResume() {
        super.onResume()
        messages.seen = true
        terminal.requestFocus()
    }

    override fun onPause() {
        messages.seen = false
        super.onPause()
    }

    override fun onStop() {
        Toxxi.save()
        super.onStop()
    }

    override fun onKeyDown(keyCode: Int, event: KeyEvent): Boolean {
        val step = textSizeStep(keyCode)

        if (step == 0) {
            return super.onKeyDown(keyCode, event)
        }

        terminal.stepTextSize(step)
        return true
    }

    override fun onKeyUp(keyCode: Int, event: KeyEvent) =
        textSizeStep(keyCode) != 0 || super.onKeyUp(keyCode, event)

    /** The volume keys change the text size: toxxi makes no sound. */
    private fun textSizeStep(keyCode: Int) = when (keyCode) {
        KeyEvent.KEYCODE_VOLUME_UP -> 1
        KeyEvent.KEYCODE_VOLUME_DOWN -> -1
        else -> 0
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        // Keep toxxi running. Only /quit stops it.
        moveTaskToBack(true)
    }

    private fun extraKeys(): View {
        lateinit var ctrl: Button
        ctrl = key("Ctrl") {
            ctrlLatched = !ctrlLatched
            ctrl.setTextColor(if (ctrlLatched) KEY_LATCHED_FG else KEY_FG)
            terminal.setCtrlLatched(ctrlLatched) {
                ctrlLatched = false
                ctrl.setTextColor(KEY_FG)
            }
        }

        return keyRow(
            pressing("Esc", Toxxi.ESC),
            ctrl,
            pressing("Tab", Toxxi.TAB),
            // toxxi's keys for the chat list and the previous and next chat.
            pressing("Chats", ' '.code, Toxxi.CTRL),
            pressing("◀", 'p'.code, Toxxi.CTRL),
            pressing("▶", 'n'.code, Toxxi.CTRL),
            pressing("↑", Toxxi.UP),
            pressing("↓", Toxxi.DOWN),
            pressing("PgUp", Toxxi.PAGE_UP),
            pressing("PgDn", Toxxi.PAGE_DOWN),
        )
    }

    private fun keyRow(vararg keys: Button) = LinearLayout(this).apply {
        setBackgroundColor(KEYS_BG)
        gravity = Gravity.CENTER_VERTICAL

        for (key in keys) {
            addView(key, LinearLayout.LayoutParams(0, WRAP_CONTENT, 1f))
        }
    }

    private fun pressing(label: String, code: Int, modifiers: Int = 0) =
        key(label) { terminal.press(code, modifiers) }

    private fun key(label: String, onClick: () -> Unit) =
        Button(this, null, android.R.attr.borderlessButtonStyle).apply {
            text = label
            isAllCaps = false
            setTextColor(KEY_FG)
            setTextSize(TypedValue.COMPLEX_UNIT_SP, 13f)
            minWidth = 0
            minimumWidth = 0
            setPadding(0, 0, 0, 0)
            setOnClickListener { onClick() }
        }

    companion object {
        private const val KEYS_BG = 0xff202020.toInt()
        private const val KEY_FG = 0xffd0d0d0.toInt()
        private const val KEY_LATCHED_FG = 0xff6fbf6f.toInt()

        private const val CHAT = "chat"

        /** Opens the app on a chat, or where it was if chat is null. */
        fun opening(context: Context, chat: String?): PendingIntent = PendingIntent.getActivity(context,
            chat.hashCode(), Intent(context, MainActivity::class.java).putExtra(CHAT, chat),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
    }
}
