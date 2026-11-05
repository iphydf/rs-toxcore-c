// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 The TokTok team.

package chat.tox.toxxi

/** toxxi runs in this process on its own thread and draws on a screen we copy (src/lib.rs). */
object Toxxi {
    init {
        System.loadLibrary("toxxi_android")
    }

    /** A cell's look is its foreground and background as ARGB, then its style (screen.rs). */
    const val LOOK_INTS = 3

    // Style flags, as in screen.rs. The cell's width in columns is above them.
    const val BOLD = 1
    const val ITALIC = 2
    const val UNDERLINE = 4
    const val CROSSED_OUT = 8
    const val CURSOR = 16
    const val WIDTH_SHIFT = 8

    // Keys that aren't characters, as in lib.rs' key_code.
    const val ENTER = -1
    const val BACKSPACE = -2
    const val DELETE = -3
    const val TAB = -4
    const val BACK_TAB = -5
    const val ESC = -6
    const val UP = -7
    const val DOWN = -8
    const val LEFT = -9
    const val RIGHT = -10
    const val HOME = -11
    const val END = -12
    const val PAGE_UP = -13
    const val PAGE_DOWN = -14
    const val INSERT = -15

    /** F1 to F12 are F1 - 1 to F1 - 11. */
    const val F1 = -21

    // Modifiers, as crossterm's KeyModifiers.
    const val SHIFT = 1
    const val CTRL = 2
    const val ALT = 4

    /** toxxi drew a new frame. Called on toxxi's thread. */
    @Volatile
    var screenListener: (() -> Unit)? = null

    /** A friend wrote, or someone in a group mentioned us. Called on toxxi's thread. */
    @Volatile
    var messageListener: ((chat: String, title: String, text: String) -> Unit)? = null

    /**
     * Whether toxxi's input line is a chat message, which the keyboard may correct, rather than
     * something to type exactly: a command, a chat's name or a key.
     */
    @Volatile
    var writingMessage = false
        private set

    /** writingMessage changed. Called on toxxi's thread. */
    @Volatile
    var writingListener: (() -> Unit)? = null

    /** toxxi quit and saved everything. Called on toxxi's thread. */
    @Volatile
    var exitListener: (() -> Unit)? = null

    // Called from lib.rs. These must return void, or JNI won't find them.

    @JvmStatic
    @Suppress("unused")
    private fun onScreenChanged() {
        screenListener?.invoke()
    }

    @JvmStatic
    @Suppress("unused")
    private fun onMessage(chat: String, title: String, text: String) {
        messageListener?.invoke(chat, title, text)
    }

    @JvmStatic
    @Suppress("unused")
    private fun onWriting(message: Boolean) {
        writingMessage = message
        writingListener?.invoke()
    }

    @JvmStatic
    @Suppress("unused")
    private fun onExit() {
        exitListener?.invoke()
    }

    /**
     * Starts toxxi once per process, with its profile and settings in files. Later calls do nothing
     * and return false.
     */
    @JvmStatic
    external fun start(files: String, downloads: String, pictures: String, rows: Int, cols: Int): Boolean

    @JvmStatic
    external fun resize(rows: Int, cols: Int)

    /** Presses a key: a character's code point, or one of the keys above, with modifiers. */
    @JvmStatic
    external fun key(code: Int, modifiers: Int)

    /** Scrolls the chat lines down, or up if lines is negative. */
    @JvmStatic
    external fun scroll(lines: Int)

    /** Shows the chat a message notification was about (onMessage's chat). */
    @JvmStatic
    external fun show(chat: String)

    /** Asks toxxi to save everything now: Android may end the app without warning. */
    @JvmStatic
    external fun save()

    /**
     * Copies the screen as a rows × cols grid: each cell's look into looks (LOOK_INTS per cell) and
     * where its text starts in the returned string into starts, with the string's length last.
     */
    @JvmStatic
    external fun snapshot(rows: Int, cols: Int, looks: IntArray, starts: IntArray): String?
}
