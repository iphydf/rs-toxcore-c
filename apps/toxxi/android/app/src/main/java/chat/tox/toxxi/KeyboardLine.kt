// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 The TokTok team.

package chat.tox.toxxi

import android.text.Editable
import android.text.Selection
import android.text.Spanned
import android.text.TextWatcher

/**
 * Holds what the on-screen keyboard typed on toxxi's input line since the last reset. The keyboard
 * edits it like a text field, so it can suggest, correct and swipe, and we pass every change on.
 *
 * @param type gets text to type into toxxi.
 * @param backspace gets how many characters to delete before toxxi's cursor.
 */
class KeyboardLine(type: (String) -> Unit, backspace: (Int) -> Unit) {
    val text: Editable = Editable.Factory.getInstance().newEditable("")

    /** The line as toxxi has it. */
    private var typed = ""

    init {
        text.setSpan(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence, start: Int, count: Int, after: Int) {}

            override fun onTextChanged(s: CharSequence, start: Int, before: Int, count: Int) {}

            /**
             * Makes toxxi's line match: a backspace for each character after the first difference,
             * then the rest. This assumes toxxi's cursor is at the end of the line.
             */
            override fun afterTextChanged(s: Editable) {
                val now = text.toString()
                // commonPrefixWith doesn't split a surrogate pair.
                val same = now.commonPrefixWith(typed).length
                val deleted = typed.codePointCount(same, typed.length)
                typed = now

                if (deleted > 0) backspace(deleted)
                if (same < now.length) type(now.substring(same))
            }
        }, 0, 0, Spanned.SPAN_INCLUSIVE_INCLUSIVE)
    }

    fun isEmpty() = text.isEmpty()

    /** Forgets the line. Call this when something other than the keyboard changed toxxi's line. */
    fun reset() {
        typed = ""
        text.clear()
        Selection.setSelection(text, 0)
    }
}
