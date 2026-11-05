// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright © 2026 The TokTok team.

package chat.tox.toxxi

import android.content.Context
import android.graphics.Canvas
import android.graphics.Paint
import android.graphics.Typeface
import android.icu.text.Normalizer2
import android.text.InputType
import android.text.Selection
import android.util.TypedValue
import android.view.GestureDetector
import android.view.KeyCharacterMap
import android.view.KeyEvent
import android.view.MotionEvent
import android.view.ScaleGestureDetector
import android.view.View
import android.view.inputmethod.BaseInputConnection
import android.view.inputmethod.EditorInfo
import android.view.inputmethod.InputConnection
import android.view.inputmethod.InputMethodManager
import android.widget.OverScroller
import kotlin.math.ceil
import kotlin.math.roundToInt

/** Draws toxxi's screen and types into it. */
class TerminalView(context: Context) : View(context) {
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply { typeface = Typeface.MONOSPACE }
    private val fill = Paint()
    private val sizeLabel = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        typeface = Typeface.MONOSPACE
        color = SIZE_FG
        textSize = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_SP, SIZE_TEXT_SP, resources.displayMetrics)
    }
    private val composed = Normalizer2.getNFCInstance()
    private val imm get() = context.getSystemService(InputMethodManager::class.java)
    private val preferences get() = context.getSharedPreferences(PREFERENCES, Context.MODE_PRIVATE)

    private var textSizeSp = preferences.getFloat(TEXT_SIZE, DEFAULT_TEXT_SP)
    private var textSize = 0f
    private var cellWidth = 0f
    private var cellHeight = 0f
    private var baseline = 0f

    /** How far below the baseline the middle of the font's glyphs is (negative: above). */
    private var glyphMiddle = 0f
    private var rows = 0
    private var cols = 0
    private var looks = IntArray(0)
    private var starts = IntArray(1)

    /** How far a drag went past the last whole line it scrolled. */
    private var scrolled = 0f
    private val flinger = OverScroller(context)
    private var flungTo = 0

    /** True for a second after the text size changes, to show the grid's size. */
    private var sizeShown = false
    private val hideSize = Runnable {
        sizeShown = false
        invalidate()
    }

    private val keyboardLine = KeyboardLine(::typeText) { repeat(it) { Toxxi.key(Toxxi.BACKSPACE, 0) } }

    /** What the keyboard was last told about the input line (Toxxi.writingMessage). */
    private var writingMessage = Toxxi.writingMessage

    /** Whether the extra keys' Ctrl applies to the next key. */
    private var ctrlLatched = false
    private var onCtrlUsed: (() -> Unit)? = null

    private val scaleDetector = ScaleGestureDetector(context, object : ScaleGestureDetector.SimpleOnScaleGestureListener() {
        override fun onScale(detector: ScaleGestureDetector): Boolean {
            setTextSizeSp(textSizeSp * detector.scaleFactor)
            return true
        }

        override fun onScaleEnd(detector: ScaleGestureDetector) = saveTextSize()
    })

    private val gestureDetector = GestureDetector(context, object : GestureDetector.SimpleOnGestureListener() {
        override fun onDown(e: MotionEvent): Boolean {
            flinger.forceFinished(true)
            return true
        }

        override fun onSingleTapUp(e: MotionEvent): Boolean {
            showKeyboard()
            return true
        }

        override fun onScroll(e1: MotionEvent?, e2: MotionEvent, dx: Float, dy: Float): Boolean {
            scrollBy(dy)
            return true
        }

        override fun onFling(e1: MotionEvent?, e2: MotionEvent, vx: Float, vy: Float): Boolean {
            flungTo = 0
            flinger.fling(0, 0, 0, -vy.toInt(), 0, 0, Int.MIN_VALUE, Int.MAX_VALUE)
            postOnAnimation(::fling)
            return true
        }
    })

    init {
        isFocusable = true
        isFocusableInTouchMode = true
        updateTextSize()
    }

    /** Scrolls the chat a line for each line's height dragged. Dragging down shows older messages. */
    private fun scrollBy(dy: Float) {
        scrolled += dy

        val lines = (scrolled / cellHeight).toInt()

        if (lines != 0) {
            Toxxi.scroll(lines)
            scrolled -= lines * cellHeight
        }
    }

    private fun fling() {
        if (!flinger.computeScrollOffset()) {
            return
        }

        scrollBy((flinger.currY - flungTo).toFloat())
        flungTo = flinger.currY
        postOnAnimation(::fling)
    }

    fun setCtrlLatched(latched: Boolean, onUsed: () -> Unit) {
        ctrlLatched = latched
        onCtrlUsed = onUsed
    }

    fun showKeyboard() {
        requestFocus()
        imm.showSoftInput(this, InputMethodManager.SHOW_IMPLICIT)
    }

    /** Presses a key that isn't a character, or a character with Ctrl if it's latched. */
    fun press(code: Int, modifiers: Int = 0) {
        var mods = modifiers

        if (ctrlLatched) {
            mods = mods or Toxxi.CTRL
            ctrlLatched = false
            onCtrlUsed?.invoke()
        }

        // toxxi's input line may change now, so the keyboard's copy is out of date.
        forgetKeyboardLine()
        Toxxi.key(code, mods)
    }

    private fun forgetKeyboardLine() {
        if (!keyboardLine.isEmpty()) {
            keyboardLine.reset()
            post { imm.restartInput(this) }
        }
    }

    /** Types text the keyboard committed, a key per code point. */
    private fun typeText(text: String) = text.codePoints().forEach { Toxxi.key(it, 0) }

    /** Tells the keyboard where the cursor and the word it's composing are, as text fields do. */
    private fun reportSelection() {
        val line = keyboardLine.text
        imm.updateSelection(this, Selection.getSelectionStart(line), Selection.getSelectionEnd(line),
            BaseInputConnection.getComposingSpanStart(line), BaseInputConnection.getComposingSpanEnd(line))
    }

    /** Makes the text step sp bigger, or smaller if step is negative. */
    fun stepTextSize(step: Int) {
        setTextSizeSp(textSizeSp.roundToInt() + step.toFloat())
        saveTextSize()
    }

    private fun setTextSizeSp(sp: Float) {
        textSizeSp = sp.coerceIn(MIN_TEXT_SP, MAX_TEXT_SP)
        updateTextSize()
        sizeShown = true
        removeCallbacks(hideSize)
        postDelayed(hideSize, SIZE_SHOWN_MS)
        updateGrid()
    }

    private fun saveTextSize() = preferences.edit().putFloat(TEXT_SIZE, textSizeSp).apply()

    private fun updateTextSize() {
        textSize = TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_SP, textSizeSp, resources.displayMetrics)
        paint.textSize = textSize
        val metrics = paint.fontMetrics
        cellWidth = paint.measureText("M")
        cellHeight = ceil(metrics.descent - metrics.ascent)
        baseline = -metrics.ascent
        glyphMiddle = (metrics.ascent + metrics.descent) / 2
    }

    private fun updateGrid() {
        if (width == 0 || height == 0) {
            return
        }

        val newCols = maxOf(1, (width / cellWidth).toInt())
        val newRows = maxOf(1, (height / cellHeight).toInt())

        if (newRows == rows && newCols == cols) {
            invalidate()
            return
        }

        rows = newRows
        cols = newCols
        looks = IntArray(rows * cols * Toxxi.LOOK_INTS)
        starts = IntArray(rows * cols + 1)
        val files = context.filesDir
        val downloads = context.getExternalFilesDir(android.os.Environment.DIRECTORY_DOWNLOADS) ?: files
        val pictures = context.getExternalFilesDir(android.os.Environment.DIRECTORY_PICTURES) ?: files

        if (!Toxxi.start(files.absolutePath, downloads.absolutePath, pictures.absolutePath, rows, cols)) {
            Toxxi.resize(rows, cols)
        }

        invalidate()
    }

    override fun onAttachedToWindow() {
        super.onAttachedToWindow()
        Toxxi.screenListener = ::postInvalidate
        Toxxi.writingListener = {
            post {
                if (Toxxi.writingMessage != writingMessage) {
                    imm.restartInput(this)
                }
            }
        }
    }

    override fun onDetachedFromWindow() {
        Toxxi.screenListener = null
        Toxxi.writingListener = null
        super.onDetachedFromWindow()
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) = updateGrid()

    private fun width(cell: Int) = looks[cell * Toxxi.LOOK_INTS + 2] shr Toxxi.WIDTH_SHIFT

    override fun onDraw(canvas: Canvas) {
        canvas.drawColor(BACKGROUND)

        if (rows == 0) {
            return
        }

        val text = Toxxi.snapshot(rows, cols, looks, starts) ?: return

        for (row in 0 until rows) {
            drawBackgrounds(canvas, row)

            for (col in 0 until cols) {
                drawCell(canvas, text, row, col)
            }
        }

        if (sizeShown) {
            drawSize(canvas)
        }
    }

    /** Draws the grid's size (columns × rows) in the middle of the view. */
    private fun drawSize(canvas: Canvas) {
        val size = "$cols×$rows"
        val metrics = sizeLabel.fontMetrics
        val padding = sizeLabel.textSize / 2
        val labelWidth = sizeLabel.measureText(size)
        val x = (width - labelWidth) / 2
        val y = (height - metrics.ascent - metrics.descent) / 2
        fill.color = SIZE_BG
        canvas.drawRoundRect(x - padding, y + metrics.ascent - padding, x + labelWidth + padding,
            y + metrics.descent + padding, padding, padding, fill)
        canvas.drawText(size, x, y, sizeLabel)
    }

    /** Draws a row's backgrounds, a rectangle for each run of cells with the same one. */
    private fun drawBackgrounds(canvas: Canvas, row: Int) {
        val y = row * cellHeight
        var col = 0

        while (col < cols) {
            val bg = looks[(row * cols + col) * Toxxi.LOOK_INTS + 1]
            var end = col + 1

            while (end < cols && looks[(row * cols + end) * Toxxi.LOOK_INTS + 1] == bg) end++

            if (bg != BACKGROUND) {
                fill.color = bg
                canvas.drawRect(col * cellWidth, y, end * cellWidth, y + cellHeight, fill)
            }

            col = end
        }
    }

    /** Draws a cell's text (a grapheme cluster) across the columns it covers, in its style. */
    private fun drawCell(canvas: Canvas, text: String, row: Int, col: Int) {
        val cell = row * cols + col
        val look = cell * Toxxi.LOOK_INTS
        val style = looks[look + 2]
        val cells = style shr Toxxi.WIDTH_SHIFT
        val x = col * cellWidth
        val y = row * cellHeight
        paint.color = looks[look]

        if (style and Toxxi.CURSOR != 0) {
            // A bar before the cell, as in a text field.
            fill.color = paint.color
            canvas.drawRect(x, y, x + maxOf(2f, cellWidth / 8), y + cellHeight, fill)
        }

        val start = starts[cell]
        val end = starts[cell + 1]

        if (cells == 0 || end == start + 1 && text[start] == ' ') {
            return
        }

        paint.isFakeBoldText = style and Toxxi.BOLD != 0
        paint.textSkewX = if (style and Toxxi.ITALIC != 0) -0.25f else 0f
        paint.isUnderlineText = style and Toxxi.UNDERLINE != 0
        paint.isStrikeThruText = style and Toxxi.CROSSED_OUT != 0
        val ch = if (end == start + 1) text[start] else ' '
        val arms = boxArms(ch)
        val block = blockPart(ch)

        when {
            arms != 0 -> drawBoxLines(canvas, arms, x, y)

            block != null -> {
                fill.color = paint.color
                canvas.drawRect(x + block[0] * cellWidth, y + block[1] * cellHeight, x + block[2] * cellWidth,
                    y + block[3] * cellHeight, fill)
            }

            // Use the composed form (NFC): the monospace font has é, but not always a lone combining accent.
            Character.charCount(text.codePointAt(start)) < end - start -> {
                val cluster = composed.normalize(text.substring(start, end))
                drawFitted(canvas, cluster, 0, cluster.length, x, y, cells * cellWidth)
            }

            else -> drawFitted(canvas, text, start, end, x, y, cells * cellWidth)
        }
    }

    /**
     * Draws box lines to the cell's edges so they join the next cell's. The monospace font has no
     * box-drawing characters, and the fallback fonts' often don't join.
     */
    private fun drawBoxLines(canvas: Canvas, arms: Int, x: Float, y: Float) {
        val thickness = maxOf(1, (cellWidth / 8).roundToInt()).toFloat()
        val left = (x + (cellWidth - thickness) / 2).roundToInt().toFloat()
        val top = (y + (cellHeight - thickness) / 2).roundToInt().toFloat()
        val right = left + thickness
        val bottom = top + thickness
        fill.color = paint.color

        if (arms and LEFT != 0) canvas.drawRect(x, top, right, bottom, fill)
        if (arms and RIGHT != 0) canvas.drawRect(left, top, x + cellWidth, bottom, fill)
        if (arms and UP != 0) canvas.drawRect(left, y, right, bottom, fill)
        if (arms and DOWN != 0) canvas.drawRect(left, top, right, y + cellHeight, fill)
    }

    /** Draws text at x, y, scaled down if it's wider than width (e.g. an emoji in one cell). */
    private fun drawFitted(canvas: Canvas, text: String, start: Int, end: Int, x: Float, y: Float, width: Float) {
        // ASCII fits its cell, other characters may not.
        val natural = if (end == start + 1 && text[start].code < 0x80) 0f else paint.measureText(text, start, end)

        if (natural <= width) {
            canvas.drawText(text, start, end, x, y + baseline, paint)
            return
        }

        // Scale it down and centre it vertically.
        val scale = width / natural
        paint.textSize = textSize * scale
        canvas.drawText(text, start, end, x, y + cellHeight / 2 - scale * glyphMiddle, paint)
        paint.textSize = textSize
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        scaleDetector.onTouchEvent(event)

        if (!scaleDetector.isInProgress) {
            gestureDetector.onTouchEvent(event)
        }

        return true
    }

    override fun onCheckIsTextEditor() = true

    override fun onCreateInputConnection(outAttrs: EditorInfo): InputConnection {
        // For messages, tell the keyboard this is a message field, so it suggests, corrects and swipes.
        // Anything else it must type as is; keyboards honour "visible password" more than "no suggestions".
        writingMessage = Toxxi.writingMessage
        outAttrs.inputType = if (writingMessage) {
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_SHORT_MESSAGE or
                InputType.TYPE_TEXT_FLAG_AUTO_CORRECT or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
        } else {
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD or
                InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        }
        // Enter sends.
        outAttrs.imeOptions = EditorInfo.IME_FLAG_NO_FULLSCREEN or EditorInfo.IME_FLAG_NO_EXTRACT_UI or
            EditorInfo.IME_FLAG_NO_ENTER_ACTION or EditorInfo.IME_ACTION_NONE
        outAttrs.initialSelStart = keyboardLine.text.length
        outAttrs.initialSelEnd = keyboardLine.text.length
        return KeyboardConnection()
    }

    /** Lets the keyboard edit keyboardLine, which passes each change on to toxxi. */
    private inner class KeyboardConnection : BaseInputConnection(this@TerminalView, true) {
        private var batchDepth = 0

        override fun getEditable() = keyboardLine.text

        override fun beginBatchEdit(): Boolean {
            ++batchDepth
            return true
        }

        override fun endBatchEdit(): Boolean {
            if (batchDepth > 0 && --batchDepth == 0) {
                reportSelection()
            }

            return batchDepth > 0
        }

        override fun commitText(text: CharSequence, newCursorPosition: Int): Boolean {
            val string = text.toString()

            if (ctrlLatched && string.codePointCount(0, string.length) == 1) {
                super.finishComposingText()
                press(string.codePointAt(0))
                return true
            }

            // Each line break sends the line so far, like Enter.
            for ((i, line) in string.split('\n').withIndex()) {
                if (i > 0) press(Toxxi.ENTER)
                super.commitText(line, newCursorPosition)
            }

            return true
        }

        override fun deleteSurroundingText(beforeLength: Int, afterLength: Int): Boolean {
            // The keyboard can't see what toxxi had before its line, so send toxxi backspaces for that part.
            val known = minOf(beforeLength, Selection.getSelectionStart(keyboardLine.text))
            val done = super.deleteSurroundingText(known, afterLength)
            repeat(beforeLength - known) { Toxxi.key(Toxxi.BACKSPACE, 0) }
            return done
        }

        override fun deleteSurroundingTextInCodePoints(beforeLength: Int, afterLength: Int): Boolean {
            val line = keyboardLine.text
            val known = minOf(beforeLength, Character.codePointCount(line, 0, Selection.getSelectionStart(line)))
            val done = super.deleteSurroundingTextInCodePoints(known, afterLength)
            repeat(beforeLength - known) { Toxxi.key(Toxxi.BACKSPACE, 0) }
            return done
        }

        override fun performEditorAction(actionCode: Int): Boolean {
            press(Toxxi.ENTER)
            return true
        }
    }

    override fun onKeyDown(keyCode: Int, event: KeyEvent): Boolean {
        val modifiers = (if (event.isShiftPressed) Toxxi.SHIFT else 0) or
            (if (event.isCtrlPressed) Toxxi.CTRL else 0) or (if (event.isAltPressed) Toxxi.ALT else 0)

        specialKey(keyCode, event)?.let {
            press(it, modifiers and if (it == Toxxi.BACK_TAB) Toxxi.SHIFT.inv() else -1)
            return true
        }

        val ch = event.getUnicodeChar(event.metaState and (KeyEvent.META_CTRL_MASK or KeyEvent.META_ALT_MASK).inv())

        if (ch == 0 || ch and KeyCharacterMap.COMBINING_ACCENT != 0) {
            return super.onKeyDown(keyCode, event)
        }

        // Shift is in the character already.
        press(ch, modifiers and Toxxi.SHIFT.inv())
        return true
    }

    private companion object {
        /** Cells with this background don't need drawing: the same as screen.rs' BACKGROUND. */
        const val BACKGROUND = 0xff000000.toInt()
        const val SIZE_FG = 0xffd0d0d0.toInt()
        const val LEFT = 1
        const val RIGHT = 2
        const val UP = 4
        const val DOWN = 8
        const val MIN_TEXT_SP = 6f
        const val MAX_TEXT_SP = 40f
        const val DEFAULT_TEXT_SP = 13f
        const val SIZE_TEXT_SP = 20f
        const val SIZE_BG = 0xe0303030.toInt()
        const val SIZE_SHOWN_MS = 1000L
        const val PREFERENCES = "terminal"
        const val TEXT_SIZE = "text_size_sp"

        /**
         * Returns the lines (LEFT, RIGHT, UP, DOWN) from the middle of the cell for the box-drawing
         * characters, light and heavy, or 0 for any other character.
         */
        fun boxArms(ch: Char) = when (ch) {
            '─', '━' -> LEFT or RIGHT
            '│', '┃' -> UP or DOWN
            '┌', '┏', '╭' -> RIGHT or DOWN
            '┐', '┓', '╮' -> LEFT or DOWN
            '└', '┗', '╰' -> RIGHT or UP
            '┘', '┛', '╯' -> LEFT or UP
            '├', '┣' -> UP or DOWN or RIGHT
            '┤', '┫' -> UP or DOWN or LEFT
            '┬', '┳' -> LEFT or RIGHT or DOWN
            '┴', '┻' -> LEFT or RIGHT or UP
            '┼', '╋' -> LEFT or RIGHT or UP or DOWN
            else -> 0
        }

        /**
         * Returns the part of the cell (left, top, right, bottom, as fractions) a block element
         * fills, or null for any other character. The font's blocks don't fill whole cells.
         */
        fun blockPart(ch: Char) = when (ch) {
            '█' -> floatArrayOf(0f, 0f, 1f, 1f)
            '▀' -> floatArrayOf(0f, 0f, 1f, 0.5f)
            '▄' -> floatArrayOf(0f, 0.5f, 1f, 1f)
            '▌' -> floatArrayOf(0f, 0f, 0.5f, 1f)
            '▐' -> floatArrayOf(0.5f, 0f, 1f, 1f)
            else -> null
        }

        /** Returns toxxi's key for a key that isn't a character, or null for other keys. */
        fun specialKey(keyCode: Int, event: KeyEvent) = when (keyCode) {
            KeyEvent.KEYCODE_DEL -> Toxxi.BACKSPACE
            KeyEvent.KEYCODE_FORWARD_DEL -> Toxxi.DELETE
            KeyEvent.KEYCODE_ENTER, KeyEvent.KEYCODE_NUMPAD_ENTER -> Toxxi.ENTER
            KeyEvent.KEYCODE_TAB -> if (event.isShiftPressed) Toxxi.BACK_TAB else Toxxi.TAB
            KeyEvent.KEYCODE_ESCAPE -> Toxxi.ESC
            KeyEvent.KEYCODE_DPAD_UP -> Toxxi.UP
            KeyEvent.KEYCODE_DPAD_DOWN -> Toxxi.DOWN
            KeyEvent.KEYCODE_DPAD_RIGHT -> Toxxi.RIGHT
            KeyEvent.KEYCODE_DPAD_LEFT -> Toxxi.LEFT
            KeyEvent.KEYCODE_MOVE_HOME -> Toxxi.HOME
            KeyEvent.KEYCODE_MOVE_END -> Toxxi.END
            KeyEvent.KEYCODE_INSERT -> Toxxi.INSERT
            KeyEvent.KEYCODE_PAGE_UP -> Toxxi.PAGE_UP
            KeyEvent.KEYCODE_PAGE_DOWN -> Toxxi.PAGE_DOWN
            in KeyEvent.KEYCODE_F1..KeyEvent.KEYCODE_F12 -> Toxxi.F1 - (keyCode - KeyEvent.KEYCODE_F1)
            else -> null
        }
    }
}
