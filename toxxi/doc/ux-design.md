# Toxxi UX Design Specification

## 1. Introduction
Toxxi is a modern, high-performance TUI (Terminal User Interface) chat client for the Tox protocol, written in Rust. This document outlines the user experience (UX) and user interface (UI) design principles, layout structures, and interaction models that define the application.

The primary goal of Toxxi is to provide a "power-user" experience that is fast, discoverable, and aesthetically modern, while remaining functional over SSH and across different operating systems (Linux, macOS). It prioritizes keyboard-driven navigation, low latency, and a high-information-density display.

---

## 2. Global Layout Structure
Toxxi uses a multi-pane layout to maximize screen real estate and provide immediate access to information. The layout is managed by a flexible grid system that can adapt to varying terminal sizes.

### 2.1 Pane Overview
1.  **Sidebar (Left):** Context navigation (Friends, Groups, Conferences). Fixed width by default (e.g., 25 chars), but toggleable or resizable.
2.  **Main Content (Center):** The active conversation, game, or file manager. This is the primary focal point.
3.  **Info Pane (Right - Optional):** Metadata about the current context (Profile info, member list, shared files).
4.  **Input Area (Bottom-Center):** The framed, dynamic text entry box that grows vertically.
5.  **Status Bar (Bottom-Global):** System-wide status, notifications, and connectivity health.

### 2.2 Responsive Layout Logic
The UI adaptively changes based on the terminal width (`W`) and height (`H`):

#### 2.2.1 Wide Mode (W > 120 chars)
*   **Sidebar:** Visible with full names and status icons.
*   **Main Chat:** Uses an "irssi-style" layout.
    ```text
    [14:30] <  Alice> | Hey, are we still on for the game?
    [14:31] <     Me> | Yeah, just finishing some work.
    [14:32] <  Alice> | Cool. I'll send the invite in a bit.
                      | It's going to be a long night!
    ```
*   **Info Pane:** Visible on the right, showing participants or file history.

#### 2.2.2 Medium Mode (80 < W <= 120 chars)
*   **Sidebar:** Visible but potentially collapsed to icons/initials if space is needed.
*   **Main Chat:** Standard linear layout.
*   **Info Pane:** Hidden by default; accessible via the `i` toggle.

#### 2.2.3 Narrow Mode (W <= 80 chars)
*   **Sidebar:** Hidden; accessible via a modal or a slide-out overlay.
*   **Main Chat:** Stacked layout to maximize horizontal space.
    ```text
    14:30 Alice:
    Hey, are we still on for the game?
    ---------------------------------
    14:31 Me:
    Yeah, just finishing some work.
    ```

---

## 3. Navigation: The Sidebar and Quick Switcher

### 3.1 The Sidebar Structure
The Sidebar is organized into logical sections. Each section can be collapsed using the arrow keys or specific shortcuts. Conversations are identified by a `ConversationId` (see [doc/merkle-tox-dag.md](../../doc/merkle-tox-dag.md)).

*   **[F] Friends (1:1)**
    *   `● Alice` (Online, Green)
    *   `◑ Bob` (Away, Yellow)
    *   `● Charlie` (Busy, Red)
    *   `○ Dave` (Offline, Gray)
*   **[G] DHT Groups (New)**
    *   `# Rust-Devs` (42 Online)
    *   `# Tox-General` (128 Online)
*   **[C] Conferences (Legacy)**
    *   `& Old-School-Tox`

### 3.2 The Quick Switcher (Ctrl+P)
The Quick Switcher is a fuzzy-find modal that allows for instantaneous context switching without leaving the keyboard's home row.

#### 3.2.1 Search Logic
Using a weighted fuzzy-matching algorithm (like `fzf`'s Smith-Waterman variant):
*   **Exact Matches:** Boosted to the top.
*   **Prefix Matches:** High priority.
*   **Acronym Matches:** (e.g., `rd` matches `Rust-Devs`) Medium priority.

#### 3.2.2 Action Prefixes
The switcher is not just for navigation; it can also trigger actions:
*   `f: <name>`: Filter for friends only.
*   `g: <name>`: Filter for groups only.
*   `h: <text>`: Search message history globally. Selecting a result jumps to that conversation and scrolls to the message.
*   `>: <command>`: Quick access to settings or UI actions (e.g., `> Theme: Dark`).

---

## 4. The Message Gutter and Display

### 4.1 The Gutter (Status Column)
To the left of every message is a 2-character wide "Gutter". This provides immediate feedback on the message state without cluttering the text.

*   `● ` : Delivered.
*   `○ ` : Sending (not yet acknowledged by the peer).
*   `! ` : Error (peer unreachable or message rejected).
*   `✓ ` : Read (if supported by the client and protocol extensions).
*   `⚙ ` : System information (e.g., "Alice changed her name").

**Visibility:** The display of timestamps and status indicators in the gutter can be toggled globally via a shortcut or `/set` command to provide a cleaner, "chat-focused" view.

### 4.2 Message Grouping
To reduce visual noise, consecutive messages from the same sender within a short timeframe (e.g., 2 minutes) are grouped.
*   The first message shows the timestamp and name.
*   Subsequent messages only show the "Gutter" status and the message body.

---

## 5. Input Mechanics: The Framed Box

The input box is a sophisticated line editor wrapped in a Unicode frame.

### 5.1 Dynamic Framing
The box lives at the bottom of the main chat pane.
```text
╭─────────────────────────────────────────────────────────────────────────────╮
│ > This is a long message that will eventually wrap to the next line. As I   │
│   continue to type, the box will grow upwards until it reaches its max size.│
╰─────────────────────────────────────────────────────────────────────────────╯
```
*   **Max Height:** The input box grows vertically to accommodate text. The maximum height is configurable, with a default of 10 text rows (12 total rows including the top and bottom borders).
*   **Border Styling:** When the input box is focused, the border color changes (e.g., to Cyan or Bold White). When unfocused, it dims.
*   **Visual Wrap Marker:** If a line is wrapped by the UI (not a hard newline), a small Unicode arrow (`↳`) or a dimmed vertical line on the right border indicates the continuation, distinguishing it from an intentional newline.

### 5.2 Editing Features
*   **Multi-line Support:** 
    *   **Mode A (Default):** `Enter` sends the message, `Shift+Enter` (or `Ctrl+Enter`/`Alt+Enter`) inserts a literal newline.
    *   **Mode B:** `Enter` inserts a literal newline, `Shift+Enter` sends the message.
    *   **Toggling:** A keyboard shortcut or command allows users to swap between these modes on the fly.
*   **Selection:** `Shift+Left/Right` selects characters. `Ctrl+Shift+Left/Right` selects words.
*   **Clipboard:** `Ctrl+C/V/X` integration with the system clipboard (via `arboard` or similar).
*   **Readline Shortcuts:**
    *   `Ctrl+A`: Home
    *   `Ctrl+E`: End
    *   `Ctrl+K`: Kill to end of line
    *   `Ctrl+U`: Kill to start of line
    *   `Ctrl+W`: Kill previous word

---

## 6. The Slash Command System

Commands provide a structured way to interact with the Tox protocol and the UI.

### 6.1 Discoverability
Typing `/` at the start of the input box triggers the "Command Discovery Overlay".

#### 6.1.1 The Suggestion List
A list of commands appears above the input box, sorted by relevance or frequency of use.
```text
  /about             Show version info
  /attach            Attach a file to the current chat
  /block             Block the current user
  /call              Start an audio call
  /clear             Clear the current window
  --------------------------------------------------
  (1/24) Press [Tab] to complete
```

#### 6.1.2 Fuzzy Argument Completion
For commands like `/file send`, Toxxi provides fuzzy matching for the local filesystem.
```text
  /file send ~/Docu_
  ------------------
  ~/Documents/
  ~/Downloads/
```
The UI will proactively suggest completions for:
*   **Friends' names:** (e.g., `/msg Al<tab>`)
*   **Paths:** (e.g., `/file send <tab>`)
*   **Settings keys:** (e.g., `/set ui.th<tab>`)

---

## 7. File Transfers

File transfers are a core part of the Tox experience and require a high-friction-reduction UX.

### 7.1 Inline Presence
When a file transfer is offered, it appears as a "Card" in the chat.
```text
╭─ 📄 incoming: presentation.zip ─────────────────────────────────────────────╮
│ Size: 45.2 MB                                                               │
│ [ (a) Accept ] [ (x) Decline ] [ (o) Change Destination ]                   │
╰─────────────────────────────────────────────────────────────────────────────╯
```

### 7.2 Progress Visualization
Once accepted, the card updates with a progress bar and throughput stats.
```text
╭─ 📄 downloading: presentation.zip ──────────────────────────────────────────╮
│ [████████████████████░░░░░░░] 72%                                           │
│ Rate: 1.2 MB/s | ETA: 12s                                                   │
│ [ (p) Pause ] [ (x) Cancel ]                                                │
╰─────────────────────────────────────────────────────────────────────────────╯
```

### 7.3 The File Manager Modal
A global view (accessible via `/file list` or `Ctrl+F`) shows all active, completed, and failed transfers across all profiles and chats. This allows for bulk actions (e.g., "Cancel all active").

---

## 8. Network Games and Extensibility

Toxxi is designed to be a platform for P2P interaction beyond simple text.

### 8.1 Custom Packet Handling
The `core` logic handles the routing of custom DHT packets. The UI provides "Hooks" for these packets to render specialized views.

### 8.2 Game Session Lifecycle
1.  **Invite:** A game-specific invite box appears.
2.  **Acceptance:** The UI enters "Game Mode".
3.  **Split-Screen:** The main area splits. The game UI (e.g., a Chess board or a simple 2D grid) takes the top 70%, and the chat takes the bottom 30%.
4.  **Input Capturing:** In Game Mode, the terminal is put into "Raw Input" mode for the game pane. The user must hit a specific escape sequence (e.g., `Ctrl+G`) to switch focus back to the chat input.

### 8.3 The "Oscilloscope" Widget
For audio calls, a real-time visualization helps users know they are being heard and that the peer is sending data.
*   Uses Braille Unicode characters (`⠇`, `⠏`, `⠹`, etc.) to create a high-resolution waveform in a 1-line or 2-line height box.

---

## 9. Advanced UX Features

### 9.1 Multi-Profile Support
Toxxi can run multiple Tox IDs simultaneously.
*   **Tabs:** If more than one profile is active, a tab bar appears at the very top.
*   **Shortcuts:** `Alt + [1..9]` jumps to the respective profile.
*   **Combined View:** An optional "All Messages" view that aggregates mentions and notifications from all profiles into a single stream.

### 9.2 Notifications and Beeps
*   **In-TUI Visuals:** The sidebar item for a chat flashes or changes color.
*   **Terminal Bell:** A standard `\a` (ASCII Bell) can be triggered for mentions, configurable in settings.
*   **External Integration:** Support for `libnotify` (Linux) or `terminal-notifier` (macOS) via optional feature flags.

### 9.3 Connectivity Health (The Heartbeat)
A small section in the status bar provides a "Health Check" of the Tox network. Toxxi uses the median-based consensus clock for monotonic time (see [doc/merkle-tox-clock.md](../../doc/merkle-tox-clock.md)).
*   `Nodes: [ ⠿⠿⠿⠿⠶ ]`: A Braille sparkline showing the number of connected DHT nodes over the last 10 minutes.
*   `Mode: [ UDP/DHT ]`: Shows if the connection is direct (UDP) or relayed (TCP).

---

## 10. Design Trade-offs and Rationale

### 10.1 Why TUI?
*   **Performance:** Extremely low memory footprint.
*   **Accessibility:** Works perfectly over SSH/Mosh.
*   **Focus:** Minimizes distractions compared to GUI applications.

### 10.2 Why Unicode Frames?
*   Provides a modern look and feel that distinguishes Toxxi from legacy IRC-style clients.
*   Helps visually separate the input area from the history.

### 10.3 The "Alt" Key Problem
Terminals often struggle with the `Alt` (Option) key, especially on macOS.
*   **Rationale:** Toxxi favors `Ctrl` and `Esc` for primary navigation. `Alt` is reserved for "Power User" shortcuts (like profile switching) that can also be performed via slash commands or the quick switcher.

---

## 11. Interaction State Machine (Internal)

To ensure a predictable experience, the UI follows a strict state machine:

1.  **Normal Mode:** Input box is focused. Standard typing.
2.  **Command Mode:** Triggered by `/`. Tab completion is active.
3.  **Navigation Mode:** Triggered by `Esc`. Input box loses focus. Arrows move focus between Sidebar, Chat history (for selection), and Info Pane.
4.  **Modal Mode:** (Quick Switcher, File Manager). All input is captured by the modal until `Enter` or `Esc` is pressed.
5.  **Game Mode:** Special input capturing for custom game logic.

---

## 12. Accessibility and Customization

### 12.1 Themes
All colors are defined in a `theme.toml` file.
*   Support for 16-color, 256-color, and TrueColor (RGB) terminals.
*   "No-Unicode" mode for legacy terminals that can't render the frames or Braille symbols.

### 12.2 Keyboard Mapping
Every action in Toxxi is bindable. A `keys.toml` allows users to remap the entire interaction model (e.g., for Vim-like navigation).

---

## 13. UX Scenarios / User Journeys

### 13.1 Scenario: Sending a File to Alice
1.  User starts typing `/fi` in the chat with Alice.
2.  The command overlay suggests `/file`. User hits `Tab`.
3.  The overlay suggests `send`. User hits `Tab`.
4.  The overlay suggests `~/`. User types `Do` and hits `Tab` to complete `~/Documents/`.
5.  User selects `photo.jpg` from the fuzzy list and hits `Enter`.
6.  An inline transfer card appears in the chat stream.
7.  Alice accepts; the user sees the progress bar fill in real-time.

### 13.2 Scenario: Joining a Group Game
1.  A notification appears in the `#General` DHT group: "Bob has started a game of 2048".
2.  User hits `Esc` to leave input mode.
3.  User uses `Up Arrow` to highlight the game invite card.
4.  User hits `j` to join.
5.  The screen splits; the game appears in the top half.
6.  User plays using arrow keys. When someone mentions them in chat, the "New Message" indicator in the status bar flashes.
7.  User hits `Ctrl+G` to jump focus back to the chat to reply, then `Ctrl+G` again to resume the game.

### 13.3 Scenario: Finding an Old Message
1.  User hits `Ctrl+P`.
2.  User types `h: sushi`.
3.  A list of messages containing "sushi" appears from all chats.
4.  User selects one from "Alice" from 3 days ago.
5.  The UI switches context to the Alice chat and scrolls back to the exact timestamp, highlighting the message in a temporary background color.

---

## 14. UI Component Architecture (Internal Perspective)

From an implementation standpoint, the UI is built from atomic components that manage their own state and rendering logic.

### 14.1 The `MessageList` Component
*   **Virtual Scrolling:** Only calculates the layout for messages that are currently on-screen.
*   **Reflow Logic:** Recalculates wrapping and column alignment whenever the terminal is resized.
*   **Search Overlay:** Highlights matched text during history searches.

### 14.2 The `DynamicInput` Component
*   **Syntax Highlighting:** Colors `/commands` and `@mentions` in real-time.
*   **Buffer Management:** Handles multi-line strings and maintains its own undo/redo stack.

### 14.3 The `StatusLine` Component
*   **Polling:** Updates DHT health and node count on a background timer (every 1-5 seconds).
*   **Transient Alerts:** Displays temporary messages (e.g., "File saved to ...") which fade out after 3 seconds.

---

## 15. Conclusion
The Toxxi UX is designed to be "invisible"—staying out of the way of the conversation while providing powerful tools at a moment's notice. By combining traditional IRC-like efficiency with modern IDE-inspired navigation, it sets a new standard for Tox clients.

(End of Document)
