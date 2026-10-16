# Toxxi

A Terminal Tox Client (TUI) with advanced automation capabilities.

Toxxi is designed to be both a functional daily client and a powerful tool for
automated testing and bot development.

## Features

-   **TUI Mode**: A full-featured terminal interface based on `ratatui` and
    `crossterm`.
-   **Headless Mode**: Run scripts without any UI, perfect for CI/CD and
    automation.
-   **Rhai Scripting**: Integrated [Rhai](https://rhai.rs/) scripting engine for
    complex automation tasks.
-   **Dynamic Help**: Built-in command registry providing automatic help and
    scripting bindings.
-   **Event Tracking**: Real-time monitoring of network events, read receipts,
    and status changes.

## Running

### TUI Mode

Simply run the binary to start the interactive client:

```bash
bazel run //rs-toxcore-c/toxxi
```

### Scripting Mode

Use the `--script` flag to run a Rhai script:

```bash
bazel run //rs-toxcore-c/toxxi -- --script path/to/script.rhai
```

## Scripting API

Toxxi exposes its internal commands as script functions. Example:

```js
// Set nickname
nick("RegistryBot");

// Wait for network connection
wait_online();

// Send message to friend 0
msg("0 Hello from Rhai!");

// Wait for read receipt
wait_read_receipt(0);

// Send a file
file("send 0 test.txt");

// Close the application
quit();
```

### Receiving a file in a script

```js
// Wait for friend to send a file
wait_file_recv(0);

// Accept the file (assuming file ID 0 for the first one)
file("accept 0 0");

// Wait some time for transfer (or use logic to track progress)
sleep(5000);

quit();
```

### Available Functions

-   `nick(name)`: Set your nickname.
-   `status(msg)`: Set your status message.
-   `msg(id_text)`: Send a message to a friend (e.g., `msg("0 hello")`).
-   `me(action_text)`: Send an action message to the current window (e.g.,
    `me("is testing")`).
-   `wait_online()`: Block until connected to the DHT.
-   `wait_friend_online(id)`: Block until a specific friend is online.
-   `wait_friend_msg(id, substring)`: Block until a message containing the
    substring is received.
-   `wait_read_receipt(id)`: Block until the last sent message is read by the
    peer.
-   `wait_file_recv(id)`: Block until a file transfer request is received from a
    specific friend.
-   `timeout(ms)`: Set a global timeout for the script.
-   `sleep(ms)`: Sleep for a specific amount of time.
-   `whois(id)`: Show information about a friend.
-   `topic(text)`: Set the topic of the current group or conference.
-   `file(args)`: Manage file transfers (e.g., `file("send 0 path")`).
-   `quit()`: Exit the application.
-   `cmd(text)`: Run any command (e.g., `cmd("/help")`).

## Development

Toxxi uses a Registry-Based Architecture. To add a new command:

1. Add a new `CommandDef` to the `COMMANDS` array of the matching module in
   `src/commands/`.
2. (Optional) Add a `WaitDef` to the `WAITS` array in `src/waits.rs` if it
   requires asynchronous fulfillment tracking.

The new command will automatically appear in `/help` and become available as a
Rhai function.

## Testing

### UI Snapshot Tests

Toxxi uses "golden" snapshot tests to verify the UI and widget rendering. These
tests compare the rendered terminal output against stored reference files in
`tests/snapshots/`.

To run all UI and widget tests:

```bash
bazel test //rs-toxcore-c/toxxi:...
```

To update widget snapshots (e.g., after changing a single widget's rendering):

```bash
INSTA_UPDATE=always bazel run //rs-toxcore-c/toxxi:widgets-sidebar-test -- --nocapture
```

To update full UI snapshots (e.g., after changing the global layout or status
bar):

```bash
INSTA_UPDATE=always bazel run //rs-toxcore-c/toxxi:ui-golden-test -- --nocapture
```

To update all snapshots in the project:

```bash
# This will run all UI and widget tests and update snapshots in the source tree
for t in $(bazel query 'kind(rust_test, //rs-toxcore-c/toxxi:all)' | grep -E "widgets|ui-golden"); do
    INSTA_UPDATE=always bazel run $t -- --nocapture
done
```

The snapshots are stored in `tests/snapshots/`. We use a `FakeTimeProvider`
initialized to a fixed UTC time (2023-01-01 12:00:00 UTC) to ensure
deterministic output across different environments and timezones.
