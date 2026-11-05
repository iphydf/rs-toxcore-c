# Toxxi

A Terminal Tox Client (TUI).

## Features

-   **TUI Mode**: A full-featured terminal interface based on `ratatui` and
    `crossterm`.
-   **Dynamic Help**: Built-in command registry providing automatic help.
-   **Event Tracking**: Real-time monitoring of network events, read receipts,
    and status changes.

## Running

Simply run the binary to start the interactive client:

```bash
bazel run //rs-toxcore-c/apps/toxxi
```

## Linking to another toxxi

A toxxi can be a device of an account another toxxi runs, its home (see
[account sync](../doc/account-sync.md)):

1.  On the home, `/device pair` gives a link, valid for 10 minutes.
2.  On the other toxxi, with a profile that has no friends and is in no
    groups or conferences, `/link <link>`.

The linked toxxi's own Tox key becomes the device's, whose one friend is the
home. Everything it shows comes from the account's events and facts: friends,
chats and their history, requests and invites. What you do there goes to the
home, which does it on Tox: messages, names and status, friends, making,
joining and leaving chats, answering invites. Files, avatars and calls are
only on the home so far. The profile's own event log is set aside as
`events-<device key>.log`.

## Android

`android/` is an Android app of toxxi: toxxi runs in the app's process and
draws on a ratatui backend whose cells the app's view draws, with the phone's
keyboard typing into it. See `android/build-native.sh` for what it needs, then:

```bash
android/build-native.sh x86_64      # or arm64-v8a, into app/src/main/jniLibs
(cd android && ./gradlew assembleDebug)
```

A new profile starts with UDP off. `/link` makes the app a device of the
toxxi on your server.

## Development

Toxxi uses a Registry-Based Architecture. To add a new command, add a new
`CommandDef` to the `COMMANDS` array of the matching module in `src/commands/`.
It will automatically appear in `/help`.

## Testing

### UI Snapshot Tests

Toxxi uses "golden" snapshot tests to verify the UI and widget rendering. These
tests compare the rendered terminal output against stored reference files in
`tests/snapshots/`.

To run all UI and widget tests:

```bash
bazel test //rs-toxcore-c/apps/toxxi:...
```

To update widget snapshots (e.g., after changing a single widget's rendering):

```bash
INSTA_UPDATE=always bazel run //rs-toxcore-c/apps/toxxi:widgets-sidebar-test -- --nocapture
```

To update full UI snapshots (e.g., after changing the global layout or status
bar):

```bash
INSTA_UPDATE=always bazel run //rs-toxcore-c/apps/toxxi:ui-golden-test -- --nocapture
```

To update all snapshots in the project:

```bash
# This will run all UI and widget tests and update snapshots in the source tree
for t in $(bazel query 'kind(rust_test, //rs-toxcore-c/apps/toxxi:all)' | grep -E "widgets|ui-golden"); do
    INSTA_UPDATE=always bazel run $t -- --nocapture
done
```

### Tests without Tox

What toxxis say to each other (account sync, pairing, linked profiles) is
tested on `toxxi::testing::network`: models in one process, where what one
sends a friend arrives as the friend's event straight away. These tests take
milliseconds and come out the same every time; `tests/linked_test.rs` is an
example. Tests with real Tox (`*_e2e_test.rs`) are for what the home does on
Tox: joining groups, invites, receipts.

### Snapshots

The snapshots are stored in `tests/snapshots/`. We use a `FakeTimeProvider`
initialized to a fixed UTC time (2023-01-01 12:00:00 UTC) to ensure
deterministic output across different environments and timezones.
