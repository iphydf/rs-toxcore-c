# Account sync

Implemented by the `tox_sync` crate (`rs-toxcore-c/sync`) and bTox's
`lib/sync`.

An account has several devices. Each keeps a replica of the account's state;
replicas converge by exchanging events over Tox. Devices record what they know
or want, offline if need be, and the home device makes the Tox network match.

Not yet: devices with Tox IDs of their own whose friends and history the
other devices sync, devices syncing with each other without the home, and
friends seeing that the devices are one person; message IDs shared with
friends, edits, reactions; encryption beyond Tox's; devices that distrust each
other; group histories merged from several members (groups are synced as the
home sees them).

## Roles

-   **Home device**: the one device running the account's Tox identity (two
    instances with one key fight over the DHT), such as toxxi on a server or
    bTox for its own profiles. It turns Tox traffic into events and carries
    out the intents other devices record. It is also a replica.
-   **Replica**: any other device. It runs its own *device key*, whose only
    friend is the home. bTox shows the account as a separate profile backed by
    that key.
-   **Devices**: the device keys allowed to sync, edited at the home (in
    toxxi, `/device allow <friend>`, `/device remove <friend>`) or by any
    device, and recorded in the account graph as `Device` and `DeviceGone`,
    so every device knows which of the home's friends are its devices. The
    home is always one. Every friend gets a `Hello`, but only the devices are
    offered sync; sync messages from other keys are ignored and create no
    state.

### Pairing

1.  The home hands out `tox:<home address>?pair=<code>` as text and QR. The
    code is 16 random bytes in hex, single use, valid 10 minutes.
2.  The new device creates its device key and sends the home a friend request
    with message `pair:<code>`.
3.  The home accepts a request with a valid code, makes the key a device and
    records it with `Device`. Other requests are ordinary friend requests.

## Data model

### Events

All state derives from immutable events, msgpack arrays:

```
Event = [
  version: uint,          -- 3
  graph:   bin(32),       -- which graph it belongs to
  author:  bin(32),       -- device key of the device that wrote it
  parents: [bin(32)],     -- every head of the graph when it was written
  rank:    uint,          -- 1 + max(rank of parents), 0 for no parents
  time:    int,           -- author's clock, ms since the Unix epoch
  content: Content,
]
```

-   The event ID is SHA-256 of the exact encoded bytes, which devices store and
    forward unchanged.
-   Listing all heads as parents merges concurrent branches on the next write.
-   `time` is for display only. It must be within 8.64 × 10¹⁵ ms of the epoch
    (the ECMAScript/Dart date range), or the event doesn't decode.

### Graphs

Graph IDs are deterministic, so any device can write a graph's first event:

| Graph | ID | Holds |
|---|---|---|
| Account | `SHA-256("account" ‖ account_pk)` | Desired state and friend details |
| Friend chat | `SHA-256("friend" ‖ account_pk ‖ friend_pk)` | Messages and receipts |
| Group | `SHA-256("group" ‖ chat_id)` | Messages |
| Conference | `SHA-256("conference" ‖ conference_id)` | Messages |

The account graph is always synced in full. Conversation graphs can be synced
partially, with older history paged on demand.

### Content

`Content` is `[tag: uint, ...fields]`. Unknown tags are stored and forwarded
untouched and contribute nothing to state.

Tag numbering: within each msgpack integer size, the lower half is for
conversation kinds and the upper half for account kinds, each numbered from the
start of its half without gaps. One byte: conversation from 0, account from 64.
When a half is full, it continues in the next size (two bytes: conversation
from 128, account from 192). `tox-proto` reads one-byte tags today, so tags
past 255 need it widened first.

Account graph:

| Tag | Content | Merge rule |
|---|---|---|
| 64 | `WantFriend[pk: bin, request_message: str?, nospam: uint?]` | Per friend, last writer wins against `UnwantFriend`; any device, but never for the account's devices |
| 65 | `UnwantFriend[pk: bin]` | " |
| 66 | `ReadUpTo[graph: bin, event: bin, rank: uint]` | Per graph, highest rank wins; reads every event of that rank or lower |
| 67 | `FriendRequest[pk: bin, message: str]` | Pending until a later `WantFriend` or `UnwantFriend` for `pk`; home |
| 68 | `MergeChat[chat: ChatId, bot: bin, into: ChatId, into_bot: bin, merged: bool]` | Per `chat`, last writer wins; `chat` shows with `into`, whose bot `into_bot` relays its messages as `bot` does in `chat`; `merged: false` shows them apart; any device |
| 69 | `RelayBot[chat: ChatId, bot: bin, relays: bool]` | Per `chat`, last writer wins; `bot` relays another chat's messages in `chat`; `relays: false` stops; any device |
| 70 | `Fact[subject: Subject, value: Value]` | Per subject and value kind, last writer wins; home (see Facts and wishes) |
| 71 | `Want[subject: Subject, value: Value]` | What a device asks Tox to say; per subject and value kind, the last `Fact` or `Want` wins; any device |
| 72 | `ChatInvite[from: bin, kind: uint, name: str, invite: bin]` | Pending until answered; friend `from` invites the account to a chat of `kind` (as in `ChatId`) named `name` (empty for a conference); `invite` is what Tox joins with; home |
| 73 | `AnswerInvite[invite: bin, join: bool, password: str?]` | Per invite, last writer wins; `invite` is the `ChatInvite` event; `join` asks the home to join, with `password` for a group that has one; `false` declines; any device |
| 74 | `InviteJoined[invite: bin, chat: ChatId?, needs_password: bool]` | Per invite, last writer wins; the chat the home joined, or none where Tox refused; `needs_password` for a missing or wrong password; home |
| 75 | `Setting[scope: Scope, setting: Setting]` | Per scope and setting kind, last writer wins; any device (see Settings) |
| 76 | `ClearSetting[scope: Scope, kind: uint]` | Removes the setting of `kind` for `scope`, same rule; any device |
| 77 | `Device[pk: bin, name: str]` | Per `pk`, last writer wins against `DeviceGone`; `pk` is one of the account's devices, named `name`; any device |
| 78 | `DeviceGone[pk: bin]` | Same rule; `pk` is no longer one of the account's devices; any device, but never for the home |
| 79 | `NewChat[kind: uint, name: str, privacy: uint]` | The home founds a group (`kind` 0, `privacy` as in `Privacy`) or a conference (`kind` 1) named `name`; any device |
| 80 | `JoinChat[chat_id: bin, password: str?]` | The home joins a public group by its chat ID; any device |
| 81 | `InviteToChat[chat: ChatId, friend: bin]` | The home invites a friend to a chat; any device |
| 82 | `ChatJoined[intent: bin, chat: ChatId?]` | Per intent, last writer wins; what the home made of `NewChat` or `JoinChat` event `intent`: the chat, or none where Tox refused; home |

`ChatId` is `[kind: uint, id: bin]`: 0 group, 1 conference.

-   The home writes `WantFriend`/`UnwantFriend` to record its friends, and
    devices write them to add, accept or remove friends.
-   Every device writes `ReadUpTo` when it has shown a conversation to its end.
-   **Merged chats** (`MergeChat`): two chats bridged by a bot that relays each
    message as `<name> message`. A client merging them shows one chat: a
    relayed message shows as `name`'s, and of a message and its relayed copy
    only the first to arrive shows, is unread and notifies. Messages written
    there go to `into`. Clients that don't merge show both chats.
-   **Relay bots** (`RelayBot`): the same display for one such chat alone. A
    merged chat uses its `MergeChat` instead.

#### Settings

Settings are the account's, so they're the same on every device. They're
defined here so any client understands them; client-local settings stay on
the client.

```
Scope = Account                  -- tag 0
      | Conversation(graph: bin) -- tag 1
```

`Setting` is `[kind, [fields]]`, fields always in an array:

| Kind | Setting | Scope | Fields |
|---|---|---|---|
| 0 | `Mute` | Conversation | `until: uint?, mentions: bool`; no notifications until `until` (ms since the epoch; none = forever), except for messages naming the account where `mentions`; unread still counts |
| 1 | `PictureFormat` | Conversation | `format: uint`; camera/gallery pictures sent as they are (0) or as lossless QOI (1); unknown formats send as they are |

-   Per kind and scope, higher rank wins, then higher event ID; times aren't
    used. `ClearSetting` takes part the same way and restores the default.
-   A kind is one decision written whole, never merged with another of its
    kind. Independently changed things are separate kinds.
-   A client changing a setting keeps the fields after the ones it knows as
    they came. A setting written afresh keeps none.
-   Fields are only appended, each with a default meaning the old behaviour.
    Readers skip unknown fields. A change older readers would misread needs a
    new kind; readers knowing both act on the newer.
-   A setting a reader can't decode or doesn't know is kept and passed on, and
    acts on nothing.
-   An encoded setting is at most 1024 bytes; the home refuses longer ones.
-   The client decides what counts as naming the account for `Mute`.

#### Invites

-   An invite shows on every device until declined or joined.
-   It is being joined while its last answer is `join` with no later
    `InviteJoined`. An `InviteJoined` without a chat means it failed; answering
    `join` again retries.
-   Tox takes an invite once and checks a group's password only after, so a
    device answering `join` asks for the password if the group has one.
-   An `InviteJoined` without a chat after one with a chat means the chat
    turned the home away (e.g. wrong password): the invite is spent.
-   Once joined, the chat shows from its facts.

Conversation graphs:

| Tag | Content | Written by |
|---|---|---|
| 0 | `Received[from: bin?, sender: str, message: bin, kind: uint]` | Home, for incoming messages |
| 1 | `Send[sender: str, message: bin, kind: uint]` | Any device: "please send this" |
| 2 | `Sent[intent: bin]` | Home, once toxcore accepted the message |
| 3 | `Delivered[intent: bin]` | Home, on the friend's read receipt |
| 4 | `Notice[text: str]` | Home: joins, leaves, topic changes and similar |
| 5 | `File[sender: str, file_id: bin?, name: str, size: uint, incoming: bool, blob: bin?]` | Home, when a transfer starts; any device, as "please send blob `blob`" in a friend chat |
| 6 | `FileEnded[file: bin, ok: bool, blob: bin?]` | Home, when it finishes or fails; `blob` is set, and held by the home, when it ended well |
| 7 | `FileAnswered[file: bin, accepted: bool]` | Any device: accept or decline `file`; the home ends a file it no longer has as failed |
| 8 | `Call[sender: str, incoming: bool, video: bool]` | Home, when a call with the friend starts ringing |
| 9 | `CallEnded[call: bin, duration: uint?, declined: bool]` | Home, when `call` ends; `duration` connected time in ms, if any; `declined` if it rang here and was declined |
| 10 | `ReceivedPrivately[from: bin, sender: str, message: bin, kind: uint]` | Home, for a message to the account alone in a group |
| 11 | `SendPrivately[to: bin, sender: str, message: bin, kind: uint]` | Any device: "please send this to `to` alone"; `Sent` and `Delivered` answer it as they answer `Send` |

-   `message` is the bytes exactly as Tox carries them; only displaying clients
    decode them, so in-message formats (e.g. TRIfA's V3 trailer) survive.
-   `kind` is the Tox message type (normal or action).
-   `from` is the sender's key in groups and conferences, absent in friend
    chats. `sender` is the name at the time of writing.

**Last writer wins** compares `(rank, id)`: higher rank wins (a causally later
write always has a higher rank), then higher event ID. No clocks.

### Display order

By rank, then effective time (`max(time, effective time of parents)`), then
event ID.

### Facts and wishes

Tox's knowledge about the account, friends, chats and their members is *facts*:
values a subject has.

```
Subject = Account                 -- tag 0
        | Friend(pk: bin)         -- tag 1
        | Chat(chat: ChatId)      -- tag 2
        | Peer[chat: ChatId, pk: bin]  -- tag 3, someone in a chat
```

`Value` is `[kind, value]`; at most one value per kind per subject:

| Kind | Value | Subjects | Kept | Wish |
|---|---|---|---|---|
| 0 | `Name(str)` | Account, Friend, Chat, Peer | Account, Friend, Chat; Peer live | Account; Chat for conferences, whose name is their title |
| 1 | `StatusMessage(str)` | Account, Friend | yes | Account |
| 2 | `Status(UserStatus)` | Account, Friend, Peer | Account; Friend and Peer live | Account |
| 3 | `Connection(Connection)` | Account, Friend | live | |
| 4 | `Typing(bool)` | Friend | live | |
| 5 | `Topic(str)` | Chat, groups only: a conference's title is its name | yes | Chat |
| 6 | `Role(Role)` | Chat (ours), Peer | Chat; Peer live | Peer |
| 7 | `Privacy(Privacy)` | Chat | yes | Chat |
| 8 | `PeerLimit(uint)` | Chat | yes | Chat |
| 9 | `Password(str)` | Chat; empty for none | yes | Chat |
| 10 | `TopicLock(bool)` | Chat | yes | Chat |
| 11 | `VoiceState(VoiceState)` | Chat | yes | Chat |
| 12 | `Joined(bool)` | Chat | yes | Chat, `false` only: leave it |
| 13 | `SelfName(str)` | Chat, where our name in it is its own | yes | Chat |
| 14 | `Present(bool)` | Peer | live | Peer, `false` only: kick them |
| 15 | `Address(bin)` | Account, its Tox address | yes | |
| 16 | `Call(CallState)` | Friend, their call with the account | live | |
| 17 | `CallRelay(bool)` | Account: the home connects devices to its calls | live | |
| 18 | `SelfKey(bin)` | Chat, groups only: our key in it, which is its own | yes | |
| 19 | `Avatar(bin?)` | Account, Friend: the blob of their avatar image, none when they have none | yes | Account |

Tox's own values: `UserStatus` 0 online, 1 away, 2 busy; `Connection` 0 none,
1 TCP, 2 UDP; `Role` 0 founder, 1 moderator, 2 user, 3 observer; `Privacy`
0 public, 1 private; `VoiceState` 0 everyone, 1 moderators, 2 founder.
`CallState` is 0 none, `[1, video: bool]` ringing at the home, 2 answered by a
device. Unknown kinds and values are kept, passed on, and show nothing.

-   *Kept* facts are `Fact` events in the account graph, written by the home
    whenever Tox's view changes, so they're known offline.
-   *Live* facts change too often and are only true while the home is online.
    They're sent in-session (`Facts`) and never stored. Chat membership is
    live.
-   A *wish*, `Want[subject, value]`, asks for a fact to be true. For the kinds
    marked in the table, the home makes Tox match and records the resulting
    fact. A refused wish leaves the fact unchanged. Wishes are declarative:
    repeating one is a no-op, and an offline one applies when it reaches the
    home, unless a `Fact` or `Want` of the same subject and kind ranks after
    it.
-   Clients build all Tox state they show from facts.

## Bridging to Tox

The home makes toxcore match the account state:

-   **Incoming** messages become `Received` in that conversation's graph.
-   **Outgoing**: a `Send` without a `Sent` is pending. The home sends it when
    the friend is online, split if longer than Tox takes, then writes `Sent`.
    A crash between toxcore accepting it and `Sent` hitting disk resends it on
    restart (one rare duplicate is accepted).
-   **Receipts** become `Delivered`, for a split message that of its last part.
-   **Friends**: `WantFriend` for an unknown key sends a request or accepts a
    pending one; `UnwantFriend` deletes the friend. A device's change that a
    later one for the same friend outranks does nothing. Incoming requests
    become `FriendRequest`.
-   **Invites**: incoming invites become `ChatInvite`. A `join` answer is
    carried out with `tox_group_invite_accept` (with its password) or
    `tox_conference_join` once the inviting friend is online, and recorded as
    `InviteJoined`. A group that turns the home away afterwards is left, and
    the invite re-recorded without a chat. A later `join` on a spent invite is
    recorded at once: joined if the home is in the chat, failed otherwise.
    Answers given on the home are recorded too.
-   **Facts**: Tox reports become `Fact` events (kept kinds, on change) or
    `Facts` messages to devices in session (live kinds). A session starts with
    all live facts.
-   **Wishes**: carried out with the matching Tox call (`tox_self_set_name`,
    `tox_group_set_topic`, `tox_group_set_role`, `tox_group_kick_peer`, ...).
-   **Avatars** are Tox file transfers of kind 1 (`TOX_FILE_KIND_AVATAR`)
    whose file ID is the image's SHA-256, its blob ID. The home takes a
    friend's avatar unless it holds that blob, keeps it only if the SHA-256
    matches, and records `Avatar` for the friend; size 0 records none. It
    sends the account's avatar, or size 0 for none, to each friend that comes
    online and again when it changes. For an `Avatar` wish it fetches the blob
    from the device first.

## Files

A file's bytes are a *blob*, identified by its SHA-256 (blob ID). Events name
blobs but never carry them. Files are only sent in friend chats.

-   **From a device**: it keeps the file and writes `File` with
    `incoming: false`, no `file_id`, and its `blob` (both message and intent).
    The home fetches the blob unless it holds it, sends the file once the
    friend is online, and writes `FileEnded`. A blob the device no longer has
    fails the file.
-   **Through the home**: files that ended well are held by the home, named in
    `FileEnded`.
-   **To a device**: it fetches the blob named in `File` or `FileEnded`. bTox
    fetches up to its auto-accept size as they come, files it accepted, and
    the rest on request. Devices fetch the blobs `Avatar` facts name.

Blob transfer, either direction within a session:

1.  `WantBlob[blob]` asks for a blob.
2.  The other side answers with a Tox file transfer of kind 176, file ID = blob
    ID, size = blob size, or `NoBlob[blob]`.
3.  The receiver takes only blobs it asked that friend for, may seek to resume,
    and keeps a blob only if its SHA-256 matches (otherwise treats it as
    `NoBlob`).

A transfer cut off with the session is asked for again in the next.

## Calls

The home takes the account's calls and relays each to a device. A ringing
friend shows as `Call(Ringing)` on every device in session. The device that
answers or places a call sends `Call[friend, Connect]`; the home answers or
places the friend's call, then calls that device with toxav and passes frames
between the two calls until either ends. The fact becomes `Answered`, so
other devices stop ringing. The home records `Call` and `CallEnded` in the
friend's chat. Re-encoding at the home costs a codec's delay and CPU.

## Transport

### Packets

All traffic uses Tox custom lossless packet `0xb0` (176). Lossless packets are
reliable and ordered per friend, so the protocol has no sequence numbers,
acks or retransmissions.

```
[packet id: u8] [flags: u8] [payload: up to 1371 bytes]
```

`flags` bit 0 = final frame, bit 1 = first frame. A message is the payloads
from a first frame through a final frame. A first frame discards anything
before it (a connection that ended mid-message). One message at a time per
connection, so no reassembly IDs.

Example: `Hello[version: 1, features: 1]` is `b0 03 92 00 92 01 01`. Both
implementations test against these bytes.

### Back-pressure

Each connection has a frame FIFO. On `SENDQ` from
`tox_friend_send_lossless_packet`, sending pauses until the next
`tox_iterate`. On disconnect the queue is dropped and the session restarts on
reconnect.

### Limits

Checked before decoding; an oversized message is dropped with the rest of its
frames.

| Limit | Value |
|---|---|
| Message | 1 MiB |
| Event | 64 KiB |
| Avatar | 64 KiB |
| Events per `Events` | Whatever fits in one message |

A `Want` is answered for its first 64 hashes only.

## Sync protocol

Each session message is `[tag: uint, ...fields]`, one framed message.

| Tag | Message | Meaning |
|---|---|---|
| 0 | `Hello[version: uint, features: uint]` | First message from both sides |
| 1 | `Summary[[graph: bin, digest: bin]]` | Per graph, SHA-256 of its sorted heads |
| 2 | `Heads[graph: bin, heads: [bin]]` | The sender's heads of one graph |
| 3 | `Want[hashes: [bin]]` | Send me these events |
| 4 | `Events[events: [bin]]` | Encoded events, as stored |
| 5 | `History[graph: bin, before: [bin], limit: uint]` | Send up to `limit` ancestors of `before`, newest first |
| 6 | `WantBlob[blob: bin]` | Send me this blob as a file transfer |
| 7 | `NoBlob[blob: bin]` | I don't hold this blob |
| 8 | `Facts[facts: [[Subject, Value]], all: bool]` | Live facts, never stored; `all` replaces all sent before; `Present(false)` drops a subject's live facts |
| 9 | `Call[friend: bin, action: CallAction]` | From a device: `[0, video: bool]` connects it to the friend's call, answering or placing it; 1 hangs up or declines |

Session:

1.  Both sides send `Hello` when the friend comes online, before anything
    else, and again when what they offer changes. Either `Hello` may arrive
    first. The home answers a device's repeated `Hello` with its own (a device
    may restart before Tox notices); devices don't answer `Hello`. `features`
    is a bit set, account sync is bit 0; unknown bits are kept and ignored.
2.  Both send `Summary` for the graphs they hold; the home also sends `Facts`
    with `all`.
3.  Each answers the other's `Summary` with `Heads` for every graph it holds
    whose digest differs or is missing. Graphs only the other side holds come
    back in its answer to ours.
4.  Each sends `Want` for heads it lacks, then for missing parents of received
    events, until the account graph is complete and each conversation graph is
    complete as far back as the device wants.
5.  New events are then pushed as `Events` when written. An unknown parent
    triggers a `Want`.

A replica may keep conversation graphs incomplete (heads and recent events),
fetching older ones with `History` on scroll-back. It fills gaps with
`History` rather than a `Want` per parent, until the account graph is whole
and each conversation joins up with what it holds.

## Storage

-   **toxxi**: `events.log`, append-only records
    `[length: u32 big-endian][event]`. A record cut short by a crash is dropped
    on start. Events hit disk before devices get them, so no device holds a
    home event a crash lost; the home takes from devices only events they
    authored. Conversations are rebuilt from the log at startup.
    `state.json` keeps everything else but messages: the profile, friends,
    conversations (peers, topic, ignored peers), pending requests and invites,
    file transfers, console, Tox logs, windows, input history and log filters.
    Snapshots are deferred. Blobs, avatars included, are in `blobs/`,
    named by hex ID; received files are also in the downloads directory.
-   **bTox**: a linked account is a profile with a `home` device. Events are in
    `sync_events` (`profile`, `id`, `graph`, `rank`, `bytes`), live facts in
    `live_facts` (a device running its own Tox fills them the same way).
    Chats and messages are derived from them when shown, not copied into
    bTox's own contacts and messages. Backups leave them out. Blobs are
    attachments, except avatars, which are in `avatars`; sent and fetched
    files are in `transfers`.

## Encoding

msgpack as `tox-proto` writes it (`tox-proto/ENCODING.md`). Rust derives its
codec; bTox's Dart codec follows the same rules by hand:

-   Structures and tuples are arrays in field order.
-   An enum value is `[tag, [fields]]`, `[tag, field]` for a single field, or
    the bare tag for none. Tags are those in the tables above.
-   An optional is `[]` when absent, `[value]` when present.
-   Byte strings are `bin`, text is `str`.
-   An event is `[version, event]`, read exactly: trailing bytes are an error.
-   New fields are only appended, marked `#[tox(default)]`; readers accept
    them missing and ignore unknown ones. A single-field variant can't gain
    fields, so a new field there needs a new tag. Unknown tags are kept as
    they came.
-   `#[tox(lenient)]` enums (e.g. `Setting`) put every variant's fields in an
    array, and read a variant whose fields don't decode as its unknown
    variant, keeping its bytes.
-   Skipping a value reads it without recursion and allocates nothing for the
    lengths it claims.

The cases in `sync/conformance` are checked against both implementations.

## Security

-   Only allowlisted device keys are offered sync. Sync messages from any
    friend are decoded (bounded, non-recursive); from keys not allowed, only
    `Hello` is acted on.
-   Devices are changed through sync only by `Device` and `DeviceGone` from a
    device, which can't remove the home.
-   The home takes from a device only events that device authored, of the
    kinds devices write: in this account's conversations, `Send`,
    `SendPrivately`, `FileAnswered`, and `File` with a blob to send in friend
    chats; in the account graph, `ReadUpTo`, `MergeChat`, `RelayBot`, `Setting`
    and `ClearSetting` (for the account or its conversations), `WantFriend`
    and `UnwantFriend` for keys other than the account's devices, `AnswerInvite`
    for a pending invite, `Want` for the wishes the table allows, `Device`,
    `DeviceGone`, `NewChat`, `JoinChat`, and `InviteToChat` for a chat the
    account is in. The home records everything else itself.
-   The home takes a device's event once all its parents are present, lowest
    rank first; one without parents only at rank 0. It keeps account events
    of a chat that's gone, acting on none, so no graph has a gap.
-   Removing a device ends its session and refuses new ones. No key rotation
    is needed; Tox's per-friend encryption excludes it.
-   Events aren't signed; replicas trust events relayed through the home.
-   Limits are enforced before decoding or storage.
-   A blob is taken only from the friend asked, and only with the ID asked.
-   Avatars come from any friend, so clients decode them with a pixel limit.
-   Nothing is encrypted at rest. Group passwords (kept facts, invite answers)
    are in plaintext in the account graph on every device and in `events.log`.

