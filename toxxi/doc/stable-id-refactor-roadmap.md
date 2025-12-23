# Roadmap: Refactoring toxxi to Stable Identifiers

This document outlines the exhaustive plan to decouple the `toxxi` UI and data model from the transient numeric IDs provided by `toxcore`.

## 1. Problem Statement
`toxcore` uses numeric identifiers (`FriendNumber`, `GroupNumber`, `ConferenceNumber`, `FileNumber`, `GroupPeerNumber`) that are:
1. **Transient:** They only exist for the current session.
2. **Reused:** Once a friend is deleted or a group is left, the number is freed and reassigned.
3. **Session-Dependent:** On restart, the same friend/group may be assigned a different number.

`toxxi` currently uses these numbers as primary keys in `HashMap`s, causing history loss on restarts and potential race conditions if IDs are reassigned.

## 2. Target Architecture
The application will transition to using stable, session-independent identifiers:
- **Friends:** `PublicKey`
- **Groups:** `ChatId` (32-byte hash)
- **Conferences:** `ConferenceId` (32-byte unique ID)
- **Files:** `FileId` (32-byte unique ID)
- **Peers:** `PublicKey`

### Key Data Structure Changes
| Structure | Current Key/ID | Target Key/ID |
| :--- | :--- | :--- |
| `WindowId` | `Friend(FriendNumber)` | `Friend(PublicKey)` |
| `WindowId` | `Group(GroupNumber)` | `Group(ChatId)` |
| `WindowId` | `Conference(ConferenceNumber)` | `Conference(ConferenceId)` |
| `DomainState.friends` | `HashMap<FriendNumber, ...>` | `HashMap<PublicKey, ...>` |
| `DomainState.file_transfers` | `HashMap<(FriendNumber, FileNumber), ...>` | `HashMap<FileId, ...>` |
| `PeerId` | `Group(GroupPeerNumber, PublicKey)` | `PublicKey` |

---

## 3. Phase-by-Phase Roadmap

### Phase 1: Knowledge & Reconciliation (The Foundation)
**Goal:** Fix the bug where group/conference history is lost on restart by establishing a mapping between numbers and stable IDs.

- **[x]** **[toxcore/src/types.rs]** Defined `ChatId` wrapper using `impl_byte_array_type!`.
- **[x]** **[toxcore]** Updated `group_get_chat_id` and `Group::chat_id` to return `Result<ChatId>` for type safety.
- **[x]** **[worker.rs]** Update `get_initial_state` to retrieve `ChatId` for groups and `ConferenceId` for conferences alongside their numbers.
- **[x]** **[msg.rs]** Update `ToxEvent::GroupCreated` and `ToxEvent::ConferenceCreated` to include stable IDs.
- **[x]** **[model.rs]** Update signatures of `reconcile`, `initialize_model`, etc. to accept stable IDs.
- **[x]** **[model.rs]** Update the `Conversation` struct to store an `Option<StableId>` (the stable variant).
- **[x]** **[model.rs]** Refactor `model::reconcile` to use these stable IDs for mapping old conversation history to new session numbers.
- **[x]** **[update.rs]** In `handle_tox_event`, when a new group/conference is created, immediately associate the numeric ID with the stable ID in the model.

**Checkpoint 1:** History for groups and conferences now survives Tox restarts.

### Retrospective: Phase 1 (Part 1)
- **Missing Wrappers:** `ChatId` did not exist in `toxcore`, requiring a definition in `toxcore/src/types.rs`.
- **API Safety:** `toxcore`'s C-bindings returned raw `[u8; 32]`. We upgraded the Rust wrapper to return `Result<ChatId>` to match `ConferenceId` patterns and ensure type safety.
- **Error Handling:** `get_initial_state` now propagates errors if IDs cannot be fetched, rather than unsafely defaulting to `[0u8; 32]`.
- **Test Fallout:** Changes to `ToxEvent` and `model` signatures required extensive updates to `update_test.rs`, `tester.rs`, `model_test.rs`, and `persistence_real_test.rs`.

### Retrospective: Phase 1 (Part 2)
- **StableId Definition:** Introduced `StableId` enum in `model.rs` (wrapping `PublicKey`, `ChatId`, `ConferenceId`) instead of reusing `WindowId` immediately. This allows for a smoother transition where `Conversation` can hold both its current transient `WindowId` (implicitly by being keyed in the map) and its permanent `StableId`.
- **Reconciliation Logic:** The `reconcile` function now creates a temporary `HashMap<StableId, WindowId>` from the *old* state before processing the new list. This allows it to detect if a Group with `ChatId X` was previously known as `GroupNumber 1` but is now `GroupNumber 5`, and correctly move the conversation history to the new window key.
- **Persistence Testing:** Updated `persistence_proptest.rs` to include strategies for `ChatId`, `ConferenceId`, and `StableId`, ensuring that the new `stable_id` field in `Conversation` is correctly serialized and deserialized.
- **Event Handling:** `ToxEvent::GroupCreated` and `ConferenceCreated` handlers in `update.rs` were updated to immediately stamp the new `Conversation` with its `StableId`, ensuring that even brand new conversations are ready for persistence from the start.

---

### Phase 2: Stable Worker Interface (The Communication)
**Goal:** Decouple UI-to-Worker intent from numeric IDs.

- **[x]** **[worker.rs]** Implement lookup helpers:
    - `fn find_friend(pk) -> Option<FriendNumber>` (via `tox.lookup_friend`)
    - `fn find_group(chat_id) -> Option<GroupNumber>` (via iteration over groups)
    - `fn find_conference(id) -> Option<ConferenceNumber>` (via `tox.conference_by_id`)
- **[x]** **[msg.rs]** Update `ToxAction` variants to accept stable IDs (e.g., `SendMessage(PublicKey, ...)`).
- **[x]** **[worker.rs]** Update the `ToxAction` handler loop to resolve stable IDs to numbers before calling `toxcore` APIs.
- **[x]** **[commands/*.rs]** Update all command call sites (e.g., `commands/chat.rs`, `commands/multi_user.rs`) to pass stable IDs from the model to the worker.

**Checkpoint 2:** The UI no longer sends numeric IDs to the worker.

---

### Phase 3: Core Model Refactor (The Heart)
**Goal:** Completely remove numeric IDs as primary keys in the model.

- **[x]** **[model.rs]** Redefine `WindowId` variants to use stable IDs.
- **[x]** **[model.rs]** Update `DomainState.friends`, `DomainState.conversations`, and `UiState.window_state` `HashMap` keys.
- **[x]** **[update.rs]** Refactor `handle_tox_event`:
    - Most events from `toxcore` will still arrive with numbers.
    - The handler must now use a temporary mapping (or scan the model) to find the `WindowId(StableID)` corresponding to the numeric ID in the event.
- **[x]** **[ui.rs, sidebar.rs, etc.]** Update all UI rendering code to use the new stable keys.

**Checkpoint 3:** The application core is fully stable-ID-driven. Transient numbers are handled as a translation layer in `update.rs`.

---

### Phase 4: Extremities & Cleanup (The Finish)
**Goal:** Finalize peer and file tracking.

- **[x]** **[model.rs]** Change `PeerId` to be just a `PublicKey` (Struct `PeerId(PublicKey)`).
- **[x]** **[update.rs]** Update group peer logic: use the `GroupPeerJoin` event (which has both number and PK) to populate the model and `SessionState`, then use `SessionState` for reverse lookups.
- [x] **[msg.rs / worker.rs / io.rs]** Transition file transfer tracking to use `FileId` (Completed: `IOAction` now uses `PublicKey` instead of `FriendNumber`, and `model.rs` keys by `(PublicKey, FileNumber)`).
- [x] **[Cleanup]** Remove all deprecated numeric fields from `model.rs` and `msg.rs`.

### Retrospective: Phase 4 (PeerId Refactor)
- **PeerId Struct:** Converted `PeerId` enum to a struct wrapping `PublicKey`.
- **Session Mapping:** Added `group_peer_numbers` to `SessionState` to map `(GroupNumber, GroupPeerNumber) -> PublicKey`. This allows the UI to use stable PKs while the worker can still resolve numeric IDs for commands (like `ignore`).
- **Deduplication:** Added explicit peer deduplication in `reconcile` to prevent duplicate peer entries in the UI list when reloading state.
- **Default Naming:** Restored "Group X" / "Conference X" default naming convention by checking `SessionState` when creating windows, fixing a regression where they were just named "Group" or "Conference".

**Checkpoint 4:** Refactoring complete. Total decoupling achieved.

---

## 4. File Impact Matrix

| File | Phase 1 | Phase 2 | Phase 3 | Phase 4 |
| :--- | :---: | :---: | :---: | :---: |
| `toxxi/src/msg.rs` | High | High | - | High |
| `toxxi/src/model.rs` | Medium | - | High | High |
| `toxxi/src/worker.rs` | Medium | High | - | Medium |
| `toxxi/src/update.rs` | Medium | - | High | Medium |
| `toxxi/src/commands/*.rs` | - | High | - | - |
| `toxxi/src/ui.rs` | - | - | Medium | - |
| `toxxi/src/io.rs` | - | - | - | Medium |

## 5. Architectural Insights & Lessons Learned

### The "SessionState" Translation Layer
"Decoupling" the UI from numeric IDs did not mean deleting them. `toxcore` APIs strictly require numeric IDs (e.g., `GroupPeerNumber`) for actions like executing commands.
*   **Insight:** `SessionState` is not just a cache; it is a critical translation layer. We moved numeric IDs out of the *Persistent Model* (`DomainState`) and into the *Runtime Session* (`SessionState`).
*   **Example:** `group_peer_numbers` was added specifically to map stable `PublicKey` back to transient IDs for the `/ignore` command.

### Reconciliation Philosophy
The `reconcile` function is designed to **preserve history**, not strictly mirror the connected state.
*   **Insight:** If a friend or group is missing from the startup list (disconnected), the UI must preserve the conversation window. Refactoring tests revealed that we must assert *existence* of data rather than *absence* during reconciliation updates.

### Default Naming & Transient IDs
User-friendly default names (e.g., "Group 1", "Conference 5") depend on the transient numeric ID.
*   **Insight:** Even when windows are keyed by stable hash (`ChatId`), the UI needs to peek into `SessionState` during window creation to generate these helpful titles, otherwise users just see "Group".

### Test Coupling
The refactor revealed high coupling between unit tests and internal data structures.
*   **Observation:** Changing `PeerId` from an enum to a struct required updates across almost every test file because tests constructed `PeerInfo` manually. Future improvements should utilize centralized test-data factories to minimize refactor overhead.
