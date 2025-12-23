# File Transfer Resumption Plan & Status

## Overview
This document outlines the architectural plan to enable file transfer resumption in Toxxi after an application restart. Currently, Toxxi loses the network session state for transfers upon restart, and its file I/O logic is destructive (truncating files), preventing safe resumption.

## Phase 1: Enable Safe File Resumption (I/O Layer) [COMPLETED]
**Goal:** Prevent data loss when resuming a download. Currently, `File::create` truncates files.

### 1. Modify `toxxi/src/io.rs`
*   **Target:** `IOAction::OpenFileForReceiving` handler.
*   **Change:** Replaced `File::create` with `tokio::fs::OpenOptions`.
*   **Configuration:** `.write(true).create(true).truncate(false)`.
*   **Status:** Done. This ensures that if a partial file exists, we open it for writing without deleting its content.

## Phase 2: Persist Transfer State (Model Layer) [COMPLETED]
**Goal:** Ensure Toxxi remembers transfer details (File ID, file path, file kind) across restarts and can restore the worker's state.

### 1. Modify `toxxi/src/model.rs`
*   **Target:** `FileTransferProgress` struct.
*   **Change:** Added fields to store essential metadata that `toxcore` needs to resume but Toxxi currently forgets:
    *   `file_kind: u32` (needed for sending)
    *   `file_path: Option<String>` (needed for sending, to reopen the source file)
    *   `status: TransferStatus` (Enum: Active, Paused, Broken) to distinguish between a finished transfer and one that needs resuming.
*   **Status:** Done. Model, UI logic, and Tests updated to use `TransferStatus` instead of `paused: bool`.

### 2. Update `toxxi/src/worker.rs` (State Hydration) [ADJUSTED]
*   **Original Plan:** Hydrate worker maps on startup.
*   **Adjustment:** The worker only needs to know about transfers *after* they are active in `toxcore` runtime. Since `toxcore` handles are ephemeral (lost on restart), we only need to provide info when we *re-initiate* the transfer (Resume).
*   **Status:** Skipped explicit hydration. Logic moved to Phase 3 (On-demand resumption).

## Phase 3: Implement Resume Logic (Worker & Protocol Layer) [COMPLETED]
**Goal:** Allow the user to "re-announce" a file with an existing ID (sender side) or seek to the correct position (receiver side).

### 1. Modify `toxxi/src/msg.rs`
*   **Target:** `ToxAction` enum.
*   **Change:** Updated `ToxAction::FileSend` to accept an `Option<FileId>`. Currently, it implies a new file (`None`).
*   **Status:** Done.

### 2. Modify `toxxi/src/worker.rs`
*   **Sending:** Updated `ToxAction::FileSend` handler to pass the optional `FileId` to `tox.file_send`.
*   **Receiving:** Resume logic for receiving is primarily about handling incoming `FileRecv` events for existing IDs (already supported by logic) and sending `FileSeek` (already supported by `worker`).
*   **Status:** Done.

## Phase 4: User Interface & Commands [COMPLETED]
**Goal:** Expose this functionality to the user.

### 1. Modify `toxxi/src/commands/io.rs`
*   **Target:** `/file` command handler.
*   **Changes Needed:**
    *   **Sender Side:** Update `/file send` signature: `file send <friend_id> <path> [resume_file_id]`. If a 3rd argument is provided, parse it as a File ID and include it in the `FileSend` action.
    *   **Receiver Side:** Update `/file accept`. If the file already exists on disk (checked via `model` or IO check), send a `ToxAction::FileSeek` command to the friend to request the specific byte offset where we left off (based on our local file size) *before* sending `FileControl::RESUME`.
*   **Status:** Done. Implemented in `toxxi/src/commands/io.rs`.

## Technical Learnings & Notes for Next Developer
1.  **Tox Protocol Resumption:** Resuming a file send involves calling `file_send` again but passing the *original* `FileId`. This "re-announces" the file to the peer. If the peer recognizes the ID, they can accept it and request a seek.
2.  **Model Migration:** We moved from `paused: bool` to `status: TransferStatus`. This required updating many tests. Future tests should use `TransferStatus`.
3.  **Command Parsing:** The `/file` command currently splits args manually. Adding optional arguments requires careful index handling.
4.  **Seek Logic:** The logic to *automatically* seek on accept is not yet implemented. Currently, if you accept a file that exists, we just open it in append mode. Use `FileSeek` to ensure we don't download duplicate data if the peer starts from 0.

## Next Steps
1.  Open `toxxi/src/commands/io.rs`.
2.  Update `/file send` to parse optional `resume_file_id`.
3.  Update `/file accept` to check for partial completion and issue `FileSeek` if needed.