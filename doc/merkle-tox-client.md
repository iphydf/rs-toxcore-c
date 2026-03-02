# Merkle-Tox Sub-Design: Client & Policy Layer

## Overview

Merkle-Tox separates **Mechanism** from **Policy**. `merkle-tox-core` provides
mechanisms (DAG synchronization, verification, chunking). `merkle-tox-client`
implements policy (auto-authorization, key management, materialized views).

## 1. Core vs. Client Responsibilities

### `merkle-tox-core` (Mechanisms)

-   **Policy-Free**: No opinions on who is an Admin or when to rotate keys.
-   **Poll-Based**: Deterministic and portable state machine.
-   **Atomic**: Handles raw packets and reassembly events.

### `merkle-tox-client` (Policies)

-   **Policy-Driven**: Implements the "Standard Tox Group" protocol.
-   **Automated Orchestration**: Auto-authors `AuthorizeDevice` and `KeyWrap`
    nodes for verified peers.
-   **Async-First**: Provides a high-level `tokio`-friendly API.
-   **Materialized View**: Maintains the current state of a chat (title, topic,
    member list) in memory.

## 2. The Orchestration Loop

The Client implements an orchestrator watching `NodeEvent`s to execute actions
via `PolicyHandler`.

### Auto-Authorization Flow

1.  **Peer Connection**: Core emits `PeerHandshakeComplete`.
2.  **Policy Check**: Orchestrator queries policy: "Should I authorize this
    peer?"
3.  **Action**: If true and local node is Admin, author `AuthorizeDevice`.

### Auto-Key Exchange

1.  **Auth Confirmed**: Core emits `NodeVerified` (AuthorizeDevice).
2.  **Action**: Orchestrator authors `KeyWrap` containing $K_{conv}$ for the
    peer.

## 3. High-Level API

The Client provides an interface for applications.

```rust
impl MerkleToxClient {
    /// High-level text message sending.
    pub async fn send_message(&self, text: String) -> Result<Hash>;

    /// Adjust room settings (Admin only).
    pub async fn set_title(&self, title: String) -> Result<Hash>;

    /// Returns the current materialized state of the conversation.
    pub fn state(&self) -> ChatState;
}
```

## 4. Policy Customization

The Client uses `PolicyHandler` to customize behavior.

```rust
pub trait PolicyHandler: Send + Sync {
    /// Decide whether to automatically authorize a device.
    fn should_authorize(&self, device_pk: &PublicKey) -> bool;

    /// Decide when to perform proactive key rotations.
    fn should_rotate_keys(&self, state: &ChatState) -> bool;
}
```

## 5. Deployment Modes

-   **Wrapper Mode**: The Client owns the Node.
-   **Controller Mode**: The Client acts as an external agent (used by the
    **Workbench** for fault injection).
-   **Consistency**: The materialized view is eventually consistent.
    Applications MUST listen to the `ClientEvent` stream for updates.
