# Merkle-Tox Sub-Design: Client & Policy Layer

## Overview

Merkle-Tox separates **Mechanism** from **Policy**. The `merkle-tox-core`
provides the mechanisms (DAG synchronization, verification, and chunking), while
the `merkle-tox-client` layer implements the policies required for a realistic
group chat experience (auto-authorization, key management, and materialized
views).

## 1. Core vs. Client Responsibilities

### `merkle-tox-core` (Mechanisms)

-   **Policy-Free**: No opinions on who is an Admin or when to rotate keys.
-   **Poll-Based**: Strictly deterministic and portable state machine.
-   **Atomic**: Handles raw packets and reassembly events.

### `merkle-tox-client` (Policies)

-   **Policy-Driven**: Implements the "Standard Tox Group" protocol.
-   **Automated Orchestration**: Auto-authors `AuthorizeDevice` and `KeyWrap`
    nodes for verified peers.
-   **Async-First**: Provides a high-level `tokio`-friendly API.
-   **Materialized View**: Maintains the current state of a chat (title, topic,
    member list) in memory.

## 2. The Orchestration Loop

The Client layer implements an orchestrator that watches for `NodeEvent`s from
the Core and takes action based on the configured `PolicyHandler`.

### Auto-Authorization Flow

1.  **Peer Connection**: Core emits `PeerHandshakeComplete`.
2.  **Policy Check**: Orchestrator asks policy: "Should I authorize this peer?"
3.  **Action**: If yes and local node is an Admin, author an `AuthorizeDevice`
    node for the peer.

### Auto-Key Exchange

1.  **Auth Confirmed**: Core emits `NodeVerified` (AuthorizeDevice).
2.  **Action**: Orchestrator authors a `KeyWrap` node containing the encrypted
    $K_{conv}$ for the newly authorized peer.

## 3. High-Level API

The Client layer provides a simplified interface for applications like `toxxi`
and `vaultbot`.

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

To support diverse use cases (e.g., public forums, private groups), the Client
uses a `PolicyHandler` trait.

```rust
pub trait PolicyHandler: Send + Sync {
    /// Decide whether to automatically authorize a device.
    fn should_authorize(&self, device_pk: &PublicKey) -> bool;

    /// Decide when to perform proactive key rotations.
    fn should_rotate_keys(&self, state: &ChatState) -> bool;
}
```

## 5. Tradeoffs and Sophistication

-   **Wrapper Mode**: The Client owns the Node. Easiest for 99% of apps.
-   **Controller Mode**: The Client acts as an external agent. Required for the
    **Workbench** to allow for fault injection (e.g., refusing to share keys to
    test sync stalls).
-   **Consistency**: The materialized view is eventually consistent.
    Applications should listen to the `ClientEvent` stream for state updates.
