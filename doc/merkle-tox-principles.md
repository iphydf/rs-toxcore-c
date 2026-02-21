# Merkle-Tox Principles

This document defines the foundational principles of the Merkle-Tox protocol.
These principles serve as a "constitution" for all design decisions, ensuring
that performance optimizations or security hardening do not compromise the
values of the Tox ecosystem.

## 1. Plausible Deniability (DARE Model)

*   **Principle**: No participant or observer should be able to
    cryptographically prove to a third party that a specific logical identity
    authored a specific content node.
*   **Implementation**: Use symmetric Message Authentication Codes (MACs) for
    all conversation content. Separate non-repudiable management (signatures for
    Admin nodes) from deniable communication (MACs for Content nodes).
*   **Trade-off**: We accept **Key Compromise Impersonation (KCI)** for content.
    If a user's key is stolen, an attacker can impersonate others *to that
    user*. This is the mandatory cost of deniability.

## 2. Strict Metadata Privacy

*   **Principle**: Observers and network relays must be blinded to the identity
    of senders, the volume of messages, and the sequence of interactions.
*   **Implementation**: Sensitive metadata (`sender_pk`, `sequence_number`) is
    encrypted within the `WireNode`. All packets are padded to power-of-2
    boundaries using ISO/IEC 7816-4.

## 3. Temporal Fingerprinting Protection

*   **Principle**: The protocol must minimize the ability of a peer to track a
    user's identity across different sessions or conversations using precise
    hardware-clock offsets (Temporal Fingerprinting).
*   **Implementation**:
    *   **Timestamp Jitter**: The `tox-sequenced` layer SHOULD inject a small
        amount of random noise (between `-TIME_JITTER_MS` and `+TIME_JITTER_MS`,
        where `TIME_JITTER_MS = 5`) into the PING/PONG timestamps. This prevents
        a peer from calculating a machine-unique microsecond-level offset.
    *   **Coarse-Grained Synchronization**: While internal RTT measurements
        require precision for congestion control, the publicly-visible
        `network_timestamp` in the DAG and the offsets shared with peers should
        be treated as fuzzy values.
*   **Rationale**: Precise machine time is a "sticky" identifier. By adding
    jitter, we maintain sufficient accuracy for DAG linearization and median-
    based consensus while breaking the precision needed for reliable cross-
    session tracking.

## 4. Byzantine-Resilient Synchronization

*   **Principle**: The protocol must converge to a consistent state across all
    honest peers regardless of network partitions, packet loss, or malicious
    interference.
*   **Implementation**: Use a Directed Acyclic Graph (DAG) for history.
    Reconcile differences using a combination of "Heads-based" sync and
    Invertible Bloom Lookup Tables (IBLT).
*   **Guardrails**: Protect against Denial of Service (DoS) using **Authorized
    Vouching** and **Contiguity-based Eviction** in speculative storage.

## 5. Low-Trust Infrastructure (Blind Relays)

*   **Principle**: History synchronization and data availability must not depend
    on the availability of room members or "trusted" servers.
*   **Implementation**: Use **Structural Vouching** to allow non-member relays
    to serve encrypted history segments that are topologically linked to
    verified Admin nodes.
*   **Current Tension**: The **500-hop Ancestry Cap** limits how much history
    can be fetched from a blind relay without an intermediate Admin "anchor"
    (e.g., a Snapshot). This protects the buffer from deep-ancestry DoS attacks.
    If a conversation has gaps in the Admin track larger than 500 hops, a new
    joiner may require a full group member to come online to "re-anchor" the
    trust.

## 6. High Availability & Offline Support

*   **Principle**: The system must support asynchronous communication, allowing
    users to send and receive messages even when their peers are offline.
*   **Implementation**: Use **Last Resort** pre-keys and **Opportunistic
    Handshakes** for 1-on-1 chats.
*   **Trade-off**: We prioritize availability in 1-on-1 chats (sending
    immediately with a Pulse) while prioritizing security in Group chats
    (buffering until a fresh KeyWrap is received).

## 7. Determinism & Portability

*   **Principle**: The sync logic must be a deterministic state machine,
    independent of system clocks or specific storage backends.
*   **Implementation**: Abstract time via a `TimeProvider` and networking via a
    `Transport` trait. Ensure 1-on-1 `ConversationID`s are derived
    deterministically from Tox shared secrets.

## 8. Zero-Trust Peer Assumption

*   **Principle**: While the Tox transport layer provides authenticated
    encryption against network observers, the protocol logic must assume that
    the peer at the other end of the tunnel is potentially malicious or
    inquisitive (e.g., a SyncBot).
*   **Implementation**:
    *   Protect against **Peer-Level Traffic Analysis** by encrypting timestamps
        and sequence numbers.
    *   Protect against **Algorithmic DoS** (like IBLT poisoning) by using Keyed
        Blake3 with secrets unknown to the peer.
    *   Protect against **Storage-Filling Attacks** by using Authorized Vouching
        to filter sync requests.
*   **Rationale**: A peer who is "authorized" to sync the room's data is not
    necessarily "trusted" to not observe your behavior or attempt to disrupt
    your service.
