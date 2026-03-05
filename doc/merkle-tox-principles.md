# Merkle-Tox Principles

Defines protocol principles to ensure performance optimizations and security
hardening do not compromise Tox ecosystem values.

## 1. Plausible Deniability (DARE Model)

*   **Principle**: No participant or observer should be able to
    cryptographically prove to a third party that a specific logical identity
    authored a specific content node.
*   **Implementation**: Use **Ephemeral Ed25519 Signatures** with intentional
    key disclosure for all conversation content. During the active epoch, only
    the sender holds the signing key (internal authentication). After epoch
    rotation, the key is disclosed to all members, making past signatures
    forgeable (deniability). Separate non-repudiable management (permanent
    signatures for Admin nodes) from deniable communication (ephemeral
    signatures for Content nodes).
*   **Trade-off**: Deniability is delayed until the epoch rotation (≤7 days /
    5,000 messages). During the active epoch, signatures are non-repudiable to
    group members.

## 2. Strict Metadata Privacy

*   **Principle**: Observers and network relays must be blinded to the identity
    of senders, the volume of messages, and the sequence of interactions.
*   **Implementation**: Sensitive metadata (`sender_pk`, `sequence_number`) is
    encrypted within the `WireNode`. All packets are padded to power-of-2
    boundaries using ISO/IEC 7816-4.

## 3. Temporal Fingerprinting Protection

*   **Principle**: Minimize the ability of peers to track users across sessions
    or conversations using precise hardware-clock offsets (Temporal
    Fingerprinting).
*   **Implementation**:
    *   **Timestamp Jitter**: The `tox-sequenced` layer SHOULD inject a small
        amount of random noise (between `-TIME_JITTER_MS` and `+TIME_JITTER_MS`,
        where `TIME_JITTER_MS = 5`) into the PING/PONG timestamps, preventing a
        peer from calculating a machine-unique microsecond-level offset.
    *   **Coarse-Grained Synchronization**: While internal RTT measurements
        require precision for congestion control, the publicly-visible
        `network_timestamp` in the DAG and the offsets shared with peers should
        be treated as fuzzy values.
*   **Rationale**: Precise machine time is a "sticky" identifier. Adding jitter
    maintains sufficient accuracy for DAG linearization and median consensus
    while breaking the precision needed for reliable cross- session tracking.

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
    (e.g., a Snapshot), protecting the buffer from deep-ancestry DoS attacks. If
    a conversation has gaps in the Admin track larger than 500 hops, a new
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
*   **Rationale**: Authorized peers are not necessarily trusted. They may
    observe behavior or attempt disruption.

## 9. Marginal Tox Transport Coupling

*   **Principle**: Merkle-Tox uses Tox only as the cheapest possible
    authenticated lossy datagram substrate. It MUST NOT depend on
    higher-level Tox machinery (lossless delivery, in-order delivery,
    fragmentation, retransmission, message ACKs, send queues). All
    reliability and ordering semantics are provided by Merkle-Tox's
    own application layer.
*   **Implementation**:
    *   All custom packets sent over Tox use *lossy* modes only:
        `tox.friend.send_lossy_packet` for direct-friend transport,
        `gc_send_custom_*_packet(lossless=false, ...)` for NGC transport.
        Lossless modes (`tox.friend.send_message`, NGC `lossless=true`)
        MUST NOT be used by Merkle-Tox.
    *   `tox-sequenced` provides congestion control, pacing, and
        rate limiting over lossy datagrams. It does not provide
        reliability or in-order delivery (see
        [merkle-tox-transport.md](merkle-tox-transport.md)).
    *   Reliability comes from Merkle-Tox's DAG sync: peers know
        what nodes they are missing and request them explicitly.
        Lost packets are recovered by application-level resync,
        not by transport-level retransmission.
    *   Application-layer state machines (sync exchanges, blob
        transfer, handshake responses) use explicit request-IDs
        and timeouts rather than relying on transport ordering.
*   **Rationale**:
    1.  **Avoids redundant reliability.** c-toxcore's lossless mode
        retransmits blindly without knowing what data Merkle-Tox
        actually wants to resend after a partial loss. The
        application has semantic knowledge — content addressing,
        DAG structure, chunk bitmasks — that the transport lacks.
    2.  **Enables Tox-library simplification.** A future c-toxcore
        whose only customer is Merkle-Tox can drop its lossless /
        ordered packet machinery entirely. The same goal motivates
        not depending on Tox conferences, the legacy chat-message
        types (`GM_PLAIN_MESSAGE`), or per-friend message-ack APIs.
    3.  **Decouples from any specific Tox implementation.** A
        Merkle-Tox client need only assume "send-this-bytes-to-this-pk"
        from its transport substrate. Any datagram protocol with
        authenticated encryption and the right MTU would substitute
        for Tox at the wire layer.
    4.  **Reduces attack surface.** Tox lossless layer has its own
        per-connection state machine, ACK timers, and overflow
        behavior (e.g. c-toxcore NGC `send_array` capacity = 2048,
        connection torn down after 58s of unacked traffic). Not
        depending on it means Merkle-Tox is unaffected by bugs or
        adversarial inputs targeting that machinery.
*   **Trade-off**: Merkle-Tox carries the cost of its own
    reliability/sequencing infrastructure (sync engine, request-ID
    state, `tox-sequenced` congestion control). This is paid once
    at the application layer and benefits from semantic awareness
    of what is being transferred.

## 10. No Privileged Infrastructure

*   **Principle**: No party may occupy a privileged role. Every
    participant and external relay is fungible; the protocol's
    correctness MUST NOT depend on any single party's availability,
    honesty, or non-compromise.
*   **Implementation**: DHT nodes, TCP relays, and blind relays
    operate under cryptographic constraint, not trust.
    Authentication, ordering, and convergence are produced by the
    signed DAG and the verifier state machine. No delivery service,
    directory server, or moderation service role exists.
    Alternatives that reintroduce privileged infrastructure
    (MLS-style delivery service, trusted setup for ZK, central
    identity directory, server-side abuse handling) are not options.
*   **Trade-off**: Capabilities cheap with a trusted server — global
    ordering, account-level moderation, identity discovery, push
    notification routing, encrypted backup escrow — are expensive or
    impossible without one. The design accepts these costs and
    provides in-protocol substitutes (DAG-derived ordering, content
    blacklist nodes, social-recovery key sharing).
