# Merkle-Tox Sub-Design: Transport Layer (`tox-sequenced`)

## Overview

Tox custom packets are lossy and have a limited MTU (~1.3KB). The
`tox-sequenced` layer provides a reliable delivery mechanism over these packets
to support syncing large Merkle nodes and binary blobs.

## 1. Transport Header

Every custom packet is serialized as a **MessagePack Positional Array**. The
first element is always the `packet_type` discriminator. The second element is
the **Payload**, which is wrapped in a nested array if it contains multiple
fields.

**Packet Structure (Positional Array):**

Index | Data (Type 0) | Ack (Type 1) | Nack (Type 2) | Ping (Type 3) | Pong (Type 4) | Datagram (Type 5)
:---- | :------------ | :----------- | :------------ | :------------ | :------------ | :----------------
0     | `0x00`        | `0x01`       | `0x02`        | `0x03`        | `0x04`        | `0x05`
1     | `[Payload]`   | `[Payload]`  | `[Payload]`   | `t1 (origin)` | `[Payload]`   | `[Payload]`

**Payload Structure:**

Type     | Field 0       | Field 1          | Field 2           | Field 3 | Field 4
:------- | :------------ | :--------------- | :---------------- | :------ | :------
Data     | `message_id`  | `fragment_index` | `total_fragments` | `data`  | -
Ack      | `message_id`  | `base_index`     | `bitmask`         | `rwnd`  | -
Nack     | `message_id`  | `missing_ids`    | -                 | -       | -
Pong     | `t1 (origin)` | `t2 (receive)`   | `t3 (trans)`      | -       | -
Datagram | `msg_type`    | `data`           | -                 | -       | -

**Overhead:** MessagePack array framing (~2-3 bytes) + integer varints.
**Remaining Space:** ~1350 bytes for payload (`data`).

## 2. Reliability Mechanism: Selective Repeat ARQ

To handle loss efficiently without stalling the stream:

-   **Fragmentation**: Large messages (Nodes, Blobs, Sync Batches) are split
    into fragments.
-   **Acknowledgments**: Receivers send `ACK` packets containing a bitset (map)
    of received fragments for a specific `message_id`.
-   **Retransmission**: The sender only re-sends fragments that were not
    acknowledged after a timeout or upon receiving a `NACK`.
-   **Reassembly**: Once all fragments for a `message_id` are received, the
    original data is reconstructed and passed to the logic layer.

## 3. Flow & Congestion Control

-   **Sliding Window**: Limits the number of in-flight fragments to prevent
    overwhelming the peer or the Tox network.
-   **Dynamic Timeouts**: Timeouts for retransmission are calculated based on
    observed Round-Trip Time (RTT).

## 4. Packet Types (Transport Header)

The `packet_type` field identifies the variant of the positional array.

-   **0 (`DATA`)**: Carries a fragment of a high-level message. Structure: `[0,
    message_id, fragment_index, total_fragments, data]`
-   **1 (`ACK`)**: Acknowledges receipt and provides flow control. Structure:
    `[1, message_id, base_index, bitmask, rwnd]`
-   **2 (`NACK`)**: Requests retransmission of specific fragments. Structure:
    `[2, message_id, missing_ids]`
-   **3 (`PING`)**: Keep-alive and RTT measurement. Structure: `[3, timestamp]`
-   **4 (`PONG`)**: Response to PING. Structure: `[4, timestamp]`
-   **5 (`DATAGRAM`)**: Single-packet unreliable message. Structure: `[5,
    message_type, data]`

## 5. High-Level Message Types (DATA Payload)

When a `DATA` message is reassembled, the payload begins with a 1-byte **Message
Type** to route it to the correct subsystem:

| ID     | Message Type           | Subsystem    | Description                |
| :----- | :--------------------- | :----------- | :------------------------- |
| `0x01` | `CAPS_ANNOUNCE`        | Capabilities | Handshake / Features       |
| `0x02` | `CAPS_ACK`             | Capabilities | Handshake Acknowledgment   |
| `0x03` | `SYNC_HEADS`           | Sync Logic   | Advertises DAG tips + CAS  |
:        :                        :              : Inventory                  :
| `0x04` | `FETCH_BATCH_REQ`      | Sync Logic   | Request multiple nodes     |
| `0x05` | `MERKLE_NODE`          | Sync Logic   | A single DAG node          |
| `0x06` | `BLOB_QUERY`           | CAS          | "Do you have this hash?"   |
| `0x07` | `BLOB_AVAIL`           | CAS          | "I have it, size = X, Bao  |
:        :                        :              : root = Y"                  :
| `0x08` | `BLOB_REQ`             | CAS          | Request specific chunk     |
| `0x09` | `BLOB_DATA`            | CAS          | Fragmented blob data + Bao |
:        :                        :              : proof                      :
| `0x0A` | `SYNC_SKETCH`          | Sync         | IBLT Set Reconciliation    |
| `0x0B` | `SYNC_RECON_FAIL`      | Sync         | IBLT Decoding Failure      |
| `0x0C` | `SYNC_SHARD_CHECKSUMS` | Sync         | Shard Checksums for large  |
:        :                        :              : history                    :
| `0x0D` | `HANDSHAKE_ERROR`      | Capabilities | Signal for invalid pre-key |
:        :                        :              : during X3DH exchange       :
| `0x0E` | `RECON_POW_CHALLENGE`  | Sync         | IBLT Anti-DoS Challenge    |
| `0x0F` | `RECON_POW_SOLUTION`   | Sync         | IBLT Anti-DoS Solution     |

## 6. Heartbeats & Keep-alive

To ensure the stability of the `NetworkClock` and maintain the reliability
session during idle periods, implementations MUST adhere to the following
heartbeat rules:

*   **Mandatory PING**: A session MUST send a `PING` packet at least once every
    **60 seconds** if no other traffic has been sent.
*   **Active Sync**: During a synchronization or bulk data transfer, the
    heartbeat interval SHOULD be reduced to **10 seconds** to maintain accurate
    RTT and clock offset measurements.
*   **Timeouts**: A session is considered timed out if no valid packets (Data,
    Ack, or Pong) are received for **5 minutes**.

## 7. Pipelining & Multi-Source Rules

To maximize efficiency in a swarm-based synchronization:

-   **Message Parallelism**: `tox-sequenced` MUST support multiple concurrent
    `message_id`s. This allows fetching a DAG batch (Msg 1) while simultaneously
    downloading blob chunks (Msg 2, 3, 4) from the same peer.
-   **Peer Aggregation**: When downloading a single blob from multiple sources,
    the logic layer allocates unique `fragment_index` ranges or separate
    `message_id`s per peer to avoid collisions during reassembly.
-   **Congestion Window**: The sliding window is managed per-peer to ensure that
    one slow member of a swarm doesn't stall the overall progress.

## 8. Hard Limits and Constraints

To prevent Denial of Service (DoS) and resource exhaustion attacks, the
following limits are enforced (see `merkle-tox.md` for the full list of Protocol
Constants):

-   **MAX_MESSAGE_SIZE**: Total reassembled message size limit.
-   **MAX_INFLIGHT_MESSAGES**: Maximum concurrent reassemblies per peer.
-   **Cycle Detection**: The logic layer MUST reject any node that creates a
    circular dependency in the DAG.
