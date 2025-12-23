# Tox-Sequenced: Type-System Hardening Plan (Level 8)

## Overview

This document outlines the plan to move the `tox-sequenced` transport layer to **Level 8 (Semantic & Data Safety)**. Following the patterns established in `merkle-tox-core`, we aim to eliminate logic errors arising from unit confusion, state inconsistencies, and sensitive data persistence by utilizing Rust's type system.

--------------------------------------------------------------------------------

## Phase 1: Semantic Labeling (Newtypes)

We have replaced raw primitives (`u32`, `u16`, `i64`) with distinct newtypes to prevent accidental cross-usage and clarify protocol intent.

### 1.1. Protocol Identifiers
-   **`MessageId`**: Uniquely identifies a reliable message within a session.
-   **`FragmentIndex`**: Identifies a specific fragment within a message.
-   **`FragmentCount`**: Represents the total number of fragments or window sizes (rwnd).

### 1.2. Protocol Timing
-   **`TimestampMs`**: NTP-style milliseconds since epoch.

**Status:** COMPLETED. These types use `#[tox(flat)]` for wire compatibility and are integrated across the session, reassembly, and test layers.

--------------------------------------------------------------------------------

## Phase 2: Hardened Physical Quantities (Planned)

Replace raw `usize` and `f32` in congestion control algorithms with types that carry physical meaning.

### 2.1. Dimensional Safety
-   **`Bytes`**: A wrapper for data sizes.
-   **`Bandwidth`**: Represents `Bytes` per second.
-   **`PacingRate`**: A specialized rate for packet scheduling.

### 2.2. Invariants
-   Ensure that `Bandwidth * Duration` correctly yields `Bytes`.
-   Prevent mixing of bits-per-second and bytes-per-second in BBR/Cubic logic.

--------------------------------------------------------------------------------

## Phase 3: Cryptographic Hygiene (Planned)

Ensure that application data buffered during reassembly is handled as sensitive material.

### 3.1. Zeroize Integration
-   Wrap reassembly buffers in `FragmentBuffer` with types that implement `Zeroize`.
-   Ensure that `OutgoingMessage` data is wiped from memory once fully acknowledged or timed out.

--------------------------------------------------------------------------------

## Phase 4: State Machine Hardening (Typestates) (Planned)

Refactor `SequenceSession` from a single large struct into a state machine enforced by the type system.

### 4.1. Session Lifecycle
-   **`Session<Initial>`**: Can only process Pings/Pongs to establish RTT and Clock Offset.
-   **`Session<Active>`**: Full transport capabilities (Data/Ack/Nack).
-   **`Session<Closed>`**: Terminal state, no further packets allowed.

--------------------------------------------------------------------------------

## Phase 5: Protocol-Specific Math (Planned)

Introduction of safe arithmetic wrappers for network calculations.

### 5.1. Network Arithmetic Trait
-   Implement a trait that defaults to `saturating` operations for all protocol newtypes.
-   Prevent overflows in RTT variance and pacing gap calculations even under extreme network jitter.

--------------------------------------------------------------------------------

## Summary of Hardening Goals

Threat Class            | Mitigation (Level 8)       | Tool
:---------------------- | :------------------------- | :---------------------
**ID Confusion**        | Newtypes for IDs/Indices   | Struct Wrappers
**Unit Confusion**      | Dimensional Newtypes       | Explicit Units
**Memory Forensics**    | Zero-on-drop Buffers       | `zeroize` crate
**Invalid State**       | Session Typestates         | Generic State Para
**Math Overflows**      | Saturating Protocol Math   | Arithmetic Traits
