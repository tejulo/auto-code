# Finalization Launcher Boundary Design

**Date:** 2026-09-13
**Status:** Approved for specification review

## Objective

Complete Task 3 finalization without exposing Git, Linear, signing, state, artifact, or Active Run Index capabilities to the ticket runner. A finalization request must be accepted only by a launcher-owned service whose authority is bound to one Active Run. The terminal release of that run must remain exactly recoverable across a crash.

## Scope

This change replaces the test-only finalization composition with a launcher-owned composition, provisions a dedicated finalization trust anchor during the Preparation Transaction, and makes index release durably reconciled.

It does not change Crew Iteration budgets, browser validation, repair activation, Git commit semantics, or Linear finalization ordering.

## Decision

Use a dedicated finalization Ed25519 key pair, distinct from the Repair activation key. The launcher keeps the private key outside the target repository. Preparation stores the immutable public key and SHA-256 hash in the Active Run. A ticket process receives only a signed, short-lived capability descriptor and a verified public trust envelope through protected file descriptors.

Finalization execution belongs to a launcher-owned entrypoint. The target repository CLI remains an identifier-only IPC client and must not construct a finalizer, supply a callback, load an artifact, or accept a signing key.

## Components

### Immutable Finalization Trust

`RunState` gains `finalization_public_key` and `finalization_public_key_hash`. Preparation writes both atomically when it creates the Active Run. Later transitions preserve both fields. A mismatch, absent field, malformed key, or hash mismatch invalidates finalization and enters Human Review without external effects.

The capability descriptor binds:

- operation, repository identity, Active Run ID, expected state revision and generation hash;
- request identifiers and receipt correlation where applicable;
- authoritative state root;
- dedicated finalization public-key hash;
- expiry, nonce, deadline, and pinned Unix-socket identity.

Descriptor and response validation always receives an expected state root and expected dedicated key hash. There is no optional verification mode. The client rejects all input before connecting when the descriptor, state, public key, hash, run, revision, generation, or socket identity differs.

### Launcher-Owned Finalization Service

A launcher entrypoint runs outside the target repository and alone constructs the service. It owns the finalization private key, `RunStateStore`, `ActiveRunIndex`, trusted Linear/MCP bridge, Git guard, project policy, and authoritative artifact authority.

The launcher entrypoint:

1. Loads the exact Active Run and validates its finalization public key/hash.
2. Constructs the internal finalizer and handler set from launcher-owned objects.
3. Issues descriptor and trust-envelope FDs only for the exact run and expected generation.
4. Serves one bounded IPC request, durably records nonce lifecycle and response, and closes the capability.

Internal implementation classes may remain implementation details, but no installed ticket command or library API may compose them from caller-provided keys, handlers, Git objects, index objects, Linear gateways, or artifact callbacks. Tests use a launcher harness that invokes the same service protocol rather than a ticket-facing factory.

### Authoritative Artifacts

The launcher artifact authority derives ticket identity, snapshot hash, original state, and external revision exclusively from the persisted `PreparationContextAuthority` for the Active Run. It loads review manifests, approvals, verification evidence, browser decision/results, build identity, and trusted receipts by their hashes recorded in the run state.

It rejects missing, duplicate, malformed, or hash-mismatched artifacts. No artifact supplied by an IPC client can replace the prepared ticket baseline. The finalizer still re-fetches the trusted Linear projection before any Git effect.

### Durable Index Release

`ActiveRunIndex.release()` writes and fsyncs an `IndexReleaseReceipt` before removing the exact index record. The receipt binds repository ID, run ID, prior index revision/hash, terminal state generation hash, and a deterministic release record hash. It is stored under the authoritative state root and cannot be synthesized from an absent index.

Finalization persists the exact receipt binding as part of the allowed terminal release-marker transition. If a process crashes after the index removal but before that CAS, recovery loads and verifies the receipt against the persisted release binding and terminal state. It then marks `finalization_index_released` true. An absent index without a matching receipt is unsafe and transitions to Human Review.

## Data Flow

1. Preparation provisions the dedicated finalization public key/hash in the new Active Run.
2. The launcher loads the run and starts its composed finalization service.
3. The launcher emits descriptor/trust FDs bound to that run and its state root.
4. The ticket CLI sends only the descriptor-selected operation identifiers through the pinned socket.
5. The service validates trust, nonce, request, and state; invokes its internally composed finalizer; and stores the signed response.
6. The finalizer completes Git/Linear reconciliation, persists `DONE`, records the verified release receipt, and releases the Active Run Index exactly once.
7. Restart recovery uses the durable receipt to complete only the pending release-marker CAS.

## Failure Handling

- Trust, descriptor, socket, state, artifact, ticket projection, or receipt mismatch fails closed before effects.
- A consumed nonce without completed response fails closed; a completed nonce returns the exact durable response.
- Retryable transport failures persist next eligibility and total wait accounting without advancing a Crew Iteration.
- Any failed index receipt verification or absent receipt for a missing index enters Human Review rather than inferring success.

## Verification

Tests must prove:

- a descriptor and trust envelope signed by an attacker key are rejected even when both FDs are replaced;
- finalization fails when the dedicated key/hash is missing or does not match the Active Run;
- ticket-facing CLI interfaces cannot provide finalizer dependencies or handlers;
- authoritative artifacts cannot substitute the preparation baseline;
- the service rejects replay, socket replacement, malformed frames, stalled peers, and expired capabilities;
- index release crash recovery succeeds only with a verified exact release receipt and otherwise reaches Human Review;
- focused Task 3 suites, full suite, `compileall`, and `git diff --check` pass.

Browser E2E is not required: this is launcher state, IPC, Git/Linear reconciliation, and durable storage behavior, all validated with deterministic fakes and local Unix sockets.
