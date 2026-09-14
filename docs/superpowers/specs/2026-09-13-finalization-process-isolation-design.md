# Finalization Process Isolation Design

**Date:** 2026-09-13
**Status:** Approved for specification review

## Objective

Prevent a ticket child from reading launcher-owned bootstrap descriptors or the finalization private key through the parent process, while allowing an installed launcher to complete real Git/Linear finalization and recover bridge timeouts safely.

## Decision

The installed launcher uses the existing launcher-owned sandbox to run the ticket child in a distinct PID namespace or an equivalent procfs-isolated process boundary. The process holding bootstrap FDs 3-9 never becomes a readable parent for the child. The child receives only sealed finalization descriptor, trust, and binding FDs.

The launcher composes `GitGuard` with a protected `ProcessGitExecutor` and verified sandbox capability. The finalization bridge has one total deadline covering request write and response read. When a timeout occurs after the nonce becomes consumed, the launcher writes a signed terminal error response, allowing later invocation of the same nonce to replay that result without a second effect.

## Process Boundary

1. The privileged launcher validates bootstrap capabilities and retains state, index, bridge transport, Git executor, and finalization key in memory.
2. It asks the launcher sandbox to start the ticket command under procfs/PID isolation.
3. The sandboxed child receives only finalization FDs 4-6 and identifier arguments.
4. The launcher validates the child peer and serves one request.
5. The child cannot enumerate or open bootstrap FDs through `/proc/$PPID/fd` or equivalent parent-process paths.

Failure to establish the isolated child boundary fails closed before issuing a capability.

## Git Composition

The bootstrap descriptor binds the verified Git executor/sandbox identity. The launcher constructs `ProcessGitExecutor` from that capability and supplies it to `GitGuard`. The executor permits only the Project Policy allowlisted Git commands. Tests use a deterministic executor/sandbox fake and prove a valid finalization reaches it without a network or repository effect.

## Bridge Deadline And Recovery

Bridge I/O uses the descriptor-configured total deadline. Both send and receive recompute remaining budget before each blocking operation. If the deadline expires after nonce consumption and before a trusted receipt/result exists, the service signs and durably stores an error response for that exact request. Replays return the stored error response; they do not redispatch bridge, Git, or Linear work. Invalid or incomplete bridge frames also follow this terminal-error path.

## Verification

- A sandboxed ticket child cannot read the launcher's bootstrap/key FD through procfs.
- A missing or unsuitable sandbox boundary rejects finalization before child startup.
- A valid finalization invokes the protected Git executor after all approved constraints hold.
- Stalled bridge write/read observes the total deadline and creates one durable signed response.
- Replay after bridge timeout returns that response without another effect.
- Full suite, compilation, whitespace check, and independent review pass.

Browser E2E is not required: the behavior is deterministic process isolation, descriptor handling, bridge I/O, and launcher state.
