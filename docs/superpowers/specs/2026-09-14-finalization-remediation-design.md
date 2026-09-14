# Finalization Security Remediation Design

## Purpose

Close the final review gaps so finalization is operationally usable while preserving launcher-owned authority and fail-closed behavior.

## Pre-Transfer Failure Cleanup

The sandbox returns a child identifier before evidence validation. If that evidence is malformed, stale, forged, or otherwise invalid, the launcher must invoke `kill_finalization_child` and `wait_finalization_child` for that identifier before closing the transport. It must attempt both actions independently and retain both failures in an `ExceptionGroup`; it may not silently leave a child alive.

## Procfs Isolation Proof

Before finalization FDs are transferred, the sandbox runs a fixed child probe that attempts to open the launcher's bootstrap descriptor path. The signed preparation evidence includes `bootstrap_fd_access` with the sole accepted value `denied`, bound to challenge, child ID, sandbox identity, namespace inodes, and the empty child FD table. The launcher rejects every other value. A real Unix-socket integration test runs the probe path and proves access to `/proc/$PPID/fd/8` is denied before capability transfer.

## Durable Bridge Completion

The protected bridge client accepts a deadline derived from the finalization descriptor and applies it to the entire write/read transaction. The finalization service converts handler exceptions and deadline expiry to a signed terminal error `FinalizationResponse`, atomically writes it as `completed`, and returns the same signed error for a replay of the nonce. A nonce may not remain persistently `consumed` after a terminal failure.

## Protected Git Executor

Bootstrap composition constructs `ProcessGitExecutor` from protected launcher descriptors and injects it into `GitGuard`. The executor runs only allowlisted Git invocations under launcher-owned policy and returns trusted command evidence. Finalization uses this executor for reconciliation, commit, and push paths; ticket child processes never receive Git credentials or executor descriptors.

## Failure Rules

- Missing, malformed, or unauthorized sandbox evidence kills and reaps the prepared child before the launcher reports failure.
- A failed kill and failed reap are both surfaced to the caller.
- Any bridge I/O deadline or handler failure produces a durable signed error response.
- Missing protected Git execution capability prevents finalization before any unprotected Git invocation.

## Verification

- Regression coverage simulates invalid pre-transfer evidence and asserts kill plus reap.
- A real child probe verifies denied procfs access to FD 8 and receives no capabilities until verification succeeds.
- Bridge timeout and handler exception tests verify a stable signed replay response.
- Bootstrap composition test drives a valid finalization through a fake protected Git executor without running Git.
