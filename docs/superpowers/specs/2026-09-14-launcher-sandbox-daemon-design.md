# Launcher Sandbox Daemon Design

**Date:** 2026-09-14

## Objective

Implement and deploy the launcher-owned sandbox assumed by finalization isolation. It must prove that a finalization child cannot read the launcher's bootstrap FD through procfs before the launcher transfers finalization capabilities.

## Scope

The daemon is installed from this repository and runs as a root-owned systemd service in the Ubuntu VirtualBox VM. It owns a Unix socket at `/run/auto-code/launcher-sandbox.sock` and serves only the versioned launcher sandbox protocol.

The daemon is not a general command execution service. It accepts only the existing finalization child lifecycle operations and launcher process-runner requests after authenticating its local peer.

## Trust Boundary

The launcher retains bootstrap descriptors, finalization keys, bridge transport, Git capabilities, and authoritative state. The ticket child is untrusted until it has received only the minimum finalization FDs after verified isolation.

The daemon is trusted to create the isolation boundary and to sign evidence. Its Ed25519 public key, identity, and socket path are bound by the launcher bootstrap descriptor. The daemon private key is root-readable only and is never exposed to ticket children.

## Socket Service

The daemon listens only on `/run/auto-code/launcher-sandbox.sock`. systemd creates `/run/auto-code` through `RuntimeDirectory=auto-code`; the socket is owned by root and access is limited to the launcher service group.

On every connection, the daemon obtains `SO_PEERCRED` and rejects peers outside the configured launcher UID/GID policy. It validates the complete versioned request schema before taking any action. Requests must carry the configured sandbox identity. Malformed, unknown, or unauthorised operations fail without creating a child.

The daemon signs all child evidence over the canonical payload already verified by `LauncherSocketSandbox`, including the request challenge and configured sandbox identity.

## Child Preparation

For `prepare_finalization_child`, the daemon:

1. Validates the fixed finalization argv contract and creates a child with no finalization capability FDs.
2. Creates a new PID namespace and mount namespace for the child.
3. Mounts a new procfs instance inside that mount namespace.
4. Drops the child to the configured unprivileged UID/GID before it executes ticket code.
5. Runs a daemon-controlled, fixed probe in that child context which attempts to open `/proc/$PPID/fd/8`.
6. Records `bootstrap_fd_access: "denied"` only when the attempted open fails with an access or absence error.
7. Returns a signed evidence record containing `child_id`, challenge, namespace inodes, an empty initial FD table, and the probe result.

The probe is not provided by the ticket argv and cannot be skipped or substituted by caller-controlled output. Any successful open, unexpected error, missing namespace, failure to drop privilege, or failure to construct evidence causes the daemon to kill and reap the child and return failure.

The launcher must continue to reject any evidence other than signed `bootstrap_fd_access: "denied"`, and must kill/reap a child when pre-transfer evidence fails validation.

## Capability Transfer And Lifecycle

Only `transfer_finalization_capabilities` may pass the three approved descriptors using `SCM_RIGHTS`, and only after a successful preparation probe. The daemon verifies the exact count and expected FD positions, then returns signed post-transfer FD-table evidence.

The daemon holds minimal child state (`child_id`, pid or pidfd, namespace metadata, lifecycle status) until `wait_finalization_child` reaps it. `kill_finalization_child` and `wait_finalization_child` are idempotent. On client disconnect, protocol timeout, invalid follow-up request, or daemon-side invariant violation, it kills and reaps every child still associated with that connection.

## Systemd Deployment

The package provides `auto-code-launcher-sandbox.service` and a root-only configuration file that identifies:

- socket path and launcher group;
- sandbox identity;
- daemon Ed25519 private-key path;
- unprivileged child UID/GID;
- allowed finalization executable and runtime roots;
- lifecycle and protocol timeouts.

The service starts as root because namespace and procfs mount setup require privilege. It exposes no network listener and runs no ticket code as root. The daemon drops to the configured unprivileged identity before executing the child. Its systemd unit restricts filesystem access to required runtime, executable, state, evidence, and controlled-home paths; it does not grant broader network or device access.

The bootstrap producer must publish the same absolute socket path, sandbox identity, and daemon public key in the signed finalization bootstrap descriptor. A missing socket, mismatched peer, socket replacement, identity mismatch, or signature mismatch fails closed.

## Verification

Unit tests cover request validation, peer credential rejection, canonical signing, lifecycle cleanup, descriptor count validation, and all fail-closed paths.

Privileged Linux integration tests start the actual daemon, prepare a child, and prove the fixed child probe cannot open `/proc/$PPID/fd/8` before FD transfer. They also verify that an attempted successful access kills/reaps the child and that capabilities cannot transfer without signed denial evidence.

Deployment verification installs the unit in the Ubuntu VM, starts it through systemd, confirms socket ownership and permissions, invokes the installed finalization launcher, and records the signed evidence. CI runners without Linux namespace/mount privileges may skip the privileged integration suite only with an explicit skip reason; mocked signed evidence is not an acceptable substitute for the deployment gate.

## Non-Goals

- Supporting arbitrary commands or caller-selected isolation policies.
- Replacing the protected bridge, Git executor, or finalization service.
- Providing container or network isolation beyond what finalization requires.
