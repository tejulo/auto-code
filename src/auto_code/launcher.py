"""Installed privileged launcher entrypoint.

The ticket-facing CLI never imports this module. Launcher configuration and
credentials are supplied through inherited descriptors rather than arguments.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import socket
import stat
import struct
import sys
import time
from typing import Sequence
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from launcher_finalization import FinalizationArtifactAuthority, FinalizationLauncher, FinalizationLauncherError, _LauncherRuntime

from .contracts import EffectOutcome
from .finalization_service import FinalizationParentCapability
from .git import GitGuard
from .hashing import canonical_json_bytes
from .linear import LinearGateway
from .mcp_bridge import McpToolResult, TrustedLinearBridge
from .process import LauncherSocketSandbox
from .run_index import ActiveRunIndex
from .state import RunStateStore


_BOOTSTRAP_FD = 3
_STATE_FD = 4
_INDEX_FD = 5
_BRIDGE_FD = 6
_GIT_FD = 7
_KEY_FD = 8
_BRIDGE_TRANSPORT_FD = 9
_MAX_BOOTSTRAP_BYTES = 16_384
# Public trust anchor only. The matching launcher-owned private key is not in
# this package. Test harnesses use the matching fixture key through protected FDs.
_BOOTSTRAP_VERIFICATION_KEY = bytes.fromhex("d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737")


class FinalizationLauncherBootstrapError(RuntimeError):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _read_protected(fd: int, *, maximum: int = _MAX_BOOTSTRAP_BYTES) -> bytes:
    try:
        duplicate = os.dup(fd)
    except OSError as error:
        raise FinalizationLauncherBootstrapError("protected descriptor is unavailable") from error
    try:
        metadata = os.fstat(duplicate)
        mode = fcntl.fcntl(duplicate, fcntl.F_GETFL) & os.O_ACCMODE
        if (
            not stat.S_ISREG(metadata.st_mode)
            or mode != os.O_RDONLY
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise FinalizationLauncherBootstrapError("protected descriptor is invalid")
        payload = os.pread(duplicate, maximum + 1, 0)
    except OSError as error:
        raise FinalizationLauncherBootstrapError("protected descriptor is invalid") from error
    finally:
        os.close(duplicate)
    if len(payload) > maximum:
        raise FinalizationLauncherBootstrapError("protected descriptor is invalid")
    return payload


def _read_protected_json(fd: int) -> tuple[dict[str, object], bytes]:
    try:
        raw = _read_protected(fd)
        payload = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise FinalizationLauncherBootstrapError("protected descriptor is invalid") from error
    if not isinstance(payload, dict) or canonical_json_bytes(payload) != raw:
        raise FinalizationLauncherBootstrapError("protected descriptor is invalid")
    return payload, raw


def _require_path(value: object, description: str) -> Path:
    if not isinstance(value, str):
        raise ValueError(f"{description} is invalid")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or path.is_symlink() or not path.is_dir():
        raise ValueError(f"{description} is invalid")
    metadata = path.stat()
    if metadata.st_uid != os.geteuid():
        raise ValueError(f"{description} is invalid")
    return path


def _require_hash(value: object, description: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{description} is invalid")
    return value


def _require_public_key(value: object, description: str) -> bytes:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{description} is invalid")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{description} is invalid") from error


def _require_nonnegative_int(value: object, description: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{description} is invalid")
    return value


def _protected_bridge_transport(expected_identity: tuple[int, int, int, int, int]) -> socket.socket:
    try:
        duplicate = os.dup(_BRIDGE_TRANSPORT_FD)
        metadata = os.fstat(duplicate)
        mode = fcntl.fcntl(duplicate, fcntl.F_GETFL) & os.O_ACCMODE
        if not stat.S_ISSOCK(metadata.st_mode) or mode != os.O_RDWR:
            raise ValueError
        transport = socket.socket(fileno=duplicate)
        credentials = transport.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        peer_pid, peer_uid, peer_gid = struct.unpack("3i", credentials)
        if (
            (metadata.st_dev, metadata.st_ino, peer_pid, peer_uid, peer_gid) != expected_identity
            or peer_uid != os.geteuid()
        ):
            transport.close()
            raise ValueError
        return transport
    except (OSError, ValueError) as error:
        try:
            os.close(duplicate)
        except UnboundLocalError:
            pass
        except OSError:
            pass
        raise FinalizationLauncherBootstrapError("bridge capability is invalid") from error


class _ProtectedBridgeClient:
    """One bridge call over the descriptor-bound Unix-stream capability."""

    def __init__(self, transport: socket.socket, server_identity: str) -> None:
        self._transport = transport
        self._server_identity = server_identity

    def call(self, server_identity: str, tool_name: str, arguments: object, *, deadline: float | None = None) -> McpToolResult:
        if server_identity != self._server_identity or not isinstance(tool_name, str):
            raise RuntimeError("bridge request is invalid")
        if deadline is None:
            deadline = time.monotonic() + 5.0
        if isinstance(deadline, bool) or not isinstance(deadline, (int, float)) or not math.isfinite(deadline):
            raise RuntimeError("bridge deadline is invalid")

        def remaining() -> float:
            timeout = deadline - time.monotonic()
            if timeout <= 0:
                raise RuntimeError("bridge response is unavailable")
            return timeout

        request = canonical_json_bytes(
            {"domain": "auto-code-launcher-bridge-request/v1", "server_identity": server_identity, "tool_name": tool_name, "arguments": arguments}
        ) + b"\n"
        try:
            self._transport.settimeout(remaining())
            self._transport.sendall(request)
            self._transport.settimeout(remaining())
            with self._transport.makefile("rb") as response_stream:
                response = response_stream.readline(_MAX_BOOTSTRAP_BYTES + 1)
        except OSError as error:
            raise RuntimeError("bridge response is unavailable") from error
        if len(response) > _MAX_BOOTSTRAP_BYTES:
            raise RuntimeError("bridge response is invalid")
        try:
            payload = json.loads(response.decode("ascii"), object_pairs_hook=_reject_duplicate_json_keys)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise RuntimeError("bridge response is invalid") from error
        if not isinstance(payload, dict) or set(payload) != {"tool_call_id", "result", "external_revision", "observed_state_id", "outcome", "observations"}:
            raise RuntimeError("bridge response is invalid")
        return McpToolResult(
            tool_call_id=payload["tool_call_id"],
            result=payload["result"],
            external_revision=payload["external_revision"],
            observed_state_id=payload["observed_state_id"],
            outcome=EffectOutcome(payload["outcome"]),
            observations=tuple(payload["observations"]),
        )


def load_protected_bootstrap() -> _LauncherRuntime:
    """Validate launcher-owned descriptors before constructing operational objects."""

    try:
        config, _ = _read_protected_json(_BOOTSTRAP_FD)
        expected = {
            "domain", "state_root", "repository_root", "bridge_identity", "mcp_server_identity", "bridge_fd",
            "state_fd", "index_fd", "git_fd", "key_fd", "state_sha256", "index_sha256", "bridge_sha256",
            "git_sha256", "key_sha256", "bridge_transport_device", "bridge_transport_inode",
            "bridge_transport_peer_pid", "bridge_transport_peer_uid", "bridge_transport_peer_gid",
            "finalization_public_key_hash", "finalization_parent", "sandbox_socket_path", "sandbox_identity", "sandbox_public_key", "signature",
        }
        if set(config) != expected or config["domain"] != "auto-code-launcher-bootstrap/v1":
            raise ValueError
        unsigned_config = dict(config)
        signature = unsigned_config.pop("signature")
        if not isinstance(signature, str) or len(signature) != 128:
            raise ValueError
        Ed25519PublicKey.from_public_bytes(_BOOTSTRAP_VERIFICATION_KEY).verify(bytes.fromhex(signature), canonical_json_bytes(unsigned_config))
        if (
            config["state_fd"] != _STATE_FD
            or config["index_fd"] != _INDEX_FD
            or config["bridge_fd"] != _BRIDGE_FD
            or config["git_fd"] != _GIT_FD
            or config["key_fd"] != _KEY_FD
        ):
            raise ValueError
        state_root = _require_path(config["state_root"], "state root")
        repository_root = _require_path(config["repository_root"], "repository root")
        sandbox = LauncherSocketSandbox(
            Path(_require_path_value(config["sandbox_socket_path"], "sandbox socket")),
            _require_sandbox_identity(config["sandbox_identity"]),
            _require_public_key(config["sandbox_public_key"], "sandbox public key"),
        )
        key_hash = _require_hash(config["finalization_public_key_hash"], "finalization public key hash")
        parent = FinalizationParentCapability.from_payload(config["finalization_parent"])
        parent.verify()
        if not hmac.compare_digest(parent.finalization_public_key_hash, key_hash):
            raise ValueError
        state, state_raw = _read_protected_json(_STATE_FD)
        index, index_raw = _read_protected_json(_INDEX_FD)
        bridge, bridge_raw = _read_protected_json(_BRIDGE_FD)
        git, git_raw = _read_protected_json(_GIT_FD)
        key_bytes = _read_protected(_KEY_FD, maximum=32)
        protected_payloads = (
            ("state", state_raw),
            ("index", index_raw),
            ("bridge", bridge_raw),
            ("git", git_raw),
            ("key", key_bytes),
        )
        for name, raw in protected_payloads:
            if not hmac.compare_digest(hashlib.sha256(raw).hexdigest(), _require_hash(config[f"{name}_sha256"], f"{name} descriptor hash")):
                raise ValueError
        transport_identity = (
            _require_nonnegative_int(config["bridge_transport_device"], "bridge transport device"),
            _require_nonnegative_int(config["bridge_transport_inode"], "bridge transport inode"),
            _require_nonnegative_int(config["bridge_transport_peer_pid"], "bridge transport peer PID"),
            _require_nonnegative_int(config["bridge_transport_peer_uid"], "bridge transport peer UID"),
            _require_nonnegative_int(config["bridge_transport_peer_gid"], "bridge transport peer GID"),
        )
        if state != {"domain": "auto-code-launcher-state/v1", "state_root": str(state_root)}:
            raise ValueError
        if index != {"domain": "auto-code-launcher-index/v1", "state_root": str(state_root), "finalization_public_key_hash": key_hash}:
            raise ValueError
        if (
            not isinstance(bridge, dict)
            or set(bridge) != {"domain", "state_root", "bridge_identity", "mcp_server_identity", "receipt_signing_key", "transport_fd"}
            or bridge["domain"] != "auto-code-launcher-bridge/v1"
            or bridge["state_root"] != str(state_root)
            or bridge["bridge_identity"] != config["bridge_identity"]
            or bridge["mcp_server_identity"] != config["mcp_server_identity"]
            or bridge["transport_fd"] != _BRIDGE_TRANSPORT_FD
            or not isinstance(bridge["receipt_signing_key"], str)
        ):
            raise ValueError
        receipt_key = bytes.fromhex(bridge["receipt_signing_key"])
        if len(receipt_key) < 16:
            raise ValueError
        if (
            not isinstance(git, dict)
            or set(git) != {"domain", "repository_root", "remote", "base_branch", "protected_paths", "commit_excluded_paths"}
            or git["domain"] != "auto-code-launcher-git/v1"
            or git["repository_root"] != str(repository_root)
            or not isinstance(git["remote"], str)
            or (git["base_branch"] is not None and not isinstance(git["base_branch"], str))
            or not all(isinstance(value, str) for value in git["protected_paths"])
            or not all(isinstance(value, str) for value in git["commit_excluded_paths"])
        ):
            raise ValueError
        if len(key_bytes) != 32:
            raise ValueError
        signing_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
        if hashlib.sha256(signing_key.public_key().public_bytes_raw()).hexdigest() != key_hash:
            raise ValueError
        transport = _protected_bridge_transport(transport_identity)
        trusted_bridge = TrustedLinearBridge(
            state_root=state_root,
            bridge_identity=config["bridge_identity"],
            mcp_server_identity=config["mcp_server_identity"],
            receipt_signing_key=receipt_key,
            client=_ProtectedBridgeClient(transport, config["mcp_server_identity"]),
        )
        return _LauncherRuntime(
            state_root=state_root,
            linear=LinearGateway(
                RunStateStore(state_root, "bootstrap", receipt_authority=trusted_bridge.receipt_authority),
                trusted_bridge.receipt_authority,
            ),
            bridge=trusted_bridge,
            git_guard=GitGuard(
                repository_root,
                remote=git["remote"],
                base_branch=git["base_branch"],
                protected_paths=git["protected_paths"],
                commit_excluded_paths=git["commit_excluded_paths"],
            ),
            active_run_index=ActiveRunIndex(state_root, finalization_signing_key=signing_key),
            artifact_authority=FinalizationArtifactAuthority(state_root),
            signing_key=signing_key,
            finalization_parent=parent,
            sandbox=sandbox,
        )
    except (InvalidSignature, OSError, TypeError, ValueError, FinalizationLauncherBootstrapError) as error:
        raise FinalizationLauncherBootstrapError("protected bootstrap is invalid") from error


def _require_path_value(value: object, description: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{description} is invalid")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or path.is_symlink():
        raise ValueError(f"{description} is invalid")
    return value


def _require_sandbox_identity(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 255:
        raise ValueError("sandbox identity is invalid")
    return value


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="auto-code-launcher")
    commands = parser.add_subparsers(dest="command", parser_class=_Parser, required=True)
    for name in ("finalize", "receipt"):
        command = commands.add_parser(name)
        command.add_argument("--run", required=True)
        command.add_argument("--expected-revision", required=True)
        command.add_argument("--expected-hash", required=True)
        if name == "receipt":
            command.add_argument("--request-id", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
        revision = int(args.expected_revision)
        if revision < 1 or len(args.expected_hash) != 64 or any(character not in "0123456789abcdef" for character in args.expected_hash):
            raise ValueError
        request_id = None if args.command == "finalize" else str(uuid.UUID(args.request_id))
        runtime = load_protected_bootstrap()
        ticket_argv = (
            sys.executable,
            "-m",
            "auto_code",
            args.command,
            "--run",
            args.run,
            "--expected-revision",
            str(revision),
            "--expected-hash",
            args.expected_hash,
            *( () if request_id is None else ("--request-id", request_id) ),
        )
        return FinalizationLauncher(runtime).serve_ticket_process(
            args.run,
            revision,
            args.expected_hash,
            ticket_argv,
            operation=args.command,
            request_id=request_id,
        )
    except (FinalizationLauncherBootstrapError, FinalizationLauncherError, OSError, ValueError):
        print("auto-code-launcher: protected runtime unavailable", file=sys.stderr)
        return 2


def entrypoint() -> None:
    raise SystemExit(main())


__all__ = ["FinalizationLauncher", "FinalizationLauncherError", "entrypoint", "main"]
