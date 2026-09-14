from __future__ import annotations

from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import stat
from typing import Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .process import SandboxChildEvidence, _sandbox_child_evidence_payload


class SandboxProtocolError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SandboxDaemonConfig:
    socket_path: Path
    identity: str
    signing_key_path: Path
    launcher_uid: int
    launcher_gid: int
    child_uid: int
    child_gid: int
    executable_roots: tuple[Path, ...]
    protocol_timeout: float
    _signing_key: Ed25519PrivateKey | None = field(default=None, repr=False, compare=False)


class LauncherSandboxDaemon:
    """Own the daemon signing key while later lifecycle tasks add socket serving."""

    def __init__(self, config: SandboxDaemonConfig) -> None:
        self.config = config
        self._signing_key = config._signing_key or _read_ed25519_private_key(config.signing_key_path)

    def sign_child_evidence(
        self,
        child_id: str,
        challenge: str,
        pid: int,
        pid_namespace_inode: int,
        mount_namespace_inode: int,
        fd_numbers: tuple[int, ...],
        bootstrap_fd_access: Literal["denied"],
    ) -> SandboxChildEvidence:
        unsigned = SandboxChildEvidence(
            child_id=child_id,
            challenge=challenge,
            pid=pid,
            pid_namespace_inode=pid_namespace_inode,
            mount_namespace_inode=mount_namespace_inode,
            fd_numbers=fd_numbers,
            bootstrap_fd_access=bootstrap_fd_access,
            signature="",
        )
        signature = self._signing_key.sign(_sandbox_child_evidence_payload(unsigned, self.config.identity)).hex()
        return SandboxChildEvidence(
            child_id=unsigned.child_id,
            challenge=unsigned.challenge,
            pid=unsigned.pid,
            pid_namespace_inode=unsigned.pid_namespace_inode,
            mount_namespace_inode=unsigned.mount_namespace_inode,
            fd_numbers=unsigned.fd_numbers,
            bootstrap_fd_access=unsigned.bootstrap_fd_access,
            signature=signature,
        )


def load_sandbox_daemon_config(path: Path) -> SandboxDaemonConfig:
    try:
        config_path = _absolute_path(path)
        _require_regular_file(config_path)
        payload = json.loads(config_path.read_text(encoding="ascii"), object_pairs_hook=_reject_duplicate_keys)
        if not isinstance(payload, dict) or set(payload) != {
            "socket_path",
            "identity",
            "signing_key_path",
            "launcher_uid",
            "launcher_gid",
            "child_uid",
            "child_gid",
            "executable_roots",
            "protocol_timeout",
        }:
            raise ValueError
        socket_path = _absolute_path(payload["socket_path"])
        signing_key_path = _absolute_path(payload["signing_key_path"])
        identity = payload["identity"]
        if not isinstance(identity, str) or not identity or len(identity) > 255:
            raise ValueError
        launcher_uid = _identifier(payload["launcher_uid"])
        launcher_gid = _identifier(payload["launcher_gid"])
        child_uid = _identifier(payload["child_uid"])
        child_gid = _identifier(payload["child_gid"])
        if child_uid == 0 or child_gid == 0:
            raise ValueError
        roots = payload["executable_roots"]
        if not isinstance(roots, list) or not roots or len(set(roots)) != len(roots):
            raise ValueError
        executable_roots = tuple(_absolute_path(root) for root in roots)
        timeout = payload["protocol_timeout"]
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0:
            raise ValueError
        signing_key = _read_root_only_ed25519_private_key(signing_key_path)
    except (OSError, TypeError, UnicodeError, ValueError, json.JSONDecodeError) as error:
        raise SandboxProtocolError("Launcher sandbox daemon configuration is invalid") from error
    return SandboxDaemonConfig(
        socket_path=socket_path,
        identity=identity,
        signing_key_path=signing_key_path,
        launcher_uid=launcher_uid,
        launcher_gid=launcher_gid,
        child_uid=child_uid,
        child_gid=child_gid,
        executable_roots=executable_roots,
        protocol_timeout=float(timeout),
        _signing_key=signing_key,
    )


def sandbox_daemon_entrypoint() -> None:
    daemon = LauncherSandboxDaemon(load_sandbox_daemon_config(Path("/etc/auto-code/launcher-sandbox.json")))
    daemon.serve_forever()  # type: ignore[attr-defined]


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _absolute_path(value: object) -> Path:
    if not isinstance(value, (str, Path)):
        raise ValueError("path is invalid")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or "\x00" in str(path):
        raise ValueError("path is invalid")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            break
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("path is a symlink")
    return path


def _require_regular_file(path: Path) -> None:
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("configuration file is invalid")


def _identifier(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError("identity is invalid")
    return value


def _read_root_only_ed25519_private_key(path: Path) -> Ed25519PrivateKey:
    metadata = os.lstat(path)
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ValueError("signing key permissions are invalid")
    return _read_ed25519_private_key(path)


def _read_ed25519_private_key(path: Path) -> Ed25519PrivateKey:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
    try:
        return Ed25519PrivateKey.from_private_bytes(os.read(descriptor, 64))
    finally:
        os.close(descriptor)
