from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auto_code.launcher_sandbox_daemon import (
    LauncherSandboxDaemon,
    SandboxDaemonConfig,
    SandboxProtocolError,
    load_sandbox_daemon_config,
)
from auto_code.process import _sandbox_child_evidence_payload


def _write_private_key(path: Path) -> Ed25519PrivateKey:
    private_key = Ed25519PrivateKey.generate()
    path.write_bytes(
        private_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    )
    os.chmod(path, 0o644)
    return private_key


def test_config_rejects_relative_socket_and_insecure_key(tmp_path: Path) -> None:
    key_path = tmp_path / "sandbox.key"
    _write_private_key(key_path)
    config_path = tmp_path / "bad.json"
    config_path.write_text(
        json.dumps(
            {
                "socket_path": "launcher-sandbox.sock",
                "identity": "launcher",
                "signing_key_path": str(key_path),
                "launcher_uid": 1000,
                "launcher_gid": 1000,
                "child_uid": 1001,
                "child_gid": 1001,
                "executable_roots": ["/opt/auto-code/bin"],
                "protocol_timeout": 5,
            }
        ),
        encoding="ascii",
    )

    with pytest.raises(SandboxProtocolError):
        load_sandbox_daemon_config(config_path)


def test_config_rejects_symlink_paths(tmp_path: Path) -> None:
    key_path = tmp_path / "sandbox.key"
    _write_private_key(key_path)
    config_path = tmp_path / "config.json"
    config_path.write_text("{}", encoding="ascii")
    linked_config_path = tmp_path / "linked-config.json"
    linked_config_path.symlink_to(config_path)

    with pytest.raises(SandboxProtocolError):
        load_sandbox_daemon_config(linked_config_path)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("protocol_timeout", 0),
        ("child_uid", 0),
        ("child_gid", 0),
    ),
)
def test_config_rejects_nonpositive_timeout_and_root_child_identity(
    tmp_path: Path,
    field: str,
    value: int,
) -> None:
    key_path = tmp_path / "sandbox.key"
    _write_private_key(key_path)
    config_path = tmp_path / "bad.json"
    config = {
        "socket_path": "/run/auto-code/launcher-sandbox.sock",
        "identity": "launcher",
        "signing_key_path": str(key_path),
        "launcher_uid": 1000,
        "launcher_gid": 1000,
        "child_uid": 1001,
        "child_gid": 1001,
        "executable_roots": ["/opt/auto-code/bin"],
        "protocol_timeout": 5,
    }
    config[field] = value
    config_path.write_text(json.dumps(config), encoding="ascii")

    with pytest.raises(SandboxProtocolError):
        load_sandbox_daemon_config(config_path)


def test_evidence_signature_matches_launcher_payload(tmp_path: Path) -> None:
    key_path = tmp_path / "sandbox.key"
    public_key = _write_private_key(key_path).public_key()
    config = SandboxDaemonConfig(
        socket_path=Path("/run/auto-code/launcher-sandbox.sock"),
        identity="launcher",
        signing_key_path=key_path,
        launcher_uid=1000,
        launcher_gid=1000,
        child_uid=1001,
        child_gid=1001,
        executable_roots=(Path("/opt/auto-code/bin"),),
        protocol_timeout=5.0,
    )
    daemon = LauncherSandboxDaemon(config)
    child_id = "a" * 32
    challenge = "b" * 64

    evidence = daemon.sign_child_evidence(child_id, challenge, 123, 7, 8, (), "denied")

    public_key.verify(bytes.fromhex(evidence.signature), _sandbox_child_evidence_payload(evidence, "launcher"))
