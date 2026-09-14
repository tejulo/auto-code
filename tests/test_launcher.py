from __future__ import annotations

import socket
import threading
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import auto_code.finalization_service as finalization_service_module
import auto_code.launcher as launcher_module
from auto_code.git import ProcessGitExecutor
from auto_code.hashing import canonical_json_bytes
from auto_code.launcher import _ProtectedBridgeClient, load_protected_bootstrap


def test_protected_bridge_client_timeout_applies_one_deadline_to_the_response() -> None:
    """Resetting bridge socket timeouts would let a stalled response outlive the request deadline."""

    client_transport, bridge_transport = socket.socketpair()
    request_received = threading.Event()

    def stall_response() -> None:
        with bridge_transport:
            bridge_transport.recv(65_536)
            request_received.set()
            threading.Event().wait(0.2)

    worker = threading.Thread(target=stall_response, daemon=True)
    worker.start()
    try:
        client = _ProtectedBridgeClient(client_transport, "linear-mcp")
        started = time.monotonic()
        with pytest.raises(RuntimeError, match="bridge response is unavailable"):
            client.call("linear-mcp", "query_ticket_state", {"id": "ENG-1"}, deadline=started + 0.05)
        assert request_received.is_set()
        assert time.monotonic() - started < 0.15
    finally:
        client_transport.close()
        worker.join(timeout=1)


def test_protected_bridge_client_requires_the_propagated_finalization_deadline() -> None:
    """Creating a new bridge timeout would let it outlive the original finalization budget."""

    client_transport, bridge_transport = socket.socketpair()

    def return_response() -> None:
        with bridge_transport:
            bridge_transport.recv(65_536)
            try:
                bridge_transport.sendall(
                    canonical_json_bytes(
                        {
                            "tool_call_id": "tool-call-1",
                            "result": {"id": "ENG-1"},
                            "external_revision": "4",
                            "observed_state_id": "state-4",
                            "outcome": "success",
                            "observations": ["Ticket is in progress."],
                        }
                    )
                    + b"\n"
                )
            except BrokenPipeError:
                pass

    worker = threading.Thread(target=return_response, daemon=True)
    worker.start()
    try:
        client = _ProtectedBridgeClient(client_transport, "linear-mcp")
        with pytest.raises(TypeError):
            client.call("linear-mcp", "query_ticket_state", {"id": "ENG-1"})

        response = client.call(
            "linear-mcp",
            "query_ticket_state",
            {"id": "ENG-1"},
            deadline=time.monotonic() + 1,
        )

        assert response.tool_call_id == "tool-call-1"
    finally:
        client_transport.close()
        worker.join(timeout=1)


def test_protected_bootstrap_finalization_uses_process_git_executor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Removing protected Git composition would leave finalization without a trusted executor."""

    state_root = tmp_path / "state"
    repository_root = tmp_path / "repository"
    evidence_root = state_root / "git-evidence"
    controlled_home = tmp_path / "git-home"
    state_root.mkdir()
    repository_root.mkdir()
    evidence_root.mkdir()
    controlled_home.mkdir()
    bootstrap_key = Ed25519PrivateKey.generate()
    finalization_key = Ed25519PrivateKey.generate()
    finalization_public_key_hash = __import__("hashlib").sha256(
        finalization_key.public_key().public_bytes_raw()
    ).hexdigest()
    parent_payload = {
        "domain": "auto-code-finalization-parent/v1",
        "public_key": bootstrap_key.public_key().public_bytes_raw().hex(),
        "finalization_public_key_hash": finalization_public_key_hash,
    }
    parent = {
        **parent_payload,
        "signature": bootstrap_key.sign(canonical_json_bytes(parent_payload)).hex(),
    }
    state = {"domain": "auto-code-launcher-state/v1", "state_root": str(state_root)}
    index = {
        "domain": "auto-code-launcher-index/v1",
        "state_root": str(state_root),
        "finalization_public_key_hash": finalization_public_key_hash,
    }
    bridge = {
        "domain": "auto-code-launcher-bridge/v1",
        "state_root": str(state_root),
        "bridge_identity": "launcher-bridge",
        "mcp_server_identity": "linear-mcp",
        "receipt_signing_key": "22" * 16,
        "transport_fd": 9,
    }
    git = {
        "domain": "auto-code-launcher-git/v1",
        "repository_root": str(repository_root),
        "remote": "origin",
        "base_branch": "main",
        "protected_paths": [".auto-code"],
        "commit_excluded_paths": ["run-local"],
        "git_executable": str(Path(__import__("sys").executable).resolve()),
        "git_executable_sha256": __import__("hashlib").sha256(Path(__import__("sys").executable).resolve().read_bytes()).hexdigest(),
        "timeout_seconds": 5,
        "evidence_root": str(evidence_root),
        "controlled_home": str(controlled_home),
    }
    config = {
        "domain": "auto-code-launcher-bootstrap/v1",
        "state_root": str(state_root),
        "repository_root": str(repository_root),
        "bridge_identity": "launcher-bridge",
        "mcp_server_identity": "linear-mcp",
        "bridge_fd": 6,
        "state_fd": 4,
        "index_fd": 5,
        "git_fd": 7,
        "key_fd": 8,
        "state_sha256": __import__("hashlib").sha256(canonical_json_bytes(state)).hexdigest(),
        "index_sha256": __import__("hashlib").sha256(canonical_json_bytes(index)).hexdigest(),
        "bridge_sha256": __import__("hashlib").sha256(canonical_json_bytes(bridge)).hexdigest(),
        "git_sha256": __import__("hashlib").sha256(canonical_json_bytes(git)).hexdigest(),
        "key_sha256": __import__("hashlib").sha256(finalization_key.private_bytes_raw()).hexdigest(),
        "bridge_transport_device": 1,
        "bridge_transport_inode": 1,
        "bridge_transport_peer_pid": 1,
        "bridge_transport_peer_uid": 1,
        "bridge_transport_peer_gid": 1,
        "finalization_public_key_hash": finalization_public_key_hash,
        "finalization_parent": parent,
        "sandbox_socket_path": str(tmp_path / "sandbox.sock"),
        "sandbox_identity": "launcher",
        "sandbox_public_key": Ed25519PrivateKey.generate().public_key().public_bytes_raw().hex(),
    }
    config["signature"] = bootstrap_key.sign(canonical_json_bytes(config)).hex()
    payloads = {
        3: config,
        4: state,
        5: index,
        6: bridge,
        7: git,
    }

    monkeypatch.setattr(launcher_module, "_BOOTSTRAP_VERIFICATION_KEY", bootstrap_key.public_key().public_bytes_raw())
    monkeypatch.setattr(
        finalization_service_module,
        "_FINALIZATION_PARENT_PUBLIC_KEY_HASH",
        __import__("hashlib").sha256(bootstrap_key.public_key().public_bytes_raw()).hexdigest(),
    )
    monkeypatch.setattr(
        launcher_module,
        "_read_protected_json",
        lambda descriptor: (payloads[descriptor], canonical_json_bytes(payloads[descriptor])),
    )
    monkeypatch.setattr(launcher_module, "_read_protected", lambda descriptor, **_: finalization_key.private_bytes_raw())
    monkeypatch.setattr(launcher_module, "_protected_bridge_transport", lambda _: object())
    monkeypatch.setattr(launcher_module, "LauncherSocketSandbox", lambda *_: SimpleNamespace())
    monkeypatch.setattr(launcher_module, "TrustedLinearBridge", lambda **_: SimpleNamespace(receipt_authority=object()))
    monkeypatch.setattr(launcher_module, "RunStateStore", lambda *_args, **_kwargs: object())
    monkeypatch.setattr(launcher_module, "LinearGateway", lambda *_args, **_kwargs: SimpleNamespace())
    monkeypatch.setattr(launcher_module, "ActiveRunIndex", lambda *_args, **_kwargs: SimpleNamespace())
    monkeypatch.setattr(launcher_module, "FinalizationArtifactAuthority", lambda *_args, **_kwargs: SimpleNamespace())

    runtime = load_protected_bootstrap()

    assert isinstance(runtime.git_guard.executor, ProcessGitExecutor)
