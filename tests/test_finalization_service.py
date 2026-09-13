from __future__ import annotations

from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
import socket
import threading
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auto_code.cli import main
from auto_code.contracts import StepKind, StepResult
from auto_code.finalization_service import (
    FinalizationCapabilityDescriptor,
    FinalizationHandlers,
    FinalizationService,
    FinalizationServiceError,
    FinalizationTrustMaterial,
    invoke_descriptor,
    invoke_protected_capability,
    load_capability_from_protected_fd,
)
from auto_code import finalization_service
from auto_code.hashing import canonical_json_bytes


class RecordingHandlers:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, int, str, str | None]] = []

    def finalize(self, request: object) -> StepResult:
        return self._result(request)

    def receipt(self, request: object) -> StepResult:
        return self._result(request)

    def _result(self, request: object) -> StepResult:
        operation = getattr(request, "operation")
        run_id = getattr(request, "run_id")
        revision = getattr(request, "expected_revision")
        state_hash = getattr(request, "expected_state_hash")
        request_id = getattr(request, "request_id")
        self.calls.append((operation, run_id, revision, state_hash, request_id))
        return StepResult(kind=StepKind.READY_TO_FINALIZE, run_id=run_id, state_revision=revision, state_hash=state_hash)


@pytest.fixture
def handlers() -> RecordingHandlers:
    return RecordingHandlers()


@pytest.fixture
def service(handlers: RecordingHandlers, tmp_path: Path) -> FinalizationService:
    return FinalizationService(
        signing_key=Ed25519PrivateKey.generate(),
        state_root=tmp_path / "state",
        handlers=FinalizationHandlers(finalize=handlers.finalize, receipt=handlers.receipt),
    )


def ensure_socket_node(path: Path) -> None:
    if path.exists():
        return
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(path))
    finally:
        listener.close()


def descriptor(
    service: FinalizationService,
    socket_path: Path,
    *,
    operation: str = "finalize",
    expires_at: datetime | None = None,
) -> FinalizationCapabilityDescriptor:
    ensure_socket_node(socket_path)
    return service.issue_descriptor(
        operation=operation,
        run_id="run-1",
        expected_revision=3,
        expected_state_hash="a" * 64,
        request_id="11111111-1111-4111-8111-111111111111" if operation == "receipt" else None,
        socket_path=socket_path,
        expires_at=expires_at or datetime.now(UTC) + timedelta(minutes=1),
        timeout_seconds=0.05,
    )


def trust(service: FinalizationService) -> FinalizationTrustMaterial:
    return FinalizationTrustMaterial(public_key=service.public_key, state_root=service.state_root)


def test_forged_descriptor_signature_is_rejected(service: FinalizationService, tmp_path: Path) -> None:
    """Removing launcher signature verification would accept a forged capability."""

    issued = descriptor(service, tmp_path / "launcher.sock")
    forged = issued.payload()
    forged["run_id"] = "run-2"

    with pytest.raises(FinalizationServiceError, match="signature"):
        FinalizationCapabilityDescriptor.from_payload(forged).verify(service.public_key)


def test_capability_descriptor_requires_a_signed_fixed_fd(
    service: FinalizationService,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Replacing the inherited descriptor must fail before any socket request is sent."""

    issued = descriptor(service, tmp_path / "launcher.sock")
    descriptor_path = tmp_path / "capability.json"
    descriptor_path.write_bytes(issued.to_bytes())
    fd = os.open(descriptor_path, os.O_RDONLY)
    try:
        monkeypatch.setattr(finalization_service, "_LAUNCHER_FINALIZATION_FD", fd)
        assert load_capability_from_protected_fd(trust(service)) == issued
    finally:
        os.close(fd)


def test_expired_descriptor_never_invokes_a_finalizer(
    service: FinalizationService,
    handlers: RecordingHandlers,
    tmp_path: Path,
) -> None:
    """Dropping expiry validation would authorize a stale finalization capability."""

    expired = descriptor(service, tmp_path / "launcher.sock", expires_at=datetime.now(UTC) - timedelta(seconds=1))

    with pytest.raises(FinalizationServiceError, match="expired"):
        service.dispatch(expired.request())

    assert handlers.calls == []


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("operation", "receipt"),
        ("run_id", "run-2"),
        ("expected_revision", 4),
        ("expected_state_hash", "b" * 64),
    ),
)
def test_descriptor_rejects_identifier_mismatches_before_dispatch(
    service: FinalizationService,
    handlers: RecordingHandlers,
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    """Weakening descriptor binding would dispatch a different operation or CAS target."""

    issued = descriptor(service, tmp_path / "launcher.sock")
    request = issued.request().payload()
    request[field] = value
    if field == "operation":
        request["request_id"] = "11111111-1111-4111-8111-111111111111"

    with pytest.raises(FinalizationServiceError, match="binding"):
        service.dispatch(request)

    assert handlers.calls == []


def test_descriptor_nonce_is_single_use(service: FinalizationService, handlers: RecordingHandlers, tmp_path: Path) -> None:
    """Not consuming the nonce would allow a finalization request replay."""

    issued = descriptor(service, tmp_path / "launcher.sock")

    response = service.dispatch(issued.request())

    assert response.result is not None
    assert service.dispatch(issued.request()) == response
    assert handlers.calls == [("finalize", "run-1", 3, "a" * 64, None)]


def test_receipt_capability_binds_its_request_id(service: FinalizationService, handlers: RecordingHandlers, tmp_path: Path) -> None:
    """Omitting the receipt correlation ID would let another bridge receipt be consumed."""

    issued = descriptor(service, tmp_path / "launcher.sock", operation="receipt")

    response = service.dispatch(issued.request())

    assert response.result is not None
    assert handlers.calls == [("receipt", "run-1", 3, "a" * 64, "11111111-1111-4111-8111-111111111111")]


def test_identifier_only_socket_request_returns_a_signed_correlated_response(
    service: FinalizationService,
    handlers: RecordingHandlers,
    tmp_path: Path,
) -> None:
    """Changing IPC payloads or response correlation would let a forged socket response succeed."""

    socket_path = tmp_path / "launcher.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(1)
    issued = descriptor(service, socket_path)
    worker = threading.Thread(target=service.serve_once, args=(listener,), daemon=True)
    worker.start()
    try:
        response = invoke_descriptor(issued, trust=trust(service))
    finally:
        worker.join(timeout=2)
        listener.close()

    assert not worker.is_alive()
    assert response.operation == "finalize"
    assert response.run_id == "run-1"
    assert response.expected_revision == 3
    assert response.expected_state_hash == "a" * 64
    assert response.result is not None
    assert handlers.calls == [("finalize", "run-1", 3, "a" * 64, None)]


def test_forged_socket_response_is_rejected(
    service: FinalizationService,
    tmp_path: Path,
) -> None:
    """Trusting an arbitrary local socket response would report a forged finalization success."""

    socket_path = tmp_path / "launcher.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(1)
    issued = descriptor(service, socket_path)
    result = StepResult(kind=StepKind.READY_TO_FINALIZE, run_id="run-1", state_revision=3, state_hash="a" * 64)
    attacker = FinalizationService(
        signing_key=Ed25519PrivateKey.generate(),
        state_root=tmp_path / "attacker-state",
        handlers=FinalizationHandlers(finalize=lambda _: result, receipt=lambda _: result),
    )

    def reply_with_forged_signature() -> None:
        connection, _ = listener.accept()
        with connection:
            connection.recv(65_536)
            response = attacker._response(issued.request(), result=result, error=None)
            connection.sendall(canonical_json_bytes(response.payload()) + b"\n")

    worker = threading.Thread(target=reply_with_forged_signature, daemon=True)
    worker.start()
    try:
        with pytest.raises(FinalizationServiceError, match="signature"):
            invoke_descriptor(issued, trust=trust(service))
    finally:
        listener.close()
        worker.join(timeout=2)


def test_installed_finalize_cli_uses_only_the_fixed_fd_capability(
    service: FinalizationService,
    handlers: RecordingHandlers,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Keeping finalizer injection in the installed command would bypass launcher IPC."""

    socket_path = tmp_path / "launcher.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(1)
    issued = descriptor(service, socket_path)
    descriptor_path = tmp_path / "capability.json"
    descriptor_path.write_bytes(issued.to_bytes())
    trust_path = tmp_path / "trust.json"
    trust_path.write_bytes(trust(service).to_bytes())
    fd = os.open(descriptor_path, os.O_RDONLY)
    trust_fd = os.open(trust_path, os.O_RDONLY)
    monkeypatch.setattr(finalization_service, "_LAUNCHER_FINALIZATION_FD", fd)
    monkeypatch.setattr(finalization_service, "_LAUNCHER_FINALIZATION_TRUST_FD", trust_fd)
    worker = threading.Thread(target=service.serve_once, args=(listener,), daemon=True)
    worker.start()
    try:
        assert main(["finalize", "--run", "run-1", "--expected-revision", "3", "--expected-hash", "a" * 64]) == 0
    finally:
        listener.close()
        worker.join(timeout=2)
        os.close(fd)
        os.close(trust_fd)

    assert not worker.is_alive()
    assert '"kind":"ready_to_finalize"' in capsys.readouterr().out
    assert handlers.calls == [("finalize", "run-1", 3, "a" * 64, None)]


def test_trusted_fd_rejects_attacker_descriptor_before_connect(
    service: FinalizationService,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Trusting a public key carried by the descriptor would connect to an attacker's socket."""

    attacker_socket = tmp_path / "attacker.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(attacker_socket))
    listener.listen(1)
    listener.settimeout(0.05)
    attacker = FinalizationService(
        signing_key=Ed25519PrivateKey.generate(),
        state_root=tmp_path / "attacker-state",
        handlers=FinalizationHandlers(finalize=lambda _: StepResult(kind=StepKind.READY_TO_FINALIZE, run_id="run-1", state_revision=3, state_hash="a" * 64), receipt=lambda _: StepResult(kind=StepKind.READY_TO_FINALIZE, run_id="run-1", state_revision=3, state_hash="a" * 64)),
    )
    attacker_descriptor = descriptor(attacker, attacker_socket)
    descriptor_path = tmp_path / "attacker-capability.json"
    descriptor_path.write_bytes(attacker_descriptor.to_bytes())
    trust_path = tmp_path / "trusted-material.json"
    trust_path.write_bytes(FinalizationTrustMaterial(public_key=service.public_key, state_root=service.state_root).to_bytes())
    descriptor_fd = os.open(descriptor_path, os.O_RDONLY)
    trust_fd = os.open(trust_path, os.O_RDONLY)
    try:
        monkeypatch.setattr(finalization_service, "_LAUNCHER_FINALIZATION_FD", descriptor_fd)
        monkeypatch.setattr(finalization_service, "_LAUNCHER_FINALIZATION_TRUST_FD", trust_fd)
        with pytest.raises(FinalizationServiceError, match="trust"):
            invoke_protected_capability("finalize", "run-1", 3, "a" * 64, None)
        with pytest.raises(TimeoutError):
            listener.accept()
    finally:
        listener.close()
        os.close(descriptor_fd)
        os.close(trust_fd)


def test_restart_replays_the_exact_durable_response_without_reinvoking_handler(tmp_path: Path) -> None:
    """Keeping nonce state in memory would repeat an already completed finalization after restart."""

    key = Ed25519PrivateKey.generate()
    first_handlers = RecordingHandlers()
    first = FinalizationService(
        signing_key=key,
        state_root=tmp_path / "state",
        handlers=FinalizationHandlers(finalize=first_handlers.finalize, receipt=first_handlers.receipt),
    )
    issued = descriptor(first, tmp_path / "launcher.sock")
    completed = first.dispatch(issued.request())
    second_handlers = RecordingHandlers()
    restarted = FinalizationService(
        signing_key=key,
        state_root=tmp_path / "state",
        handlers=FinalizationHandlers(finalize=second_handlers.finalize, receipt=second_handlers.receipt),
    )

    replayed = restarted.dispatch(issued.request())

    assert replayed == completed
    assert first_handlers.calls == [("finalize", "run-1", 3, "a" * 64, None)]
    assert second_handlers.calls == []


def test_socket_path_replacement_is_rejected_before_connect(service: FinalizationService, tmp_path: Path) -> None:
    """Checking only a socket pathname would permit a replacement listener to receive the capability."""

    socket_path = tmp_path / "launcher.sock"
    original = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    original.bind(str(socket_path))
    original.listen(1)
    issued = descriptor(service, socket_path)
    original.close()
    socket_path.unlink()
    replacement = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    replacement.bind(str(socket_path))
    replacement.listen(1)
    replacement.settimeout(0.05)
    try:
        with pytest.raises(FinalizationServiceError, match="identity"):
            invoke_descriptor(issued, trust=FinalizationTrustMaterial(public_key=service.public_key, state_root=service.state_root))
        with pytest.raises(TimeoutError):
            replacement.accept()
    finally:
        replacement.close()


@pytest.mark.parametrize("response", (b'{"partial":true}', b""))
def test_socket_eof_without_a_newline_fails_closed(
    service: FinalizationService,
    tmp_path: Path,
    response: bytes,
) -> None:
    """Accepting EOF as framing would parse a truncated launcher response."""

    socket_path = tmp_path / "launcher.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(1)
    issued = descriptor(service, socket_path)

    def send_partial_response() -> None:
        connection, _ = listener.accept()
        with connection:
            connection.recv(65_536)
            connection.sendall(response)

    worker = threading.Thread(target=send_partial_response, daemon=True)
    worker.start()
    try:
        with pytest.raises(FinalizationServiceError, match="socket"):
            invoke_descriptor(issued, trust=FinalizationTrustMaterial(public_key=service.public_key, state_root=service.state_root))
    finally:
        listener.close()
        worker.join(timeout=2)


def test_socket_read_deadline_fails_closed(service: FinalizationService, tmp_path: Path) -> None:
    """An unbounded recv would let a stalled local peer hold finalization indefinitely."""

    socket_path = tmp_path / "launcher.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(1)
    issued = descriptor(service, socket_path)
    accepted = threading.Event()

    def stall_response() -> None:
        connection, _ = listener.accept()
        with connection:
            connection.recv(65_536)
            accepted.set()
            threading.Event().wait(0.2)

    worker = threading.Thread(target=stall_response, daemon=True)
    worker.start()
    try:
        with pytest.raises(FinalizationServiceError, match="socket"):
            invoke_descriptor(issued, trust=FinalizationTrustMaterial(public_key=service.public_key, state_root=service.state_root))
    finally:
        listener.close()
        worker.join(timeout=2)
    assert accepted.is_set()


def test_client_rejects_dripped_valid_partial_response_at_one_total_deadline(
    service: FinalizationService,
    tmp_path: Path,
) -> None:
    """Resetting the read timeout after every byte would let a peer extend the descriptor deadline."""

    socket_path = tmp_path / "launcher.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(1)
    issued = descriptor(service, socket_path)

    def drip_response() -> None:
        connection, _ = listener.accept()
        with connection:
            connection.recv(65_536)
            for chunk in (b"{", b'"', b"d", b"o", b"m"):
                try:
                    connection.sendall(chunk)
                except BrokenPipeError:
                    return
                time.sleep(issued.timeout_seconds * 0.6)

    worker = threading.Thread(target=drip_response, daemon=True)
    worker.start()
    started = time.monotonic()
    try:
        with pytest.raises(FinalizationServiceError, match="socket"):
            invoke_descriptor(issued, trust=trust(service))
    finally:
        listener.close()
        worker.join(timeout=2)
    assert time.monotonic() - started < issued.timeout_seconds * 2


def test_launcher_rejects_dripped_partial_request_at_one_total_deadline(
    service: FinalizationService,
    handlers: RecordingHandlers,
    tmp_path: Path,
) -> None:
    """Resetting launcher frame reads would leave a connection alive while each byte arrives in time."""

    socket_path = tmp_path / "launcher.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(1)
    issued = descriptor(service, socket_path)
    worker = threading.Thread(target=service.serve_once, args=(listener,), daemon=True)
    worker.start()
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(str(socket_path))
    try:
        for chunk in (b"{", b'"', b"d", b"o", b"m"):
            try:
                client.sendall(chunk)
            except BrokenPipeError:
                break
            time.sleep(issued.timeout_seconds * 0.6)
        worker.join(timeout=issued.timeout_seconds * 2)
    finally:
        client.close()
        listener.close()
    assert not worker.is_alive()
    assert handlers.calls == []


def test_finalization_commands_do_not_accept_composition_callbacks() -> None:
    """Keeping callable injection on main would leave an in-process privilege bypass."""

    with pytest.raises(TypeError):
        main(["finalize"], finalizer_factory=lambda _: object())
