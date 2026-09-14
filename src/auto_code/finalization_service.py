from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import socket
import stat
import struct
import threading
import time
from typing import Literal
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .contracts import StepResult
from .hashing import canonical_json_bytes
from .state import _atomic_replace_json, _ensure_directory, _interprocess_lock, _normalize_state_root, _read_canonical_json, _write_new_json


_LAUNCHER_FINALIZATION_FD = 4
_LAUNCHER_FINALIZATION_TRUST_FD = 5
_LAUNCHER_FINALIZATION_BINDING_FD = 6
_MAX_DESCRIPTOR_BYTES = 8192
_MAX_MESSAGE_BYTES = 65_536
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,254}\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_NONCE = re.compile(r"[0-9a-f]{64}\Z")
_SIGNATURE = re.compile(r"[0-9a-f]{128}\Z")
_FINALIZATION_PARENT_PUBLIC_KEY_HASH = "10ba682c8ad13513971e8b56881aab8bd702bb807796eca81932c735a94d6e6d"


class FinalizationServiceError(RuntimeError):
    pass


class FinalizationCapabilityError(FinalizationServiceError):
    pass


@dataclass(frozen=True, slots=True)
class _Deadline:
    expires_at: float

    @classmethod
    def start(cls, timeout_seconds: float) -> _Deadline:
        return cls(time.monotonic() + timeout_seconds)

    def remaining(self) -> float:
        remaining = self.expires_at - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("finalization IPC deadline elapsed")
        return remaining


@dataclass(frozen=True, slots=True)
class FinalizationParentCapability:
    public_key: str
    finalization_public_key_hash: str
    signature: str

    def __post_init__(self) -> None:
        _require_public_key(self.public_key)
        _require_hash(self.finalization_public_key_hash, "finalization public key hash")
        if not isinstance(self.signature, str) or _SIGNATURE.fullmatch(self.signature) is None:
            raise ValueError("finalization parent signature is invalid")

    def unsigned_payload(self) -> dict[str, object]:
        return {
            "domain": "auto-code-finalization-parent/v1",
            "public_key": self.public_key,
            "finalization_public_key_hash": self.finalization_public_key_hash,
        }

    def payload(self) -> dict[str, object]:
        return {**self.unsigned_payload(), "signature": self.signature}

    def to_bytes(self) -> bytes:
        return canonical_json_bytes(self.payload())

    def verify(self) -> None:
        try:
            if not hmac.compare_digest(
                hashlib.sha256(bytes.fromhex(self.public_key)).hexdigest(),
                _FINALIZATION_PARENT_PUBLIC_KEY_HASH,
            ):
                raise ValueError
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.public_key)).verify(
                bytes.fromhex(self.signature), canonical_json_bytes(self.unsigned_payload())
            )
        except (InvalidSignature, ValueError):
            raise FinalizationServiceError("finalization parent capability is invalid") from None

    @classmethod
    def from_payload(cls, value: object) -> FinalizationParentCapability:
        expected = {"domain", "public_key", "finalization_public_key_hash", "signature"}
        if not isinstance(value, dict) or set(value) != expected or value["domain"] != "auto-code-finalization-parent/v1":
            raise ValueError("finalization parent capability is invalid")
        return cls(
            public_key=value["public_key"],
            finalization_public_key_hash=value["finalization_public_key_hash"],
            signature=value["signature"],
        )


@dataclass(frozen=True, slots=True)
class FinalizationTrustMaterial:
    public_key: str
    descriptor_hash: str | None = None
    parent: FinalizationParentCapability | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.public_key, str) or re.fullmatch(r"[0-9a-f]{64}", self.public_key) is None:
            raise ValueError("finalization trust public key is invalid")
        if self.descriptor_hash is not None:
            _require_hash(self.descriptor_hash, "finalization descriptor hash")
        if self.parent is not None and not isinstance(self.parent, FinalizationParentCapability):
            raise ValueError("finalization parent capability is invalid")

    def payload(self) -> dict[str, object]:
        return {
            "domain": "auto-code-finalization-trust/v1",
            "public_key": self.public_key,
            "descriptor_hash": self.descriptor_hash,
            "parent": None if self.parent is None else self.parent.payload(),
        }

    def to_bytes(self) -> bytes:
        return canonical_json_bytes(self.payload())

    @classmethod
    def from_payload(cls, value: object) -> FinalizationTrustMaterial:
        if not isinstance(value, dict) or value.get("domain") != "auto-code-finalization-trust/v1":
            raise ValueError("finalization trust material is invalid")
        expected = {"domain", "public_key", "descriptor_hash"}
        if set(value) == expected:
            parent = None
        elif set(value) == {*expected, "parent"}:
            parent = None if value["parent"] is None else FinalizationParentCapability.from_payload(value["parent"])
        else:
            raise ValueError("finalization trust material is invalid")
        return cls(
            public_key=value["public_key"],
            descriptor_hash=value["descriptor_hash"],
            parent=parent,
        )


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _require_identifier(value: object, description: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{description} is invalid")
    return value


def _require_hash(value: object, description: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{description} is invalid")
    return value


def _require_public_key(value: object) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError("finalization trust public key is invalid")
    return value


def _require_request_id(value: object, operation: str) -> str | None:
    if operation == "finalize":
        if value is not None:
            raise ValueError("finalize request ID is invalid")
        return None
    if not isinstance(value, str) or str(uuid.UUID(value)) != value:
        raise ValueError("receipt request ID is invalid")
    return value


def _require_expiry(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("capability expiry is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ValueError("capability expiry is invalid") from None
    if parsed.tzinfo is None:
        raise ValueError("capability expiry is invalid")
    return parsed.astimezone(UTC)


def _require_socket_path(value: object) -> Path:
    if not isinstance(value, str):
        raise ValueError("launcher socket path is invalid")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or len(os.fsencode(path)) >= 108:
        raise ValueError("launcher socket path is invalid")
    return path


def _socket_identity(path: Path) -> tuple[int, int, int, int, int]:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise FinalizationServiceError("launcher socket identity is invalid") from error
    if not stat.S_ISSOCK(metadata.st_mode):
        raise FinalizationServiceError("launcher socket identity is invalid")
    return metadata.st_dev, metadata.st_ino, metadata.st_uid, stat.S_IMODE(metadata.st_mode), metadata.st_ctime_ns


@dataclass(frozen=True, slots=True)
class FinalizationRequest:
    operation: Literal["finalize", "receipt"]
    run_id: str
    expected_revision: int
    expected_state_hash: str
    request_id: str | None
    nonce: str

    def __post_init__(self) -> None:
        if self.operation not in {"finalize", "receipt"}:
            raise ValueError("finalization operation is invalid")
        _require_identifier(self.run_id, "run ID")
        if not isinstance(self.expected_revision, int) or isinstance(self.expected_revision, bool) or self.expected_revision < 1:
            raise ValueError("expected revision is invalid")
        _require_hash(self.expected_state_hash, "expected state hash")
        _require_request_id(self.request_id, self.operation)
        if not isinstance(self.nonce, str) or _NONCE.fullmatch(self.nonce) is None:
            raise ValueError("capability nonce is invalid")

    def payload(self) -> dict[str, object]:
        return {
            "domain": "auto-code-finalization-request/v1",
            "operation": self.operation,
            "run_id": self.run_id,
            "expected_revision": self.expected_revision,
            "expected_state_hash": self.expected_state_hash,
            "request_id": self.request_id,
            "nonce": self.nonce,
        }

    @classmethod
    def from_payload(cls, value: object) -> FinalizationRequest:
        expected = {
            "domain", "operation", "run_id", "expected_revision", "expected_state_hash", "request_id", "nonce",
        }
        if not isinstance(value, dict) or set(value) != expected or value["domain"] != "auto-code-finalization-request/v1":
            raise ValueError("finalization request is invalid")
        try:
            return cls(
                operation=value["operation"],
                run_id=value["run_id"],
                expected_revision=value["expected_revision"],
                expected_state_hash=value["expected_state_hash"],
                request_id=value["request_id"],
                nonce=value["nonce"],
            )
        except (TypeError, ValueError):
            raise ValueError("finalization request is invalid") from None


@dataclass(frozen=True, slots=True)
class FinalizationCapabilityDescriptor:
    operation: Literal["finalize", "receipt"]
    run_id: str
    expected_revision: int
    expected_state_hash: str
    request_id: str | None
    expires_at: datetime
    nonce: str
    socket_path: Path
    socket_device: int
    socket_inode: int
    socket_uid: int
    socket_mode: int
    socket_ctime_ns: int
    timeout_seconds: float
    signature: str

    def __post_init__(self) -> None:
        FinalizationRequest(
            operation=self.operation,
            run_id=self.run_id,
            expected_revision=self.expected_revision,
            expected_state_hash=self.expected_state_hash,
            request_id=self.request_id,
            nonce=self.nonce,
        )
        if self.expires_at.tzinfo is None:
            raise ValueError("capability expiry is invalid")
        object.__setattr__(self, "expires_at", self.expires_at.astimezone(UTC))
        object.__setattr__(self, "socket_path", _require_socket_path(str(self.socket_path)))
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in (self.socket_device, self.socket_inode, self.socket_uid, self.socket_mode, self.socket_ctime_ns)):
            raise ValueError("launcher socket identity is invalid")
        if not isinstance(self.timeout_seconds, float) or not 0 < self.timeout_seconds <= 60:
            raise ValueError("launcher socket timeout is invalid")
        if not isinstance(self.signature, str) or _SIGNATURE.fullmatch(self.signature) is None:
            raise ValueError("capability signature is invalid")

    def unsigned_payload(self) -> dict[str, object]:
        return {
            "domain": "auto-code-finalization-capability/v1",
            "operation": self.operation,
            "run_id": self.run_id,
            "expected_revision": self.expected_revision,
            "expected_state_hash": self.expected_state_hash,
            "request_id": self.request_id,
            "expires_at": self.expires_at.isoformat().replace("+00:00", "Z"),
            "nonce": self.nonce,
            "socket_path": str(self.socket_path),
            "socket_device": self.socket_device,
            "socket_inode": self.socket_inode,
            "socket_uid": self.socket_uid,
            "socket_mode": self.socket_mode,
            "socket_ctime_ns": self.socket_ctime_ns,
            "timeout_seconds": self.timeout_seconds,
        }

    def payload(self) -> dict[str, object]:
        return {**self.unsigned_payload(), "signature": self.signature}

    def to_bytes(self) -> bytes:
        return canonical_json_bytes(self.payload())

    def request(self) -> FinalizationRequest:
        return FinalizationRequest(
            operation=self.operation,
            run_id=self.run_id,
            expected_revision=self.expected_revision,
            expected_state_hash=self.expected_state_hash,
            request_id=self.request_id,
            nonce=self.nonce,
        )

    def verify(self, public_key: str) -> None:
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(_require_public_key(public_key))).verify(
                bytes.fromhex(self.signature), canonical_json_bytes(self.unsigned_payload())
            )
        except (InvalidSignature, ValueError):
            raise FinalizationServiceError("capability signature is invalid") from None

    @classmethod
    def from_payload(cls, value: object) -> FinalizationCapabilityDescriptor:
        expected = {
            "domain", "operation", "run_id", "expected_revision", "expected_state_hash", "request_id", "expires_at",
            "nonce", "socket_path", "socket_device", "socket_inode", "socket_uid", "socket_mode", "socket_ctime_ns", "timeout_seconds", "signature",
        }
        if not isinstance(value, dict) or set(value) != expected or value["domain"] != "auto-code-finalization-capability/v1":
            raise ValueError("capability descriptor is invalid")
        try:
            return cls(
                operation=value["operation"],
                run_id=value["run_id"],
                expected_revision=value["expected_revision"],
                expected_state_hash=value["expected_state_hash"],
                request_id=value["request_id"],
                expires_at=_require_expiry(value["expires_at"]),
                nonce=value["nonce"],
                socket_path=_require_socket_path(value["socket_path"]),
                socket_device=value["socket_device"],
                socket_inode=value["socket_inode"],
                socket_uid=value["socket_uid"],
                socket_mode=value["socket_mode"],
                socket_ctime_ns=value["socket_ctime_ns"],
                timeout_seconds=value["timeout_seconds"],
                signature=value["signature"],
            )
        except (TypeError, ValueError):
            raise ValueError("capability descriptor is invalid") from None


@dataclass(frozen=True, slots=True)
class FinalizationCapabilityBinding:
    run_id: str
    expected_revision: int
    expected_state_hash: str
    finalization_public_key_hash: str
    descriptor_hash: str
    trust_hash: str
    parent_hash: str
    signature: str

    def __post_init__(self) -> None:
        _require_identifier(self.run_id, "run ID")
        if not isinstance(self.expected_revision, int) or isinstance(self.expected_revision, bool) or self.expected_revision < 1:
            raise ValueError("expected revision is invalid")
        for value, description in (
            (self.expected_state_hash, "expected state hash"),
            (self.finalization_public_key_hash, "finalization public key hash"),
            (self.descriptor_hash, "finalization descriptor hash"),
            (self.trust_hash, "finalization trust hash"),
            (self.parent_hash, "finalization parent hash"),
        ):
            _require_hash(value, description)
        if not isinstance(self.signature, str) or _SIGNATURE.fullmatch(self.signature) is None:
            raise ValueError("finalization binding signature is invalid")

    def unsigned_payload(self) -> dict[str, object]:
        return {
            "domain": "auto-code-finalization-binding/v2",
            "run_id": self.run_id,
            "expected_revision": self.expected_revision,
            "expected_state_hash": self.expected_state_hash,
            "finalization_public_key_hash": self.finalization_public_key_hash,
            "descriptor_hash": self.descriptor_hash,
            "trust_hash": self.trust_hash,
            "parent_hash": self.parent_hash,
        }

    def payload(self) -> dict[str, object]:
        return {**self.unsigned_payload(), "signature": self.signature}

    def to_bytes(self) -> bytes:
        return canonical_json_bytes(self.payload())

    @classmethod
    def issue(
        cls,
        descriptor: FinalizationCapabilityDescriptor,
        trust: FinalizationTrustMaterial,
        descriptor_raw: bytes,
        trust_raw: bytes,
        signing_key: Ed25519PrivateKey,
    ) -> FinalizationCapabilityBinding:
        if trust.parent is None or not isinstance(signing_key, Ed25519PrivateKey):
            raise ValueError("finalization binding is invalid")
        unsigned = cls(
            run_id=descriptor.run_id,
            expected_revision=descriptor.expected_revision,
            expected_state_hash=descriptor.expected_state_hash,
            finalization_public_key_hash=hashlib.sha256(bytes.fromhex(trust.public_key)).hexdigest(),
            descriptor_hash=hashlib.sha256(descriptor_raw).hexdigest(),
            trust_hash=hashlib.sha256(trust_raw).hexdigest(),
            parent_hash=hashlib.sha256(trust.parent.to_bytes()).hexdigest(),
            signature="0" * 128,
        )
        return cls(
            run_id=unsigned.run_id,
            expected_revision=unsigned.expected_revision,
            expected_state_hash=unsigned.expected_state_hash,
            finalization_public_key_hash=unsigned.finalization_public_key_hash,
            descriptor_hash=unsigned.descriptor_hash,
            trust_hash=unsigned.trust_hash,
            parent_hash=unsigned.parent_hash,
            signature=signing_key.sign(canonical_json_bytes(unsigned.unsigned_payload())).hex(),
        )

    def validate(
        self,
        descriptor: FinalizationCapabilityDescriptor,
        trust: FinalizationTrustMaterial,
        descriptor_raw: bytes,
        trust_raw: bytes,
    ) -> None:
        try:
            parent = trust.parent
            if parent is None:
                raise ValueError
            parent.verify()
            if (
                self.run_id != descriptor.run_id
                or self.expected_revision != descriptor.expected_revision
                or not hmac.compare_digest(self.expected_state_hash, descriptor.expected_state_hash)
                or not hmac.compare_digest(self.finalization_public_key_hash, parent.finalization_public_key_hash)
                or not hmac.compare_digest(self.finalization_public_key_hash, hashlib.sha256(bytes.fromhex(trust.public_key)).hexdigest())
                or not hmac.compare_digest(self.descriptor_hash, hashlib.sha256(descriptor_raw).hexdigest())
                or not hmac.compare_digest(self.trust_hash, hashlib.sha256(trust_raw).hexdigest())
                or not hmac.compare_digest(self.parent_hash, hashlib.sha256(parent.to_bytes()).hexdigest())
            ):
                raise ValueError
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(trust.public_key)).verify(
                bytes.fromhex(self.signature), canonical_json_bytes(self.unsigned_payload())
            )
        except (InvalidSignature, ValueError, FinalizationServiceError):
            raise FinalizationCapabilityError("launcher finalization binding is invalid") from None

    @classmethod
    def from_payload(cls, value: object) -> FinalizationCapabilityBinding:
        expected = {
            "domain", "run_id", "expected_revision", "expected_state_hash", "finalization_public_key_hash",
            "descriptor_hash", "trust_hash", "parent_hash", "signature",
        }
        if not isinstance(value, dict) or set(value) != expected or value["domain"] != "auto-code-finalization-binding/v2":
            raise ValueError("finalization binding is invalid")
        return cls(
            run_id=value["run_id"],
            expected_revision=value["expected_revision"],
            expected_state_hash=value["expected_state_hash"],
            finalization_public_key_hash=value["finalization_public_key_hash"],
            descriptor_hash=value["descriptor_hash"],
            trust_hash=value["trust_hash"],
            parent_hash=value["parent_hash"],
            signature=value["signature"],
        )


@dataclass(frozen=True, slots=True)
class FinalizationResponse:
    operation: Literal["finalize", "receipt"]
    run_id: str
    expected_revision: int
    expected_state_hash: str
    request_id: str | None
    nonce: str
    result: StepResult | None
    error: str | None
    signature: str

    def __post_init__(self) -> None:
        FinalizationRequest(
            operation=self.operation,
            run_id=self.run_id,
            expected_revision=self.expected_revision,
            expected_state_hash=self.expected_state_hash,
            request_id=self.request_id,
            nonce=self.nonce,
        )
        if (self.result is None) == (self.error is None):
            raise ValueError("finalization response is invalid")
        if self.error is not None and self.error != "rejected":
            raise ValueError("finalization response is invalid")
        if not isinstance(self.signature, str) or _SIGNATURE.fullmatch(self.signature) is None:
            raise ValueError("finalization response signature is invalid")

    def unsigned_payload(self) -> dict[str, object]:
        return {
            "domain": "auto-code-finalization-response/v1",
            "operation": self.operation,
            "run_id": self.run_id,
            "expected_revision": self.expected_revision,
            "expected_state_hash": self.expected_state_hash,
            "request_id": self.request_id,
            "nonce": self.nonce,
            "result": None if self.result is None else self.result.model_dump(mode="json", round_trip=True),
            "error": self.error,
        }

    def payload(self) -> dict[str, object]:
        return {**self.unsigned_payload(), "signature": self.signature}

    def verify(self, descriptor: FinalizationCapabilityDescriptor, trust: FinalizationTrustMaterial) -> None:
        if self.request() != descriptor.request():
            raise FinalizationServiceError("finalization response binding is invalid")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(trust.public_key)).verify(
                bytes.fromhex(self.signature), canonical_json_bytes(self.unsigned_payload())
            )
        except (InvalidSignature, ValueError):
            raise FinalizationServiceError("finalization response signature is invalid") from None

    def request(self) -> FinalizationRequest:
        return FinalizationRequest(
            operation=self.operation,
            run_id=self.run_id,
            expected_revision=self.expected_revision,
            expected_state_hash=self.expected_state_hash,
            request_id=self.request_id,
            nonce=self.nonce,
        )

    @classmethod
    def from_payload(cls, value: object) -> FinalizationResponse:
        expected = {
            "domain", "operation", "run_id", "expected_revision", "expected_state_hash", "request_id", "nonce", "result",
            "error", "signature",
        }
        if not isinstance(value, dict) or set(value) != expected or value["domain"] != "auto-code-finalization-response/v1":
            raise ValueError("finalization response is invalid")
        try:
            return cls(
                operation=value["operation"],
                run_id=value["run_id"],
                expected_revision=value["expected_revision"],
                expected_state_hash=value["expected_state_hash"],
                request_id=value["request_id"],
                nonce=value["nonce"],
                result=None if value["result"] is None else StepResult.model_validate(value["result"]),
                error=value["error"],
                signature=value["signature"],
            )
        except (TypeError, ValueError):
            raise ValueError("finalization response is invalid") from None


@dataclass(frozen=True, slots=True)
class _FinalizationHandlersInternal:
    finalize: Callable[[FinalizationRequest, float], StepResult]
    receipt: Callable[[FinalizationRequest, float], StepResult]

    def __post_init__(self) -> None:
        if not callable(self.finalize) or not callable(self.receipt):
            raise ValueError("finalization handlers are invalid")


class _LauncherFinalizationServiceInternal:
    """Launcher-owned finalizer and receipt composition behind a one-use local capability."""

    def __init__(self, *, signing_key: Ed25519PrivateKey, state_root: Path, handlers: _FinalizationHandlersInternal, peer_uid: int | None = None, peer_pid: int | None = None) -> None:
        if not isinstance(signing_key, Ed25519PrivateKey) or not isinstance(handlers, _FinalizationHandlersInternal):
            raise ValueError("finalization service is invalid")
        self._signing_key = signing_key
        self._public_key = signing_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.state_root = _normalize_state_root(state_root)
        self._record_root = _ensure_directory(self.state_root, self.state_root / "finalization-capabilities")
        self._handlers = handlers
        self._peer_uid = os.getuid() if peer_uid is None else peer_uid
        if not isinstance(self._peer_uid, int) or self._peer_uid < 0:
            raise ValueError("launcher peer UID is invalid")
        self._peer_pid = peer_pid
        if self._peer_pid is not None and (not isinstance(self._peer_pid, int) or self._peer_pid < 1):
            raise ValueError("launcher peer PID is invalid")
        self._lock = threading.Lock()
        self._io_timeout_seconds: float | None = None

    @property
    def public_key(self) -> str:
        return self._public_key.hex()

    def issue_descriptor(
        self,
        *,
        operation: Literal["finalize", "receipt"],
        run_id: str,
        expected_revision: int,
        expected_state_hash: str,
        request_id: str | None,
        socket_path: Path,
        expires_at: datetime,
        timeout_seconds: float,
    ) -> FinalizationCapabilityDescriptor:
        request = FinalizationRequest(
            operation=operation,
            run_id=run_id,
            expected_revision=expected_revision,
            expected_state_hash=expected_state_hash,
            request_id=request_id,
            nonce=os.urandom(32).hex(),
        )
        socket_identity = _socket_identity(socket_path)
        unsigned = FinalizationCapabilityDescriptor(
            operation=request.operation,
            run_id=request.run_id,
            expected_revision=request.expected_revision,
            expected_state_hash=request.expected_state_hash,
            request_id=request.request_id,
            nonce=request.nonce,
            expires_at=expires_at,
            socket_path=socket_path,
            socket_device=socket_identity[0],
            socket_inode=socket_identity[1],
            socket_uid=socket_identity[2],
            socket_mode=socket_identity[3],
            socket_ctime_ns=socket_identity[4],
            timeout_seconds=timeout_seconds,
            signature="0" * 128,
        )
        descriptor = FinalizationCapabilityDescriptor(
            operation=unsigned.operation,
            run_id=unsigned.run_id,
            expected_revision=unsigned.expected_revision,
            expected_state_hash=unsigned.expected_state_hash,
            request_id=unsigned.request_id,
            expires_at=unsigned.expires_at,
            nonce=unsigned.nonce,
            socket_path=unsigned.socket_path,
            socket_device=unsigned.socket_device,
            socket_inode=unsigned.socket_inode,
            socket_uid=unsigned.socket_uid,
            socket_mode=unsigned.socket_mode,
            socket_ctime_ns=unsigned.socket_ctime_ns,
            timeout_seconds=unsigned.timeout_seconds,
            signature=self._signing_key.sign(canonical_json_bytes(unsigned.unsigned_payload())).hex(),
        )
        if not _write_new_json(self._record_path(descriptor.nonce), {"descriptor": descriptor.payload(), "status": "issued", "response": None}):
            raise FinalizationServiceError("capability nonce conflicts")
        self._io_timeout_seconds = timeout_seconds if self._io_timeout_seconds is None else min(self._io_timeout_seconds, timeout_seconds)
        return descriptor

    def dispatch(
        self,
        value: FinalizationRequest | Mapping[str, object],
        *,
        deadline: _Deadline | None = None,
    ) -> FinalizationResponse:
        try:
            request = value if isinstance(value, FinalizationRequest) else FinalizationRequest.from_payload(dict(value))
        except (TypeError, ValueError):
            raise FinalizationServiceError("finalization request is invalid") from None
        with _interprocess_lock(self._record_root / "lock"):
            record = self._load_record(request.nonce)
            descriptor = FinalizationCapabilityDescriptor.from_payload(record["descriptor"])
            descriptor.verify(self.public_key)
            if descriptor.request() != request:
                raise FinalizationServiceError("capability binding is invalid")
            if descriptor.expires_at <= datetime.now(UTC):
                raise FinalizationServiceError("capability is expired")
            if record["status"] == "completed":
                response = FinalizationResponse.from_payload(record["response"])
                response.verify(
                    descriptor,
                    FinalizationTrustMaterial(
                        public_key=self.public_key,
                        descriptor_hash=hashlib.sha256(descriptor.to_bytes()).hexdigest(),
                    ),
                )
                return response
            if record["status"] != "issued":
                raise FinalizationServiceError("capability is replayed")
            _atomic_replace_json(self._record_path(request.nonce), {"descriptor": descriptor.payload(), "status": "consumed", "response": None})
        deadline = _Deadline.start(descriptor.timeout_seconds) if deadline is None else deadline
        try:
            deadline.remaining()
            result = self._dispatch_handler(request, deadline.expires_at)
            deadline.remaining()
            response = self._response(request, result=result, error=None)
        except Exception:
            response = self._response(request, result=None, error="rejected")
        with _interprocess_lock(self._record_root / "lock"):
            _atomic_replace_json(self._record_path(request.nonce), {"descriptor": descriptor.payload(), "status": "completed", "response": response.payload()})
        return response

    def _dispatch_handler(self, request: FinalizationRequest, deadline: float) -> StepResult:
        """Run a launcher-originated request through the same handler validation as IPC."""

        if not isinstance(request, FinalizationRequest):
            raise FinalizationServiceError("finalization request is invalid")
        handler = self._handlers.finalize if request.operation == "finalize" else self._handlers.receipt
        try:
            result = handler(request, deadline)
        except Exception as error:
            raise FinalizationServiceError("finalization operation is unavailable") from error
        if not isinstance(result, StepResult):
            raise FinalizationServiceError("finalization response is invalid")
        return result

    def _record_path(self, nonce: str) -> Path:
        return self._record_root / f"{nonce}.json"

    def _load_record(self, nonce: str) -> dict[str, object]:
        try:
            record = _read_canonical_json(self._record_path(nonce), "finalization capability record")
            if not isinstance(record, dict) or set(record) != {"descriptor", "status", "response"} or record["status"] not in {"issued", "consumed", "completed"} or (record["status"] == "completed") != (record["response"] is not None):
                raise ValueError
            return record
        except Exception:
            raise FinalizationServiceError("capability binding is invalid") from None

    def serve_once(self, listener: socket.socket) -> None:
        if self._io_timeout_seconds is None:
            return
        deadline = _Deadline.start(self._io_timeout_seconds)
        try:
            listener.settimeout(deadline.remaining())
            connection, _ = listener.accept()
        except OSError:
            return
        with connection:
            if not self._authenticated_peer(connection):
                return
            try:
                request = FinalizationRequest.from_payload(_read_frame(connection, deadline))
                response = self.dispatch(request, deadline=deadline)
            except (FinalizationServiceError, ValueError, OSError):
                return
            connection.settimeout(deadline.remaining())
            connection.sendall(canonical_json_bytes(response.payload()) + b"\n")

    def _authenticated_peer(self, connection: socket.socket) -> bool:
        try:
            credentials = connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            pid, uid, _ = struct.unpack("3i", credentials)
        except (AttributeError, OSError, struct.error):
            return False
        return uid == self._peer_uid and (self._peer_pid is None or pid == self._peer_pid)

    def _response(
        self,
        request: FinalizationRequest,
        *,
        result: StepResult | None,
        error: str | None,
    ) -> FinalizationResponse:
        unsigned = FinalizationResponse(
            operation=request.operation,
            run_id=request.run_id,
            expected_revision=request.expected_revision,
            expected_state_hash=request.expected_state_hash,
            request_id=request.request_id,
            nonce=request.nonce,
            result=result,
            error=error,
            signature="0" * 128,
        )
        return FinalizationResponse(
            operation=unsigned.operation,
            run_id=unsigned.run_id,
            expected_revision=unsigned.expected_revision,
            expected_state_hash=unsigned.expected_state_hash,
            request_id=unsigned.request_id,
            nonce=unsigned.nonce,
            result=unsigned.result,
            error=unsigned.error,
            signature=self._signing_key.sign(canonical_json_bytes(unsigned.unsigned_payload())).hex(),
        )


def _load_protected_json(fd_number: int, description: str) -> tuple[object, bytes]:
    try:
        descriptor = os.dup(fd_number)
    except OSError as error:
        raise FinalizationServiceError(f"launcher finalization {description} is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        access_mode = fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
        if not stat.S_ISREG(metadata.st_mode) or access_mode != os.O_RDONLY:
            raise FinalizationServiceError(f"launcher finalization {description} is invalid")
        raw = os.pread(descriptor, _MAX_DESCRIPTOR_BYTES + 1, 0)
    except OSError as error:
        raise FinalizationServiceError(f"launcher finalization {description} is invalid") from error
    finally:
        os.close(descriptor)
    if len(raw) > _MAX_DESCRIPTOR_BYTES:
        raise FinalizationServiceError(f"launcher finalization {description} is invalid")
    try:
        payload = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_json_keys)
        if raw != canonical_json_bytes(payload):
            raise ValueError
        return payload, raw
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise FinalizationServiceError(f"launcher finalization {description} is invalid") from error


def load_finalization_trust_from_protected_fd() -> FinalizationTrustMaterial:
    try:
        payload, _ = _load_protected_json(_LAUNCHER_FINALIZATION_TRUST_FD, "trust")
        return FinalizationTrustMaterial.from_payload(payload)
    except (TypeError, ValueError, FinalizationServiceError) as error:
        raise FinalizationServiceError("launcher finalization trust is invalid") from error


def validate_finalization_capability(
    capability: FinalizationCapabilityDescriptor,
    trust: FinalizationTrustMaterial,
    expected_public_key_hash: str,
) -> None:
    try:
        capability.verify(trust.public_key)
        if hashlib.sha256(bytes.fromhex(trust.public_key)).hexdigest() != _require_hash(
            expected_public_key_hash,
            "finalization public key hash",
        ):
            raise FinalizationCapabilityError("finalization trust binding is invalid")
        if trust.descriptor_hash != hashlib.sha256(capability.to_bytes()).hexdigest():
            raise FinalizationCapabilityError("finalization trust binding is invalid")
        if capability.socket_uid != os.getuid() or _socket_identity(capability.socket_path) != (capability.socket_device, capability.socket_inode, capability.socket_uid, capability.socket_mode, capability.socket_ctime_ns):
            raise FinalizationCapabilityError("launcher socket identity is invalid")
    except (TypeError, ValueError, FinalizationServiceError) as error:
        raise FinalizationCapabilityError("launcher finalization trust binding is invalid") from error


def load_capability_from_protected_fd(
    trust: FinalizationTrustMaterial,
    expected_public_key_hash: str,
) -> FinalizationCapabilityDescriptor:
    try:
        payload, _ = _load_protected_json(_LAUNCHER_FINALIZATION_FD, "capability")
        capability = FinalizationCapabilityDescriptor.from_payload(payload)
        validate_finalization_capability(
            capability,
            trust,
            expected_public_key_hash,
        )
        return capability
    except (TypeError, ValueError, FinalizationServiceError) as error:
        raise FinalizationCapabilityError("launcher finalization trust binding is invalid") from error


def invoke_descriptor(descriptor: FinalizationCapabilityDescriptor, *, trust: FinalizationTrustMaterial) -> FinalizationResponse:
    descriptor.verify(trust.public_key)
    if descriptor.expires_at <= datetime.now(UTC):
        raise FinalizationServiceError("capability is expired")
    request = descriptor.request()
    deadline = _Deadline.start(descriptor.timeout_seconds)
    try:
        if _socket_identity(descriptor.socket_path) != (descriptor.socket_device, descriptor.socket_inode, descriptor.socket_uid, descriptor.socket_mode, descriptor.socket_ctime_ns):
            raise FinalizationServiceError("launcher socket identity changed")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(deadline.remaining())
            client.connect(str(descriptor.socket_path))
            client.settimeout(deadline.remaining())
            client.sendall(canonical_json_bytes(request.payload()) + b"\n")
            response = FinalizationResponse.from_payload(_read_frame(client, deadline))
    except (OSError, ValueError) as error:
        raise FinalizationServiceError("launcher finalization socket is unavailable") from error
    response.verify(descriptor, trust)
    if response.error is not None or response.result is None:
        raise FinalizationServiceError("launcher finalization request was rejected")
    return response


def invoke_protected_capability(
    operation: Literal["finalize", "receipt"],
    run_id: str,
    expected_revision: int,
    expected_state_hash: str,
    request_id: str | None,
) -> FinalizationResponse:
    try:
        descriptor_payload, descriptor_raw = _load_protected_json(_LAUNCHER_FINALIZATION_FD, "capability")
        trust_payload, trust_raw = _load_protected_json(_LAUNCHER_FINALIZATION_TRUST_FD, "trust")
        binding_payload, _ = _load_protected_json(_LAUNCHER_FINALIZATION_BINDING_FD, "binding")
        descriptor = FinalizationCapabilityDescriptor.from_payload(descriptor_payload)
        trust = FinalizationTrustMaterial.from_payload(trust_payload)
        binding = FinalizationCapabilityBinding.from_payload(binding_payload)
        binding.validate(descriptor, trust, descriptor_raw, trust_raw)
        validate_finalization_capability(descriptor, trust, binding.finalization_public_key_hash)
    except (TypeError, ValueError, FinalizationServiceError) as error:
        raise FinalizationCapabilityError("launcher finalization trust binding is invalid") from error
    request = FinalizationRequest(
        operation=operation,
        run_id=run_id,
        expected_revision=expected_revision,
        expected_state_hash=expected_state_hash,
        request_id=request_id,
        nonce=descriptor.nonce,
    )
    if request != descriptor.request():
        raise FinalizationServiceError("capability binding is invalid")
    return invoke_descriptor(descriptor, trust=trust)


def _read_frame(connection: socket.socket, deadline: _Deadline) -> object:
    received = bytearray()
    complete = False
    while len(received) <= _MAX_MESSAGE_BYTES:
        connection.settimeout(deadline.remaining())
        chunk = connection.recv(min(4096, _MAX_MESSAGE_BYTES + 1 - len(received)))
        if not chunk:
            raise ValueError("finalization IPC frame is incomplete")
        received.extend(chunk)
        if b"\n" in chunk:
            if not received.endswith(b"\n"):
                raise ValueError("finalization IPC frame is invalid")
            received.pop()
            complete = True
            break
    if not complete or not received or len(received) > _MAX_MESSAGE_BYTES:
        raise ValueError("finalization IPC frame is invalid")
    try:
        return json.loads(received.decode("ascii"), object_pairs_hook=_reject_duplicate_json_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("finalization IPC frame is invalid") from error


__all__ = [
    "FinalizationCapabilityDescriptor",
    "FinalizationCapabilityError",
    "FinalizationRequest",
    "FinalizationResponse",
    "FinalizationServiceError",
    "FinalizationTrustMaterial",
    "invoke_descriptor",
    "invoke_protected_capability",
    "load_capability_from_protected_fd",
    "load_finalization_trust_from_protected_fd",
    "validate_finalization_capability",
]
