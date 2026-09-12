from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
import errno
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import uuid
from typing import Any, Callable
import weakref

from pydantic import ValidationError

from .contracts import (
    AuthorizationVerifier,
    EvidenceRef,
    EffectIntention,
    EffectOutcome,
    EffectInvocation,
    EffectInvocationPayload,
    EffectObservation,
    EffectReconciliation,
    HumanAuthorization,
    HumanAuthorizationAction,
    PreparationPhase,
    RunDisposition,
    RunState,
    Stage,
    TrustedMcpReceipt,
    UnitStatus,
    reject_unsafe_persisted_value,
)
from .hashing import canonical_json_bytes, hash_json


_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z")
_SHA256 = re.compile(r"[0-9A-Fa-f]{64}\Z")
_GENERATION_FILE = re.compile(r"([1-9][0-9]*)-([0-9a-f]{64})\.json\Z")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b(?:api[_-]?key|password|private[_-]?key|access[_-]?token|bearer)\s*[:=]"
)
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_FILE_FLAGS = os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
EMPTY_STATE_HASH = hash_json(None)


class StateStoreError(RuntimeError):
    pass


class StateNotFound(StateStoreError):
    pass


class AuthoritativeStateCorrupt(StateStoreError):
    pass


class CompareAndSwapConflict(StateStoreError):
    pass


class InvalidStateTransition(StateStoreError):
    pass


def _is_sha256(value: object) -> bool:
    return isinstance(value, str) and _SHA256.fullmatch(value) is not None


def _require_sha256(value: object, name: str) -> str:
    if not _is_sha256(value):
        raise ValueError(f"{name} must be a SHA-256 digest")
    return value.lower()


def _require_identifier(value: object, name: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None or value in {".", ".."}:
        raise ValueError(f"{name} must be a safe identifier")
    return value


def _path_parts(path: Path) -> tuple[str, ...]:
    if not path.is_absolute():
        raise ValueError("authoritative paths must be absolute")
    parts = tuple(part for part in path.parts if part not in {path.anchor, "."})
    if ".." in parts:
        raise ValueError("authoritative paths cannot contain parent traversal")
    return parts


def _open_directory_at(parent_fd: int, name: str, *, create: bool, description: str) -> int:
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        except OSError as error:
            raise AuthoritativeStateCorrupt(f"{description} cannot be created safely") from error
    try:
        descriptor = os.open(name, _DIRECTORY_FLAGS, dir_fd=parent_fd)
    except OSError as error:
        raise AuthoritativeStateCorrupt(f"{description} is missing, not a directory, or a symlink") from error
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise AuthoritativeStateCorrupt(f"{description} is not a directory")
    return descriptor


def _open_absolute_directory(path: Path, *, create: bool = False, description: str = "authoritative directory") -> int:
    descriptor = os.open("/", _DIRECTORY_FLAGS)
    try:
        for part in _path_parts(path):
            child = _open_directory_at(descriptor, part, create=create, description=description)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_parent(path: Path, *, description: str) -> tuple[int, str]:
    name = path.name
    if name in {"", ".", ".."}:
        raise ValueError("authoritative file name must be a single path component")
    return _open_absolute_directory(path.parent, description=f"{description} parent"), name


def _normalize_state_root(root: Path, *, create: bool = True) -> Path:
    path = Path(root)
    if not path.is_absolute():
        raise ValueError("state root must be an absolute launcher-owned path")
    descriptor = _open_absolute_directory(path, create=create, description="state root")
    os.close(descriptor)
    return path


def _ensure_directory(root: Path, path: Path, *, create: bool = True) -> Path:
    try:
        path.relative_to(root)
    except ValueError as error:
        raise ValueError("state path escapes the authoritative root") from error
    descriptor = _open_absolute_directory(path, create=create, description="authoritative state directory")
    os.close(descriptor)
    return path


def _fsync_directory_fd(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except OSError as error:
        if error.errno not in {errno.EINVAL, errno.ENOTSUP, errno.EOPNOTSUPP}:
            raise


def _fsync_directory(directory: Path) -> None:
    descriptor = _open_absolute_directory(directory, description="authoritative directory")
    try:
        _fsync_directory_fd(descriptor)
    finally:
        os.close(descriptor)


def _lstat_at(parent_fd: int, name: str, description: str) -> os.stat_result | None:
    try:
        result = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise AuthoritativeStateCorrupt(f"{description} cannot be inspected safely") from error
    if stat.S_ISLNK(result.st_mode):
        raise AuthoritativeStateCorrupt(f"{description} cannot be a symlink")
    return result


def _path_lstat(path: Path, description: str) -> os.stat_result | None:
    parent_fd, name = _open_parent(path, description=description)
    try:
        return _lstat_at(parent_fd, name, description)
    finally:
        os.close(parent_fd)


def _unlink_regular_file(path: Path, description: str) -> None:
    parent_fd, name = _open_parent(path, description=description)
    try:
        metadata = _lstat_at(parent_fd, name, description)
        if metadata is None:
            raise FileNotFoundError(name)
        if not stat.S_ISREG(metadata.st_mode):
            raise AuthoritativeStateCorrupt(f"{description} is not a regular file")
        os.unlink(name, dir_fd=parent_fd)
        _fsync_directory_fd(parent_fd)
    finally:
        os.close(parent_fd)


def _write_file_and_fsync_at(parent_fd: int, name: str, payload: bytes) -> None:
    descriptor = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _FILE_FLAGS, 0o600, dir_fd=parent_fd)
    try:
        with os.fdopen(descriptor, "wb") as file:
            file.write(payload)
            file.flush()
            os.fsync(file.fileno())
    except BaseException:
        try:
            os.unlink(name, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        raise


def _temporary_name(stem: str) -> str:
    return f".{stem}.{uuid.uuid4().hex}.tmp"


def _write_new_json(path: Path, value: object) -> bool:
    """Publish a fully synced immutable JSON file without following any path component."""
    parent_fd, name = _open_parent(path, description="immutable JSON file")
    temporary = _temporary_name(name)
    try:
        if _lstat_at(parent_fd, name, "immutable JSON file") is not None:
            return False
        _write_file_and_fsync_at(parent_fd, temporary, canonical_json_bytes(value))
        try:
            os.link(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd, follow_symlinks=False)
        except FileExistsError:
            return False
        _fsync_directory_fd(parent_fd)
        return True
    finally:
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def _atomic_replace_json(path: Path, value: object) -> None:
    """Atomically replace a regular pointer-like file through a verified parent descriptor."""
    parent_fd, name = _open_parent(path, description="atomic JSON file")
    temporary = _temporary_name(name)
    try:
        existing = _lstat_at(parent_fd, name, "atomic JSON file")
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise AuthoritativeStateCorrupt("atomic JSON file is not a regular file")
        _write_file_and_fsync_at(parent_fd, temporary, canonical_json_bytes(value))
        os.replace(temporary, name, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        _fsync_directory_fd(parent_fd)
    finally:
        try:
            os.unlink(temporary, dir_fd=parent_fd)
        except FileNotFoundError:
            pass
        os.close(parent_fd)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def _read_canonical_json(path: Path, description: str) -> object:
    parent_fd, name = _open_parent(path, description=description)
    try:
        metadata = _lstat_at(parent_fd, name, description)
        if metadata is None:
            raise AuthoritativeStateCorrupt(f"{description} is missing")
        if not stat.S_ISREG(metadata.st_mode):
            raise AuthoritativeStateCorrupt(f"{description} is not a regular file")
        descriptor = os.open(name, os.O_RDONLY | _FILE_FLAGS, dir_fd=parent_fd)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise AuthoritativeStateCorrupt(f"{description} is not a regular file")
            with os.fdopen(descriptor, "rb") as file:
                raw = file.read()
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
        try:
            value = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_keys)
            if canonical_json_bytes(value) != raw:
                raise ValueError("JSON is not canonical")
            return value
        except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
            raise AuthoritativeStateCorrupt(f"{description} is corrupt") from error
    except OSError as error:
        raise AuthoritativeStateCorrupt(f"{description} cannot be read safely") from error
    finally:
        os.close(parent_fd)


@dataclass(frozen=True, slots=True, init=False, eq=False)
class BridgeReceiptAuthority:
    """Load bridge-signed receipt evidence rooted in one authoritative state root."""

    state_root: Path
    bridge_identity: str
    mcp_server_identity: str
    _signing_key: bytes = field(repr=False)

    def __init__(self, state_root: Path, bridge_identity: str, mcp_server_identity: str, signing_key: bytes) -> None:
        object.__setattr__(self, "state_root", _normalize_state_root(state_root))
        object.__setattr__(self, "bridge_identity", _require_identifier(bridge_identity, "bridge identity"))
        object.__setattr__(self, "mcp_server_identity", _require_identifier(mcp_server_identity, "MCP server identity"))
        if not isinstance(signing_key, bytes) or len(signing_key) < 16:
            raise ValueError("receipt authority signing key is invalid")
        object.__setattr__(self, "_signing_key", bytes(signing_key))

    def load_verified_receipt(self, evidence: EvidenceRef) -> TrustedMcpReceipt:
        try:
            if (
                not isinstance(evidence, EvidenceRef)
                or evidence.creator != "trusted-mcp-bridge"
                or evidence.media_type != "application/json"
            ):
                raise ValueError("invalid receipt evidence")
            path = self._receipt_path(evidence.relative_path)
            receipt = TrustedMcpReceipt.model_validate(_read_canonical_json(path, "trusted MCP receipt"))
            if (
                receipt.relative_path != evidence.relative_path
                or Path(receipt.relative_path).name != f"{receipt.receipt_id}.json"
                or not hmac.compare_digest(receipt.content_hash, evidence.sha256)
                or not self._signature_matches(receipt)
            ):
                raise ValueError("invalid receipt evidence")
            return receipt
        except Exception:
            raise ValueError("trusted MCP receipt evidence is invalid") from None

    def _receipt_path(self, relative_path: str) -> Path:
        if not isinstance(relative_path, str):
            raise ValueError("receipt path is invalid")
        relative = Path(relative_path)
        if (
            relative.is_absolute()
            or len(relative.parts) != 3
            or relative.parts[:2] != ("trusted-mcp", "receipts")
            or relative.suffix != ".json"
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise ValueError("receipt path is invalid")
        try:
            if str(uuid.UUID(relative.stem)) != relative.stem:
                raise ValueError("receipt path is invalid")
        except ValueError:
            raise ValueError("receipt path is invalid") from None
        return self.state_root.joinpath(*relative.parts)

    def _signature_matches(self, receipt: TrustedMcpReceipt) -> bool:
        if (
            receipt.bridge_identity != self.bridge_identity
            or receipt.mcp_server_identity != self.mcp_server_identity
            or receipt.bridge_signature is None
        ):
            return False
        expected = hmac.new(
            self._signing_key,
            canonical_json_bytes(receipt.signed_payload()),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(receipt.bridge_signature, expected)


@contextmanager
def _interprocess_lock(path: Path) -> Iterator[None]:
    parent_fd, name = _open_parent(path, description="interprocess lock")
    try:
        _lstat_at(parent_fd, name, "interprocess lock")
        descriptor = os.open(name, os.O_RDWR | os.O_CREAT | _FILE_FLAGS, 0o600, dir_fd=parent_fd)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise AuthoritativeStateCorrupt("interprocess lock is not a regular file")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            finally:
                os.close(descriptor)
    finally:
        os.close(parent_fd)


def _run_binding_path(root: Path, run_id: str) -> Path:
    return root / "active-run-bindings" / f"{hash_json(run_id)}.json"


def _validate_persisted_value(value: object) -> None:
    if isinstance(value, str):
        try:
            reject_unsafe_persisted_value(value)
        except ValueError as error:
            raise InvalidStateTransition("unsafe value cannot be persisted") from error
        if _SECRET_ASSIGNMENT.search(value):
            raise InvalidStateTransition("unsafe value cannot be persisted")
    elif isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise InvalidStateTransition("unsafe value cannot be persisted")
            _validate_persisted_value(key)
            _validate_persisted_value(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _validate_persisted_value(item)


@dataclass(frozen=True)
class StateGeneration:
    revision: int
    state_hash: str
    state: RunState

    @classmethod
    def create(cls, revision: int, state: RunState) -> StateGeneration:
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise ValueError("generation revision must be positive")
        if not isinstance(state, RunState):
            raise TypeError("state must be a RunState")
        return cls(
            revision=revision,
            state_hash=hash_json(state.model_dump(mode="json", round_trip=True)),
            state=state,
        )

    def envelope(self) -> dict[str, object]:
        return {
            "revision": self.revision,
            "state_hash": self.state_hash,
            "state": self.state.model_dump(mode="json", round_trip=True),
        }


def _make_store_receipt_authority_binding() -> tuple[
    Callable[[object, BridgeReceiptAuthority | None], None],
    Callable[[object], BridgeReceiptAuthority | None],
]:
    bindings: weakref.WeakKeyDictionary[object, BridgeReceiptAuthority | None] = weakref.WeakKeyDictionary()

    def bind(store: object, authority: BridgeReceiptAuthority | None) -> None:
        bindings[store] = authority

    def resolve(store: object) -> BridgeReceiptAuthority | None:
        try:
            return bindings[store]
        except KeyError:
            raise InvalidStateTransition("receipt authority binding is unavailable") from None

    return bind, resolve


_BIND_STORE_RECEIPT_AUTHORITY, _RESOLVE_STORE_RECEIPT_AUTHORITY = _make_store_receipt_authority_binding()


class RunStateStore:
    """A launcher-rooted, immutable-generation store for one run."""

    def __init__(
        self,
        root: Path,
        run_id: str,
        *,
        authorization_verifier: AuthorizationVerifier | None = None,
        receipt_authority: BridgeReceiptAuthority | None = None,
    ) -> None:
        self.root = _normalize_state_root(root)
        if receipt_authority is not None and (
            not isinstance(receipt_authority, BridgeReceiptAuthority) or receipt_authority.state_root != self.root
        ):
            raise ValueError("receipt authority must use this state root")
        self.run_id = _require_identifier(run_id, "run ID")
        self.authorization_verifier = authorization_verifier
        self.runs_dir = _ensure_directory(self.root, self.root / "runs")
        self.run_dir = _ensure_directory(self.root, self.runs_dir / self.run_id)
        self.generations_dir = _ensure_directory(self.root, self.run_dir / "generations")
        self.locks_dir = _ensure_directory(self.root, self.root / "locks")
        _ensure_directory(self.root, self.root / "active-run-bindings")
        self.current_path = self.run_dir / "current.json"
        self.lock_path = self.locks_dir / f"run-{hash_json(self.run_id)}.lock"
        _BIND_STORE_RECEIPT_AUTHORITY(self, receipt_authority)

    @property
    def receipt_authority(self) -> BridgeReceiptAuthority | None:
        return _RESOLVE_STORE_RECEIPT_AUTHORITY(self)

    @classmethod
    def load_read_only(cls, root: Path, run_id: str) -> StateGeneration:
        """Load an existing generation without creating state paths or a lock."""
        store = cls.__new__(cls)
        store.root = _normalize_state_root(root, create=False)
        store.run_id = _require_identifier(run_id, "run ID")
        store.authorization_verifier = None
        store.runs_dir = _ensure_directory(store.root, store.root / "runs", create=False)
        store.run_dir = _ensure_directory(store.root, store.runs_dir / store.run_id, create=False)
        store.generations_dir = _ensure_directory(store.root, store.run_dir / "generations", create=False)
        store.current_path = store.run_dir / "current.json"
        _BIND_STORE_RECEIPT_AUTHORITY(store, None)
        return store.load_locked()

    def generation_path(self, revision: int, state_hash: str) -> Path:
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise ValueError("generation revision must be positive")
        return self.generations_dir / f"{revision}-{_require_sha256(state_hash, 'state hash')}.json"

    @classmethod
    def run_directory_exists(cls, root: Path, run_id: str) -> bool:
        state_root = _normalize_state_root(root)
        run_id = _require_identifier(run_id, "run ID")
        runs_dir = state_root / "runs"
        runs = _path_lstat(runs_dir, "runs directory")
        if runs is None:
            return False
        if not stat.S_ISDIR(runs.st_mode):
            raise AuthoritativeStateCorrupt("runs directory is not a directory")
        run_dir = _path_lstat(runs_dir / run_id, "run directory")
        if run_dir is None:
            return False
        if not stat.S_ISDIR(run_dir.st_mode):
            raise AuthoritativeStateCorrupt("run directory is not a directory")
        return True

    @contextmanager
    def interprocess_lock(self) -> Iterator[None]:
        with _interprocess_lock(self.lock_path):
            yield

    def load(self) -> StateGeneration:
        with self.interprocess_lock():
            return self.load_locked()

    def load_locked(self) -> StateGeneration:
        generation = self.load_optional_locked()
        if generation is None:
            raise StateNotFound(f"run {self.run_id} has no authoritative generation")
        return generation

    def load_optional_locked(self, *, allow_orphaned_recovery: bool = False) -> StateGeneration | None:
        if _path_lstat(self.current_path, "current state pointer") is None:
            if self._generation_records() and not allow_orphaned_recovery:
                raise AuthoritativeStateCorrupt("current state pointer is missing after a generation was written")
            return None
        pointer = _read_canonical_json(self.current_path, "current state pointer")
        if not isinstance(pointer, dict) or set(pointer) != {"revision", "state_hash"}:
            raise AuthoritativeStateCorrupt("current state pointer has an invalid shape")
        revision = pointer["revision"]
        state_hash = pointer["state_hash"]
        if (
            not isinstance(revision, int)
            or isinstance(revision, bool)
            or revision < 1
            or not _is_sha256(state_hash)
            or state_hash != state_hash.lower()
        ):
            raise AuthoritativeStateCorrupt("current state pointer has invalid values")
        generation = self._load_generation_locked(revision, state_hash)
        if not allow_orphaned_recovery:
            self._require_complete_generation_history(generation)
        return generation

    def _load_generation_locked(self, revision: int, state_hash: str) -> StateGeneration:
        path = self.generation_path(revision, state_hash)
        if _path_lstat(path, "referenced state generation") is None:
            raise AuthoritativeStateCorrupt("current state pointer references a missing generation")
        envelope = _read_canonical_json(path, "referenced state generation")
        if not isinstance(envelope, dict) or set(envelope) != {"revision", "state_hash", "state"}:
            raise AuthoritativeStateCorrupt("referenced state generation has an invalid shape")
        raw_revision = envelope["revision"]
        raw_hash = envelope["state_hash"]
        raw_state = envelope["state"]
        if (
            raw_revision != revision
            or raw_hash != state_hash
            or not isinstance(raw_hash, str)
            or raw_hash != raw_hash.lower()
            or not isinstance(raw_state, dict)
        ):
            raise AuthoritativeStateCorrupt("referenced state generation does not match its pointer")
        if hash_json(raw_state) != state_hash:
            raise AuthoritativeStateCorrupt("referenced state generation checksum does not match")
        try:
            _validate_persisted_value(raw_state)
            state = RunState.model_validate(raw_state)
        except (InvalidStateTransition, ValidationError) as error:
            raise AuthoritativeStateCorrupt("referenced state generation violates its contract") from error
        if state.run_id != self.run_id:
            raise AuthoritativeStateCorrupt("embedded run ID does not match the generation path")
        try:
            self._validate_identifiers(state)
        except ValueError as error:
            raise AuthoritativeStateCorrupt("referenced state has unsafe identifiers") from error
        return StateGeneration(revision=revision, state_hash=state_hash, state=state)

    def compare_and_swap(self, expected_revision: int, expected_hash: str, state: RunState) -> StateGeneration:
        with self.interprocess_lock():
            return self.compare_and_swap_locked(expected_revision, expected_hash, state)

    def compare_and_swap_locked(self, expected_revision: int, expected_hash: str, state: RunState) -> StateGeneration:
        _RESOLVE_STORE_RECEIPT_AUTHORITY(self)
        if not isinstance(expected_revision, int) or isinstance(expected_revision, bool) or expected_revision < 0:
            raise ValueError("expected revision must be a non-negative integer")
        expected_hash = _require_sha256(expected_hash, "expected hash")
        if not isinstance(state, RunState):
            raise TypeError("state must be a RunState")
        current = self.load_optional_locked(allow_orphaned_recovery=True)
        self._require_expected(current, expected_revision, expected_hash)
        state = self._validate_transition(current, state)
        generation = StateGeneration.create(expected_revision + 1, state)
        self._require_recoverable_generation(current, generation)
        path = self.generation_path(generation.revision, generation.state_hash)
        if not _write_new_json(path, generation.envelope()):
            existing = self._load_generation_locked(generation.revision, generation.state_hash)
            if existing != generation:
                raise AuthoritativeStateCorrupt("immutable generation path has conflicting contents")
        _atomic_replace_json(
            self.current_path,
            {"revision": generation.revision, "state_hash": generation.state_hash},
        )
        return generation

    def _require_expected(
        self,
        current: StateGeneration | None,
        expected_revision: int,
        expected_hash: str,
    ) -> None:
        if current is None:
            if expected_revision == 0 and expected_hash == EMPTY_STATE_HASH:
                return
        elif current.revision == expected_revision and current.state_hash == expected_hash:
            return
        raise CompareAndSwapConflict("authoritative state no longer matches the expected revision and hash")

    def _validate_transition(self, previous_generation: StateGeneration | None, state: RunState) -> RunState:
        raw_state = state.model_dump(mode="json", round_trip=True)
        _validate_persisted_value(raw_state)
        try:
            state = RunState.model_validate(raw_state)
        except ValidationError as error:
            raise InvalidStateTransition("state violates its persisted contract") from error
        self._validate_identifiers(state)
        if state.run_id != self.run_id:
            raise InvalidStateTransition("state run_id does not match this store")
        binding = self._load_repository_binding()
        if binding is not None and binding != state.repository_id:
            raise InvalidStateTransition("state repository_id does not match its ActiveRunIndex binding")
        previous = previous_generation.state if previous_generation is not None else None
        if previous is None:
            self._validate_initial_state(state)
            return state
        self._validate_pending_lifecycle(previous_generation, state)
        for field in ("run_id", "ticket_id", "repository_id", "max_crew_iterations"):
            if getattr(previous, field) != getattr(state, field):
                raise InvalidStateTransition(f"immutable field {field} cannot change")
        if previous.has_preparation_binding != state.has_preparation_binding:
            raise InvalidStateTransition("preparation binding must be present in the initial state")
        if previous.has_preparation_binding:
            for field in (
                "project_policy_hash",
                "preparation_input_ref",
                "preparation_input_hash",
                "ticket_snapshot_hash",
                "compatibility_receipt_hash",
                "compatibility_receipt_ref",
            ):
                if getattr(previous, field) != getattr(state, field):
                    raise InvalidStateTransition(f"immutable preparation binding {field} cannot change")
        if previous.branch is not None and state.branch != previous.branch:
            raise InvalidStateTransition("immutable field branch cannot change after it is set")
        if previous.branch_binding is not None and state.branch_binding != previous.branch_binding:
            raise InvalidStateTransition("branch binding cannot change after it is set")
        for field in ("effect_ledger", "failure_history", "human_authorizations"):
            old = getattr(previous, field)
            new = getattr(state, field)
            if len(new) < len(old) or tuple(new[: len(old)]) != tuple(old):
                raise InvalidStateTransition(f"append-only collection {field} must preserve its prefix")
        if previous.disposition in {RunDisposition.DONE, RunDisposition.ABANDONED}:
            if state != previous:
                raise InvalidStateTransition("terminal state is immutable")
            return state
        appended_authorizations = self._validate_appended_authorizations(previous, state)
        self._validate_iteration_transition(previous, state)
        self._validate_task_transition(previous, state)
        self._validate_disposition_transition(previous, state, appended_authorizations)
        self._validate_preparation_transition(previous, state, appended_authorizations)
        return state

    @staticmethod
    def _validate_initial_state(state: RunState, *, require_preparation_binding: bool = False) -> None:
        if require_preparation_binding and not state.has_preparation_binding:
            raise InvalidStateTransition("initial preparation state requires a complete preparation binding")
        values: dict[str, object] = {
            "run_id": state.run_id,
            "ticket_id": state.ticket_id,
            "repository_id": state.repository_id,
            "max_crew_iterations": state.max_crew_iterations,
        }
        if state.has_preparation_binding:
            values.update(
                {
                    "project_policy_hash": state.project_policy_hash,
                    "preparation_input_ref": state.preparation_input_ref,
                    "preparation_input_hash": state.preparation_input_hash,
                    "ticket_snapshot_hash": state.ticket_snapshot_hash,
                    "compatibility_receipt_hash": state.compatibility_receipt_hash,
                    "compatibility_receipt_ref": state.compatibility_receipt_ref,
                    "runner_identity": state.runner_identity,
                }
            )
        elif state.preparation_phase is PreparationPhase.SELECTED and state.disposition is RunDisposition.HUMAN_REVIEW:
            values["disposition"] = RunDisposition.HUMAN_REVIEW
        initial = RunState(**values)
        if state != initial:
            raise InvalidStateTransition("initial state must be the selected active run snapshot")

    def _validate_pending_lifecycle(
        self,
        previous_generation: StateGeneration,
        state: RunState,
    ) -> TrustedMcpReceipt | None:
        previous = previous_generation.state
        if previous.pending_external_request is None:
            self._require_new_pending_matches_predecessor(previous_generation, state)
            return None
        if state.pending_external_request == previous.pending_external_request:
            appended = state.effect_ledger[len(previous.effect_ledger) :]
            if any(event.effect_id == previous.pending_external_request.effect_id for event in appended):
                raise InvalidStateTransition("pending request cannot append events for its own effect")
            return None
        if state.pending_external_request is not None:
            raise InvalidStateTransition("pending request cannot be replaced")
        return self._require_authenticated_pending_reconciliation(previous, state)

    def _require_new_pending_matches_predecessor(
        self,
        previous_generation: StateGeneration,
        state: RunState,
    ) -> None:
        pending = state.pending_external_request
        if pending is None:
            return
        previous = previous_generation.state
        appended = state.effect_ledger[len(previous.effect_ledger) :]
        if (
            pending.expected_revision != previous_generation.revision
            or pending.expected_state_hash != previous_generation.state_hash
        ):
            raise InvalidStateTransition("pending request must bind to its predecessor generation")
        if (
            state.disposition is not RunDisposition.WAITING_MCP
            or len(appended) != 1
            or not isinstance(appended[0], EffectIntention)
            or appended[0].effect_id != pending.effect_id
            or appended[0].payload.operation != pending.operation
            or not hmac.compare_digest(
                appended[0].payload.request_hash.lower(),
                pending.request_hash.lower(),
            )
        ):
            raise InvalidStateTransition("pending request must append its matching intention and enter waiting MCP")

    def _require_authenticated_pending_reconciliation(
        self,
        previous: RunState,
        state: RunState,
    ) -> TrustedMcpReceipt:
        error = "pending request requires a trusted receipt reconciliation"
        pending = previous.pending_external_request
        authority = _RESOLVE_STORE_RECEIPT_AUTHORITY(self)
        if pending is None or state.pending_external_request is not None or authority is None:
            raise InvalidStateTransition(error)
        appended = state.effect_ledger[len(previous.effect_ledger) :]
        if len(appended) != 3:
            raise InvalidStateTransition(error)
        invocation, observation, reconciliation = appended
        if (
            not isinstance(invocation, EffectInvocation)
            or not isinstance(observation, EffectObservation)
            or not isinstance(reconciliation, EffectReconciliation)
            or invocation.payload != EffectInvocationPayload()
            or invocation.effect_id != pending.effect_id
            or observation.effect_id != pending.effect_id
            or reconciliation.effect_id != pending.effect_id
            or invocation.sequence != previous.effect_ledger[-1].sequence + 1
            or observation.sequence != invocation.sequence + 1
            or reconciliation.sequence != observation.sequence + 1
            or observation.payload.outcome is not reconciliation.payload.outcome
            or len(observation.payload.evidence_refs) != 1
            or observation.payload.evidence_refs != reconciliation.payload.evidence_refs
        ):
            raise InvalidStateTransition(error)
        evidence = observation.payload.evidence_refs[0]
        if (
            evidence.creator != "trusted-mcp-bridge"
            or evidence.media_type != "application/json"
            or reconciliation.payload.receipt_hash != evidence.sha256
        ):
            raise InvalidStateTransition(error)
        try:
            receipt = authority.load_verified_receipt(evidence)
            intentions, _ = previous.validate_effect_ledger()
            intention = intentions.get(pending.effect_id)
        except Exception:
            raise InvalidStateTransition(error) from None
        if (
            intention is None
            or intention.payload.operation != pending.operation
            or intention.payload.target != receipt.target
            or not hmac.compare_digest(intention.payload.request_hash.lower(), pending.request_hash.lower())
            or receipt.content_hash != evidence.sha256
            or receipt.relative_path != evidence.relative_path
            or receipt.run_id != state.run_id
            or receipt.request_id != pending.request_id
            or receipt.effect_id != pending.effect_id
            or not hmac.compare_digest(receipt.request_hash.lower(), pending.request_hash.lower())
            or receipt.effect_hash != pending.effect_hash
            or receipt.operation != pending.operation
            or receipt.expected_revision != pending.expected_revision
            or receipt.expected_state_hash != pending.expected_state_hash
            or receipt.expected_external_revision != pending.expected_external_revision
            or receipt.payload_hash != pending.payload_hash
            or receipt.outcome is not observation.payload.outcome
            or invocation.timestamp != receipt.observed_at
            or observation.timestamp != receipt.observed_at
            or reconciliation.timestamp != receipt.observed_at
            or observation.payload.external_revision != receipt.external_revision
        ):
            raise InvalidStateTransition(error)
        return receipt

    def _validate_iteration_transition(self, previous: RunState, state: RunState) -> None:
        if state.crew_iteration_count < previous.crew_iteration_count:
            raise InvalidStateTransition("Crew Iteration count cannot decrease")
        if state.crew_iteration_count > previous.crew_iteration_count:
            if (
                state.crew_iteration_count != previous.crew_iteration_count + 1
                or not previous.can_start_iteration()
                or not state.iteration_open
            ):
                raise InvalidStateTransition("Crew Iteration count may increase only for a legitimate opening")
        elif not previous.iteration_open and state.iteration_open:
            raise InvalidStateTransition("Crew Iteration opening must increment its count")

    def _validate_preparation_transition(
        self,
        previous: RunState,
        state: RunState,
        appended_authorizations: tuple[HumanAuthorization, ...],
    ) -> None:
        if not previous.has_preparation_binding:
            return
        if previous.runner_identity != state.runner_identity and not (
            previous.disposition is RunDisposition.REPAIR_REQUIRED and state.disposition is RunDisposition.ACTIVE
        ):
            raise InvalidStateTransition("immutable preparation binding runner_identity cannot change")
        allowed = {
            PreparationPhase.SELECTED: {
                PreparationPhase.SELECTED,
                PreparationPhase.IN_PROGRESS_REQUESTED,
            },
            PreparationPhase.IN_PROGRESS_REQUESTED: {
                PreparationPhase.IN_PROGRESS_REQUESTED,
                PreparationPhase.IN_PROGRESS_CONFIRMED,
            },
            PreparationPhase.IN_PROGRESS_CONFIRMED: {
                PreparationPhase.IN_PROGRESS_CONFIRMED,
                PreparationPhase.BRANCH_CREATED,
                PreparationPhase.COMPENSATION_REQUIRED,
            },
            PreparationPhase.BRANCH_CREATED: {
                PreparationPhase.BRANCH_CREATED,
                PreparationPhase.READY,
            },
            PreparationPhase.READY: {PreparationPhase.READY},
            PreparationPhase.COMPENSATION_REQUIRED: {
                PreparationPhase.COMPENSATION_REQUIRED,
                PreparationPhase.SELECTED,
            },
        }
        if state.preparation_phase not in allowed[previous.preparation_phase]:
            raise InvalidStateTransition("preparation phase transition is not authorized")
        if (
            previous.preparation_phase is PreparationPhase.IN_PROGRESS_REQUESTED
            and state.preparation_phase is PreparationPhase.IN_PROGRESS_CONFIRMED
            and not self._has_authenticated_receipt_reconciliation(
                previous,
                state,
                "compare_and_start_ticket",
                EffectOutcome.SUCCESS,
            )
        ):
            raise InvalidStateTransition(
                "preparation confirmation requires a trusted receipt-backed compare_and_start_ticket reconciliation in the current transition"
            )
        if previous.compensated and not state.compensated:
            raise InvalidStateTransition("preparation compensation cannot be cleared")
        if not previous.compensated and state.compensated:
            if (
                previous.preparation_phase is not PreparationPhase.COMPENSATION_REQUIRED
                or state.preparation_phase is not PreparationPhase.COMPENSATION_REQUIRED
                or state.disposition is not RunDisposition.HUMAN_REVIEW
                or not self._has_authenticated_receipt_reconciliation(
                    previous,
                    state,
                    "restore_ticket_state",
                    EffectOutcome.SUCCESS,
                )
            ):
                raise InvalidStateTransition(
                    "preparation compensation requires a persisted compensation phase and successful restore reconciliation"
                )
        if (
            state.compensated
            and state.preparation_phase is PreparationPhase.COMPENSATION_REQUIRED
            and previous.disposition is not RunDisposition.HUMAN_REVIEW
            and state.disposition is RunDisposition.HUMAN_REVIEW
            and not self._has_authenticated_receipt_reconciliation(
                previous,
                state,
                "restore_ticket_state",
                EffectOutcome.SUCCESS,
            )
        ):
            raise InvalidStateTransition(
                "preparation compensation requires a persisted compensation phase and successful restore reconciliation"
            )
        if (
            previous.preparation_phase is PreparationPhase.IN_PROGRESS_CONFIRMED
            and state.preparation_phase is PreparationPhase.COMPENSATION_REQUIRED
        ):
            if previous.pending_external_request is not None:
                raise InvalidStateTransition("preparation compensation cannot begin with a pending request")
            if previous.disposition is not RunDisposition.ACTIVE or state.disposition is not RunDisposition.ACTIVE:
                raise InvalidStateTransition("preparation compensation must begin from active confirmation")
            if not self._has_reconciliation_appended(
                previous,
                state,
                "create_ticket_branch",
                EffectOutcome.FAILURE,
            ):
                raise InvalidStateTransition("preparation compensation requires a recorded branch failure")
        if (
            previous.preparation_phase is PreparationPhase.COMPENSATION_REQUIRED
            and previous.disposition is RunDisposition.HUMAN_REVIEW
            and state.disposition is RunDisposition.ACTIVE
            and state.preparation_phase is not PreparationPhase.SELECTED
        ):
            raise InvalidStateTransition("preparation Human Review resume must reset the compensation phase")
        if previous.preparation_phase is PreparationPhase.COMPENSATION_REQUIRED and state.preparation_phase is PreparationPhase.SELECTED:
            if (
                not previous.compensated
                or not state.compensated
                or previous.disposition is not RunDisposition.HUMAN_REVIEW
                or state.disposition is not RunDisposition.ACTIVE
                or len(appended_authorizations) != 1
                or appended_authorizations[0].action is not HumanAuthorizationAction.RESUME
            ):
                raise InvalidStateTransition("preparation reset requires a consumed trusted resume authorization")
            if state.pending_external_request is not None:
                raise InvalidStateTransition("preparation reset cannot have a pending request")
            if not self._has_current_preparation_restore(previous):
                raise InvalidStateTransition("preparation reset requires a current preparation episode restore")

    def _has_current_preparation_restore(self, state: RunState) -> bool:
        receipt_events = self._trusted_receipt_reconciliations(state)
        latest_start = max(
            (
                (reconciliation, receipt)
                for reconciliation, receipt in receipt_events
                if receipt.operation == "compare_and_start_ticket"
                and receipt.outcome is EffectOutcome.SUCCESS
                and receipt.target == state.ticket_id
            ),
            key=lambda pair: pair[0].sequence,
            default=None,
        )
        return latest_start is not None and any(
            reconciliation.sequence > latest_start[0].sequence
            and receipt.operation == "restore_ticket_state"
            and receipt.outcome is EffectOutcome.SUCCESS
            and receipt.target == state.ticket_id
            and self._restore_receipt_started_from_active_compensation(receipt)
            for reconciliation, receipt in receipt_events
        )

    def _trusted_receipt_reconciliations(
        self,
        state: RunState,
    ) -> tuple[tuple[EffectReconciliation, TrustedMcpReceipt], ...]:
        authority = _RESOLVE_STORE_RECEIPT_AUTHORITY(self)
        if authority is None:
            return ()
        try:
            intentions, _ = state.validate_effect_ledger()
        except ValueError:
            return ()

        reconciliations: list[tuple[EffectReconciliation, TrustedMcpReceipt]] = []
        for index, reconciliation in enumerate(state.effect_ledger):
            if not isinstance(reconciliation, EffectReconciliation) or index < 2:
                continue
            invocation = state.effect_ledger[index - 2]
            observation = state.effect_ledger[index - 1]
            intention = intentions.get(reconciliation.effect_id)
            if (
                intention is None
                or not isinstance(invocation, EffectInvocation)
                or not isinstance(observation, EffectObservation)
                or invocation.payload != EffectInvocationPayload()
                or invocation.effect_id != reconciliation.effect_id
                or observation.effect_id != reconciliation.effect_id
                or intention.sequence >= invocation.sequence
                or observation.sequence != invocation.sequence + 1
                or reconciliation.sequence != observation.sequence + 1
                or observation.payload.outcome is not reconciliation.payload.outcome
                or len(observation.payload.evidence_refs) != 1
                or observation.payload.evidence_refs != reconciliation.payload.evidence_refs
            ):
                continue
            evidence = observation.payload.evidence_refs[0]
            if (
                evidence.creator != "trusted-mcp-bridge"
                or evidence.media_type != "application/json"
                or reconciliation.payload.receipt_hash != evidence.sha256
            ):
                continue
            try:
                receipt = authority.load_verified_receipt(evidence)
            except ValueError:
                continue
            if (
                receipt.content_hash != evidence.sha256
                or receipt.relative_path != evidence.relative_path
                or receipt.run_id != state.run_id
                or receipt.effect_id != reconciliation.effect_id
                or receipt.operation != intention.payload.operation
                or receipt.target != intention.payload.target
                or not hmac.compare_digest(receipt.request_hash.lower(), intention.payload.request_hash.lower())
                or receipt.outcome is not observation.payload.outcome
                or receipt.external_revision != observation.payload.external_revision
                or invocation.timestamp != receipt.observed_at
                or observation.timestamp != receipt.observed_at
                or reconciliation.timestamp != receipt.observed_at
            ):
                continue
            reconciliations.append((reconciliation, receipt))
        return tuple(reconciliations)

    def _has_authenticated_receipt_reconciliation(
        self,
        previous: RunState,
        state: RunState,
        operation: str,
        outcome: EffectOutcome,
    ) -> bool:
        try:
            receipt = self._require_authenticated_pending_reconciliation(previous, state)
        except InvalidStateTransition:
            return False
        if receipt.operation != operation or receipt.outcome is not outcome or receipt.target != state.ticket_id:
            return False
        if operation == "restore_ticket_state" and outcome is EffectOutcome.SUCCESS:
            return self._restore_receipt_started_from_active_compensation(receipt)
        return True

    def _restore_receipt_started_from_active_compensation(self, receipt: TrustedMcpReceipt) -> bool:
        try:
            source = self._load_generation_locked(receipt.expected_revision, receipt.expected_state_hash)
        except Exception:
            return False
        return (
            source.state.preparation_phase is PreparationPhase.COMPENSATION_REQUIRED
            and source.state.disposition is RunDisposition.ACTIVE
        )

    @staticmethod
    def _has_reconciliation_appended(
        previous: RunState,
        state: RunState,
        operation: str,
        outcome: EffectOutcome,
    ) -> bool:
        intentions, _ = state.validate_effect_ledger()
        return any(
            isinstance(event, EffectReconciliation)
            and event.payload.outcome is outcome
            and intentions.get(event.effect_id) is not None
            and intentions[event.effect_id].payload.operation == operation
            for event in state.effect_ledger[len(previous.effect_ledger) :]
        )

    def _validate_task_transition(self, previous: RunState, state: RunState) -> None:
        if previous.task_definition_manifest == state.task_definition_manifest:
            previous_statuses = previous.task_status_manifest
            statuses = state.task_status_manifest
            if previous_statuses is None:
                if statuses is not None and any(status.status is UnitStatus.CHECKED for status in statuses.statuses):
                    raise InvalidStateTransition("Task status initialization must be unchecked")
                return
            if statuses is None:
                raise InvalidStateTransition("Task status cannot be cleared without changing definitions")
            old = {status.task_id: status.status for status in previous_statuses.statuses}
            new = {status.task_id: status.status for status in statuses.statuses}
            if any(old[task_id] is UnitStatus.CHECKED and new[task_id] is not UnitStatus.CHECKED for task_id in old):
                raise InvalidStateTransition("Task status cannot change from checked to unchecked")
            return
        if state.task_status_manifest is not None:
            raise InvalidStateTransition("Task definition change must clear Task status")
        dependent_fields = (
            "product_change_manifest",
            "build_identity",
            "verification_result",
            "browser_result",
            "review_manifest",
            "review_result",
            "prefinalization_ticket_projection",
            "commit_sha",
            "pushed_sha",
            "linear_done_receipt",
            "finalization",
            "finalization_evidence",
        )
        if any(getattr(state, field) is not None for field in dependent_fields) or state.finalization_eligible:
            raise InvalidStateTransition("Task definition change must clear dependent state")
        invalidated_stages = {Stage.PROGRAMMER, Stage.VERIFICATION, Stage.TESTER, Stage.REVIEWER}
        if previous.task_definition_manifest is not None:
            invalidated_stages.add(Stage.ARCHITECT_TASKS)
        if invalidated_stages.intersection(state.checkpoints) or any(
            output.stage in invalidated_stages for output in state.stage_outputs
        ):
            raise InvalidStateTransition("Task definition change must clear downstream checkpoints and outputs")

    def _validate_appended_authorizations(
        self,
        previous: RunState,
        state: RunState,
    ) -> tuple[HumanAuthorization, ...]:
        appended = tuple(state.human_authorizations[len(previous.human_authorizations) :])
        if not appended:
            return appended
        if previous.disposition is RunDisposition.HUMAN_REVIEW and state.disposition is RunDisposition.ACTIVE:
            required_action = HumanAuthorizationAction.RESUME
        elif previous.disposition is RunDisposition.HUMAN_REVIEW and state.disposition is RunDisposition.ABANDONED:
            required_action = HumanAuthorizationAction.ABANDON
        else:
            raise InvalidStateTransition("Human Authorization does not authorize this transition")
        if len(appended) != 1 or appended[0].action is not required_action:
            raise InvalidStateTransition("Human Authorization does not authorize this transition")
        authorization = appended[0]
        if not self._is_trusted_authorization(authorization, required_action):
            action = "resume" if required_action is HumanAuthorizationAction.RESUME else "abandon"
            raise InvalidStateTransition(f"{action} authorization is not trusted")
        return appended

    def _is_trusted_authorization(
        self,
        authorization: HumanAuthorization,
        action: HumanAuthorizationAction,
    ) -> bool:
        if (
            authorization.action is not action
            or authorization.consumed_at is None
            or not authorization.issued_at <= authorization.consumed_at <= authorization.expires_at
            or self.authorization_verifier is None
        ):
            return False
        try:
            return bool(self.authorization_verifier.verify(authorization, action))
        except Exception:
            return False

    def _validate_disposition_transition(
        self,
        previous: RunState,
        state: RunState,
        appended_authorizations: tuple[HumanAuthorization, ...],
    ) -> None:
        allowed = {
            RunDisposition.ACTIVE: {
                RunDisposition.ACTIVE,
                RunDisposition.WAITING_MCP,
                RunDisposition.REPAIR_REQUIRED,
                RunDisposition.HUMAN_REVIEW,
                RunDisposition.DONE,
            },
            RunDisposition.WAITING_MCP: {
                RunDisposition.WAITING_MCP,
                RunDisposition.ACTIVE,
                RunDisposition.REPAIR_REQUIRED,
                RunDisposition.HUMAN_REVIEW,
            },
            RunDisposition.REPAIR_REQUIRED: {
                RunDisposition.REPAIR_REQUIRED,
                RunDisposition.ACTIVE,
                RunDisposition.HUMAN_REVIEW,
            },
            RunDisposition.HUMAN_REVIEW: {
                RunDisposition.HUMAN_REVIEW,
                RunDisposition.ACTIVE,
                RunDisposition.ABANDONED,
            },
        }
        if state.disposition not in allowed[previous.disposition]:
            raise InvalidStateTransition("disposition transition is not authorized")
        if previous.disposition is state.disposition:
            if appended_authorizations:
                raise InvalidStateTransition("Human Authorization must authorize a lifecycle transition")
            return
        if state.disposition is RunDisposition.DONE:
            self._validate_done_transition(previous, state, appended_authorizations)
        elif state.disposition is RunDisposition.ABANDONED:
            if (
                previous.disposition is not RunDisposition.HUMAN_REVIEW
                or len(appended_authorizations) != 1
                or appended_authorizations[0].action is not HumanAuthorizationAction.ABANDON
            ):
                raise InvalidStateTransition("abandon requires an appended trusted authorization from Human Review")
        elif previous.disposition is RunDisposition.HUMAN_REVIEW and state.disposition is RunDisposition.ACTIVE:
            if len(appended_authorizations) != 1 or appended_authorizations[0].action is not HumanAuthorizationAction.RESUME:
                raise InvalidStateTransition("Human Review resume requires an appended trusted resume authorization")
        elif previous.disposition is RunDisposition.REPAIR_REQUIRED and state.disposition is RunDisposition.ACTIVE:
            if (
                appended_authorizations
                or state.authorized_iteration_limit != previous.authorized_iteration_limit
                or previous.runner_identity is None
                or state.runner_identity is None
                or previous.runner_identity.content_hash == state.runner_identity.content_hash
                or state.restart_receipt_hash is None
                or state.restart_receipt_hash == previous.restart_receipt_hash
            ):
                raise InvalidStateTransition("repair restart requires a changed runner and restart receipt")
        elif previous.disposition is RunDisposition.WAITING_MCP and state.disposition is RunDisposition.ACTIVE:
            pending = previous.pending_external_request
            _, phases = state.validate_effect_ledger()
            if (
                appended_authorizations
                or state.authorized_iteration_limit != previous.authorized_iteration_limit
                or pending is None
                or state.pending_external_request is not None
                or phases.get(pending.effect_id) != "reconciled"
            ):
                raise InvalidStateTransition("waiting MCP resume requires its pending effect to be reconciled")
        elif appended_authorizations:
            raise InvalidStateTransition("Human Authorization does not authorize this transition")

    def _validate_done_transition(
        self,
        previous: RunState,
        state: RunState,
        appended_authorizations: tuple[HumanAuthorization, ...],
    ) -> None:
        evidence = state.finalization_evidence
        if (
            previous.disposition is not RunDisposition.ACTIVE
            or previous.iteration_open
            or state.iteration_open
            or not previous.finalization_eligible
            or not state.finalization_eligible
            or previous.review_manifest is None
            or previous.review_result is None
            or previous.pending_external_request is not None
            or evidence is None
            or appended_authorizations
        ):
            raise InvalidStateTransition("DONE requires closed approved finalization state and evidence")
        for field in (
            "prefinalization_ticket_projection",
            "commit_sha",
            "pushed_sha",
            "linear_done_receipt",
        ):
            if getattr(state, field) != getattr(evidence, field):
                raise InvalidStateTransition("finalization evidence does not bind the completed state")

    def _validate_identifiers(self, state: RunState) -> None:
        _require_identifier(state.run_id, "state run ID")
        _require_identifier(state.ticket_id, "ticket ID")
        _require_identifier(state.repository_id, "repository ID")

    def _load_repository_binding(self) -> str | None:
        path = _run_binding_path(self.root, self.run_id)
        if _path_lstat(path, "active run binding") is None:
            return None
        binding = _read_canonical_json(path, "active run binding")
        if not isinstance(binding, dict) or set(binding) != {"repository_id", "run_id", "initial_generation_hash"}:
            raise AuthoritativeStateCorrupt("active run binding has an invalid shape")
        if binding["run_id"] != self.run_id:
            raise AuthoritativeStateCorrupt("active run binding has the wrong run ID")
        try:
            _require_sha256(binding["initial_generation_hash"], "bound initial generation hash")
            return _require_identifier(binding["repository_id"], "bound repository ID")
        except ValueError as error:
            raise AuthoritativeStateCorrupt("active run binding has an unsafe repository ID") from error

    def _generation_records(self) -> dict[int, tuple[str, Path]]:
        descriptor = _open_absolute_directory(self.generations_dir, description="generation directory")
        try:
            names = os.listdir(descriptor)
        except OSError as error:
            raise AuthoritativeStateCorrupt("generation directory cannot be read") from error
        finally:
            os.close(descriptor)
        records: dict[int, tuple[str, Path]] = {}
        for name in names:
            if name.startswith(".") and name.endswith(".tmp"):
                continue
            match = _GENERATION_FILE.fullmatch(name)
            if match is None:
                raise AuthoritativeStateCorrupt("generation directory contains an invalid final entry")
            revision = int(match.group(1))
            state_hash = match.group(2)
            path = self.generations_dir / name
            metadata = _path_lstat(path, "state generation")
            if metadata is None or not stat.S_ISREG(metadata.st_mode):
                raise AuthoritativeStateCorrupt("state generation is missing or not a regular file")
            if revision in records:
                raise AuthoritativeStateCorrupt("generation directory has conflicting revisions")
            records[revision] = (state_hash, path)
        return records

    def _require_complete_generation_history(self, current: StateGeneration) -> None:
        records = self._generation_records()
        expected_revisions = set(range(1, current.revision + 1))
        if (
            set(records) != expected_revisions
            or records.get(current.revision, (None, None))[0] != current.state_hash
        ):
            raise AuthoritativeStateCorrupt("unreferenced final state generation exists")

    def _require_recoverable_generation(
        self,
        current: StateGeneration | None,
        candidate: StateGeneration,
    ) -> None:
        records = self._generation_records()
        current_revision = current.revision if current is not None else 0
        expected_revisions = set(range(1, current_revision + 1))
        if set(records).difference(expected_revisions | {candidate.revision}):
            raise AuthoritativeStateCorrupt("current state pointer has a conflicting generation")
        if not expected_revisions.issubset(records):
            raise AuthoritativeStateCorrupt("current state pointer has a conflicting generation")
        if current is not None and records[current.revision][0] != current.state_hash:
            raise AuthoritativeStateCorrupt("current state pointer has a conflicting generation")
        candidate_record = records.get(candidate.revision)
        if candidate_record is not None and candidate_record[0] != candidate.state_hash:
            raise AuthoritativeStateCorrupt("current state pointer has a conflicting generation")
