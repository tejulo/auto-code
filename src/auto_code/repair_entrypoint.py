from __future__ import annotations

import argparse
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import shutil
import stat
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import RepairRunnerIdentity, RunnerIdentity, RunDisposition, Stage
from .git import GitGuard, ProcessGitExecutor, RepairSourceManifest
from .hashing import canonical_json_bytes, hash_json
from .process import (
    FilesystemEvidenceSink,
    HashVerifiedExecutables,
    LauncherSocketSandbox,
    PythonArchiveTicketInvoker,
    ProcessRunner,
    SandboxPolicy,
)
from .repair import RepairError, RepairGuard, RepairWorkspaceHandle, UnauthorizedRepairError
from .runner import (
    BuiltRunnerRelease,
    PendingRunnerActivation,
    ProtectedRepairService,
    ReleaseManifestEntry,
    RepairJournal,
    RepairRegression,
    RepairRunner,
    RunnerActivationReceipt,
    RunnerRegistry,
    TrustedLauncher,
    capture_built_release_manifest,
    capture_runner_archive,
)
from .state import (
    RunStateStore,
    StateStoreError,
    _atomic_replace_json,
    _ensure_directory,
    _interprocess_lock,
    _normalize_state_root,
    _path_lstat,
    _read_canonical_json,
    _write_new_json,
)


_REPAIR_DESCRIPTOR_FD = 3
_MAX_REPAIR_DESCRIPTOR_BYTES = 16_384
# Public trust anchor only. The launcher-owned matching private key is not part of this source tree.
_REPAIR_DESCRIPTOR_VERIFICATION_KEY = bytes.fromhex(
    "d7d968f09d90b953ba08b8e2c4f31eab5c4a634aa412f13f613732b540d253af"
)
_SHA256 = frozenset("0123456789abcdef")


class RepairRuntimeConfigurationError(RuntimeError):
    pass


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _absolute_path(value: object, description: str) -> Path:
    if not isinstance(value, str):
        raise ValueError(f"{description} is invalid")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{description} is invalid")
    return path


def _hash(value: object, description: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(character not in _SHA256 for character in value):
        raise ValueError(f"{description} is invalid")
    return value


def _relative_path(value: object, description: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{description} is invalid")
    path = Path(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{description} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class RepairRuntimeDescriptor:
    operation: str
    run_id: str
    expected_revision: int
    expected_state_hash: str
    failure_hash: str | None
    workspace_id: str | None
    workspace_path: Path | None
    request_hash: str | None
    repair_runner_identity: RepairRunnerIdentity
    registry_root: Path
    state_root: Path
    repair_repository_root: Path
    repair_workspace_root: Path
    git_executable: Path
    git_executable_hash: str
    regression_command: tuple[str, ...]
    regression_executable_hash: str
    regression_timeout: float
    environment: Mapping[str, str]
    sandbox_policy_hash: str
    process_runner_version: str
    sandbox_socket: Path
    sandbox_identity: str
    controlled_home: Path
    secret_paths: tuple[Path, ...]
    evidence_root: Path
    release_root: Path
    build_command: tuple[str, ...]
    build_executable_hash: str
    ticket_interpreter: Path
    ticket_interpreter_hash: str
    runner_executable: str
    contract_manifest: str
    terminate_command: tuple[str, ...]
    terminate_executable_hash: str
    start_command: tuple[str, ...]
    start_executable_hash: str
    attest_command: tuple[str, ...]
    attest_executable_hash: str
    expiry: datetime
    nonce: str

    @classmethod
    def from_payload(cls, value: object, *, now: datetime) -> RepairRuntimeDescriptor:
        common = {
            "operation", "run_id", "expected_revision", "expected_state_hash", "repair_runner_identity",
            "registry_root", "state_root", "repair_repository_root", "repair_workspace_root", "git_executable",
            "git_executable_hash", "regression_command", "regression_executable_hash", "regression_timeout",
            "environment", "sandbox_policy_hash", "process_runner_version", "sandbox_socket", "sandbox_identity",
            "controlled_home", "secret_paths", "evidence_root", "release_root", "build_command",
            "build_executable_hash", "ticket_interpreter", "ticket_interpreter_hash", "runner_executable", "contract_manifest", "terminate_command",
            "terminate_executable_hash", "start_command", "start_executable_hash", "attest_command",
            "attest_executable_hash", "expiry", "nonce",
        }
        if not isinstance(value, dict) or value.get("operation") not in {"prepare", "apply"}:
            raise ValueError("repair descriptor shape is invalid")
        operation = value["operation"]
        specific = {"failure_hash"} if operation == "prepare" else {"workspace_id", "workspace_path", "request_hash"}
        if set(value) != common | specific:
            raise ValueError("repair descriptor shape is invalid")
        command = value["regression_command"]
        commands = {
            "regression": command,
            "build": value["build_command"],
            "terminate": value["terminate_command"],
            "start": value["start_command"],
            "attest": value["attest_command"],
        }
        environment = value["environment"]
        for name, configured in commands.items():
            if (
                not isinstance(configured, list)
                or not configured
                or len(configured) > 64
                or any(
                    not isinstance(argument, str) or not argument or len(argument) > 4_096 or "\x00" in argument
                    for argument in configured
                )
                or not Path(configured[0]).is_absolute()
            ):
                raise ValueError(f"repair {name} command is invalid")
        if (
            not isinstance(environment, dict)
            or len(environment) > 16
            or any(not isinstance(key, str) or not isinstance(item, str) or len(key) > 128 or len(item) > 4_096 for key, item in environment.items())
            or "HOME" in environment
            or "PATH" in environment
        ):
            raise ValueError("repair environment is invalid")
        expiry = datetime.fromisoformat(value["expiry"])
        if expiry.tzinfo is None or expiry <= now or expiry > now + timedelta(minutes=5):
            raise ValueError("repair descriptor is expired")
        revision = value["expected_revision"]
        timeout = value["regression_timeout"]
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise ValueError("repair expected revision is invalid")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > 3_600:
            raise ValueError("repair regression timeout is invalid")
        nonce = _hash(value["nonce"], "repair nonce")
        run_id = value["run_id"]
        if not isinstance(run_id, str) or not run_id or len(run_id) > 255:
            raise ValueError("repair run ID is invalid")
        workspace_id = value.get("workspace_id")
        if workspace_id is not None and (not isinstance(workspace_id, str) or not workspace_id or len(workspace_id) > 255):
            raise ValueError("repair workspace ID is invalid")
        secret_paths = value["secret_paths"]
        if (
            not isinstance(secret_paths, list)
            or len(secret_paths) > 32
            or len(secret_paths) != len(set(secret_paths))
        ):
            raise ValueError("repair secret paths are invalid")
        parsed_secret_paths = tuple(_absolute_path(path, "repair secret path") for path in secret_paths)
        sandbox_identity = value["sandbox_identity"]
        if not isinstance(sandbox_identity, str) or not sandbox_identity or len(sandbox_identity) > 255:
            raise ValueError("repair sandbox identity is invalid")
        if value["process_runner_version"] != "auto-code-process-v1":
            raise ValueError("repair process runner version is invalid")
        runner_executable = _relative_path(value["runner_executable"], "runner executable")
        contract_manifest = _relative_path(value["contract_manifest"], "contract manifest")
        sandbox_payload = {
            "repair_repository_root": value["repair_repository_root"],
            "repair_workspace_root": value["repair_workspace_root"],
            "controlled_home": value["controlled_home"],
            "secret_paths": secret_paths,
            "environment_allowlist": sorted(environment),
            "dynamic_downloads_disabled": True,
        }
        if _hash(value["sandbox_policy_hash"], "sandbox policy") != hash_json(sandbox_payload):
            raise ValueError("repair sandbox policy hash is invalid")
        return cls(
            operation=operation,
            run_id=run_id,
            expected_revision=revision,
            expected_state_hash=_hash(value["expected_state_hash"], "expected state hash"),
            failure_hash=_hash(value["failure_hash"], "failure hash") if operation == "prepare" else None,
            workspace_id=workspace_id,
            workspace_path=_absolute_path(value["workspace_path"], "repair workspace") if operation == "apply" else None,
            request_hash=_hash(value["request_hash"], "repair request hash") if operation == "apply" else None,
            repair_runner_identity=RepairRunnerIdentity.model_validate(value["repair_runner_identity"]),
            registry_root=_absolute_path(value["registry_root"], "registry root"),
            state_root=_absolute_path(value["state_root"], "state root"),
            repair_repository_root=_absolute_path(value["repair_repository_root"], "repair repository root"),
            repair_workspace_root=_absolute_path(value["repair_workspace_root"], "repair workspace root"),
            git_executable=_absolute_path(value["git_executable"], "git executable"),
            git_executable_hash=_hash(value["git_executable_hash"], "Git executable hash"),
            regression_command=tuple(command),
            regression_executable_hash=_hash(value["regression_executable_hash"], "regression executable hash"),
            regression_timeout=float(timeout),
            environment=dict(environment),
            sandbox_policy_hash=_hash(value["sandbox_policy_hash"], "sandbox policy hash"),
            process_runner_version=value["process_runner_version"],
            sandbox_socket=_absolute_path(value["sandbox_socket"], "sandbox socket"),
            sandbox_identity=sandbox_identity,
            controlled_home=_absolute_path(value["controlled_home"], "controlled home"),
            secret_paths=parsed_secret_paths,
            evidence_root=_absolute_path(value["evidence_root"], "repair evidence root"),
            release_root=_absolute_path(value["release_root"], "runner release root"),
            build_command=tuple(commands["build"]),
            build_executable_hash=_hash(value["build_executable_hash"], "build executable hash"),
            ticket_interpreter=_absolute_path(value["ticket_interpreter"], "ticket interpreter"),
            ticket_interpreter_hash=_hash(value["ticket_interpreter_hash"], "ticket interpreter hash"),
            runner_executable=runner_executable,
            contract_manifest=contract_manifest,
            terminate_command=tuple(commands["terminate"]),
            terminate_executable_hash=_hash(value["terminate_executable_hash"], "termination executable hash"),
            start_command=tuple(commands["start"]),
            start_executable_hash=_hash(value["start_executable_hash"], "start executable hash"),
            attest_command=tuple(commands["attest"]),
            attest_executable_hash=_hash(value["attest_executable_hash"], "attestation executable hash"),
            expiry=expiry,
            nonce=nonce,
        )

    def authorizes(self, operation: str, **bindings: object) -> bool:
        expected: dict[str, object] = {
            "run_id": self.run_id,
            "expected_revision": self.expected_revision,
            "expected_state_hash": self.expected_state_hash,
        }
        if self.operation == "prepare":
            expected["failure_hash"] = self.failure_hash
        else:
            expected.update(
                {
                    "workspace_id": self.workspace_id,
                    "workspace_path": self.workspace_path,
                    "request_hash": self.request_hash,
                }
            )
        normalized = dict(bindings)
        if "workspace_path" in normalized:
            normalized["workspace_path"] = Path(normalized["workspace_path"])
        return operation == self.operation and normalized == expected

    def nonce_binding(self) -> dict[str, object]:
        binding: dict[str, object] = {
            "operation": self.operation,
            "run_id": self.run_id,
            "expected_revision": self.expected_revision,
            "expected_state_hash": self.expected_state_hash,
            "expiry": self.expiry.isoformat(),
        }
        if self.operation == "prepare":
            binding["failure_hash"] = self.failure_hash
        else:
            binding.update(
                {
                    "workspace_id": self.workspace_id,
                    "workspace_path": str(self.workspace_path),
                    "request_hash": self.request_hash,
                }
            )
        return binding


class DescriptorNonceStore:
    """Persist one signed descriptor's exact operation transaction and terminal use."""

    def __init__(self, root: Path, *, now: Callable[[], datetime] | None = None) -> None:
        self.root = _normalize_state_root(root)
        self.directory = _ensure_directory(self.root, self.root / "repair-descriptor-nonces")
        self.locks = _ensure_directory(self.root, self.root / "locks")
        self.now = now or (lambda: datetime.now(UTC))

    def begin(self, descriptor: RepairRuntimeDescriptor) -> str:
        self._require_unexpired(descriptor)
        binding_hash = hash_json(descriptor.nonce_binding())
        path, lock = self._paths(descriptor.nonce)
        payload = {
            "nonce": descriptor.nonce,
            "binding_hash": binding_hash,
            "operation": descriptor.operation,
            "expiry": descriptor.expiry.isoformat(),
            "status": "pending",
            "result_hash": None,
        }
        with _interprocess_lock(lock):
            if _write_new_json(path, payload):
                return binding_hash
            existing = self._load(path, descriptor)
            if existing["binding_hash"] != binding_hash:
                raise PermissionError("repair descriptor nonce binding conflicts")
            if existing["status"] != "pending":
                raise PermissionError("repair descriptor nonce was consumed")
            return binding_hash

    @contextmanager
    def transaction(
        self,
        descriptor: RepairRuntimeDescriptor,
        *,
        reconcile_completed: bool = False,
    ) -> Iterator[_DescriptorNonceTransaction]:
        self._require_unexpired(descriptor)
        binding_hash = hash_json(descriptor.nonce_binding())
        path, lock = self._paths(descriptor.nonce)
        payload = {
            "nonce": descriptor.nonce,
            "binding_hash": binding_hash,
            "operation": descriptor.operation,
            "expiry": descriptor.expiry.isoformat(),
            "status": "pending",
            "result_hash": None,
        }
        with _interprocess_lock(lock):
            result_hash: str | None = None
            if not _write_new_json(path, payload):
                existing = self._load(path, descriptor)
                if existing["binding_hash"] != binding_hash:
                    raise PermissionError("repair descriptor nonce binding conflicts")
                if existing["status"] == "completed" and reconcile_completed:
                    result_hash = _hash(existing["result_hash"], "repair descriptor result")
                elif existing["status"] != "pending":
                    raise PermissionError("repair descriptor nonce was consumed")
            yield _DescriptorNonceTransaction(self, descriptor, path, result_hash)

    def require_active(self, descriptor: RepairRuntimeDescriptor) -> str:
        self._require_unexpired(descriptor)
        path, lock = self._paths(descriptor.nonce)
        with _interprocess_lock(lock):
            payload = self._load(path, descriptor)
            if payload["status"] != "pending":
                raise PermissionError("repair descriptor nonce was consumed")
            expected = hash_json(descriptor.nonce_binding())
            if payload["binding_hash"] != expected:
                raise PermissionError("repair descriptor nonce binding conflicts")
            return expected

    def complete(self, descriptor: RepairRuntimeDescriptor, result_hash: str) -> None:
        _hash(result_hash, "repair descriptor result")
        self._require_unexpired(descriptor)
        path, lock = self._paths(descriptor.nonce)
        with _interprocess_lock(lock):
            payload = self._load(path, descriptor)
            if payload["status"] != "pending" or payload["binding_hash"] != hash_json(descriptor.nonce_binding()):
                raise PermissionError("repair descriptor nonce was consumed")
            _atomic_replace_json(path, {**payload, "status": "completed", "result_hash": result_hash})

    def _paths(self, nonce: str) -> tuple[Path, Path]:
        nonce = _hash(nonce, "repair nonce")
        return self.directory / f"{nonce}.json", self.locks / f"repair-nonce-{nonce}.lock"

    def _load(self, path: Path, descriptor: RepairRuntimeDescriptor) -> dict[str, object]:
        if _path_lstat(path, "repair descriptor nonce") is None:
            raise PermissionError("repair descriptor nonce transaction is unavailable")
        payload = _read_canonical_json(path, "repair descriptor nonce")
        expected = {"nonce", "binding_hash", "operation", "expiry", "status", "result_hash"}
        if not isinstance(payload, dict) or set(payload) != expected:
            raise PermissionError("repair descriptor nonce transaction is invalid")
        if (
            payload["nonce"] != descriptor.nonce
            or payload["operation"] != descriptor.operation
            or payload["expiry"] != descriptor.expiry.isoformat()
            or payload["status"] not in {"pending", "completed"}
            or (payload["result_hash"] is None) != (payload["status"] == "pending")
        ):
            raise PermissionError("repair descriptor nonce transaction is invalid")
        _hash(payload["binding_hash"], "repair descriptor binding")
        if payload["result_hash"] is not None:
            _hash(payload["result_hash"], "repair descriptor result")
        return payload

    def _require_unexpired(self, descriptor: RepairRuntimeDescriptor) -> None:
        if descriptor.expiry <= self.now():
            raise PermissionError("repair descriptor is expired")


@dataclass(frozen=True, slots=True)
class _DescriptorNonceTransaction:
    store: DescriptorNonceStore
    descriptor: RepairRuntimeDescriptor
    path: Path
    completed_result_hash: str | None = None

    def require_active(self, descriptor: RepairRuntimeDescriptor) -> str:
        if descriptor != self.descriptor:
            raise PermissionError("repair descriptor nonce binding conflicts")
        self.store._require_unexpired(descriptor)
        payload = self.store._load(self.path, descriptor)
        expected = hash_json(descriptor.nonce_binding())
        if payload["status"] != "pending" or payload["binding_hash"] != expected:
            raise PermissionError("repair descriptor nonce was consumed")
        return expected

    def complete(self, result_hash: str) -> None:
        _hash(result_hash, "repair descriptor result")
        if self.completed_result_hash is not None:
            if result_hash != self.completed_result_hash:
                raise PermissionError("repair descriptor result conflicts")
            return
        self.require_active(self.descriptor)
        payload = self.store._load(self.path, self.descriptor)
        _atomic_replace_json(self.path, {**payload, "status": "completed", "result_hash": result_hash})


@dataclass(frozen=True, slots=True)
class _ProtectedRepairService:
    descriptor: RepairRuntimeDescriptor
    nonce_store: DescriptorNonceStore | _DescriptorNonceTransaction

    def require_prepare(self, generation: object, failure_hash: str) -> None:
        self.nonce_store.require_active(self.descriptor)
        if (
            self.descriptor.operation != "prepare"
            or getattr(generation, "revision", None) != self.descriptor.expected_revision
            or getattr(generation, "state_hash", None) != self.descriptor.expected_state_hash
            or failure_hash != self.descriptor.failure_hash
        ):
            raise PermissionError("repair prepare transaction is not authorized")

    def require_apply(self, request_hash: str) -> None:
        self.nonce_store.require_active(self.descriptor)
        if self.descriptor.operation != "apply" or request_hash != self.descriptor.request_hash:
            raise PermissionError("repair apply transaction is not authorized")

    def prepare_handle_id(self, generation: object, failure_hash: str) -> str:
        self.require_prepare(generation, failure_hash)
        handle_id = self.descriptor.nonce[:32]
        directory = _ensure_directory(
            self.descriptor.registry_root,
            self.descriptor.registry_root / "repair-prepare-journals",
        )
        path = directory / f"{self.descriptor.nonce}.json"
        payload = {
            "nonce": self.descriptor.nonce,
            "binding_hash": hash_json(self.descriptor.nonce_binding()),
            "handle_id": handle_id,
            "workspace_path": str(self.descriptor.repair_workspace_root / handle_id),
            "status": "intended",
            "handle_hash": None,
        }
        if not _write_new_json(path, payload):
            existing = _read_canonical_json(path, "repair prepare journal")
            if not isinstance(existing, dict) or any(
                existing.get(key) != value
                for key, value in payload.items()
                if key not in {"status", "handle_hash"}
            ) or existing.get("status") not in {"intended", "completed"}:
                raise PermissionError("repair prepare journal conflicts")
        return handle_id

    def load_prepared_handle(
        self,
        registry: RunnerRegistry,
        handle_id: str,
    ) -> RepairWorkspaceHandle | None:
        self.nonce_store.require_active(self.descriptor)
        path = registry.handles / f"{handle_id}.json"
        if _path_lstat(path, "repair workspace handle") is None:
            return None
        handle = registry.load_workspace_handle(handle_id)
        if (
            handle.run_id != self.descriptor.run_id
            or handle.expected_revision != self.descriptor.expected_revision
            or handle.expected_state_hash != self.descriptor.expected_state_hash
            or handle.failure_hash != self.descriptor.failure_hash
            or handle.path != self.descriptor.repair_workspace_root / handle_id
        ):
            raise PermissionError("prepared workspace handle does not match descriptor")
        journal = _read_canonical_json(
            self.descriptor.registry_root / "repair-prepare-journals" / f"{self.descriptor.nonce}.json",
            "repair prepare journal",
        )
        if (
            not isinstance(journal, dict)
            or journal.get("status") != "completed"
            or journal.get("handle_hash") != hash_json(handle.payload())
        ):
            raise PermissionError("prepared workspace handle is not reconciled")
        return handle

    def issue_workspace_handle(
        self,
        registry: RunnerRegistry,
        handle: object,
    ) -> object:
        if not isinstance(handle, RepairWorkspaceHandle):
            raise PermissionError("repair workspace handle is invalid")
        self.require_prepare(
            type("GenerationBinding", (), {
                "revision": handle.expected_revision,
                "state_hash": handle.expected_state_hash,
            })(),
            handle.failure_hash,
        )
        if registry.repair_runner_identity != self.descriptor.repair_runner_identity:
            raise PermissionError("repair runner identity is not launcher pinned")
        path = registry.handles / f"{handle.id}.json"
        if not _write_new_json(path, handle.payload()) and registry.load_workspace_handle(handle.id) != handle:
            raise PermissionError("issued workspace handle conflicts")
        journal = self.descriptor.registry_root / "repair-prepare-journals" / f"{self.descriptor.nonce}.json"
        prepared = _read_canonical_json(journal, "repair prepare journal")
        if not isinstance(prepared, dict) or prepared.get("handle_id") != handle.id:
            raise PermissionError("repair prepare journal is invalid")
        _atomic_replace_json(
            journal,
            {**prepared, "status": "completed", "handle_hash": hash_json(handle.payload())},
        )
        return handle

    def record_pending(
        self,
        registry: RunnerRegistry,
        pending: PendingRunnerActivation,
    ) -> PendingRunnerActivation:
        self.require_apply(pending.request_hash)
        self._require_registry(registry)
        if (
            pending.run_id != self.descriptor.run_id
            or pending.expected_revision != self.descriptor.expected_revision
            or pending.expected_state_hash != self.descriptor.expected_state_hash
        ):
            raise PermissionError("pending activation does not match repair descriptor")
        path = registry.pending_path(pending.request_hash)
        if not _write_new_json(path, pending.payload()):
            existing = registry.lookup_pending(pending.request_hash)
            if existing != pending:
                raise PermissionError("pending activation conflicts with its request")
            return existing
        return pending

    def publish_activation(
        self,
        registry: RunnerRegistry,
        pending: PendingRunnerActivation,
        receipt: RunnerActivationReceipt,
        journal: RepairJournal,
    ) -> RunnerActivationReceipt:
        self.require_apply(receipt.request_hash)
        self._require_registry(registry)
        if receipt.request_hash != pending.request_hash or receipt.old_runner_identity != pending.old_runner_identity:
            raise PermissionError("activation does not match pending repair transaction")
        journal.require(
            "source_manifest",
            "regression",
            "build",
            "old_runner_terminated",
            "new_runner_started",
            "identity_attested",
        )
        generation = RunStateStore.load_read_only(self.descriptor.state_root, self.descriptor.run_id)
        if (
            generation.revision != pending.expected_revision
            or generation.state_hash != pending.expected_state_hash
            or generation.state.disposition is not RunDisposition.REPAIR_REQUIRED
            or generation.state.runner_identity != pending.old_runner_identity
        ):
            raise PermissionError("activation expected-old state changed")
        pointer_published = False
        with _interprocess_lock(registry.pointer_lock):
            if _path_lstat(registry.pointer_path, "runner activation pointer") is not None:
                pointer = _read_canonical_json(registry.pointer_path, "runner activation pointer")
                if not isinstance(pointer, dict) or set(pointer) != {"request_hash", "receipt_hash", "runner_identity"}:
                    raise PermissionError("runner activation pointer is invalid")
                current_identity = RunnerIdentity.model_validate(pointer["runner_identity"])
                if current_identity == receipt.new_runner_identity and registry.lookup_activation(receipt.request_hash) == receipt:
                    pointer_published = True
                elif current_identity != pending.old_runner_identity:
                    raise PermissionError("runner activation pointer does not match expected old runner")
            if not pointer_published:
                activation_path = registry.activation_path(receipt.request_hash)
                if not _write_new_json(activation_path, receipt.payload()):
                    existing = registry.lookup_activation(receipt.request_hash)
                    if existing != receipt:
                        raise PermissionError("activation replay conflicts with its request")
                    receipt = existing
                _atomic_replace_json(
                    registry.pointer_path,
                    {
                        "request_hash": receipt.request_hash,
                        "receipt_hash": receipt.content_hash,
                        "runner_identity": receipt.new_runner_identity.model_dump(mode="json", round_trip=True),
                    },
                )
        return receipt

    def _require_registry(self, registry: RunnerRegistry) -> None:
        if (
            registry.root != self.descriptor.registry_root
            or registry.repair_runner_identity != self.descriptor.repair_runner_identity
        ):
            raise PermissionError("repair registry is not descriptor bound")


class _RepairWorktreeFactory:
    def __init__(self, descriptor: RepairRuntimeDescriptor, executor: ProcessGitExecutor) -> None:
        self.descriptor = descriptor
        self.executor = executor

    def create(self, handle_id: str) -> Path:
        if not isinstance(handle_id, str) or len(handle_id) != 32 or any(character not in _SHA256 for character in handle_id):
            raise PermissionError("repair workspace handle is invalid")
        path = self.descriptor.repair_workspace_root / handle_id
        if path.is_symlink():
            raise PermissionError("repair workspace already exists")
        if path.exists():
            if not path.is_dir() or not any(path.iterdir()):
                raise PermissionError("repair workspace is incomplete")
            return path
        result = self.executor.run(
            ("worktree", "add", "--detach", str(path)),
            cwd=self.descriptor.repair_repository_root,
        )
        result.require_success()
        return path


class _RepairGit:
    def __init__(
        self,
        executor: ProcessGitExecutor,
        baseline_executor: Callable[[Path], ProcessGitExecutor] | None = None,
    ) -> None:
        self.executor = executor
        self.baseline_executor = baseline_executor
        self.workspace: Path | None = None

    def baseline_hash(self, workspace: Path) -> str:
        self.workspace = workspace
        executor = self.executor if self.baseline_executor is None else self.baseline_executor(workspace)
        result = executor.run(("rev-parse", "HEAD"), cwd=workspace)
        result.require_success()
        value = executor.read_stdout(result).strip()
        if len(value) not in {40, 64} or any(character not in _SHA256 for character in value):
            raise PermissionError("repair baseline is invalid")
        return value

    def collect_repair_source_manifest(
        self,
        baseline_hash: str,
        *,
        planned_paths: tuple[str, ...],
        control_paths: tuple[str, ...],
    ) -> RepairSourceManifest:
        if self.workspace is None:
            raise PermissionError("repair workspace is unavailable")
        return GitGuard(self.workspace, executor=self.executor).collect_repair_source_manifest(
            baseline_hash,
            planned_paths=planned_paths,
            control_paths=control_paths,
        )

    def dependency_lock_hash(self, workspace: Path) -> str:
        return GitGuard(workspace, executor=self.executor).dependency_lock_hash()


class _WorkspaceRepairGit(_RepairGit):
    def __init__(self, executor: ProcessGitExecutor, workspace: Path) -> None:
        super().__init__(executor)
        self.workspace = workspace

    def collect_repair_source_manifest(
        self,
        baseline_hash: str,
        *,
        planned_paths: tuple[str, ...],
        control_paths: tuple[str, ...],
    ) -> RepairSourceManifest:
        return GitGuard(self.workspace, executor=self.executor).collect_repair_source_manifest(
            baseline_hash,
            planned_paths=planned_paths,
            control_paths=control_paths,
        )


class _UnavailableBuilder:
    def observe(self, effect_id: str) -> BuiltRunnerRelease | None:
        return None

    def build(self, *args: object, **kwargs: object) -> BuiltRunnerRelease:
        raise PermissionError("runner build is unavailable for prepare")


class _ProcessBuilder:
    def __init__(
        self,
        descriptor: RepairRuntimeDescriptor,
        process: ProcessRunner,
        evidence: FilesystemEvidenceSink,
        policy: SandboxPolicy,
    ) -> None:
        self.descriptor = descriptor
        self.process = process
        self.evidence = evidence
        self.policy = policy
        self.receipt_root = _ensure_directory(
            descriptor.registry_root,
            descriptor.registry_root / "repair-build-results",
        )
        self.snapshot_root = descriptor.release_root.parent / "repair-source-snapshots"
        self.snapshot_root.mkdir(mode=0o700, exist_ok=True)
        if self.snapshot_root.is_symlink() or not self.snapshot_root.is_dir():
            raise PermissionError("repair source snapshot root is invalid")

    def _receipt_path(self, effect_id: str) -> Path:
        return self.receipt_root / f"{_hash(effect_id, 'build effect')}.json"

    def observe(self, effect_id: str) -> BuiltRunnerRelease | None:
        path = self._receipt_path(effect_id)
        if _path_lstat(path, "repair build receipt") is None:
            return None
        payload = _read_canonical_json(path, "repair build receipt")
        expected = {
            "effect_id", "root", "release_manifest", "release_manifest_hash", "runner_executable",
            "runner_archive_hash",
            "repair_source_manifest_hash", "dependency_lock_hash", "contract_hashes",
            "contract_manifest_hash", "build_evidence_hash", "built_at",
        }
        if not isinstance(payload, dict) or set(payload) != expected or payload["effect_id"] != effect_id:
            raise PermissionError("repair build receipt is invalid")
        contract_hashes = payload["contract_hashes"]
        manifest = payload["release_manifest"]
        if not isinstance(contract_hashes, dict) or not isinstance(manifest, list):
            raise PermissionError("repair build receipt is invalid")
        built = BuiltRunnerRelease(
            root=_absolute_path(payload["root"], "built release root"),
            release_manifest=tuple(ReleaseManifestEntry.from_payload(item) for item in manifest),
            release_manifest_hash=_hash(payload["release_manifest_hash"], "release manifest"),
            runner_archive_hash=_hash(payload["runner_archive_hash"], "runner archive"),
            runner_executable=_relative_path(payload["runner_executable"], "runner executable"),
            repair_source_manifest_hash=_hash(payload["repair_source_manifest_hash"], "repair source manifest"),
            dependency_lock_hash=_hash(payload["dependency_lock_hash"], "dependency lock"),
            contract_hashes={Stage(stage): _hash(digest, "built contract") for stage, digest in contract_hashes.items()},
            contract_manifest_hash=_hash(payload["contract_manifest_hash"], "contract manifest"),
            build_evidence_hash=_hash(payload["build_evidence_hash"], "build evidence"),
            built_at=datetime.fromisoformat(payload["built_at"]),
        )
        expected_root = self.descriptor.release_root / effect_id
        if built.root != expected_root:
            raise PermissionError("repair build receipt release is invalid")
        built.verify()
        return built

    def build(
        self,
        effect_id: str,
        workspace: Path,
        source_manifest: RepairSourceManifest,
        dependency_lock_hash: str,
        contract_manifest_hash: str,
    ) -> BuiltRunnerRelease:
        effect_id = _hash(effect_id, "build effect")
        snapshot = self._materialize_snapshot(effect_id, workspace, source_manifest, dependency_lock_hash)
        binding_hash = hash_json(
            {
                "command": list(self.descriptor.build_command),
                "executable_hash": self.descriptor.build_executable_hash,
                "sandbox_policy_hash": self.descriptor.sandbox_policy_hash,
                "snapshot": str(snapshot),
                "source_manifest_hash": source_manifest.content_hash,
                "dependency_lock_hash": dependency_lock_hash,
                "previous_contract_manifest_hash": contract_manifest_hash,
            }
        )
        release = self.descriptor.release_root / effect_id
        observed = self.process.observe_reconciled_effect(
            effect_id,
            binding_hash,
            self.descriptor.regression_timeout,
        )
        if observed is not None and observed.returncode != 0:
            raise PermissionError("observed runner build failed")
        external_receipt = None if observed is None else observed.receipt_hash
        if _path_lstat(release, "runner release") is None:
            if external_receipt is not None:
                raise PermissionError("observed runner build has no immutable release")
            result, external_receipt = self.process.run_reconciled_effect(
                effect_id,
                binding_hash,
                (
                    *self.descriptor.build_command,
                    "--effect-id", effect_id,
                    "--workspace", str(snapshot),
                    "--release-root", str(release),
                    "--source-manifest", source_manifest.content_hash,
                    "--dependency-lock", dependency_lock_hash,
                    "--previous-contract-manifest", contract_manifest_hash,
                ),
                self.descriptor.repair_repository_root,
                self.descriptor.regression_timeout,
                self.evidence,
                self.descriptor.environment,
                self.policy,
            )
            result.require_success()
        elif not release.is_dir() or release.is_symlink():
            raise PermissionError("runner release path is invalid")
        elif external_receipt is None:
            raise PermissionError("runner release has no launcher effect receipt")
        contract_path = release / self.descriptor.contract_manifest
        contracts = _read_canonical_json(contract_path, "built contract manifest")
        if (
            not isinstance(contracts, dict)
            or len(contracts) > len(Stage)
            or any(key not in {stage.value for stage in Stage} for key in contracts)
        ):
            raise PermissionError("built contract manifest is invalid")
        contract_hashes = {Stage(stage): _hash(digest, "built contract") for stage, digest in contracts.items()}
        manifest = capture_built_release_manifest(release)
        manifest_hash = hash_json([entry.payload() for entry in manifest])
        runner_archive_hash = sha256(
            capture_runner_archive(release, manifest, self.descriptor.runner_executable)
        ).hexdigest()
        built = BuiltRunnerRelease(
            root=release,
            release_manifest=manifest,
            release_manifest_hash=manifest_hash,
            runner_archive_hash=runner_archive_hash,
            runner_executable=self.descriptor.runner_executable,
            repair_source_manifest_hash=source_manifest.content_hash,
            dependency_lock_hash=_hash(dependency_lock_hash, "dependency lock"),
            contract_hashes=contract_hashes,
            contract_manifest_hash=hash_json(
                {stage.value: digest for stage, digest in sorted(contract_hashes.items(), key=lambda item: item[0].value)}
            ),
            build_evidence_hash=_hash(external_receipt, "build evidence"),
            built_at=datetime.now(UTC),
        )
        built.verify()
        payload = {
            "effect_id": effect_id,
            "root": str(built.root),
            "release_manifest": [entry.payload() for entry in built.release_manifest],
            "release_manifest_hash": built.release_manifest_hash,
            "runner_archive_hash": built.runner_archive_hash,
            "runner_executable": built.runner_executable,
            "repair_source_manifest_hash": built.repair_source_manifest_hash,
            "dependency_lock_hash": built.dependency_lock_hash,
            "contract_hashes": {stage.value: digest for stage, digest in built.contract_hashes.items()},
            "contract_manifest_hash": built.contract_manifest_hash,
            "build_evidence_hash": built.build_evidence_hash,
            "built_at": built.built_at.isoformat(),
        }
        if not _write_new_json(self._receipt_path(effect_id), payload):
            observed = self.observe(effect_id)
            if observed != built:
                raise PermissionError("repair build receipt conflicts")
            return observed
        return built

    def _materialize_snapshot(
        self,
        effect_id: str,
        workspace: Path,
        source_manifest: RepairSourceManifest,
        dependency_lock_hash: str,
    ) -> Path:
        snapshot = self.snapshot_root / effect_id
        if _path_lstat(snapshot, "repair source snapshot") is not None:
            self._verify_snapshot(snapshot, source_manifest, dependency_lock_hash)
            return snapshot
        temporary = self.snapshot_root / f".{effect_id}.{self.descriptor.nonce}"
        if _path_lstat(temporary, "repair source snapshot temporary") is not None:
            raise PermissionError("repair source snapshot is incomplete")
        temporary.mkdir(mode=0o700)
        try:
            for entry in source_manifest.workspace_files:
                relative = _relative_path(entry.path, "repair source snapshot path")
                source = workspace / relative
                destination = temporary / relative
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                metadata = os.lstat(source)
                expected_mode = entry.mode
                actual_mode = "120000" if stat.S_ISLNK(metadata.st_mode) else (
                    "100755" if stat.S_ISREG(metadata.st_mode) and metadata.st_mode & 0o111 else "100644"
                )
                if actual_mode != expected_mode:
                    raise PermissionError("repair source changed before snapshot")
                if entry.kind == "symlink" and stat.S_ISLNK(metadata.st_mode):
                    target = os.readlink(source)
                    if sha256(os.fsencode(target)).hexdigest() != entry.content_sha256:
                        raise PermissionError("repair source changed before snapshot")
                    destination.symlink_to(target)
                elif entry.kind == "file" and stat.S_ISREG(metadata.st_mode):
                    source_descriptor = os.open(
                        source,
                        os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                    )
                    destination_descriptor = os.open(
                        destination,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                        stat.S_IMODE(metadata.st_mode) & ~0o222,
                    )
                    digest = sha256()
                    try:
                        while chunk := os.read(source_descriptor, 65_536):
                            digest.update(chunk)
                            remaining = memoryview(chunk)
                            while remaining:
                                remaining = remaining[os.write(destination_descriptor, remaining):]
                        os.fsync(destination_descriptor)
                    finally:
                        os.close(source_descriptor)
                        os.close(destination_descriptor)
                    if digest.hexdigest() != entry.content_sha256:
                        raise PermissionError("repair source changed before snapshot")
                else:
                    raise PermissionError("repair source changed before snapshot")
            for current, directories, _ in os.walk(temporary, topdown=False, followlinks=False):
                for directory in directories:
                    path = Path(current) / directory
                    if not path.is_symlink():
                        path.chmod(0o555)
                Path(current).chmod(0o555)
            os.replace(temporary, snapshot)
        except BaseException:
            shutil.rmtree(temporary, ignore_errors=True)
            raise
        self._verify_snapshot(snapshot, source_manifest, dependency_lock_hash)
        return snapshot

    @staticmethod
    def _verify_snapshot(
        snapshot: Path,
        source_manifest: RepairSourceManifest,
        dependency_lock_hash: str,
    ) -> None:
        expected = {entry.path: entry for entry in source_manifest.workspace_files}
        observed: set[str] = set()
        for current, directories, files in os.walk(snapshot, followlinks=False):
            current_path = Path(current)
            for name in tuple(directories):
                path = current_path / name
                if path.is_symlink():
                    directories.remove(name)
                    files.append(name)
            for name in files:
                path = current_path / name
                relative = path.relative_to(snapshot).as_posix()
                entry = expected.get(relative)
                metadata = os.lstat(path)
                if entry is None:
                    raise PermissionError("repair source snapshot contains an unexpected path")
                if stat.S_ISLNK(metadata.st_mode):
                    kind = "symlink"
                    digest = sha256(os.fsencode(os.readlink(path))).hexdigest()
                elif stat.S_ISREG(metadata.st_mode):
                    kind = "file"
                    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
                    content_hash = sha256()
                    try:
                        while chunk := os.read(descriptor, 65_536):
                            content_hash.update(chunk)
                    finally:
                        os.close(descriptor)
                    digest = content_hash.hexdigest()
                else:
                    raise PermissionError("repair source snapshot contains an unsupported path")
                if kind != entry.kind or digest != entry.content_sha256 or metadata.st_mode & 0o222:
                    raise PermissionError("repair source snapshot does not match its manifest")
                observed.add(relative)
        if observed != set(expected) or snapshot.stat().st_mode & 0o222:
            raise PermissionError("repair source snapshot is incomplete or mutable")
        if GitGuard(snapshot).dependency_lock_hash() != dependency_lock_hash:
            raise PermissionError("repair source snapshot dependency lock does not match")


class _ProcessLifecycleEffect:
    def __init__(
        self,
        *,
        label: str,
        command: tuple[str, ...],
        executable_hash: str,
        descriptor: RepairRuntimeDescriptor,
        process: ProcessRunner,
        evidence: FilesystemEvidenceSink,
        policy: SandboxPolicy,
        repair_service: ProtectedRepairService,
    ) -> None:
        self.label = label
        self.command = command
        self.executable_hash = executable_hash
        self.descriptor = descriptor
        self.process = process
        self.evidence = evidence
        self.policy = policy
        self.repair_service = repair_service
        self.receipt_root = _ensure_directory(
            descriptor.registry_root,
            descriptor.registry_root / "repair-lifecycle-results",
        )

    def _path(self, effect_id: str) -> Path:
        return self.receipt_root / f"{_hash(effect_id, 'lifecycle effect')}.json"

    def observe(self, effect_id: str, run_id: str, runner: RunnerIdentity) -> str | None:
        self.repair_service.require_apply(self.descriptor.request_hash or "")
        path = self._path(effect_id)
        if _path_lstat(path, "repair lifecycle receipt") is None:
            observed = self.process.observe_reconciled_effect(
                effect_id,
                self._binding_hash(run_id, runner),
                self.descriptor.regression_timeout,
            )
            if observed is None:
                return None
            if observed.returncode != 0:
                raise PermissionError("observed repair lifecycle effect failed")
            return observed.receipt_hash
        payload = _read_canonical_json(path, "repair lifecycle receipt")
        if (
            not isinstance(payload, dict)
            or set(payload) != {"effect_id", "label", "run_id", "runner_identity", "evidence_hash"}
            or payload["effect_id"] != effect_id
            or payload["label"] != self.label
            or payload["run_id"] != run_id
            or RunnerIdentity.model_validate(payload["runner_identity"]) != runner
        ):
            raise PermissionError("repair lifecycle receipt is invalid")
        return _hash(payload["evidence_hash"], "lifecycle evidence")

    def invoke(self, effect_id: str, run_id: str, runner: RunnerIdentity) -> str:
        self.repair_service.require_apply(self.descriptor.request_hash or "")
        result, evidence_hash = self.process.run_reconciled_effect(
            effect_id,
            self._binding_hash(run_id, runner),
            (
                *self.command,
                "--effect-id", effect_id,
                "--run", run_id,
                "--runner", json.dumps(runner.model_dump(mode="json"), sort_keys=True, separators=(",", ":")),
            ),
            self.descriptor.repair_repository_root,
            self.descriptor.regression_timeout,
            self.evidence,
            self.descriptor.environment,
            self.policy,
        )
        result.require_success()
        evidence_hash = _hash(evidence_hash, "lifecycle evidence")
        payload = {
            "effect_id": effect_id,
            "label": self.label,
            "run_id": run_id,
            "runner_identity": runner.model_dump(mode="json", round_trip=True),
            "evidence_hash": evidence_hash,
        }
        if not _write_new_json(self._path(effect_id), payload) and self.observe(effect_id, run_id, runner) != evidence_hash:
            raise PermissionError("repair lifecycle receipt conflicts")
        return evidence_hash

    def _binding_hash(self, run_id: str, runner: RunnerIdentity) -> str:
        return hash_json(
            {
                "label": self.label,
                "run_id": run_id,
                "runner_identity": runner.model_dump(mode="json", round_trip=True),
                "command": list(self.command),
                "executable_hash": self.executable_hash,
                "sandbox_policy_hash": self.descriptor.sandbox_policy_hash,
            }
        )


@dataclass(frozen=True, slots=True)
class _LauncherActivationSigner:
    sandbox: LauncherSocketSandbox
    timeout: float

    def sign(self, payload: bytes, public_key_hash: str) -> str:
        return self.sandbox.sign_activation(payload, public_key_hash, timeout=self.timeout)


@dataclass(frozen=True, slots=True)
class ProtectedRepairRuntime:
    descriptor: RepairRuntimeDescriptor

    def prepare(self, run_id: str, expected_revision: int, expected_state_hash: str, failure_hash: str) -> object:
        if not self.descriptor.authorizes(
            "prepare",
            run_id=run_id,
            expected_revision=expected_revision,
            expected_state_hash=expected_state_hash,
            failure_hash=failure_hash,
        ):
            raise PermissionError("repair prepare is not authorized")
        nonce_store = DescriptorNonceStore(self.descriptor.registry_root)
        with nonce_store.transaction(self.descriptor, reconcile_completed=True) as transaction:
            if transaction.completed_result_hash is not None:
                return self._recover_prepared_handle(transaction.completed_result_hash)
            repair_service = _ProtectedRepairService(self.descriptor, transaction)  # type: ignore[arg-type]
            generation = RunStateStore.load_read_only(self.descriptor.state_root, run_id)
            if generation.revision != expected_revision or generation.state_hash != expected_state_hash:
                raise PermissionError("repair prepare generation is stale")
            runner = self._compose_runner(workspace=None, repair_service=repair_service)
            handle = runner.prepare_workspace(generation, failure_hash)
            transaction.complete(hash_json(handle.payload()))
            return handle

    def apply(self, workspace: str, request_hash: str) -> object:
        workspace_path = _absolute_path(workspace, "repair workspace")
        if not self.descriptor.authorizes(
            "apply",
            run_id=self.descriptor.run_id,
            expected_revision=self.descriptor.expected_revision,
            expected_state_hash=self.descriptor.expected_state_hash,
            workspace_id=workspace_path.name,
            workspace_path=workspace_path,
            request_hash=request_hash,
        ):
            raise PermissionError("repair apply is not authorized")
        request = RepairGuard(workspace_path).load_request(request_hash)
        if (
            request.workspace.id != self.descriptor.workspace_id
            or request.expected_revision != self.descriptor.expected_revision
            or request.expected_state_hash != self.descriptor.expected_state_hash
        ):
            raise PermissionError("repair request does not match descriptor")
        nonce_store = DescriptorNonceStore(self.descriptor.registry_root)
        with nonce_store.transaction(self.descriptor, reconcile_completed=True) as transaction:
            if transaction.completed_result_hash is not None:
                return self._recover_applied_generation(transaction.completed_result_hash)
            return self._apply_transaction(workspace_path, request, transaction)

    def _recover_prepared_handle(self, result_hash: str) -> RepairWorkspaceHandle:
        descriptor = self.descriptor
        registry = RunnerRegistry(
            descriptor.registry_root,
            repair_runner_identity=descriptor.repair_runner_identity,
        )
        handle = registry.load_workspace_handle(descriptor.nonce[:32])
        if (
            handle.run_id != descriptor.run_id
            or handle.expected_revision != descriptor.expected_revision
            or handle.expected_state_hash != descriptor.expected_state_hash
            or handle.failure_hash != descriptor.failure_hash
            or handle.path != descriptor.repair_workspace_root / handle.id
            or hash_json(handle.payload()) != result_hash
        ):
            raise PermissionError("completed repair prepare result does not match descriptor")
        journal = _read_canonical_json(
            descriptor.registry_root / "repair-prepare-journals" / f"{descriptor.nonce}.json",
            "repair prepare journal",
        )
        if (
            not isinstance(journal, dict)
            or journal.get("status") != "completed"
            or journal.get("handle_hash") != result_hash
        ):
            raise PermissionError("completed repair prepare result is not reconciled")
        handle.identity.verify()
        return handle

    def _recover_applied_generation(self, result_hash: str) -> object:
        descriptor = self.descriptor
        registry = RunnerRegistry(
            descriptor.registry_root,
            repair_runner_identity=descriptor.repair_runner_identity,
        )
        store = RunStateStore(descriptor.state_root, descriptor.run_id)
        generation = store.load()
        receipt = registry.current_activation()
        journal = RepairJournal(descriptor.state_root, descriptor.request_hash or "")
        journal.require(
            "source_manifest",
            "regression",
            "build",
            "old_runner_terminated",
            "new_runner_started",
            "identity_attested",
            "activation",
            "state_activated",
        )
        if (
            generation.revision != descriptor.expected_revision + 1
            or generation.state_hash != result_hash
            or generation.state.disposition is not RunDisposition.ACTIVE
            or generation.state.restart_receipt_hash != receipt.content_hash
            or generation.state.runner_identity != receipt.new_runner_identity
            or receipt.request_hash != descriptor.request_hash
            or journal.completed("state_activated") != result_hash
        ):
            raise PermissionError("completed repair apply result does not match descriptor")
        return generation

    def _apply_transaction(
        self,
        workspace_path: Path,
        request: object,
        transaction: _DescriptorNonceTransaction,
    ) -> object:
        from .repair import RepairRequest

        if not isinstance(request, RepairRequest):
            raise PermissionError("repair request is invalid")
        repair_service = _ProtectedRepairService(self.descriptor, transaction)  # type: ignore[arg-type]
        repair_service.require_apply(request.content_hash)
        generation = RunStateStore.load_read_only(self.descriptor.state_root, self.descriptor.run_id)
        generation_changed = (
            generation.revision != self.descriptor.expected_revision
            or generation.state_hash != self.descriptor.expected_state_hash
        )
        if generation_changed and generation.state.disposition is not RunDisposition.ACTIVE:
            raise PermissionError("repair apply generation is stale")
        capabilities = self._compose_process_capabilities(exact_workspace=workspace_path)
        runner = self._compose_runner(
            workspace=workspace_path,
            repair_service=repair_service,
            capabilities=capabilities,
        )
        if not generation_changed:
            runner.validate_regress_build(request)
        process, evidence, policy, registry = capabilities
        if not isinstance(process.sandbox, LauncherSocketSandbox):
            raise RepairRuntimeConfigurationError("ticket runner sandbox is unavailable")

        def lifecycle(label: str, command: tuple[str, ...], executable_hash: str) -> _ProcessLifecycleEffect:
            return _ProcessLifecycleEffect(
                label=label,
                command=command,
                executable_hash=executable_hash,
                descriptor=self.descriptor,
                process=process,
                evidence=evidence,
                policy=policy,
                repair_service=repair_service,
            )

        store = RunStateStore(self.descriptor.state_root, self.descriptor.run_id)
        launcher = TrustedLauncher(
            store,
            registry,
            terminate_old_runner=lifecycle(
                "terminate", self.descriptor.terminate_command, self.descriptor.terminate_executable_hash
            ),
            start_new_runner=lifecycle("start", self.descriptor.start_command, self.descriptor.start_executable_hash),
            attest_new_runner=lifecycle(
                "attest", self.descriptor.attest_command, self.descriptor.attest_executable_hash
            ),
            repair_service=repair_service,
            activation_signer=_LauncherActivationSigner(
                LauncherSocketSandbox(self.descriptor.sandbox_socket, self.descriptor.sandbox_identity),
                self.descriptor.regression_timeout,
            ),
            ticket_invoker=PythonArchiveTicketInvoker(
                interpreter=self.descriptor.ticket_interpreter,
                interpreter_hash=self.descriptor.ticket_interpreter_hash,
                sandbox=process.sandbox,
                timeout=self.descriptor.regression_timeout,
                cwd=self.descriptor.repair_repository_root,
                policy=policy,
            ),
        )
        activated = launcher.reconcile_activation(self.descriptor.run_id, request.content_hash)
        transaction.complete(activated.state_hash)
        return activated

    def _compose_runner(
        self,
        *,
        workspace: Path | None,
        repair_service: ProtectedRepairService,
        capabilities: tuple[ProcessRunner, FilesystemEvidenceSink, SandboxPolicy, RunnerRegistry] | None = None,
    ) -> RepairRunner:
        descriptor = self.descriptor
        process, evidence, policy, registry = (
            self._compose_process_capabilities() if capabilities is None else capabilities
        )
        git_executor = ProcessGitExecutor(
            process_runner=process,
            git_executable=str(descriptor.git_executable),
            timeout=descriptor.regression_timeout,
            evidence_sink=evidence,
            environment=descriptor.environment,
            sandbox_policy=policy,
        )
        return RepairRunner(
            worktree_factory=_RepairWorktreeFactory(descriptor, git_executor),
            git=(
                _RepairGit(
                    git_executor,
                    baseline_executor=lambda path: self._workspace_git_executor(path),
                )
                if workspace is None
                else _WorkspaceRepairGit(git_executor, workspace)
            ),
            regression=RepairRegression(
                process,
                descriptor.regression_command,
                descriptor.regression_timeout,
                evidence,
                descriptor.environment,
                policy,
                executable_hash=descriptor.regression_executable_hash,
                sandbox_policy_hash=descriptor.sandbox_policy_hash,
                result_root=_ensure_directory(
                    descriptor.registry_root,
                    descriptor.registry_root / "repair-regression-results",
                ),
            ),
            builder=(
                _UnavailableBuilder()
                if workspace is None
                else _ProcessBuilder(descriptor, process, evidence, policy)
            ),
            registry=registry,
            repair_runner_identity=descriptor.repair_runner_identity,
            state_root=descriptor.state_root,
            repair_workspace_root=descriptor.repair_workspace_root,
            repair_service=repair_service,
        )
    def _compose_process_capabilities(
        self,
        *,
        exact_workspace: Path | None = None,
    ) -> tuple[ProcessRunner, FilesystemEvidenceSink, SandboxPolicy, RunnerRegistry]:
        descriptor = self.descriptor
        snapshot_root = descriptor.release_root.parent / "repair-source-snapshots"
        snapshot_root.mkdir(mode=0o700, exist_ok=True)
        for path in (
            descriptor.registry_root,
            descriptor.state_root,
            descriptor.repair_repository_root,
            descriptor.repair_workspace_root,
            descriptor.controlled_home,
            descriptor.release_root,
            snapshot_root,
            *descriptor.secret_paths,
        ):
            if not path.is_absolute() or path.is_symlink() or not path.is_dir():
                raise RepairRuntimeConfigurationError("repair capability root is unavailable")
        if any(descriptor.controlled_home.iterdir()):
            raise RepairRuntimeConfigurationError("repair controlled home is not empty")
        executable_hashes = {
            descriptor.git_executable: descriptor.git_executable_hash,
            Path(descriptor.regression_command[0]): descriptor.regression_executable_hash,
            Path(descriptor.build_command[0]): descriptor.build_executable_hash,
            descriptor.ticket_interpreter: descriptor.ticket_interpreter_hash,
            Path(descriptor.terminate_command[0]): descriptor.terminate_executable_hash,
            Path(descriptor.start_command[0]): descriptor.start_executable_hash,
            Path(descriptor.attest_command[0]): descriptor.attest_executable_hash,
        }
        verifier = HashVerifiedExecutables(executable_hashes)
        sandbox = LauncherSocketSandbox(descriptor.sandbox_socket, descriptor.sandbox_identity)
        process = ProcessRunner(verifier, sandbox)
        if type(process) is not ProcessRunner:
            raise RepairRuntimeConfigurationError("repair process runner is invalid")
        command_workspace = descriptor.workspace_path if exact_workspace is None else exact_workspace
        policy = SandboxPolicy(
            project_root=descriptor.repair_repository_root,
            readable_roots=(
                descriptor.repair_repository_root,
                descriptor.repair_workspace_root,
                descriptor.release_root,
                snapshot_root,
                *((command_workspace,) if command_workspace is not None else ()),
            ),
            writable_roots=(
                descriptor.repair_repository_root,
                descriptor.repair_workspace_root,
                descriptor.release_root,
                *((command_workspace,) if command_workspace is not None else ()),
            ),
            authoritative_state_root=descriptor.state_root,
            secret_paths=descriptor.secret_paths,
            controlled_home=descriptor.controlled_home,
            environment_allowlist=frozenset(descriptor.environment),
        )
        evidence = FilesystemEvidenceSink(descriptor.evidence_root)
        registry = RunnerRegistry(
            descriptor.registry_root,
            repair_runner_identity=descriptor.repair_runner_identity,
        )
        return process, evidence, policy, registry

    def _workspace_git_executor(self, workspace: Path) -> ProcessGitExecutor:
        process, evidence, policy, _ = self._compose_process_capabilities(exact_workspace=workspace)
        return ProcessGitExecutor(
            process_runner=process,
            git_executable=str(self.descriptor.git_executable),
            timeout=self.descriptor.regression_timeout,
            evidence_sink=evidence,
            environment=self.descriptor.environment,
            sandbox_policy=policy,
        )


def load_protected_runtime() -> ProtectedRepairRuntime:
    """Authenticate a one-operation launcher descriptor from fixed read-only FD 3."""
    try:
        descriptor = os.dup(_REPAIR_DESCRIPTOR_FD)
    except OSError as error:
        raise RepairRuntimeConfigurationError("repair descriptor is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        access_mode = fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
        if not stat.S_ISREG(metadata.st_mode) or access_mode != os.O_RDONLY:
            raise RepairRuntimeConfigurationError("repair descriptor is invalid")
        raw = os.pread(descriptor, _MAX_REPAIR_DESCRIPTOR_BYTES + 1, 0)
    except OSError as error:
        raise RepairRuntimeConfigurationError("repair descriptor is invalid") from error
    finally:
        os.close(descriptor)
    if len(raw) > _MAX_REPAIR_DESCRIPTOR_BYTES:
        raise RepairRuntimeConfigurationError("repair descriptor is invalid")
    try:
        envelope = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_json_keys)
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
            raise ValueError
        payload = envelope["payload"]
        signature = envelope["signature"]
        if not isinstance(signature, str) or len(signature) != 128:
            raise ValueError
        key = _REPAIR_DESCRIPTOR_VERIFICATION_KEY
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError
        Ed25519PublicKey.from_public_bytes(key).verify(bytes.fromhex(signature), canonical_json_bytes(payload))
        return ProtectedRepairRuntime(RepairRuntimeDescriptor.from_payload(payload, now=datetime.now(UTC)))
    except (InvalidSignature, TypeError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise RepairRuntimeConfigurationError("repair descriptor is invalid") from error


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="auto-code-repair")
    commands = parser.add_subparsers(dest="command", parser_class=_Parser)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--run", required=True)
    prepare.add_argument("--expected-revision", required=True)
    prepare.add_argument("--expected-hash", required=True)
    prepare.add_argument("--failure", required=True)
    apply = commands.add_parser("apply")
    apply.add_argument("--workspace", required=True)
    apply.add_argument("--request", required=True)
    return parser


def main(
    argv: Sequence[str] | None = None,
) -> int:
    try:
        args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
        protected = load_protected_runtime()
        if args.command == "prepare":
            revision = int(args.expected_revision)
            handle = protected.prepare(args.run, revision, args.expected_hash, args.failure)
            if not isinstance(handle, RepairWorkspaceHandle):
                raise ValueError("repair prepare returned an invalid handle")
            print(
                json.dumps(
                    {
                        "schema_version": "v1",
                        "operation": "prepare",
                        "run_id": handle.run_id,
                        "expected_revision": handle.expected_revision,
                        "expected_state_hash": handle.expected_state_hash,
                        "failure_hash": handle.failure_hash,
                        "workspace": {
                            "id": handle.id,
                            "path": str(handle.path),
                            "baseline_hash": handle.baseline_hash,
                        },
                    },
                    sort_keys=True,
                )
            )
            return 0
        if args.command == "apply":
            generation = protected.apply(args.workspace, args.request)
            runner_identity = getattr(generation.state, "runner_identity", None)
            if not isinstance(runner_identity, RunnerIdentity):
                raise ValueError("repair apply returned an invalid generation")
            print(
                json.dumps(
                    {
                        "schema_version": "v1",
                        "operation": "apply",
                        "run_id": generation.state.run_id,
                        "request_hash": args.request,
                        "workspace_id": Path(args.workspace).name,
                        "workspace_path": str(Path(args.workspace)),
                        "revision": generation.revision,
                        "state_hash": generation.state_hash,
                        "runner_identity_hash": runner_identity.content_hash,
                    },
                    sort_keys=True,
                )
            )
            return 0
    except (RepairRuntimeConfigurationError, RepairError, StateStoreError, ValueError, PermissionError, OSError):
        pass
    print("auto-code-repair: operation unavailable", file=sys.stderr)
    return 2


def entrypoint() -> None:
    raise SystemExit(main())
