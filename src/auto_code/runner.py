from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import os
from pathlib import Path
import stat
from typing import Protocol
import uuid

from .contracts import FailureClass, RunnerIdentity, RunDisposition, Stage
from .git import RepairSourceManifest
from .hashing import hash_json
from .process import CommandResult, EvidenceSink, ProcessRunner, SandboxPolicy
from .repair import (
    InjectedCrash,
    RepairGuard,
    RepairRequest,
    RepairTicketOverlap,
    RepairWorkspaceHandle,
    RepairWorkspaceIdentity,
    UnauthorizedRepairError,
)
from .state import (
    RunStateStore,
    StateGeneration,
    _atomic_replace_json,
    _ensure_directory,
    _interprocess_lock,
    _normalize_state_root,
    _path_lstat,
    _read_canonical_json,
    _write_new_json,
)


_PHASES = frozenset(
    {
        "source_manifest",
        "regression",
        "build",
        "activation",
        "old_runner_terminated",
        "new_runner_started",
        "identity_attested",
        "state_activated",
    }
)


class RepairWorktreeFactory(Protocol):
    def create(self, handle_id: str) -> Path: ...


class RepairGit(Protocol):
    def baseline_hash(self, workspace: Path) -> str: ...

    def collect_repair_source_manifest(
        self,
        baseline_hash: str,
        *,
        planned_paths: tuple[str, ...],
        control_paths: tuple[str, ...],
    ) -> RepairSourceManifest: ...

    def dependency_lock_hash(self) -> str: ...


class RunnerBuilder(Protocol):
    def build(
        self,
        workspace: Path,
        source_manifest: RepairSourceManifest,
        dependency_lock_hash: str,
        contract_manifest_hash: str,
    ) -> BuiltRunnerRelease: ...


@dataclass(frozen=True, slots=True)
class BuiltRunnerRelease:
    root: Path
    release_manifest_hash: str
    repair_source_manifest_hash: str
    dependency_lock_hash: str
    contract_manifest_hash: str
    build_evidence_hash: str
    built_at: datetime

    def verify(self) -> None:
        if self.built_at.tzinfo is None:
            raise UnauthorizedRepairError("built runner release timestamp is invalid")
        expected = _immutable_release_manifest_hash(self.root)
        if expected != self.release_manifest_hash:
            raise UnauthorizedRepairError("built runner release does not match its immutable manifest")
        for digest in (
            self.repair_source_manifest_hash,
            self.dependency_lock_hash,
            self.contract_manifest_hash,
            self.build_evidence_hash,
        ):
            _require_hash(digest, "built runner binding")

    @property
    def identity(self) -> RunnerIdentity:
        self.verify()
        return RunnerIdentity(
            content_hash=self.release_manifest_hash,
            source_sha=self.repair_source_manifest_hash,
            dependency_lock_hash=self.dependency_lock_hash,
            contract_bundle_hash=self.contract_manifest_hash,
            built_at=self.built_at,
        )


@dataclass(frozen=True, slots=True)
class RepairRegression:
    process_runner: ProcessRunner
    command: tuple[str, ...]
    timeout: float
    evidence_sink: EvidenceSink
    environment: Mapping[str, str]
    sandbox_policy: SandboxPolicy
    executable_hash: str | None = None
    sandbox_policy_hash: str | None = None

    def run(self, workspace: Path) -> str:
        result = self.process_runner.run(
            self.command,
            workspace,
            self.timeout,
            self.evidence_sink,
            self.environment,
            self.sandbox_policy,
        )
        result.require_success()
        if result.stdout_path is None or result.stderr_path is None:
            raise UnauthorizedRepairError("repair regression evidence is incomplete")
        return hash_json(
            {
                "argv": list(result.argv),
                "returncode": result.returncode,
                "stdout": result.stdout_path.model_dump(mode="json", round_trip=True),
                "stderr": result.stderr_path.model_dump(mode="json", round_trip=True),
            }
        )


class RepairJournal:
    """Interprocess-serialized completion records consulted before every repair effect."""

    def __init__(self, root: Path, request_hash: str) -> None:
        self.root = _normalize_state_root(Path(root))
        self.request_hash = _require_hash(request_hash, "repair request")
        self.directory = _ensure_directory(self.root, self.root / "repair-journals")
        locks = _ensure_directory(self.root, self.root / "locks")
        self.path = self.directory / f"{self.request_hash}.json"
        self.lock_path = locks / f"repair-{self.request_hash}.lock"

    def completed(self, phase: str) -> str | None:
        if phase not in _PHASES:
            raise ValueError("repair journal phase is invalid")
        with _interprocess_lock(self.lock_path):
            return self._load().get(phase)

    def record(self, phase: str, evidence_hash: str) -> str:
        if phase not in _PHASES:
            raise ValueError("repair journal phase is invalid")
        evidence_hash = _require_hash(evidence_hash, "repair phase evidence")
        with _interprocess_lock(self.lock_path):
            current = self._load()
            existing = current.get(phase)
            if existing is not None:
                if existing != evidence_hash:
                    raise UnauthorizedRepairError("repair phase replay conflicts with durable evidence")
                return existing
            current[phase] = evidence_hash
            _atomic_replace_json(self.path, {"request_hash": self.request_hash, "completed": current})
            return evidence_hash

    def run_once(self, phase: str, effect: Callable[[], str]) -> str:
        if phase not in _PHASES:
            raise ValueError("repair journal phase is invalid")
        with _interprocess_lock(self.lock_path):
            current = self._load()
            existing = current.get(phase)
            if existing is not None:
                return existing
            result = _require_hash(effect(), "repair phase evidence")
            current[phase] = result
            _atomic_replace_json(self.path, {"request_hash": self.request_hash, "completed": current})
            return result

    def require(self, *phases: str) -> None:
        completed = self._load()
        if any(phase not in completed for phase in phases):
            raise UnauthorizedRepairError("repair transaction is incomplete")

    def _load(self) -> dict[str, str]:
        if _path_lstat(self.path, "repair journal") is None:
            return {}
        payload = _read_canonical_json(self.path, "repair journal")
        if not isinstance(payload, dict) or set(payload) != {"request_hash", "completed"}:
            raise UnauthorizedRepairError("repair journal is invalid")
        completed = payload["completed"]
        if payload["request_hash"] != self.request_hash or not isinstance(completed, dict):
            raise UnauthorizedRepairError("repair journal is invalid")
        if any(phase not in _PHASES or not isinstance(digest, str) for phase, digest in completed.items()):
            raise UnauthorizedRepairError("repair journal is invalid")
        return {phase: _require_hash(digest, "repair phase evidence") for phase, digest in completed.items()}


@dataclass(frozen=True, slots=True)
class PendingRunnerActivation:
    request_hash: str
    run_id: str
    expected_revision: int
    expected_state_hash: str
    failure_hash: str
    repair_source_manifest_hash: str
    project_policy_hash: str
    regression_evidence_hash: str
    build_evidence_hash: str
    release_manifest_hash: str
    old_runner_identity: RunnerIdentity
    new_runner_identity: RunnerIdentity
    contract_hashes: Mapping[Stage, str]

    @property
    def content_hash(self) -> str:
        return hash_json(self.payload())

    def payload(self) -> dict[str, object]:
        return {
            "request_hash": self.request_hash,
            "run_id": self.run_id,
            "expected_revision": self.expected_revision,
            "expected_state_hash": self.expected_state_hash,
            "failure_hash": self.failure_hash,
            "repair_source_manifest_hash": self.repair_source_manifest_hash,
            "project_policy_hash": self.project_policy_hash,
            "regression_evidence_hash": self.regression_evidence_hash,
            "build_evidence_hash": self.build_evidence_hash,
            "release_manifest_hash": self.release_manifest_hash,
            "old_runner_identity": self.old_runner_identity.model_dump(mode="json", round_trip=True),
            "new_runner_identity": self.new_runner_identity.model_dump(mode="json", round_trip=True),
            "contract_hashes": {stage.value: digest for stage, digest in sorted(self.contract_hashes.items(), key=lambda item: item[0].value)},
        }

    @classmethod
    def from_payload(cls, payload: object) -> PendingRunnerActivation:
        expected = {
            "request_hash", "run_id", "expected_revision", "expected_state_hash", "failure_hash",
            "repair_source_manifest_hash", "project_policy_hash", "regression_evidence_hash",
            "build_evidence_hash", "release_manifest_hash", "old_runner_identity", "new_runner_identity",
            "contract_hashes",
        }
        if not isinstance(payload, dict) or set(payload) != expected or not isinstance(payload["contract_hashes"], dict):
            raise ValueError("pending runner activation is invalid")
        return cls(
            request_hash=_require_hash(payload["request_hash"], "repair request"),
            run_id=payload["run_id"],
            expected_revision=payload["expected_revision"],
            expected_state_hash=_require_hash(payload["expected_state_hash"], "expected state"),
            failure_hash=_require_hash(payload["failure_hash"], "repair failure"),
            repair_source_manifest_hash=_require_hash(payload["repair_source_manifest_hash"], "repair source"),
            project_policy_hash=_require_hash(payload["project_policy_hash"], "project policy"),
            regression_evidence_hash=_require_hash(payload["regression_evidence_hash"], "regression evidence"),
            build_evidence_hash=_require_hash(payload["build_evidence_hash"], "build evidence"),
            release_manifest_hash=_require_hash(payload["release_manifest_hash"], "release manifest"),
            old_runner_identity=RunnerIdentity.model_validate(payload["old_runner_identity"]),
            new_runner_identity=RunnerIdentity.model_validate(payload["new_runner_identity"]),
            contract_hashes={Stage(stage): _require_hash(digest, "contract") for stage, digest in payload["contract_hashes"].items()},
        )


@dataclass(frozen=True, slots=True)
class RunnerActivationReceipt:
    request_hash: str
    run_id: str
    expected_revision: int
    expected_state_hash: str
    failure_hash: str
    repair_source_manifest_hash: str
    project_policy_hash: str
    regression_evidence_hash: str
    build_evidence_hash: str
    release_manifest_hash: str
    termination_evidence_hash: str
    restart_evidence_hash: str
    attestation_evidence_hash: str
    old_runner_identity: RunnerIdentity
    new_runner_identity: RunnerIdentity
    compatible_checkpoint_stages: tuple[Stage, ...]
    contract_hashes: Mapping[Stage, str]

    @property
    def old_contract_bundle_hash(self) -> str:
        return self.old_runner_identity.contract_bundle_hash

    @property
    def new_contract_bundle_hash(self) -> str:
        return self.new_runner_identity.contract_bundle_hash

    @property
    def content_hash(self) -> str:
        return hash_json(self.payload())

    def payload(self) -> dict[str, object]:
        return {
            "request_hash": self.request_hash,
            "run_id": self.run_id,
            "expected_revision": self.expected_revision,
            "expected_state_hash": self.expected_state_hash,
            "failure_hash": self.failure_hash,
            "repair_source_manifest_hash": self.repair_source_manifest_hash,
            "project_policy_hash": self.project_policy_hash,
            "regression_evidence_hash": self.regression_evidence_hash,
            "build_evidence_hash": self.build_evidence_hash,
            "release_manifest_hash": self.release_manifest_hash,
            "termination_evidence_hash": self.termination_evidence_hash,
            "restart_evidence_hash": self.restart_evidence_hash,
            "attestation_evidence_hash": self.attestation_evidence_hash,
            "old_runner_identity": self.old_runner_identity.model_dump(mode="json", round_trip=True),
            "new_runner_identity": self.new_runner_identity.model_dump(mode="json", round_trip=True),
            "compatible_checkpoint_stages": [stage.value for stage in self.compatible_checkpoint_stages],
            "contract_hashes": {stage.value: digest for stage, digest in sorted(self.contract_hashes.items(), key=lambda item: item[0].value)},
        }

    @classmethod
    def from_payload(cls, payload: object) -> RunnerActivationReceipt:
        expected = {
            "request_hash", "run_id", "expected_revision", "expected_state_hash", "failure_hash",
            "repair_source_manifest_hash", "project_policy_hash", "regression_evidence_hash", "build_evidence_hash",
            "release_manifest_hash", "termination_evidence_hash", "restart_evidence_hash", "attestation_evidence_hash",
            "old_runner_identity", "new_runner_identity", "compatible_checkpoint_stages", "contract_hashes",
        }
        if not isinstance(payload, dict) or set(payload) != expected or not isinstance(payload["contract_hashes"], dict):
            raise ValueError("activation receipt is invalid")
        pending = PendingRunnerActivation.from_payload(
            {key: payload[key] for key in PendingRunnerActivation.__dataclass_fields__ if key != "contract_hashes"}
            | {"contract_hashes": payload["contract_hashes"]}
        )
        return cls(
            **{field: getattr(pending, field) for field in PendingRunnerActivation.__dataclass_fields__},
            termination_evidence_hash=_require_hash(payload["termination_evidence_hash"], "termination evidence"),
            restart_evidence_hash=_require_hash(payload["restart_evidence_hash"], "restart evidence"),
            attestation_evidence_hash=_require_hash(payload["attestation_evidence_hash"], "attestation evidence"),
            compatible_checkpoint_stages=tuple(Stage(stage) for stage in payload["compatible_checkpoint_stages"]),
        )


class RunnerRegistry:
    """Protected activation store with a serialized expected-old pointer CAS."""

    def __init__(self, root: Path, *, repair_runner_identity: RunnerIdentity) -> None:
        self.root = _normalize_state_root(root)
        self.repair_runner_identity = repair_runner_identity
        self.activations = _ensure_directory(self.root, self.root / "runner-activations")
        self.pending = _ensure_directory(self.root, self.root / "pending-runner-activations")
        self.handles = _ensure_directory(self.root, self.root / "repair-workspace-handles")
        locks = _ensure_directory(self.root, self.root / "locks")
        self.pointer_path = self.root / "runner-activation-pointer.json"
        self.pointer_lock = locks / "runner-activation-pointer.lock"

    def activation_path(self, request_hash: str) -> Path:
        return self.activations / f"{_require_hash(request_hash, 'repair request')}.json"

    def pending_path(self, request_hash: str) -> Path:
        return self.pending / f"{_require_hash(request_hash, 'repair request')}.json"

    def issue_workspace_handle(self, handle: RepairWorkspaceHandle) -> RepairWorkspaceHandle:
        path = self.handles / f"{handle.id}.json"
        if not _write_new_json(path, handle.payload()) and self.load_workspace_handle(handle.id) != handle:
            raise UnauthorizedRepairError("issued workspace handle conflicts")
        return handle

    def load_workspace_handle(self, handle_id: str) -> RepairWorkspaceHandle:
        try:
            handle = RepairWorkspaceHandle.from_payload(
                _read_canonical_json(self.handles / f"{handle_id}.json", "repair workspace handle")
            )
            if handle.id != handle_id:
                raise ValueError
            return handle
        except Exception:
            raise UnauthorizedRepairError("repair workspace handle was not issued") from None

    def record_pending(self, pending: PendingRunnerActivation) -> PendingRunnerActivation:
        path = self.pending_path(pending.request_hash)
        if not _write_new_json(path, pending.payload()):
            existing = self.lookup_pending(pending.request_hash)
            if existing != pending:
                raise UnauthorizedRepairError("pending activation conflicts with its request")
            return existing
        return pending

    def lookup_pending(self, request_hash: str) -> PendingRunnerActivation:
        pending = PendingRunnerActivation.from_payload(
            _read_canonical_json(self.pending_path(request_hash), "pending runner activation")
        )
        if pending.request_hash != request_hash:
            raise UnauthorizedRepairError("pending activation request hash is invalid")
        return pending

    def publish_activation(
        self,
        receipt: RunnerActivationReceipt,
        *,
        expected_old: RunnerIdentity,
    ) -> RunnerActivationReceipt:
        if receipt.old_runner_identity != expected_old:
            raise UnauthorizedRepairError("activation does not match expected old runner")
        with _interprocess_lock(self.pointer_lock):
            if _path_lstat(self.pointer_path, "runner activation pointer") is not None:
                pointer = _read_canonical_json(self.pointer_path, "runner activation pointer")
                if not isinstance(pointer, dict) or set(pointer) != {"request_hash", "receipt_hash", "runner_identity"}:
                    raise UnauthorizedRepairError("runner activation pointer is invalid")
                current = RunnerIdentity.model_validate(pointer["runner_identity"])
                if current != expected_old:
                    if current == receipt.new_runner_identity and _path_lstat(
                        self.activation_path(receipt.request_hash), "runner activation receipt"
                    ) is not None:
                        existing = self.lookup_activation(receipt.request_hash)
                        if existing == receipt:
                            return existing
                    raise UnauthorizedRepairError("runner activation pointer does not match expected old runner")
            path = self.activation_path(receipt.request_hash)
            if not _write_new_json(path, receipt.payload()):
                existing = self.lookup_activation(receipt.request_hash)
                if existing != receipt:
                    raise UnauthorizedRepairError("activation replay conflicts with its request")
                receipt = existing
            _atomic_replace_json(
                self.pointer_path,
                {
                    "request_hash": receipt.request_hash,
                    "receipt_hash": receipt.content_hash,
                    "runner_identity": receipt.new_runner_identity.model_dump(mode="json", round_trip=True),
                },
            )
            return receipt

    def lookup_activation(self, request_hash: str) -> RunnerActivationReceipt:
        receipt = RunnerActivationReceipt.from_payload(
            _read_canonical_json(self.activation_path(request_hash), "runner activation receipt")
        )
        if receipt.request_hash != request_hash:
            raise UnauthorizedRepairError("activation receipt request hash is invalid")
        return receipt

    def current_activation(self) -> RunnerActivationReceipt:
        pointer = _read_canonical_json(self.pointer_path, "runner activation pointer")
        if not isinstance(pointer, dict) or set(pointer) != {"request_hash", "receipt_hash", "runner_identity"}:
            raise UnauthorizedRepairError("runner activation pointer is invalid")
        receipt = self.lookup_activation(pointer["request_hash"])
        try:
            pointer_identity = RunnerIdentity.model_validate(pointer["runner_identity"])
        except Exception:
            raise UnauthorizedRepairError("runner activation pointer is invalid") from None
        if receipt.content_hash != pointer["receipt_hash"] or receipt.new_runner_identity != pointer_identity:
            raise UnauthorizedRepairError("runner activation pointer does not match its receipt")
        return receipt

    def verify_transition(self, previous: StateGeneration, state: object) -> bool:
        try:
            restart_hash = getattr(state, "restart_receipt_hash")
            if not isinstance(restart_hash, str):
                return False
            receipt = self.current_activation()
            return (
                receipt.content_hash == restart_hash
                and receipt.run_id == previous.state.run_id
                and receipt.expected_revision == previous.revision
                and receipt.expected_state_hash == previous.state_hash
                and receipt.old_runner_identity == previous.state.runner_identity
                and receipt.new_runner_identity == getattr(state, "runner_identity")
                and receipt.project_policy_hash == previous.state.project_policy_hash
            )
        except Exception:
            return False


class RepairRunner:
    def __init__(
        self,
        *,
        worktree_factory: RepairWorktreeFactory,
        git: RepairGit,
        regression: RepairRegression,
        builder: RunnerBuilder,
        registry: RunnerRegistry,
        repair_runner_identity: RunnerIdentity,
        state_root: Path,
        repair_workspace_root: Path,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.worktree_factory = worktree_factory
        self.git = git
        self.regression = regression
        self.builder = builder
        self.registry = registry
        self.repair_runner_identity = repair_runner_identity
        self.state_root = state_root
        self.repair_workspace_root = repair_workspace_root
        self.repair_workspace_root_identity = RepairWorkspaceIdentity.capture(repair_workspace_root)
        self.now = now or (lambda: datetime.now(UTC))

    def prepare_workspace(
        self,
        generation: StateGeneration,
        failure_hash: str,
    ) -> RepairWorkspaceHandle:
        if self.repair_runner_identity != self.registry.repair_runner_identity:
            raise PermissionError("repair runner identity is not launcher pinned")
        self.repair_workspace_root_identity.verify()
        state = generation.state
        if (
            state.disposition is not RunDisposition.REPAIR_REQUIRED
            or state.runner_identity is None
            or not state.failure_history
            or state.failure_history[-1].failure_class is not FailureClass.ORCHESTRATION
            or hash_json(state.failure_history[-1].model_dump(mode="json", round_trip=True)) != failure_hash
        ):
            raise UnauthorizedRepairError("repair workspace requires protected repair state")
        handle_id = uuid.uuid4().hex
        path = self.worktree_factory.create(handle_id)
        identity = RepairWorkspaceIdentity.capture(path)
        if not path.is_relative_to(self.repair_workspace_root) or not any(path.iterdir()):
            raise UnauthorizedRepairError("repair workspace must be a fresh populated worktree")
        return self.registry.issue_workspace_handle(
            RepairWorkspaceHandle(
                id=handle_id,
                identity=identity,
                baseline_hash=_require_git_object(self.git.baseline_hash(path)),
                run_id=state.run_id,
                expected_revision=generation.revision,
                expected_state_hash=generation.state_hash,
                failure_hash=_require_hash(failure_hash, "repair failure"),
                old_runner_hash=state.runner_identity.content_hash,
                expires_at=self.now() + timedelta(hours=1),
            )
        )

    def validate_regress_build(self, request: RepairRequest) -> PendingRunnerActivation:
        self.repair_workspace_root_identity.verify()
        request.workspace.identity.verify()
        generation = RunStateStore.load_read_only(self.state_root, request.run_id)
        if (
            generation.revision != request.expected_revision
            or generation.state_hash != request.expected_state_hash
            or generation.state.disposition is not RunDisposition.REPAIR_REQUIRED
            or generation.state.runner_identity != request.old_runner_identity
            or generation.state.repository_id != request.repository_id
            or generation.state.project_policy_hash != request.project_policy_hash
        ):
            raise UnauthorizedRepairError("repair request does not match authoritative state")
        issued = self.registry.load_workspace_handle(request.workspace.id)
        if issued != request.workspace or issued.expires_at <= self.now():
            raise UnauthorizedRepairError("repair workspace handle is invalid")
        plan = RepairGuard(request.workspace.path).validate_path(request.plan_path)
        if plan != request.plan or hash_json(plan.payload()) != request.plan_hash:
            raise UnauthorizedRepairError("repair plan does not match its request")
        journal = RepairJournal(self.state_root, request.content_hash)
        if _path_lstat(self.registry.pending_path(request.content_hash), "pending runner activation") is not None:
            pending = self.registry.lookup_pending(request.content_hash)
            if (
                pending.run_id != request.run_id
                or pending.expected_revision != request.expected_revision
                or pending.expected_state_hash != request.expected_state_hash
                or pending.failure_hash != request.failure_hash
                or pending.old_runner_identity != request.old_runner_identity
            ):
                raise UnauthorizedRepairError("pending activation does not match its request")
            journal.record("source_manifest", pending.repair_source_manifest_hash)
            journal.record("regression", pending.regression_evidence_hash)
            journal.record("build", pending.build_evidence_hash)
            return pending
        request.workspace.identity.verify()
        source = self.git.collect_repair_source_manifest(
            request.workspace.baseline_hash,
            planned_paths=request.plan.files,
            control_paths=(
                request.plan_relative_path,
                f".repair-control/requests/{request.content_hash}.json",
            ),
        )
        if request.repository_id == request.repair_repository_id:
            overlap = {entry.path for entry in source.files}.intersection(request.ticket_owned_paths)
            if overlap:
                raise RepairTicketOverlap(", ".join(sorted(overlap)))
        journal.record("source_manifest", source.content_hash)
        request.workspace.identity.verify()
        regression_hash = journal.run_once("regression", lambda: self.regression.run(request.workspace.path))
        dependency_hash = _require_hash(self.git.dependency_lock_hash(), "dependency lock")
        contract_hash = hash_json(
            {stage.value: digest for stage, digest in sorted(request.contract_hashes.items(), key=lambda item: item[0].value)}
        )
        request.workspace.identity.verify()

        built: BuiltRunnerRelease | None = None
        pending_result: PendingRunnerActivation | None = None
        def build() -> str:
            nonlocal built, pending_result
            built = self.builder.build(request.workspace.path, source, dependency_hash, contract_hash)
            if not isinstance(built, BuiltRunnerRelease):
                raise UnauthorizedRepairError("runner builder returned no built release")
            built.verify()
            if (
                built.repair_source_manifest_hash != source.content_hash
                or built.dependency_lock_hash != dependency_hash
                or built.contract_manifest_hash != contract_hash
            ):
                raise UnauthorizedRepairError("built runner release bindings are invalid")
            pending_result = PendingRunnerActivation(
                request_hash=request.content_hash,
                run_id=request.run_id,
                expected_revision=request.expected_revision,
                expected_state_hash=request.expected_state_hash,
                failure_hash=request.failure_hash,
                repair_source_manifest_hash=source.content_hash,
                project_policy_hash=request.project_policy_hash,
                regression_evidence_hash=regression_hash,
                build_evidence_hash=built.build_evidence_hash,
                release_manifest_hash=built.release_manifest_hash,
                old_runner_identity=request.old_runner_identity,
                new_runner_identity=built.identity,
                contract_hashes=dict(request.contract_hashes),
            )
            self.registry.record_pending(pending_result)
            return built.build_evidence_hash

        journal.run_once("build", build)
        return pending_result if pending_result is not None else self.registry.lookup_pending(request.content_hash)


class TrustedLauncher:
    def __init__(
        self,
        store: RunStateStore,
        registry: RunnerRegistry,
        *,
        terminate_old_runner: Callable[[str, RunnerIdentity], str],
        start_new_runner: Callable[[str, RunnerIdentity], str],
        attest_new_runner: Callable[[str, RunnerIdentity], str],
        ticket_invoker: Callable[[tuple[str, ...]], object] | None = None,
    ) -> None:
        if store.repair_activation_verifier is not registry:
            raise ValueError("state store is not bound to the protected activation registry")
        self.store = store
        self.registry = registry
        self.terminate_old_runner = terminate_old_runner
        self.start_new_runner = start_new_runner
        self.attest_new_runner = attest_new_runner
        self.ticket_invoker = ticket_invoker
        self._crash_marker: str | None = None

    def crash_after(self, marker: str) -> None:
        self._crash_marker = marker

    def reconcile_activation(self, run_id: str, request_hash: str) -> StateGeneration:
        if run_id != self.store.run_id:
            raise UnauthorizedRepairError("activation run does not match launcher")
        current = self.store.load()
        if current.state.disposition is RunDisposition.ACTIVE:
            receipt = self.registry.lookup_activation(request_hash)
            if current.state.runner_identity == receipt.new_runner_identity and current.state.restart_receipt_hash == receipt.content_hash:
                RepairJournal(self.store.root, request_hash).record("state_activated", current.state_hash)
                return current
            raise UnauthorizedRepairError("active state does not match repair activation")
        pending = self.registry.lookup_pending(request_hash)
        if (
            current.revision != pending.expected_revision
            or current.state_hash != pending.expected_state_hash
            or current.state.disposition is not RunDisposition.REPAIR_REQUIRED
            or current.state.runner_identity != pending.old_runner_identity
        ):
            raise UnauthorizedRepairError("pending activation does not match repair state")
        journal = RepairJournal(self.store.root, request_hash)
        journal.require("source_manifest", "regression", "build")
        terminated = journal.run_once(
            "old_runner_terminated",
            lambda: self.terminate_old_runner(run_id, pending.old_runner_identity),
        )
        self._maybe_crash("old_runner_terminated")
        restarted = journal.run_once(
            "new_runner_started",
            lambda: self.start_new_runner(run_id, pending.new_runner_identity),
        )
        self._maybe_crash("new_runner_started")
        attested = journal.run_once(
            "identity_attested",
            lambda: self.attest_new_runner(run_id, pending.new_runner_identity),
        )
        self._maybe_crash("identity_attested")
        compatible = (
            tuple(Stage)
            if pending.old_runner_identity.contract_bundle_hash == pending.new_runner_identity.contract_bundle_hash
            else ()
        )
        receipt = RunnerActivationReceipt(
            **{field: getattr(pending, field) for field in PendingRunnerActivation.__dataclass_fields__},
            termination_evidence_hash=terminated,
            restart_evidence_hash=restarted,
            attestation_evidence_hash=attested,
            compatible_checkpoint_stages=compatible,
        )
        self.registry.publish_activation(receipt, expected_old=pending.old_runner_identity)
        journal.record("activation", receipt.content_hash)
        checkpoints, outputs = self._compatible_checkpoints(
            current.state.checkpoints,
            current.state.stage_outputs,
            receipt,
        )
        updated = current.state.model_copy(
            update={
                "disposition": RunDisposition.ACTIVE,
                "runner_identity": pending.new_runner_identity,
                "checkpoints": checkpoints,
                "stage_outputs": outputs,
                "restart_receipt_hash": receipt.content_hash,
            }
        )
        generation = self.store.compare_and_swap(current.revision, current.state_hash, updated)
        self._maybe_crash("state_cas")
        journal.record("state_activated", generation.state_hash)
        return generation

    def invoke(self, run_id: str, argv: tuple[str, ...]) -> object:
        if run_id != self.store.run_id or self.ticket_invoker is None:
            raise PermissionError("ticket command is unavailable")
        state = self.store.load().state
        if state.disposition is not RunDisposition.ACTIVE or state.restart_receipt_hash is None:
            raise PermissionError("ticket runner is not active")
        receipt = self.registry.current_activation()
        if receipt.content_hash != state.restart_receipt_hash or receipt.new_runner_identity != state.runner_identity:
            raise PermissionError("ticket runner identity is not active")
        RepairJournal(self.store.root, receipt.request_hash).require(
            "old_runner_terminated", "new_runner_started", "identity_attested", "activation", "state_activated"
        )
        return self.ticket_invoker(argv)

    def _maybe_crash(self, marker: str) -> None:
        if self._crash_marker == marker:
            self._crash_marker = None
            raise InjectedCrash(f"injected crash after {marker}")

    @staticmethod
    def _compatible_checkpoints(
        checkpoints: Mapping[Stage, object],
        stage_outputs: tuple[object, ...],
        activation: RunnerActivationReceipt,
    ) -> tuple[dict[Stage, object], tuple[object, ...]]:
        retained: dict[Stage, object] = {}
        invalidated = False
        for stage in Stage:
            checkpoint = checkpoints.get(stage)
            if checkpoint is None:
                continue
            expected = activation.contract_hashes.get(stage)
            if stage not in activation.compatible_checkpoint_stages or (
                expected is not None and getattr(checkpoint, "contract_hash", None) != expected
            ):
                invalidated = True
            if not invalidated:
                retained[stage] = checkpoint
        outputs = tuple(output for output in stage_outputs if getattr(output, "stage", None) in retained)
        return retained, outputs


def _require_hash(value: object, description: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{description} hash is invalid")
    return value


def _require_git_object(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError("repair baseline object is invalid")
    return value


def _immutable_release_manifest_hash(root: Path) -> str:
    candidate = Path(root)
    if not candidate.is_absolute() or candidate.is_symlink() or not candidate.is_dir():
        raise UnauthorizedRepairError("built runner release root is invalid")
    entries: list[dict[str, object]] = []
    root_metadata = os.lstat(candidate)
    if root_metadata.st_mode & 0o222:
        raise UnauthorizedRepairError("built runner release is mutable")
    for current, directories, files in os.walk(candidate, followlinks=False):
        current_path = Path(current)
        for name in sorted((*directories, *files)):
            path = current_path / name
            metadata = os.lstat(path)
            if metadata.st_mode & 0o222:
                raise UnauthorizedRepairError("built runner release is mutable")
            relative = path.relative_to(candidate).as_posix()
            if stat.S_ISLNK(metadata.st_mode):
                kind = "symlink"
                content = os.fsencode(os.readlink(path))
            elif stat.S_ISREG(metadata.st_mode):
                kind = "file"
                descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
                try:
                    chunks: list[bytes] = []
                    while chunk := os.read(descriptor, 65_536):
                        chunks.append(chunk)
                    content = b"".join(chunks)
                finally:
                    os.close(descriptor)
            elif stat.S_ISDIR(metadata.st_mode):
                kind = "directory"
                content = b""
            else:
                raise UnauthorizedRepairError("built runner release contains an unsupported file")
            entries.append(
                {
                    "path": relative,
                    "kind": kind,
                    "mode": stat.S_IMODE(metadata.st_mode),
                    "content_sha256": hashlib.sha256(content).hexdigest(),
                }
            )
    return hash_json(entries)
