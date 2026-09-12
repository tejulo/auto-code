from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Protocol
import uuid

from .contracts import RunnerIdentity, RunDisposition, Stage
from .hashing import hash_json
from .repair import RepairGuard, RepairRequest, RepairTicketOverlap, RepairWorkspaceHandle, UnauthorizedRepairError, is_automation_path
from .state import (
    _atomic_replace_json,
    _ensure_directory,
    _normalize_state_root,
    _read_canonical_json,
    _write_new_json,
    RunStateStore,
    StateGeneration,
)


class RepairWorktreeFactory(Protocol):
    def create(self, handle_id: str) -> Path: ...


class RepairGit(Protocol):
    def baseline_hash(self, workspace: Path) -> str: ...

    def changed_paths_since(self, workspace: Path, baseline_hash: str) -> set[str]: ...

    def source_hash(self, workspace: Path) -> str: ...

    def dependency_lock_hash(self, workspace: Path) -> str: ...


class RepairProcess(Protocol):
    def run(self, argv: tuple[str, ...], workspace: Path) -> object: ...


@dataclass(frozen=True, slots=True)
class RunnerActivationReceipt:
    request_hash: str
    old_runner_identity: RunnerIdentity
    new_runner_identity: RunnerIdentity
    old_contract_bundle_hash: str
    new_contract_bundle_hash: str
    compatible_checkpoint_stages: tuple[Stage, ...]
    contract_hashes: Mapping[Stage, str]

    @property
    def content_hash(self) -> str:
        return hash_json(self.payload())

    def payload(self) -> dict[str, object]:
        return {
            "request_hash": self.request_hash,
            "old_runner_identity": self.old_runner_identity.model_dump(mode="json", round_trip=True),
            "new_runner_identity": self.new_runner_identity.model_dump(mode="json", round_trip=True),
            "old_contract_bundle_hash": self.old_contract_bundle_hash,
            "new_contract_bundle_hash": self.new_contract_bundle_hash,
            "compatible_checkpoint_stages": [stage.value for stage in self.compatible_checkpoint_stages],
            "contract_hashes": {stage.value: value for stage, value in self.contract_hashes.items()},
        }

    @classmethod
    def from_payload(cls, payload: object) -> RunnerActivationReceipt:
        if not isinstance(payload, dict) or set(payload) != {
            "request_hash",
            "old_runner_identity",
            "new_runner_identity",
            "old_contract_bundle_hash",
            "new_contract_bundle_hash",
            "compatible_checkpoint_stages",
            "contract_hashes",
        }:
            raise ValueError("activation receipt is invalid")
        contracts = payload["contract_hashes"]
        if not isinstance(contracts, dict):
            raise ValueError("activation receipt is invalid")
        return cls(
            request_hash=payload["request_hash"],
            old_runner_identity=RunnerIdentity.model_validate(payload["old_runner_identity"]),
            new_runner_identity=RunnerIdentity.model_validate(payload["new_runner_identity"]),
            old_contract_bundle_hash=payload["old_contract_bundle_hash"],
            new_contract_bundle_hash=payload["new_contract_bundle_hash"],
            compatible_checkpoint_stages=tuple(Stage(stage) for stage in payload["compatible_checkpoint_stages"]),
            contract_hashes={Stage(stage): value for stage, value in contracts.items()},
        )


@dataclass(frozen=True, slots=True)
class RestartReceipt:
    run_id: str
    request_hash: str
    runner_identity: RunnerIdentity

    @property
    def content_hash(self) -> str:
        return hash_json(self.payload())

    def payload(self) -> dict[str, object]:
        return {
            "run_id": self.run_id,
            "request_hash": self.request_hash,
            "runner_identity": self.runner_identity.model_dump(mode="json", round_trip=True),
        }

    @classmethod
    def from_payload(cls, payload: object) -> RestartReceipt:
        if not isinstance(payload, dict) or set(payload) != {"run_id", "request_hash", "runner_identity"}:
            raise ValueError("restart receipt is invalid")
        return cls(
            run_id=payload["run_id"],
            request_hash=payload["request_hash"],
            runner_identity=RunnerIdentity.model_validate(payload["runner_identity"]),
        )


class RunnerRegistry:
    """Durably journals activation by request hash before changing the active pointer."""

    def __init__(self, root: Path, *, repair_runner_identity: RunnerIdentity) -> None:
        self.root = _normalize_state_root(root)
        self.repair_runner_identity = repair_runner_identity
        self.activations = _ensure_directory(self.root, self.root / "runner-activations")
        self.handles = _ensure_directory(self.root, self.root / "repair-workspace-handles")
        self.nonces = _ensure_directory(self.root, self.root / "repair-nonces")
        self.pointer_path = self.root / "runner-activation-pointer.json"
        self._crash_marker: str | None = None

    def crash_after(self, marker: str) -> None:
        self._crash_marker = marker

    def activation_path(self, request_hash: str) -> Path:
        return self.activations / f"{request_hash}.json"

    def issue_workspace_handle(self, handle: RepairWorkspaceHandle) -> RepairWorkspaceHandle:
        payload = {
            "id": handle.id,
            "path": str(handle.path),
            "baseline_hash": handle.baseline_hash,
            "run_id": handle.run_id,
            "old_runner_hash": handle.old_runner_hash,
            "expires_at": handle.expires_at.isoformat(),
        }
        if not _write_new_json(self.handles / f"{handle.id}.json", payload):
            if self.load_workspace_handle(handle.id) != handle:
                raise UnauthorizedRepairError("issued workspace handle conflicts")
        return handle

    def load_workspace_handle(self, handle_id: str) -> RepairWorkspaceHandle:
        try:
            payload = _read_canonical_json(self.handles / f"{handle_id}.json", "issued repair workspace handle")
            if not isinstance(payload, dict) or set(payload) != {
                "id",
                "path",
                "baseline_hash",
                "run_id",
                "old_runner_hash",
                "expires_at",
            }:
                raise ValueError
            handle = RepairWorkspaceHandle(
                id=payload["id"],
                path=Path(payload["path"]),
                baseline_hash=payload["baseline_hash"],
                run_id=payload["run_id"],
                old_runner_hash=payload["old_runner_hash"],
                expires_at=datetime.fromisoformat(payload["expires_at"]),
            )
            if handle.id != handle_id:
                raise ValueError
            return handle
        except Exception:
            raise UnauthorizedRepairError("repair workspace handle was not issued") from None

    def lookup_activation(self, request_hash: str) -> RunnerActivationReceipt:
        payload = _read_canonical_json(self.activation_path(request_hash), "runner activation receipt")
        receipt = RunnerActivationReceipt.from_payload(payload)
        if receipt.request_hash != request_hash:
            raise ValueError("activation receipt request hash is invalid")
        return receipt

    def consume_nonce(self, nonce: str, request_hash: str) -> bool:
        """Write-once nonce consumption prevents a descriptor from authorizing a second repair."""
        return _write_new_json(self.nonces / f"{nonce}.json", {"request_hash": request_hash})

class RepairRunner:
    def __init__(
        self,
        *,
        worktree_factory: RepairWorktreeFactory,
        git: RepairGit,
        process: RepairProcess,
        registry: RunnerRegistry,
        repair_runner_identity: RunnerIdentity,
        activate: Callable[[RepairRequest, RunnerIdentity], RunnerActivationReceipt],
        state_root: Path | None = None,
        repair_workspace_root: Path | None = None,
        regression_command: tuple[str, ...] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.worktree_factory = worktree_factory
        self.git = git
        self.process = process
        self.registry = registry
        self.repair_runner_identity = repair_runner_identity
        self._activate = activate
        self.state_root = state_root
        self.repair_workspace_root = repair_workspace_root
        self.regression_command = regression_command
        self.now = now or (lambda: datetime.now(UTC))

    def prepare_workspace(self, run_id: str, failure_hash: str, old_runner_identity: RunnerIdentity) -> RepairWorkspaceHandle:
        if self.repair_runner_identity.content_hash != self.registry.repair_runner_identity.content_hash:
            raise PermissionError("repair runner identity is not pinned by the launcher")
        handle_id = uuid.uuid4().hex
        path = self.worktree_factory.create(handle_id)
        if (
            not path.is_dir()
            or not any(path.iterdir())
            or (self.repair_workspace_root is not None and not path.is_relative_to(self.repair_workspace_root))
        ):
            raise UnauthorizedRepairError("repair workspace must be a fresh populated worktree")
        return self.registry.issue_workspace_handle(RepairWorkspaceHandle(
            id=handle_id,
            path=path,
            baseline_hash=self.git.baseline_hash(path),
            run_id=run_id,
            old_runner_hash=old_runner_identity.content_hash,
            expires_at=self.now() + timedelta(hours=1),
        ))

    def crash_after(self, marker: str) -> None:
        self.registry.crash_after(marker)

    def validate_build_activate(self, request: RepairRequest) -> RunnerActivationReceipt:
        if self.repair_runner_identity.content_hash != self.registry.repair_runner_identity.content_hash:
            raise PermissionError("repair runner identity is not pinned by the launcher")
        if self.state_root is not None:
            state = RunStateStore.load_read_only(self.state_root, request.run_id).state
            if (
                state.disposition is not RunDisposition.REPAIR_REQUIRED
                or state.runner_identity != request.old_runner_identity
            ):
                raise UnauthorizedRepairError("repair request does not match protected run state")
        if (
            request.baseline.run_id != request.run_id
            or request.baseline.old_runner_hash != request.old_runner_identity.content_hash
            or request.baseline.expires_at < self.now()
        ):
            raise UnauthorizedRepairError("repair workspace handle is invalid")
        issued = self.registry.load_workspace_handle(request.baseline.workspace_id)
        if (
            issued.path != request.baseline.path
            or issued.baseline_hash != request.baseline.baseline_hash
            or issued.run_id != request.run_id
            or issued.old_runner_hash != request.old_runner_identity.content_hash
            or issued.expires_at != request.baseline.expires_at
        ):
            raise UnauthorizedRepairError("repair workspace handle was not issued")
        plan = RepairGuard(request.baseline.path).validate_path(request.plan_path)
        if plan != request.plan or hash_json(plan.payload()) != request.plan_hash:
            raise UnauthorizedRepairError("repair plan does not match its request")
        if self.repair_workspace_root is not None and not request.baseline.path.is_relative_to(self.repair_workspace_root):
            raise UnauthorizedRepairError("repair workspace is outside the protected root")
        if self.regression_command is not None and plan.regression_command != self.regression_command:
            raise UnauthorizedRepairError("repair plan regression command is not launcher approved")
        changed = self.git.changed_paths_since(request.baseline.path, request.baseline.baseline_hash)
        planned = set(request.plan.files)
        unauthorized = changed - planned
        if changed != planned or not all(is_automation_path(path) for path in changed):
            raise UnauthorizedRepairError(", ".join(sorted(unauthorized or {path for path in changed if not is_automation_path(path)})))
        if request.ticket_repository_id == request.repair_repository_id:
            overlap = changed.intersection(request.ticket_owned_paths)
            if overlap:
                raise RepairTicketOverlap(", ".join(sorted(overlap)))
        result = self.process.run(self.regression_command or plan.regression_command, request.baseline.path)
        require_success = getattr(result, "require_success", None)
        if callable(require_success):
            require_success()
        runner = self._build_content_addressed_runner(request)
        return self._activate(request, runner)

    def _build_content_addressed_runner(self, request: RepairRequest) -> RunnerIdentity:
        source_sha = self.git.source_hash(request.baseline.path)
        dependency_lock_hash = self.git.dependency_lock_hash(request.baseline.path)
        contract_bundle_hash = hash_json({stage.value: value for stage, value in request.contract_hashes.items()})
        return RunnerIdentity(
            content_hash=hash_json(
                {
                    "request_hash": request.content_hash,
                    "source_sha": source_sha,
                    "dependency_lock_hash": dependency_lock_hash,
                    "contract_bundle_hash": contract_bundle_hash,
                }
            ),
            source_sha=source_sha,
            dependency_lock_hash=dependency_lock_hash,
            contract_bundle_hash=contract_bundle_hash,
            built_at=self.now(),
        )


class TrustedLauncher:
    def __init__(
        self,
        store: RunStateStore,
        registry: RunnerRegistry,
        *,
        terminate_old_runner: Callable[[str], None] | None = None,
        ticket_invoker: Callable[[tuple[str, ...]], object] | None = None,
    ) -> None:
        self.store = store
        self.registry = registry
        self.terminate_old_runner = terminate_old_runner or (lambda _: None)
        self.ticket_invoker = ticket_invoker
        self.restarts = _ensure_directory(store.root, store.root / "runner-restarts")
        self._crash_marker: str | None = None

    def crash_after(self, marker: str) -> None:
        self._crash_marker = marker

    def reconcile_activation(self, run_id: str, request_hash: str) -> StateGeneration:
        if run_id != self.store.run_id:
            raise ValueError("activation run does not match the launcher")
        activation = self.registry.lookup_activation(request_hash)
        restart = RestartReceipt(run_id, request_hash, activation.new_runner_identity)
        current = self.store.load()
        if current.state.runner_identity == activation.new_runner_identity and current.state.restart_receipt_hash == restart.content_hash:
            self.terminate_old_runner(run_id)
            return current
        if (
            current.state.disposition is not RunDisposition.REPAIR_REQUIRED
            or current.state.runner_identity != activation.old_runner_identity
        ):
            raise UnauthorizedRepairError("activation does not match the active repair run")
        checkpoints, outputs = self._compatible_checkpoints(
            current.state.checkpoints,
            current.state.stage_outputs,
            activation,
        )
        updated = current.state.model_copy(
            update={
                "disposition": RunDisposition.ACTIVE,
                "runner_identity": activation.new_runner_identity,
                "checkpoints": checkpoints,
                "stage_outputs": outputs,
                "restart_receipt_hash": restart.content_hash,
            }
        )
        _atomic_replace_json(self.restarts / f"{run_id}.json", restart.payload())
        generation = self.store.compare_and_swap(current.revision, current.state_hash, updated)
        if self._crash_marker == "STATE_CAS_REPLACED":
            self._crash_marker = None
            from .repair import InjectedCrash
            raise InjectedCrash("injected crash after state CAS replacement")
        self.terminate_old_runner(run_id)
        return generation

    def restart_receipt(self, run_id: str) -> RestartReceipt:
        return RestartReceipt.from_payload(_read_canonical_json(self.restarts / f"{run_id}.json", "runner restart receipt"))

    def invoke(self, run_id: str, argv: tuple[str, ...]) -> object:
        if run_id != self.store.run_id or self.ticket_invoker is None:
            raise PermissionError("ticket command is unavailable")
        state = self.store.load().state
        receipt = self.restart_receipt(run_id)
        activation = self.registry.lookup_activation(receipt.request_hash)
        if state.runner_identity != receipt.runner_identity or receipt.runner_identity != activation.new_runner_identity:
            raise PermissionError("ticket runner identity is not active")
        return self.ticket_invoker(argv)

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
