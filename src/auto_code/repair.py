from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path

from .contracts import RunnerIdentity, Stage
from .hashing import hash_json
from .state import _read_canonical_json, _write_new_json


class RepairError(RuntimeError):
    pass


class MissingRepairPlanError(RepairError):
    pass


class UnauthorizedRepairError(RepairError):
    pass


class RepairTicketOverlap(RepairError):
    pass


class InjectedCrash(RepairError):
    pass


def is_automation_path(path: str) -> bool:
    return path == "pyproject.toml" or path.startswith("src/auto_code/") or path.startswith("tests/")


def _require_path(path: str) -> str:
    candidate = Path(path)
    if not isinstance(path, str) or not path or candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError("repair path is invalid")
    return path


@dataclass(frozen=True, slots=True)
class RepairPlan:
    root_cause: str
    files: tuple[str, ...]
    change: str
    regression_command: tuple[str, ...]
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        if not self.root_cause or not self.change or not self.files or not self.regression_command:
            raise ValueError("repair plan is incomplete")
        if len(set(self.files)) != len(self.files) or any(_require_path(path) != path for path in self.files):
            raise ValueError("repair plan paths are invalid")
        if any(not isinstance(argument, str) or not argument for argument in self.regression_command):
            raise ValueError("repair regression command is invalid")

    def payload(self) -> dict[str, object]:
        return {
            "root_cause": self.root_cause,
            "files": list(self.files),
            "change": self.change,
            "regression_command": list(self.regression_command),
            "evidence": list(self.evidence),
        }

    @classmethod
    def from_payload(cls, value: object) -> RepairPlan:
        if not isinstance(value, dict) or set(value) != {"root_cause", "files", "change", "regression_command", "evidence"}:
            raise MissingRepairPlanError("repair plan is invalid")
        try:
            return cls(
                root_cause=value["root_cause"],
                files=tuple(value["files"]),
                change=value["change"],
                regression_command=tuple(value["regression_command"]),
                evidence=tuple(value["evidence"]),
            )
        except (TypeError, ValueError):
            raise MissingRepairPlanError("repair plan is invalid") from None


@dataclass(frozen=True, slots=True)
class RepairWorkspaceHandle:
    id: str
    path: Path
    baseline_hash: str
    run_id: str
    old_runner_hash: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class RepairBaseline:
    workspace_id: str
    path: Path
    baseline_hash: str
    run_id: str
    old_runner_hash: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class RepairRequest:
    plan: RepairPlan
    plan_path: Path
    plan_hash: str
    baseline: RepairBaseline
    ticket_product_manifest: str
    run_id: str
    ticket_repository_id: str
    repair_repository_id: str
    old_runner_identity: RunnerIdentity
    project_policy_hash: str
    ticket_owned_paths: tuple[str, ...]
    contract_hashes: Mapping[Stage, str]

    @property
    def content_hash(self) -> str:
        return hash_json(self.payload())

    def payload(self) -> dict[str, object]:
        return {
            "plan": self.plan.payload(),
            "plan_path": str(self.plan_path),
            "plan_hash": self.plan_hash,
            "baseline": {
                "workspace_id": self.baseline.workspace_id,
                "path": str(self.baseline.path),
                "baseline_hash": self.baseline.baseline_hash,
                "run_id": self.baseline.run_id,
                "old_runner_hash": self.baseline.old_runner_hash,
                "expires_at": self.baseline.expires_at.isoformat(),
            },
            "ticket_product_manifest": self.ticket_product_manifest,
            "run_id": self.run_id,
            "ticket_repository_id": self.ticket_repository_id,
            "repair_repository_id": self.repair_repository_id,
            "old_runner_identity": self.old_runner_identity.model_dump(mode="json", round_trip=True),
            "project_policy_hash": self.project_policy_hash,
            "ticket_owned_paths": list(self.ticket_owned_paths),
            "contract_hashes": {stage.value: value for stage, value in self.contract_hashes.items()},
        }

    @classmethod
    def from_payload(cls, value: object) -> RepairRequest:
        expected = {
            "plan", "plan_path", "plan_hash", "baseline", "ticket_product_manifest", "run_id",
            "ticket_repository_id", "repair_repository_id", "old_runner_identity", "project_policy_hash",
            "ticket_owned_paths", "contract_hashes",
        }
        if not isinstance(value, dict) or set(value) != expected or not isinstance(value["baseline"], dict):
            raise UnauthorizedRepairError("repair request is invalid")
        baseline = value["baseline"]
        if set(baseline) != {"workspace_id", "path", "baseline_hash", "run_id", "old_runner_hash", "expires_at"}:
            raise UnauthorizedRepairError("repair request is invalid")
        contracts = value["contract_hashes"]
        paths = value["ticket_owned_paths"]
        if not isinstance(contracts, dict) or not isinstance(paths, list) or any(not isinstance(path, str) for path in paths):
            raise UnauthorizedRepairError("repair request is invalid")
        try:
            return cls(
                plan=RepairPlan.from_payload(value["plan"]),
                plan_path=Path(value["plan_path"]),
                plan_hash=value["plan_hash"],
                baseline=RepairBaseline(
                    workspace_id=baseline["workspace_id"],
                    path=Path(baseline["path"]),
                    baseline_hash=baseline["baseline_hash"],
                    run_id=baseline["run_id"],
                    old_runner_hash=baseline["old_runner_hash"],
                    expires_at=datetime.fromisoformat(baseline["expires_at"]),
                ),
                ticket_product_manifest=value["ticket_product_manifest"],
                run_id=value["run_id"],
                ticket_repository_id=value["ticket_repository_id"],
                repair_repository_id=value["repair_repository_id"],
                old_runner_identity=RunnerIdentity.model_validate(value["old_runner_identity"]),
                project_policy_hash=value["project_policy_hash"],
                ticket_owned_paths=tuple(paths),
                contract_hashes={Stage(stage): digest for stage, digest in contracts.items()},
            )
        except (TypeError, ValueError):
            raise UnauthorizedRepairError("repair request is invalid") from None


class RepairGuard:
    """Binds a repair request to one disposable automation workspace."""

    def __init__(self, repair_worktree: Path) -> None:
        self.repair_worktree = Path(repair_worktree)

    def validate_path(self, plan_path: Path) -> RepairPlan:
        path = Path(plan_path)
        if not path.is_file() or not path.is_relative_to(self.repair_worktree):
            raise MissingRepairPlanError("repair plan is missing")
        try:
            return RepairPlan.from_payload(json.loads(path.read_text(encoding="ascii")))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, MissingRepairPlanError):
            raise MissingRepairPlanError("repair plan is invalid") from None

    def capture_baseline(self, workspace: RepairWorkspaceHandle) -> RepairBaseline:
        if workspace.path != self.repair_worktree:
            raise UnauthorizedRepairError("repair baseline is outside its workspace")
        return RepairBaseline(
            workspace.id,
            workspace.path,
            workspace.baseline_hash,
            workspace.run_id,
            workspace.old_runner_hash,
            workspace.expires_at,
        )

    def create_request(
        self,
        plan: RepairPlan,
        baseline: RepairBaseline,
        *,
        ticket_product_manifest: str,
        run_id: str,
        ticket_repository_id: str,
        repair_repository_id: str,
        old_runner_identity: RunnerIdentity,
        project_policy_hash: str,
        ticket_owned_paths: tuple[str, ...],
        contract_hashes: Mapping[Stage, str],
    ) -> RepairRequest:
        if baseline.path != self.repair_worktree or not isinstance(plan, RepairPlan):
            raise UnauthorizedRepairError("repair request is not bound to its workspace")
        if not isinstance(old_runner_identity, RunnerIdentity):
            raise UnauthorizedRepairError("repair request has no runner identity")
        if baseline.run_id != run_id or baseline.old_runner_hash != old_runner_identity.content_hash:
            raise UnauthorizedRepairError("repair request does not match its workspace handle")
        if any(_require_path(path) != path for path in ticket_owned_paths):
            raise UnauthorizedRepairError("ticket path is invalid")
        if any(not isinstance(stage, Stage) or not isinstance(value, str) or len(value) != 64 for stage, value in contract_hashes.items()):
            raise UnauthorizedRepairError("repair contracts are invalid")
        plan_hash = hash_json(plan.payload())
        plan_path = self.repair_worktree / ".repair-plans" / f"{plan_hash}.json"
        plan_path.parent.mkdir(exist_ok=True)
        plan_path.write_text(json.dumps(plan.payload(), sort_keys=True, separators=(",", ":")), encoding="ascii")
        request = RepairRequest(
            plan=plan,
            plan_path=plan_path,
            plan_hash=plan_hash,
            baseline=baseline,
            ticket_product_manifest=ticket_product_manifest,
            run_id=run_id,
            ticket_repository_id=ticket_repository_id,
            repair_repository_id=repair_repository_id,
            old_runner_identity=old_runner_identity,
            project_policy_hash=project_policy_hash,
            ticket_owned_paths=ticket_owned_paths,
            contract_hashes=dict(contract_hashes),
        )
        request_path = self.repair_worktree / ".repair-requests" / f"{request.content_hash}.json"
        request_path.parent.mkdir(exist_ok=True)
        if not _write_new_json(request_path, request.payload()) and self.load_request(request.content_hash) != request:
            raise UnauthorizedRepairError("repair request conflicts with a prior request")
        return request

    def load_request(self, request_hash: str) -> RepairRequest:
        try:
            request = RepairRequest.from_payload(
                _read_canonical_json(self.repair_worktree / ".repair-requests" / f"{request_hash}.json", "repair request")
            )
        except Exception:
            raise UnauthorizedRepairError("repair request is unavailable") from None
        if request.content_hash != request_hash:
            raise UnauthorizedRepairError("repair request is invalid")
        return request
