from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

from .contracts import FailureClass, ProductChangeManifest, RunnerIdentity, RunDisposition, Stage
from .hashing import canonical_json_bytes, hash_json
from .state import RunStateStore, _read_canonical_json, _write_new_json


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_GIT_OBJECT = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
_MAX_PLAN_TEXT = 4_096
_MAX_PLAN_FILES = 64
_MAX_PLAN_EVIDENCE = 64


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


def _sha256(value: object, description: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ValueError(f"{description} must be a canonical SHA-256 digest")
    return value


def _git_object(value: object) -> str:
    if not isinstance(value, str) or _GIT_OBJECT.fullmatch(value) is None:
        raise ValueError("repair baseline is invalid")
    return value


def _relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError("repair path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError("repair path is invalid")
    return value


def _bounded_text(value: object, description: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > _MAX_PLAN_TEXT or "\x00" in value:
        raise ValueError(f"{description} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class RepairPlan:
    root_cause: str
    files: tuple[str, ...]
    change: str
    evidence: tuple[str, ...]

    def __post_init__(self) -> None:
        _bounded_text(self.root_cause, "repair root cause")
        _bounded_text(self.change, "repair change")
        if not self.files or len(self.files) > _MAX_PLAN_FILES or tuple(sorted(set(self.files))) != self.files:
            raise ValueError("repair plan paths must be sorted, unique, and bounded")
        if any(_relative_path(path) != path or not is_automation_path(path) for path in self.files):
            raise ValueError("repair plan path is outside automation scope")
        if not self.evidence or len(self.evidence) > _MAX_PLAN_EVIDENCE:
            raise ValueError("repair plan evidence is invalid")
        for digest in self.evidence:
            _sha256(digest, "repair evidence")

    def payload(self) -> dict[str, object]:
        return {
            "root_cause": self.root_cause,
            "files": list(self.files),
            "change": self.change,
            "evidence": list(self.evidence),
        }

    @classmethod
    def from_payload(cls, value: object) -> RepairPlan:
        if not isinstance(value, dict) or set(value) != {"root_cause", "files", "change", "evidence"}:
            raise MissingRepairPlanError("repair plan is invalid")
        if not isinstance(value["files"], list) or not isinstance(value["evidence"], list):
            raise MissingRepairPlanError("repair plan is invalid")
        try:
            return cls(
                root_cause=value["root_cause"],
                files=tuple(value["files"]),
                change=value["change"],
                evidence=tuple(value["evidence"]),
            )
        except (TypeError, ValueError):
            raise MissingRepairPlanError("repair plan is invalid") from None


@dataclass(frozen=True, slots=True)
class RepairWorkspaceIdentity:
    path: Path
    device: int
    inode: int

    @classmethod
    def capture(cls, path: Path) -> RepairWorkspaceIdentity:
        candidate = Path(path)
        descriptor = _open_directory_no_follow(candidate)
        try:
            metadata = os.fstat(descriptor)
            return cls(candidate, metadata.st_dev, metadata.st_ino)
        finally:
            os.close(descriptor)

    def verify(self) -> None:
        try:
            descriptor = _open_directory_no_follow(self.path)
            try:
                metadata = os.fstat(descriptor)
                if metadata.st_dev != self.device or metadata.st_ino != self.inode:
                    raise UnauthorizedRepairError("repair workspace identity changed")
            finally:
                os.close(descriptor)
        except UnauthorizedRepairError:
            raise
        except (OSError, ValueError):
            raise UnauthorizedRepairError("repair workspace is unavailable") from None

    def payload(self) -> dict[str, object]:
        return {"path": str(self.path), "device": self.device, "inode": self.inode}


@dataclass(frozen=True, slots=True)
class RepairWorkspaceHandle:
    id: str
    identity: RepairWorkspaceIdentity
    baseline_hash: str
    run_id: str
    expected_revision: int
    expected_state_hash: str
    failure_hash: str
    old_runner_hash: str
    expires_at: datetime

    @property
    def path(self) -> Path:
        return self.identity.path

    def payload(self) -> dict[str, object]:
        return {
            "id": self.id,
            "identity": self.identity.payload(),
            "baseline_hash": self.baseline_hash,
            "run_id": self.run_id,
            "expected_revision": self.expected_revision,
            "expected_state_hash": self.expected_state_hash,
            "failure_hash": self.failure_hash,
            "old_runner_hash": self.old_runner_hash,
            "expires_at": self.expires_at.isoformat(),
        }

    @classmethod
    def from_payload(cls, value: object) -> RepairWorkspaceHandle:
        expected = {
            "id", "identity", "baseline_hash", "run_id", "expected_revision", "expected_state_hash",
            "failure_hash", "old_runner_hash", "expires_at",
        }
        if not isinstance(value, dict) or set(value) != expected or not isinstance(value["identity"], dict):
            raise UnauthorizedRepairError("repair workspace handle is invalid")
        identity = value["identity"]
        if set(identity) != {"path", "device", "inode"}:
            raise UnauthorizedRepairError("repair workspace handle is invalid")
        try:
            handle = cls(
                id=value["id"],
                identity=RepairWorkspaceIdentity(Path(identity["path"]), identity["device"], identity["inode"]),
                baseline_hash=_git_object(value["baseline_hash"]),
                run_id=value["run_id"],
                expected_revision=value["expected_revision"],
                expected_state_hash=_sha256(value["expected_state_hash"], "expected state"),
                failure_hash=_sha256(value["failure_hash"], "repair failure"),
                old_runner_hash=_sha256(value["old_runner_hash"], "old runner"),
                expires_at=datetime.fromisoformat(value["expires_at"]),
            )
            if not isinstance(handle.id, str) or not handle.id or not isinstance(handle.run_id, str):
                raise ValueError
            if not isinstance(handle.expected_revision, int) or isinstance(handle.expected_revision, bool) or handle.expected_revision < 1:
                raise ValueError
            if handle.expires_at.tzinfo is None:
                raise ValueError
            return handle
        except (TypeError, ValueError):
            raise UnauthorizedRepairError("repair workspace handle is invalid") from None


@dataclass(frozen=True, slots=True)
class RepairRequest:
    plan: RepairPlan
    plan_relative_path: str
    plan_hash: str
    workspace: RepairWorkspaceHandle
    run_id: str
    expected_revision: int
    expected_state_hash: str
    failure_hash: str
    repository_id: str
    repair_repository_id: str
    product_manifest_hash: str
    project_policy_hash: str
    old_runner_identity: RunnerIdentity
    ticket_owned_paths: tuple[str, ...]
    contract_hashes: Mapping[Stage, str]

    def __post_init__(self) -> None:
        _relative_path(self.plan_relative_path)
        for value, description in (
            (self.plan_hash, "repair plan"),
            (self.expected_state_hash, "expected state"),
            (self.failure_hash, "repair failure"),
            (self.product_manifest_hash, "product manifest"),
            (self.project_policy_hash, "project policy"),
        ):
            _sha256(value, description)
        if self.run_id != self.workspace.run_id or self.expected_revision != self.workspace.expected_revision:
            raise ValueError("repair request does not match its workspace")
        if self.expected_state_hash != self.workspace.expected_state_hash or self.failure_hash != self.workspace.failure_hash:
            raise ValueError("repair request does not match its workspace")
        if self.old_runner_identity.content_hash != self.workspace.old_runner_hash:
            raise ValueError("repair request runner does not match its workspace")
        if (
            not isinstance(self.expected_revision, int)
            or isinstance(self.expected_revision, bool)
            or self.expected_revision < 1
            or not isinstance(self.run_id, str)
            or not self.run_id
            or len(self.run_id) > 255
            or not isinstance(self.repository_id, str)
            or not self.repository_id
            or len(self.repository_id) > 255
            or not isinstance(self.repair_repository_id, str)
            or not self.repair_repository_id
            or len(self.repair_repository_id) > 255
        ):
            raise ValueError("repair request identity fields are invalid")
        if self.plan_hash != hash_json(self.plan.payload()):
            raise ValueError("repair request plan hash is invalid")
        if tuple(sorted(set(self.ticket_owned_paths))) != self.ticket_owned_paths or len(self.ticket_owned_paths) > 512:
            raise ValueError("repair ticket paths are invalid")
        for path in self.ticket_owned_paths:
            _relative_path(path)
        if len(self.contract_hashes) > len(Stage):
            raise ValueError("repair contract manifest is invalid")
        for stage, digest in self.contract_hashes.items():
            if not isinstance(stage, Stage):
                raise ValueError("repair contract manifest is invalid")
            _sha256(digest, "contract")

    @property
    def content_hash(self) -> str:
        return hash_json(self.payload())

    @property
    def plan_path(self) -> Path:
        return self.workspace.path / self.plan_relative_path

    @property
    def baseline(self) -> RepairWorkspaceHandle:
        return self.workspace

    def payload(self) -> dict[str, object]:
        return {
            "plan": self.plan.payload(),
            "plan_relative_path": self.plan_relative_path,
            "plan_hash": self.plan_hash,
            "workspace": self.workspace.payload(),
            "run_id": self.run_id,
            "expected_revision": self.expected_revision,
            "expected_state_hash": self.expected_state_hash,
            "failure_hash": self.failure_hash,
            "repository_id": self.repository_id,
            "repair_repository_id": self.repair_repository_id,
            "product_manifest_hash": self.product_manifest_hash,
            "project_policy_hash": self.project_policy_hash,
            "old_runner_identity": self.old_runner_identity.model_dump(mode="json", round_trip=True),
            "ticket_owned_paths": list(self.ticket_owned_paths),
            "contract_hashes": {stage.value: digest for stage, digest in sorted(self.contract_hashes.items(), key=lambda item: item[0].value)},
        }

    @classmethod
    def from_payload(cls, value: object) -> RepairRequest:
        expected = {
            "plan", "plan_relative_path", "plan_hash", "workspace", "run_id", "expected_revision",
            "expected_state_hash", "failure_hash", "repository_id", "repair_repository_id",
            "product_manifest_hash", "project_policy_hash", "old_runner_identity", "ticket_owned_paths",
            "contract_hashes",
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise UnauthorizedRepairError("repair request is invalid")
        try:
            paths = value["ticket_owned_paths"]
            contracts = value["contract_hashes"]
            if not isinstance(paths, list) or not isinstance(contracts, dict):
                raise ValueError
            return cls(
                plan=RepairPlan.from_payload(value["plan"]),
                plan_relative_path=value["plan_relative_path"],
                plan_hash=value["plan_hash"],
                workspace=RepairWorkspaceHandle.from_payload(value["workspace"]),
                run_id=value["run_id"],
                expected_revision=value["expected_revision"],
                expected_state_hash=value["expected_state_hash"],
                failure_hash=value["failure_hash"],
                repository_id=value["repository_id"],
                repair_repository_id=value["repair_repository_id"],
                product_manifest_hash=value["product_manifest_hash"],
                project_policy_hash=value["project_policy_hash"],
                old_runner_identity=RunnerIdentity.model_validate(value["old_runner_identity"]),
                ticket_owned_paths=tuple(paths),
                contract_hashes={Stage(stage): digest for stage, digest in contracts.items()},
            )
        except Exception:
            raise UnauthorizedRepairError("repair request is invalid") from None


class RepairGuard:
    def __init__(self, repair_worktree: Path) -> None:
        self.identity = RepairWorkspaceIdentity.capture(Path(repair_worktree))

    @property
    def repair_worktree(self) -> Path:
        return self.identity.path

    def validate_path(self, plan_path: Path) -> RepairPlan:
        self.identity.verify()
        path = Path(plan_path)
        try:
            relative = path.relative_to(self.repair_worktree)
        except ValueError:
            raise MissingRepairPlanError("repair plan is outside its workspace") from None
        if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
            raise MissingRepairPlanError("repair plan is invalid")
        try:
            descriptor = _open_regular_no_follow(path)
            with os.fdopen(descriptor, "rb") as stream:
                raw = stream.read(65_537)
            if len(raw) > 65_536:
                raise ValueError
            value = json.loads(raw.decode("ascii"))
            if canonical_json_bytes(value) != raw:
                raise ValueError
            return RepairPlan.from_payload(value)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError, MissingRepairPlanError):
            raise MissingRepairPlanError("repair plan is invalid") from None

    def load_request(self, request_hash: str) -> RepairRequest:
        _sha256(request_hash, "repair request")
        request = RepairRequest.from_payload(
            _read_canonical_json(
                self.repair_worktree / ".repair-control" / "requests" / f"{request_hash}.json",
                "repair request",
            )
        )
        if request.content_hash != request_hash or request.workspace.identity != self.identity:
            raise UnauthorizedRepairError("repair request is invalid")
        return request


class RepairRequestCoordinator:
    """Derive every security binding from one exact authoritative generation."""

    def __init__(
        self,
        store: RunStateStore,
        *,
        load_workspace_handle: Callable[[str], RepairWorkspaceHandle],
        load_product_manifest: Callable[[str], ProductChangeManifest],
        repair_repository_id: str,
    ) -> None:
        self.store = store
        self.load_workspace_handle = load_workspace_handle
        self.load_product_manifest = load_product_manifest
        self.repair_repository_id = repair_repository_id

    def create_request(
        self,
        run_id: str,
        expected_revision: int,
        expected_state_hash: str,
        workspace: Path,
        plan_path: Path,
    ) -> RepairRequest:
        generation = self.store.load()
        if (
            run_id != self.store.run_id
            or generation.revision != expected_revision
            or generation.state_hash != expected_state_hash
        ):
            raise UnauthorizedRepairError("repair request expected generation is stale")
        state = generation.state
        if (
            state.disposition is not RunDisposition.REPAIR_REQUIRED
            or state.runner_identity is None
            or state.project_policy_hash is None
            or state.product_change_manifest is None
            or state.product_change_manifest_hash is None
            or not state.failure_history
            or state.failure_history[-1].failure_class is not FailureClass.ORCHESTRATION
        ):
            raise UnauthorizedRepairError("authoritative repair facts are incomplete")
        handle = self.load_workspace_handle(Path(workspace).name)
        handle.identity.verify()
        if handle.path != Path(workspace):
            raise UnauthorizedRepairError("repair workspace handle does not match")
        failure_hash = hash_json(state.failure_history[-1].model_dump(mode="json", round_trip=True))
        if (
            handle.run_id != run_id
            or handle.expected_revision != generation.revision
            or handle.expected_state_hash != generation.state_hash
            or handle.failure_hash != failure_hash
            or handle.old_runner_hash != state.runner_identity.content_hash
        ):
            raise UnauthorizedRepairError("repair workspace does not match authoritative state")
        guard = RepairGuard(handle.path)
        plan = guard.validate_path(plan_path)
        failure_evidence = {reference.sha256 for reference in state.failure_history[-1].evidence_refs}
        if not failure_evidence or not failure_evidence.issubset(plan.evidence):
            raise UnauthorizedRepairError("repair plan does not cite the authoritative failure evidence")
        manifest = self.load_product_manifest(state.product_change_manifest)
        if (
            not isinstance(manifest, ProductChangeManifest)
            or manifest.content_hash != state.product_change_manifest_hash
        ):
            raise UnauthorizedRepairError("authoritative product manifest is invalid")
        relative_plan = str(Path(plan_path).relative_to(handle.path).as_posix())
        if relative_plan != ".repair-control/plan.json":
            raise UnauthorizedRepairError("repair plan must use the protected control path")
        request = RepairRequest(
            plan=plan,
            plan_relative_path=relative_plan,
            plan_hash=hash_json(plan.payload()),
            workspace=handle,
            run_id=state.run_id,
            expected_revision=generation.revision,
            expected_state_hash=generation.state_hash,
            failure_hash=failure_hash,
            repository_id=state.repository_id,
            repair_repository_id=self.repair_repository_id,
            product_manifest_hash=manifest.content_hash,
            project_policy_hash=state.project_policy_hash,
            old_runner_identity=state.runner_identity,
            ticket_owned_paths=tuple(
                sorted(
                    {
                        path
                        for file in manifest.files
                        for path in (file.path, file.old_path)
                        if path is not None
                    }
                )
            ),
            contract_hashes={stage: checkpoint.contract_hash for stage, checkpoint in state.checkpoints.items()},
        )
        request_dir = handle.path / ".repair-control" / "requests"
        request_dir.mkdir(mode=0o700, exist_ok=True)
        request_path = request_dir / f"{request.content_hash}.json"
        if not _write_new_json(request_path, request.payload()):
            existing = guard.load_request(request.content_hash)
            if existing != request:
                raise UnauthorizedRepairError("repair request conflicts with a prior request")
        return request


def _open_directory_no_follow(path: Path) -> int:
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("repair workspace must be absolute")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open("/", flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_regular_no_follow(path: Path) -> int:
    parent = _open_directory_no_follow(path.parent)
    try:
        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=parent)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise OSError("repair file is not regular")
        return descriptor
    finally:
        os.close(parent)
