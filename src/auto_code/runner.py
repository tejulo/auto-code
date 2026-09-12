from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import os
from pathlib import Path, PurePosixPath
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

    def dependency_lock_hash(self, workspace: Path) -> str: ...


class RunnerBuilder(Protocol):
    def observe(self, effect_id: str) -> BuiltRunnerRelease | None: ...

    def build(
        self,
        effect_id: str,
        workspace: Path,
        source_manifest: RepairSourceManifest,
        dependency_lock_hash: str,
        contract_manifest_hash: str,
    ) -> BuiltRunnerRelease: ...


class LifecycleEffect(Protocol):
    def observe(self, effect_id: str, run_id: str, runner: RunnerIdentity) -> str | None: ...

    def invoke(self, effect_id: str, run_id: str, runner: RunnerIdentity) -> str: ...


@dataclass(frozen=True, slots=True)
class ReleaseManifestEntry:
    path: str
    kind: str
    mode: int
    content_sha256: str

    def __post_init__(self) -> None:
        path = PurePosixPath(self.path)
        if (
            not self.path
            or path.is_absolute()
            or any(part in {"", ".", ".."} for part in path.parts)
            or self.kind not in {"directory", "file", "symlink"}
            or isinstance(self.mode, bool)
            or not isinstance(self.mode, int)
            or not 0 <= self.mode <= 0o7777
        ):
            raise ValueError("release manifest entry is invalid")
        _require_hash(self.content_sha256, "release content")

    def payload(self) -> dict[str, object]:
        return {
            "path": self.path,
            "kind": self.kind,
            "mode": self.mode,
            "content_sha256": self.content_sha256,
        }

    @classmethod
    def from_payload(cls, payload: object) -> ReleaseManifestEntry:
        if not isinstance(payload, dict) or set(payload) != {"path", "kind", "mode", "content_sha256"}:
            raise ValueError("release manifest entry is invalid")
        return cls(
            path=payload["path"],
            kind=payload["kind"],
            mode=payload["mode"],
            content_sha256=payload["content_sha256"],
        )


@dataclass(frozen=True, slots=True)
class BuiltRunnerRelease:
    root: Path
    release_manifest: tuple[ReleaseManifestEntry, ...]
    release_manifest_hash: str
    runner_executable: str
    repair_source_manifest_hash: str
    dependency_lock_hash: str
    contract_hashes: Mapping[Stage, str]
    contract_manifest_hash: str
    build_evidence_hash: str
    built_at: datetime

    def verify(self) -> None:
        if self.built_at.tzinfo is None:
            raise UnauthorizedRepairError("built runner release timestamp is invalid")
        captured = _capture_immutable_release_manifest(self.root)
        if captured != self.release_manifest or hash_json([entry.payload() for entry in captured]) != self.release_manifest_hash:
            raise UnauthorizedRepairError("built runner release does not match its immutable manifest")
        executable = PurePosixPath(self.runner_executable)
        if (
            not self.runner_executable
            or executable.is_absolute()
            or any(part in {"", ".", ".."} for part in executable.parts)
        ):
            raise UnauthorizedRepairError("built runner executable is invalid")
        executable_entry = next((entry for entry in captured if entry.path == self.runner_executable), None)
        if executable_entry is None or executable_entry.kind != "file" or not executable_entry.mode & 0o111:
            raise UnauthorizedRepairError("built runner executable is unavailable")
        for digest in (
            self.repair_source_manifest_hash,
            self.dependency_lock_hash,
            self.contract_manifest_hash,
            self.build_evidence_hash,
        ):
            _require_hash(digest, "built runner binding")
        if (
            len(self.contract_hashes) > len(Stage)
            or any(not isinstance(stage, Stage) for stage in self.contract_hashes)
            or any(_require_hash(digest, "built contract") != digest for digest in self.contract_hashes.values())
            or self.contract_manifest_hash
            != hash_json(
                {
                    stage.value: digest
                    for stage, digest in sorted(self.contract_hashes.items(), key=lambda item: item[0].value)
                }
            )
        ):
            raise UnauthorizedRepairError("built runner contract manifest is invalid")

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
    result_root: Path | None = None

    def _result_path(self, effect_id: str) -> Path | None:
        if self.result_root is None:
            return None
        return self.result_root / f"{_require_hash(effect_id, 'regression effect')}.json"

    def observe(self, effect_id: str) -> str | None:
        path = self._result_path(effect_id)
        if path is not None and _path_lstat(path, "repair regression receipt") is not None:
            payload = _read_canonical_json(path, "repair regression receipt")
            if not isinstance(payload, dict) or set(payload) != {"effect_id", "evidence_hash"} or payload["effect_id"] != effect_id:
                raise UnauthorizedRepairError("repair regression receipt is invalid")
            return _require_hash(payload["evidence_hash"], "regression evidence")
        observed = self.process_runner.observe_reconciled_effect(
            effect_id,
            self._binding_hash(),
            self.timeout,
        )
        if observed is None:
            return None
        if observed.returncode != 0:
            raise UnauthorizedRepairError("observed repair regression failed")
        return observed.receipt_hash

    def run(self, effect_id: str, workspace: Path) -> str:
        result, evidence_hash = self.process_runner.run_reconciled_effect(
            effect_id,
            self._binding_hash(),
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
        evidence_hash = _require_hash(evidence_hash, "regression evidence")
        path = self._result_path(effect_id)
        if path is not None:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if not _write_new_json(path, {"effect_id": effect_id, "evidence_hash": evidence_hash}):
                if self.observe(effect_id) != evidence_hash:
                    raise UnauthorizedRepairError("repair regression receipt conflicts")
        return evidence_hash

    def _binding_hash(self) -> str:
        return hash_json(
            {
                "command": list(self.command),
                "executable_hash": self.executable_hash,
                "sandbox_policy_hash": self.sandbox_policy_hash,
            }
        )


class RepairJournal:
    """Persist effect intent and reconcile observable state before every invocation."""

    def __init__(self, root: Path, request_hash: str) -> None:
        self.root = _normalize_state_root(Path(root))
        self.request_hash = _require_hash(request_hash, "repair request")
        self.directory = _ensure_directory(self.root, self.root / "repair-journals")
        locks = _ensure_directory(self.root, self.root / "locks")
        self.path = self.directory / f"{self.request_hash}.json"
        self.lock_path = locks / f"repair-{self.request_hash}.lock"
        self._crash_marker: tuple[str, str] | None = None

    def crash_at(self, phase: str, point: str) -> None:
        if phase not in _PHASES or point not in {"before_invocation", "after_invocation", "after_observation"}:
            raise ValueError("repair journal crash point is invalid")
        self._crash_marker = (phase, point)

    def completed(self, phase: str) -> str | None:
        if phase not in _PHASES:
            raise ValueError("repair journal phase is invalid")
        with _interprocess_lock(self.lock_path):
            effect = self._load().get(phase)
            if effect is None or not effect["events"] or effect["events"][-1]["kind"] != "reconciliation":
                return None
            return effect["events"][-1]["evidence_hash"]

    def record(self, phase: str, evidence_hash: str) -> str:
        if phase not in _PHASES:
            raise ValueError("repair journal phase is invalid")
        evidence_hash = _require_hash(evidence_hash, "repair phase evidence")
        with _interprocess_lock(self.lock_path):
            current = self._load()
            existing = current.get(phase)
            if existing is not None:
                events = existing["events"]
                if events and events[-1]["kind"] == "observation" and events[-1]["evidence_hash"] == evidence_hash:
                    events.append({"kind": "reconciliation", "evidence_hash": evidence_hash})
                    self._save(current)
                    return evidence_hash
                if events and events[-1]["kind"] == "invocation":
                    events.extend(
                        (
                            {"kind": "observation", "evidence_hash": evidence_hash},
                            {"kind": "reconciliation", "evidence_hash": evidence_hash},
                        )
                    )
                    self._save(current)
                    return evidence_hash
                if not events or events[-1]["kind"] != "reconciliation" or events[-1]["evidence_hash"] != evidence_hash:
                    raise UnauthorizedRepairError("repair phase replay conflicts with durable evidence")
                return evidence_hash
            current[phase] = {
                "input_hash": evidence_hash,
                "events": [
                    {"kind": "intention"},
                    {"kind": "observation", "evidence_hash": evidence_hash},
                    {"kind": "reconciliation", "evidence_hash": evidence_hash},
                ],
            }
            self._save(current)
            return evidence_hash

    def run_once(self, phase: str, effect: Callable[[], str]) -> str:
        return self.reconcile_effect(phase, hash_json({"phase": phase}), observe=lambda: None, invoke=effect)

    def reconcile_effect(
        self,
        phase: str,
        input_hash: str,
        *,
        observe: Callable[[], str | None],
        invoke: Callable[[], str],
    ) -> str:
        if phase not in _PHASES:
            raise ValueError("repair journal phase is invalid")
        input_hash = _require_hash(input_hash, "repair effect input")
        with _interprocess_lock(self.lock_path):
            current = self._load()
            effect_state = current.get(phase)
            if effect_state is None:
                effect_state = {"input_hash": input_hash, "events": [{"kind": "intention"}]}
                current[phase] = effect_state
                self._save(current)
            elif effect_state["input_hash"] != input_hash:
                raise UnauthorizedRepairError("repair effect input changed after intention")
            events = effect_state["events"]
            if events and events[-1]["kind"] == "reconciliation":
                return events[-1]["evidence_hash"]
            if events and events[-1]["kind"] == "observation":
                observed = events[-1]["evidence_hash"]
                events.append({"kind": "reconciliation", "evidence_hash": observed})
                self._save(current)
                return observed

            observed = observe()
            if observed is None:
                if not any(event["kind"] == "invocation" for event in events):
                    events.append({"kind": "invocation"})
                    self._save(current)
                self._maybe_crash(phase, "before_invocation")
                observed = _require_hash(invoke(), "repair phase evidence")
                self._maybe_crash(phase, "after_invocation")
            else:
                observed = _require_hash(observed, "repair phase evidence")
            events.append({"kind": "observation", "evidence_hash": observed})
            self._save(current)
            self._maybe_crash(phase, "after_observation")
            events.append({"kind": "reconciliation", "evidence_hash": observed})
            self._save(current)
            return observed

    def require(self, *phases: str) -> None:
        if any(self.completed(phase) is None for phase in phases):
            raise UnauthorizedRepairError("repair transaction is incomplete")

    def _save(self, effects: Mapping[str, object]) -> None:
        _atomic_replace_json(self.path, {"request_hash": self.request_hash, "effects": effects})

    def _maybe_crash(self, phase: str, point: str) -> None:
        if self._crash_marker == (phase, point):
            self._crash_marker = None
            raise InjectedCrash(f"injected crash {point} for {phase}")

    def _load(self) -> dict[str, dict[str, object]]:
        if _path_lstat(self.path, "repair journal") is None:
            return {}
        payload = _read_canonical_json(self.path, "repair journal")
        if not isinstance(payload, dict) or set(payload) != {"request_hash", "effects"}:
            raise UnauthorizedRepairError("repair journal is invalid")
        effects = payload["effects"]
        if payload["request_hash"] != self.request_hash or not isinstance(effects, dict) or len(effects) > len(_PHASES):
            raise UnauthorizedRepairError("repair journal is invalid")
        parsed: dict[str, dict[str, object]] = {}
        for phase, effect in effects.items():
            if phase not in _PHASES or not isinstance(effect, dict) or set(effect) != {"input_hash", "events"}:
                raise UnauthorizedRepairError("repair journal is invalid")
            input_hash = _require_hash(effect["input_hash"], "repair effect input")
            events = effect["events"]
            if not isinstance(events, list) or not 1 <= len(events) <= 4:
                raise UnauthorizedRepairError("repair journal is invalid")
            kinds = [event.get("kind") if isinstance(event, dict) else None for event in events]
            allowed = (
                ["intention"],
                ["intention", "invocation"],
                ["intention", "observation"],
                ["intention", "invocation", "observation"],
                ["intention", "observation", "reconciliation"],
                ["intention", "invocation", "observation", "reconciliation"],
            )
            if kinds not in allowed:
                raise UnauthorizedRepairError("repair journal event order is invalid")
            for event in events:
                expected = {"kind"} if event["kind"] in {"intention", "invocation"} else {"kind", "evidence_hash"}
                if set(event) != expected:
                    raise UnauthorizedRepairError("repair journal event is invalid")
                if "evidence_hash" in event:
                    _require_hash(event["evidence_hash"], "repair event evidence")
            parsed[phase] = {"input_hash": input_hash, "events": events}
        return parsed


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
    release_root: Path
    release_manifest: tuple[ReleaseManifestEntry, ...]
    release_manifest_hash: str
    runner_executable: str
    old_runner_identity: RunnerIdentity
    new_runner_identity: RunnerIdentity
    previous_contract_hashes: Mapping[Stage, str]
    contract_hashes: Mapping[Stage, str]

    def __post_init__(self) -> None:
        _require_identifier(self.run_id, "activation run ID")
        if (
            not isinstance(self.expected_revision, int)
            or isinstance(self.expected_revision, bool)
            or self.expected_revision < 1
        ):
            raise ValueError("pending runner activation revision is invalid")
        for value, description in (
            (self.request_hash, "repair request"),
            (self.expected_state_hash, "expected state"),
            (self.failure_hash, "repair failure"),
            (self.repair_source_manifest_hash, "repair source"),
            (self.project_policy_hash, "project policy"),
            (self.regression_evidence_hash, "regression evidence"),
            (self.build_evidence_hash, "build evidence"),
            (self.release_manifest_hash, "release manifest"),
        ):
            _require_hash(value, description)
        if not self.release_root.is_absolute() or ".." in self.release_root.parts:
            raise ValueError("pending runner release root is invalid")
        if (
            not self.release_manifest
            or len(self.release_manifest) > 100_000
            or tuple(sorted(self.release_manifest, key=lambda entry: entry.path)) != self.release_manifest
            or len({entry.path for entry in self.release_manifest}) != len(self.release_manifest)
            or self.release_manifest_hash != hash_json([entry.payload() for entry in self.release_manifest])
            or self.new_runner_identity.content_hash != self.release_manifest_hash
            or self.new_runner_identity.source_sha != self.repair_source_manifest_hash
        ):
            raise ValueError("pending runner release manifest is invalid")
        _require_relative_path(self.runner_executable, "runner executable")
        _require_contract_map(self.previous_contract_hashes, "previous contract")
        _require_contract_map(self.contract_hashes, "contract")
        contract_hash = hash_json(
            {
                stage.value: digest
                for stage, digest in sorted(self.contract_hashes.items(), key=lambda item: item[0].value)
            }
        )
        if self.new_runner_identity.contract_bundle_hash != contract_hash:
            raise ValueError("pending runner contract manifest is invalid")

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
            "release_root": str(self.release_root),
            "release_manifest": [entry.payload() for entry in self.release_manifest],
            "release_manifest_hash": self.release_manifest_hash,
            "runner_executable": self.runner_executable,
            "old_runner_identity": self.old_runner_identity.model_dump(mode="json", round_trip=True),
            "new_runner_identity": self.new_runner_identity.model_dump(mode="json", round_trip=True),
            "previous_contract_hashes": {
                stage.value: digest
                for stage, digest in sorted(self.previous_contract_hashes.items(), key=lambda item: item[0].value)
            },
            "contract_hashes": {stage.value: digest for stage, digest in sorted(self.contract_hashes.items(), key=lambda item: item[0].value)},
        }

    @classmethod
    def from_payload(cls, payload: object) -> PendingRunnerActivation:
        expected = {
            "request_hash", "run_id", "expected_revision", "expected_state_hash", "failure_hash",
            "repair_source_manifest_hash", "project_policy_hash", "regression_evidence_hash",
            "build_evidence_hash", "release_root", "release_manifest", "release_manifest_hash",
            "runner_executable", "old_runner_identity", "new_runner_identity", "previous_contract_hashes",
            "contract_hashes",
        }
        if (
            not isinstance(payload, dict)
            or set(payload) != expected
            or not isinstance(payload["contract_hashes"], dict)
            or not isinstance(payload["previous_contract_hashes"], dict)
            or not isinstance(payload["release_manifest"], list)
        ):
            raise ValueError("pending runner activation is invalid")
        release_root = Path(payload["release_root"])
        if not release_root.is_absolute() or ".." in release_root.parts:
            raise ValueError("pending runner release root is invalid")
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
            release_root=release_root,
            release_manifest=tuple(ReleaseManifestEntry.from_payload(entry) for entry in payload["release_manifest"]),
            release_manifest_hash=_require_hash(payload["release_manifest_hash"], "release manifest"),
            runner_executable=payload["runner_executable"],
            old_runner_identity=RunnerIdentity.model_validate(payload["old_runner_identity"]),
            new_runner_identity=RunnerIdentity.model_validate(payload["new_runner_identity"]),
            previous_contract_hashes={
                Stage(stage): _require_hash(digest, "previous contract")
                for stage, digest in payload["previous_contract_hashes"].items()
            },
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
    release_root: Path
    release_manifest: tuple[ReleaseManifestEntry, ...]
    release_manifest_hash: str
    runner_executable: str
    termination_evidence_hash: str
    restart_evidence_hash: str
    attestation_evidence_hash: str
    old_runner_identity: RunnerIdentity
    new_runner_identity: RunnerIdentity
    compatible_checkpoint_stages: tuple[Stage, ...]
    previous_contract_hashes: Mapping[Stage, str]
    contract_hashes: Mapping[Stage, str]

    def __post_init__(self) -> None:
        PendingRunnerActivation(
            **{field: getattr(self, field) for field in PendingRunnerActivation.__dataclass_fields__}
        )
        for value, description in (
            (self.termination_evidence_hash, "termination evidence"),
            (self.restart_evidence_hash, "restart evidence"),
            (self.attestation_evidence_hash, "attestation evidence"),
        ):
            _require_hash(value, description)
        expected_compatible: list[Stage] = []
        for stage in Stage:
            previous = self.previous_contract_hashes.get(stage)
            if previous is None:
                continue
            if previous != self.contract_hashes.get(stage):
                break
            expected_compatible.append(stage)
        if tuple(expected_compatible) != self.compatible_checkpoint_stages:
            raise ValueError("activation receipt compatible stages are invalid")

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
            "release_root": str(self.release_root),
            "release_manifest": [entry.payload() for entry in self.release_manifest],
            "release_manifest_hash": self.release_manifest_hash,
            "runner_executable": self.runner_executable,
            "termination_evidence_hash": self.termination_evidence_hash,
            "restart_evidence_hash": self.restart_evidence_hash,
            "attestation_evidence_hash": self.attestation_evidence_hash,
            "old_runner_identity": self.old_runner_identity.model_dump(mode="json", round_trip=True),
            "new_runner_identity": self.new_runner_identity.model_dump(mode="json", round_trip=True),
            "compatible_checkpoint_stages": [stage.value for stage in self.compatible_checkpoint_stages],
            "previous_contract_hashes": {
                stage.value: digest
                for stage, digest in sorted(self.previous_contract_hashes.items(), key=lambda item: item[0].value)
            },
            "contract_hashes": {stage.value: digest for stage, digest in sorted(self.contract_hashes.items(), key=lambda item: item[0].value)},
        }

    @classmethod
    def from_payload(cls, payload: object) -> RunnerActivationReceipt:
        expected = {
            "request_hash", "run_id", "expected_revision", "expected_state_hash", "failure_hash",
            "repair_source_manifest_hash", "project_policy_hash", "regression_evidence_hash", "build_evidence_hash",
            "release_root", "release_manifest", "release_manifest_hash", "runner_executable",
            "termination_evidence_hash", "restart_evidence_hash", "attestation_evidence_hash", "old_runner_identity",
            "new_runner_identity", "compatible_checkpoint_stages", "previous_contract_hashes", "contract_hashes",
        }
        if not isinstance(payload, dict) or set(payload) != expected or not isinstance(payload["contract_hashes"], dict):
            raise ValueError("activation receipt is invalid")
        try:
            if not isinstance(payload["compatible_checkpoint_stages"], list):
                raise ValueError
            pending = PendingRunnerActivation.from_payload(
                {key: payload[key] for key in PendingRunnerActivation.__dataclass_fields__}
            )
            return cls(
                **{field: getattr(pending, field) for field in PendingRunnerActivation.__dataclass_fields__},
                termination_evidence_hash=_require_hash(payload["termination_evidence_hash"], "termination evidence"),
                restart_evidence_hash=_require_hash(payload["restart_evidence_hash"], "restart evidence"),
                attestation_evidence_hash=_require_hash(payload["attestation_evidence_hash"], "attestation evidence"),
                compatible_checkpoint_stages=tuple(Stage(stage) for stage in payload["compatible_checkpoint_stages"]),
            )
        except (TypeError, ValueError):
            raise ValueError("activation receipt is invalid") from None


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
        authorize: Callable[[], object],
        now: Callable[[], datetime] | None = None,
    ) -> None:
        if not callable(authorize):
            raise ValueError("repair authorization capability is invalid")
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
        self.authorize = authorize
        self._crash_marker: tuple[str, str] | None = None

    def crash_at(self, phase: str, point: str) -> None:
        if phase not in {"regression", "build"}:
            raise ValueError("repair runner crash phase is invalid")
        self._crash_marker = (phase, point)

    def _apply_crash_marker(self, journal: RepairJournal, phase: str) -> None:
        if self._crash_marker is not None and self._crash_marker[0] == phase:
            _, point = self._crash_marker
            self._crash_marker = None
            journal.crash_at(phase, point)

    def prepare_workspace(
        self,
        generation: StateGeneration,
        failure_hash: str,
    ) -> RepairWorkspaceHandle:
        self.authorize()
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
        self.authorize()
        path = self.worktree_factory.create(handle_id)
        identity = RepairWorkspaceIdentity.capture(path)
        if not path.is_relative_to(self.repair_workspace_root) or not any(path.iterdir()):
            raise UnauthorizedRepairError("repair workspace must be a fresh populated worktree")
        self.authorize()
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
        self.authorize()
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
        control_paths = (
            request.plan_relative_path,
            f".repair-control/requests/{request.content_hash}.json",
        )
        for _ in range(3):
            request.workspace.identity.verify()
            self.authorize()
            source = self.git.collect_repair_source_manifest(
                request.workspace.baseline_hash,
                planned_paths=request.plan.files,
                control_paths=control_paths,
            )
            if request.repository_id == request.repair_repository_id:
                overlap = {entry.path for entry in source.files}.intersection(request.ticket_owned_paths)
                if overlap:
                    raise RepairTicketOverlap(", ".join(sorted(overlap)))
            regression_journal = RepairJournal(
                self.state_root,
                hash_json({"request_hash": request.content_hash, "source_manifest_hash": source.content_hash}),
            )
            self._apply_crash_marker(regression_journal, "regression")
            regression_effect_id = regression_journal.request_hash
            request.workspace.identity.verify()
            self.authorize()
            regression_hash = regression_journal.reconcile_effect(
                "regression",
                source.content_hash,
                observe=lambda: self.regression.observe(regression_effect_id),
                invoke=lambda: self.regression.run(regression_effect_id, request.workspace.path),
            )
            self.authorize()
            after_regression = self.git.collect_repair_source_manifest(
                request.workspace.baseline_hash,
                planned_paths=request.plan.files,
                control_paths=control_paths,
            )
            if after_regression != source:
                continue
            self.authorize()
            dependency_hash = _require_hash(
                self.git.dependency_lock_hash(request.workspace.path), "dependency lock"
            )
            self.authorize()
            before_build = self.git.collect_repair_source_manifest(
                request.workspace.baseline_hash,
                planned_paths=request.plan.files,
                control_paths=control_paths,
            )
            if before_build == source:
                break
        else:
            raise UnauthorizedRepairError("repair source did not stabilize after regression")
        journal.record("source_manifest", source.content_hash)
        journal.record("regression", regression_hash)
        contract_hash = hash_json(
            {stage.value: digest for stage, digest in sorted(request.contract_hashes.items(), key=lambda item: item[0].value)}
        )
        request.workspace.identity.verify()

        built: BuiltRunnerRelease | None = None
        pending_result: PendingRunnerActivation | None = None
        build_effect_id = hash_json(
            {
                "request_hash": request.content_hash,
                "source_manifest_hash": source.content_hash,
                "dependency_lock_hash": dependency_hash,
                "previous_contract_manifest_hash": contract_hash,
            }
        )
        def build() -> str:
            nonlocal built, pending_result
            self.authorize()
            built = self.builder.observe(build_effect_id)
            if built is None:
                built = self.builder.build(
                    build_effect_id, request.workspace.path, source, dependency_hash, contract_hash
                )
            if not isinstance(built, BuiltRunnerRelease):
                raise UnauthorizedRepairError("runner builder returned no built release")
            built.verify()
            if (
                built.repair_source_manifest_hash != source.content_hash
                or built.dependency_lock_hash != dependency_hash
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
                release_root=built.root,
                release_manifest=built.release_manifest,
                release_manifest_hash=built.release_manifest_hash,
                runner_executable=built.runner_executable,
                old_runner_identity=request.old_runner_identity,
                new_runner_identity=built.identity,
                previous_contract_hashes=dict(request.contract_hashes),
                contract_hashes=dict(built.contract_hashes),
            )
            self.registry.record_pending(pending_result)
            return built.build_evidence_hash

        self._apply_crash_marker(journal, "build")
        journal.reconcile_effect(
            "build",
            build_effect_id,
            observe=lambda: (
                self.registry.lookup_pending(request.content_hash).build_evidence_hash
                if _path_lstat(self.registry.pending_path(request.content_hash), "pending runner activation") is not None
                else None
            ),
            invoke=build,
        )
        return pending_result if pending_result is not None else self.registry.lookup_pending(request.content_hash)


class TrustedLauncher:
    def __init__(
        self,
        store: RunStateStore,
        registry: RunnerRegistry,
        *,
        terminate_old_runner: LifecycleEffect,
        start_new_runner: LifecycleEffect,
        attest_new_runner: LifecycleEffect,
        authorize: Callable[[], object],
        ticket_invoker: Callable[[tuple[str, ...]], object] | None = None,
    ) -> None:
        if store.repair_activation_verifier is not registry:
            raise ValueError("state store is not bound to the protected activation registry")
        if not callable(authorize):
            raise ValueError("activation authorization capability is invalid")
        self.store = store
        self.registry = registry
        self.terminate_old_runner = terminate_old_runner
        self.start_new_runner = start_new_runner
        self.attest_new_runner = attest_new_runner
        self.ticket_invoker = ticket_invoker
        self.authorize = authorize
        self._crash_marker: str | None = None
        self._effect_crash_marker: tuple[str, str] | None = None

    def crash_after(self, marker: str) -> None:
        self._crash_marker = marker

    def crash_at(self, phase: str, point: str) -> None:
        if phase not in {"old_runner_terminated", "new_runner_started", "identity_attested"}:
            raise ValueError("launcher crash phase is invalid")
        self._effect_crash_marker = (phase, point)

    def reconcile_activation(self, run_id: str, request_hash: str) -> StateGeneration:
        self.authorize()
        if run_id != self.store.run_id:
            raise UnauthorizedRepairError("activation run does not match launcher")
        current = self.store.load()
        if current.state.disposition is RunDisposition.ACTIVE:
            receipt = self.registry.lookup_activation(request_hash)
            if (
                self.registry.current_activation() == receipt
                and current.state.runner_identity == receipt.new_runner_identity
                and current.state.restart_receipt_hash == receipt.content_hash
            ):
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
        self.authorize()
        terminated = self._reconcile_lifecycle_effect(
            journal, "old_runner_terminated", self.terminate_old_runner, run_id, pending.old_runner_identity,
        )
        self._maybe_crash("old_runner_terminated")
        self.authorize()
        restarted = self._reconcile_lifecycle_effect(
            journal, "new_runner_started", self.start_new_runner, run_id, pending.new_runner_identity,
        )
        self._maybe_crash("new_runner_started")
        self.authorize()
        attested = self._reconcile_lifecycle_effect(
            journal, "identity_attested", self.attest_new_runner, run_id, pending.new_runner_identity,
        )
        self._maybe_crash("identity_attested")
        compatible_stages: list[Stage] = []
        for stage in Stage:
            previous = pending.previous_contract_hashes.get(stage)
            if previous is None:
                continue
            if previous != pending.contract_hashes.get(stage):
                break
            compatible_stages.append(stage)
        compatible = tuple(compatible_stages)
        receipt = RunnerActivationReceipt(
            **{field: getattr(pending, field) for field in PendingRunnerActivation.__dataclass_fields__},
            termination_evidence_hash=terminated,
            restart_evidence_hash=restarted,
            attestation_evidence_hash=attested,
            compatible_checkpoint_stages=compatible,
        )
        if receipt.old_runner_identity != pending.old_runner_identity:
            raise UnauthorizedRepairError("activation does not match expected old runner")
        journal.require(
            "source_manifest", "regression", "build", "old_runner_terminated", "new_runner_started",
            "identity_attested",
        )
        self.authorize()
        with _interprocess_lock(self.registry.pointer_lock):
            if _path_lstat(self.registry.pointer_path, "runner activation pointer") is not None:
                pointer = _read_canonical_json(self.registry.pointer_path, "runner activation pointer")
                if not isinstance(pointer, dict) or set(pointer) != {"request_hash", "receipt_hash", "runner_identity"}:
                    raise UnauthorizedRepairError("runner activation pointer is invalid")
                current_identity = RunnerIdentity.model_validate(pointer["runner_identity"])
                if current_identity != pending.old_runner_identity:
                    if current_identity == receipt.new_runner_identity:
                        existing = self.registry.lookup_activation(receipt.request_hash)
                        if existing == receipt:
                            return self.store.load()
                    raise UnauthorizedRepairError("runner activation pointer does not match expected old runner")
            activation_path = self.registry.activation_path(receipt.request_hash)
            if not _write_new_json(activation_path, receipt.payload()):
                existing = self.registry.lookup_activation(receipt.request_hash)
                if existing != receipt:
                    raise UnauthorizedRepairError("activation replay conflicts with its request")
                receipt = existing
            _atomic_replace_json(
                self.registry.pointer_path,
                {
                    "request_hash": receipt.request_hash,
                    "receipt_hash": receipt.content_hash,
                    "runner_identity": receipt.new_runner_identity.model_dump(mode="json", round_trip=True),
                },
            )
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
        self.authorize()
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
        try:
            release = BuiltRunnerRelease(
                root=receipt.release_root,
                release_manifest=receipt.release_manifest,
                release_manifest_hash=receipt.release_manifest_hash,
                runner_executable=receipt.runner_executable,
                repair_source_manifest_hash=receipt.repair_source_manifest_hash,
                dependency_lock_hash=receipt.new_runner_identity.dependency_lock_hash,
                contract_hashes=receipt.contract_hashes,
                contract_manifest_hash=receipt.new_runner_identity.contract_bundle_hash,
                build_evidence_hash=receipt.build_evidence_hash,
                built_at=receipt.new_runner_identity.built_at,
            )
            release.verify()
            if release.identity != receipt.new_runner_identity:
                raise UnauthorizedRepairError("active runner release identity is invalid")
        except Exception as error:
            raise PermissionError("ticket runner release is invalid") from error
        executable = receipt.release_root / receipt.runner_executable
        return self.ticket_invoker((str(executable), *argv))

    def _maybe_crash(self, marker: str) -> None:
        if self._crash_marker == marker:
            self._crash_marker = None
            raise InjectedCrash(f"injected crash after {marker}")

    def _reconcile_lifecycle_effect(
        self,
        journal: RepairJournal,
        phase: str,
        capability: LifecycleEffect,
        run_id: str,
        runner: RunnerIdentity,
    ) -> str:
        if not callable(getattr(capability, "observe", None)) or not callable(getattr(capability, "invoke", None)):
            raise PermissionError("launcher lifecycle capability is invalid")
        effect_id = hash_json(
            {
                "request_hash": journal.request_hash,
                "phase": phase,
                "run_id": run_id,
                "runner_identity": runner.model_dump(mode="json", round_trip=True),
            }
        )
        if self._effect_crash_marker is not None and self._effect_crash_marker[0] == phase:
            _, point = self._effect_crash_marker
            self._effect_crash_marker = None
            journal.crash_at(phase, point)
        return journal.reconcile_effect(
            phase,
            effect_id,
            observe=lambda: capability.observe(effect_id, run_id, runner),
            invoke=lambda: capability.invoke(effect_id, run_id, runner),
        )

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


def _require_identifier(value: object, description: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 255
        or "\x00" in value
        or "/" in value
        or value in {".", ".."}
    ):
        raise ValueError(f"{description} is invalid")
    return value


def _require_relative_path(value: object, description: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"{description} is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ValueError(f"{description} is invalid")
    return value


def _require_contract_map(value: Mapping[Stage, str], description: str) -> None:
    if not isinstance(value, Mapping) or len(value) > len(Stage):
        raise ValueError(f"{description} manifest is invalid")
    for stage, digest in value.items():
        if not isinstance(stage, Stage):
            raise ValueError(f"{description} manifest is invalid")
        _require_hash(digest, description)


def _require_git_object(value: object) -> str:
    if (
        not isinstance(value, str)
        or len(value) not in {40, 64}
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError("repair baseline object is invalid")
    return value


def _capture_immutable_release_manifest(root: Path) -> tuple[ReleaseManifestEntry, ...]:
    candidate = Path(root)
    if not candidate.is_absolute() or candidate.is_symlink() or not candidate.is_dir():
        raise UnauthorizedRepairError("built runner release root is invalid")
    entries: list[ReleaseManifestEntry] = []
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
                ReleaseManifestEntry(
                    path=relative,
                    kind=kind,
                    mode=stat.S_IMODE(metadata.st_mode),
                    content_sha256=hashlib.sha256(content).hexdigest(),
                )
            )
    if not entries or len(entries) > 100_000:
        raise UnauthorizedRepairError("built runner release manifest is invalid")
    result = tuple(sorted(entries, key=lambda entry: entry.path))
    if len({entry.path for entry in result}) != len(result):
        raise UnauthorizedRepairError("built runner release manifest is invalid")
    return result


def capture_built_release_manifest(root: Path) -> tuple[ReleaseManifestEntry, ...]:
    """Capture a complete immutable release manifest for a trusted builder."""
    return _capture_immutable_release_manifest(root)
