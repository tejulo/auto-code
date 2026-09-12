from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
import fcntl
import hashlib
import hmac
import json
import math
import os
from pathlib import Path
import re
import stat
from types import MappingProxyType
from typing import Annotated, Literal

from pydantic import Field, ValidationError, field_serializer, field_validator, model_validator

from .checkpoint import CheckpointAuthority
from .contracts import (
    ArtifactEnvelope,
    Checkpoint,
    ContractModel,
    Sha256,
    Stage,
    TaskDefinition,
    TaskDefinitionManifest,
    TaskStatus,
    TaskStatusManifest,
    UnitStatus,
    canonical_task_definition_hash,
    reject_unsafe_persisted_value,
)
from .hashing import hash_json
from .process import (
    CommandExecution,
    CommandFailedError,
    CommandResult,
    EvidenceSink,
    ProcessBoundaryError,
    ProcessRunner,
    SandboxPolicy,
    TrustedCommandOutput,
)
from .state import (
    AuthoritativeStateCorrupt,
    _atomic_replace_json,
    _ensure_directory,
    _fsync_directory_fd,
    _lstat_at,
    _open_parent,
    _path_lstat,
    _read_canonical_json,
    _write_file_and_fsync_at,
    _write_new_json,
)


ArtifactKind = Literal["proposal", "specs", "design", "tasks"]

_ARTIFACT_KINDS = frozenset({"proposal", "specs", "design", "tasks"})
_ARTIFACT_DEPENDENCIES: Mapping[ArtifactKind, tuple[ArtifactKind, ...]] = {
    "proposal": (),
    "specs": ("proposal",),
    "design": ("proposal",),
    "tasks": ("specs", "design"),
}
_CHANGE_ID = re.compile(r"^[a-z][a-z0-9-]{0,62}$")
_OWNER_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_TASK_CHECKLIST_ITEM = re.compile(r"^\s*-\s*\[(?P<checked>[ xX])\]\s+(?P<body>.*?)\s*$")
_TASK_DEFINITION = re.compile(
    r"^(?P<task_id>[1-9][0-9]*(?:\.[1-9][0-9]*)*)(?:[.:])?\s+(?P<text>\S.*?)$"
)


class OpenSpecError(RuntimeError):
    pass


class OpenSpecInputError(OpenSpecError):
    pass


class OpenSpecProcessError(OpenSpecError):
    pass


class OpenSpecSchemaError(OpenSpecError):
    pass


class ChangeOwnershipError(OpenSpecError):
    pass


class ArtifactDependencyError(OpenSpecError):
    pass


class CheckpointMismatch(OpenSpecError):
    pass


class TaskDefinitionChanged(OpenSpecError):
    pass


class UnknownTaskId(OpenSpecError):
    pass


class ArtifactInstructions(ContractModel):
    """The fixed, local spec-driven instruction shape consumed by later artifact work."""

    schema_name: Literal["spec-driven"] = Field(alias="schema")
    change_id: Annotated[str, Field(max_length=63, pattern=_CHANGE_ID.pattern)]
    artifact: ArtifactKind
    instructions: Annotated[str, Field(min_length=1, max_length=32_768)]
    output_paths: tuple[Annotated[str, Field(min_length=1, max_length=512)], ...] = Field(min_length=1, max_length=64)
    requires: tuple[ArtifactKind, ...] = Field(max_length=3)

    @field_validator("change_id")
    @classmethod
    def validate_change_id(cls, value: str) -> str:
        return _validated_change_id(value)

    @field_validator("output_paths")
    @classmethod
    def validate_output_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for path in value:
            _validated_relative_path(path)
        if len(set(value)) != len(value):
            raise ValueError("OpenSpec output paths must be unique")
        return value

    @model_validator(mode="after")
    def validate_dependencies(self) -> ArtifactInstructions:
        if self.artifact in self.requires or len(set(self.requires)) != len(self.requires):
            raise ValueError("OpenSpec artifact dependencies are invalid")
        return self


class StagedArtifactManifest(ContractModel):
    change_id: Annotated[str, Field(max_length=63, pattern=_CHANGE_ID.pattern)]
    artifact: ArtifactKind
    envelope: ArtifactEnvelope
    contract_hash: Sha256
    input_hashes: Mapping[ArtifactKind, Sha256]
    parent_output_manifest_hash: Sha256 | None = None
    output_manifest_hash: Sha256
    output_paths: tuple[Annotated[str, Field(min_length=1, max_length=512)], ...] = Field(min_length=1, max_length=64)

    @field_validator("change_id")
    @classmethod
    def validate_change_id(cls, value: str) -> str:
        return _validated_change_id(value)

    @field_validator("output_paths")
    @classmethod
    def validate_output_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for path in value:
            _validated_relative_path(path)
        if len(set(value)) != len(value):
            raise ValueError("Staged artifact output paths must be unique")
        return value

    @field_validator("input_hashes")
    @classmethod
    def freeze_input_hashes(cls, value: Mapping[ArtifactKind, Sha256]) -> Mapping[ArtifactKind, Sha256]:
        if any(artifact not in _ARTIFACT_KINDS for artifact in value):
            raise ValueError("Staged artifact dependencies are invalid")
        return MappingProxyType(dict(value))

    @field_serializer("input_hashes")
    def serialize_input_hashes(self, value: Mapping[ArtifactKind, Sha256]) -> dict[ArtifactKind, Sha256]:
        return dict(value)

    @model_validator(mode="after")
    def validate_hash_bindings(self) -> StagedArtifactManifest:
        if set(self.input_hashes) != set(_ARTIFACT_DEPENDENCIES[self.artifact]):
            raise ValueError("Staged artifact dependencies are invalid")
        envelope_payload = self.envelope.model_dump(mode="json", round_trip=True)
        if self.contract_hash.lower() != hash_json(envelope_payload):
            raise ValueError("Staged artifact contract hash does not match its envelope")
        if self.output_paths != tuple(artifact_file.relative_path for artifact_file in self.envelope.files):
            raise ValueError("Staged artifact output paths do not match its envelope")
        output_manifest_hash = hash_json(
            {
                "change_id": self.change_id,
                "artifact": self.artifact,
                "envelope": envelope_payload,
                "input_hashes": dict(self.input_hashes),
                "parent_output_manifest_hash": self.parent_output_manifest_hash,
                "output_paths": self.output_paths,
            }
        )
        if self.output_manifest_hash.lower() != output_manifest_hash:
            raise ValueError("Staged artifact output hash does not match its bindings")
        return self


class ValidationReceipt(ContractModel):
    change_id: Annotated[str, Field(max_length=63, pattern=_CHANGE_ID.pattern)]
    artifact: ArtifactKind
    output_manifest_hash: Sha256
    validator: Literal["openspec"]
    validator_version: Literal["1.12.0"]
    validation_output_hash: Sha256
    receipt_hash: Sha256

    @field_validator("change_id")
    @classmethod
    def validate_change_id(cls, value: str) -> str:
        return _validated_change_id(value)

    @model_validator(mode="after")
    def validate_receipt_hash(self) -> ValidationReceipt:
        if self.receipt_hash.lower() != hash_json(
            self.model_dump(mode="json", round_trip=True, exclude={"receipt_hash"})
        ):
            raise ValueError("Validation receipt hash does not match content")
        return self


class _VisibleChangePointer(ContractModel):
    change_id: Annotated[str, Field(max_length=63, pattern=_CHANGE_ID.pattern)]
    revision: Annotated[int, Field(ge=1)]
    artifacts: Mapping[ArtifactKind, Sha256]
    revision_hash: Sha256

    @field_validator("change_id")
    @classmethod
    def validate_change_id(cls, value: str) -> str:
        return _validated_change_id(value)

    @field_validator("artifacts")
    @classmethod
    def freeze_artifacts(cls, value: Mapping[ArtifactKind, Sha256]) -> Mapping[ArtifactKind, Sha256]:
        if not value or any(artifact not in _ARTIFACT_KINDS for artifact in value):
            raise ValueError("OpenSpec revision artifacts are invalid")
        return MappingProxyType(dict(value))

    @field_serializer("artifacts")
    def serialize_artifacts(self, value: Mapping[ArtifactKind, Sha256]) -> dict[ArtifactKind, Sha256]:
        return dict(value)

    @model_validator(mode="after")
    def validate_revision_hash(self) -> _VisibleChangePointer:
        expected = hash_json(
            {
                "change_id": self.change_id,
                "revision": self.revision,
                "artifacts": dict(self.artifacts),
            }
        )
        if self.revision_hash.lower() != expected:
            raise ValueError("OpenSpec revision hash does not match content")
        return self


class _ArtifactValidation(ContractModel):
    schema_name: Literal["spec-driven"] = Field(alias="schema")
    change_id: Annotated[str, Field(max_length=63, pattern=_CHANGE_ID.pattern)]
    artifact: ArtifactKind
    valid: Literal[True]

    @field_validator("change_id")
    @classmethod
    def validate_change_id(cls, value: str) -> str:
        return _validated_change_id(value)


class _ChangeOwner(ContractModel):
    schema_name: Literal["spec-driven"] = Field(alias="schema")
    change_id: Annotated[str, Field(max_length=63, pattern=_CHANGE_ID.pattern)]
    ticket_id: Annotated[str, Field(max_length=128, pattern=_OWNER_ID.pattern)]
    run_id: Annotated[str, Field(max_length=128, pattern=_OWNER_ID.pattern)]

    @field_validator("change_id")
    @classmethod
    def validate_change_id(cls, value: str) -> str:
        return _validated_change_id(value)

    @field_validator("ticket_id", "run_id")
    @classmethod
    def validate_owner_id(cls, value: str) -> str:
        return _validated_owner_id(value)


class _ChangePresence(ContractModel):
    schema_name: Literal["spec-driven"] = Field(alias="schema")
    change_id: Annotated[str, Field(max_length=63, pattern=_CHANGE_ID.pattern)]

    @field_validator("change_id")
    @classmethod
    def validate_change_id(cls, value: str) -> str:
        return _validated_change_id(value)


@dataclass(frozen=True, slots=True)
class OpenSpecClient:
    """Typed local OpenSpec adapter that delegates every command to ProcessRunner."""

    root: Path
    process_runner: ProcessRunner
    openspec_executable: str
    timeout: float
    evidence_sink: EvidenceSink
    environment: Mapping[str, str]
    sandbox_policy: SandboxPolicy
    checkpoint_authority: CheckpointAuthority

    def __post_init__(self) -> None:
        if not isinstance(self.root, Path) or not self.root.is_absolute() or ".." in self.root.parts:
            raise OpenSpecInputError("OpenSpec root is invalid")
        if (
            not isinstance(self.openspec_executable, str)
            or not Path(self.openspec_executable).is_absolute()
            or ".." in Path(self.openspec_executable).parts
        ):
            raise OpenSpecInputError("OpenSpec executable is invalid")
        if (
            isinstance(self.timeout, bool)
            or not isinstance(self.timeout, (int, float))
            or not math.isfinite(self.timeout)
            or self.timeout <= 0
        ):
            raise OpenSpecInputError("OpenSpec timeout is invalid")
        if not isinstance(self.environment, Mapping) or any(
            not isinstance(name, str) or not isinstance(value, str) for name, value in self.environment.items()
        ):
            raise OpenSpecInputError("OpenSpec environment is invalid")
        if not callable(getattr(self.process_runner, "run_with_trusted_output", None)):
            raise OpenSpecInputError("OpenSpec process runner is invalid")
        if not isinstance(self.checkpoint_authority, CheckpointAuthority):
            raise OpenSpecInputError("OpenSpec checkpoint authority is invalid")
        try:
            _ensure_directory(self.root, self.root, create=False)
        except (AuthoritativeStateCorrupt, OSError, ValueError):
            raise OpenSpecInputError("OpenSpec root is invalid") from None

    def ensure_change(self, change_id: str, ticket_id: str, run_id: str) -> None:
        safe_change_id = _validated_change_id(change_id)
        safe_ticket_id = _validated_owner_id(ticket_id)
        safe_run_id = _validated_owner_id(run_id)
        try:
            # New-change JSON is only an operation receipt, never ownership evidence.
            self._run_json_command(("new", "change", safe_change_id, "--json"))
        except OpenSpecProcessError:
            self._require_existing_change(safe_change_id)
            owner = self._read_ownership_binding(safe_change_id)
        else:
            self._require_existing_change(safe_change_id)
            owner = self._write_ownership_binding(safe_change_id, safe_ticket_id, safe_run_id)
        if owner.change_id != safe_change_id or owner.ticket_id != safe_ticket_id or owner.run_id != safe_run_id:
            raise ChangeOwnershipError("OpenSpec change ownership is invalid")

    def instructions(self, change_id: str, artifact: ArtifactKind) -> ArtifactInstructions:
        safe_change_id = _validated_change_id(change_id)
        safe_artifact = _validated_artifact(artifact)
        instructions = self._parse_instructions(
            self._run_json_command(("instructions", safe_artifact, "--change", safe_change_id, "--json"))
        )
        if instructions.change_id != safe_change_id or instructions.artifact != safe_artifact:
            raise OpenSpecSchemaError("OpenSpec instruction response is invalid")
        return instructions

    def stage_artifact(self, change_id: str, envelope: ArtifactEnvelope) -> StagedArtifactManifest:
        safe_change_id = _validated_change_id(change_id)
        safe_envelope = _validated_envelope(envelope)
        safe_artifact = _validated_artifact(safe_envelope.artifact_id)
        instructions = self.instructions(safe_change_id, safe_artifact)
        required_artifacts = _ARTIFACT_DEPENDENCIES[safe_artifact]
        if instructions.requires != required_artifacts or instructions.output_paths != tuple(
            file.relative_path for file in safe_envelope.files
        ):
            raise OpenSpecSchemaError("OpenSpec artifact instructions are invalid")
        dependencies = {artifact: self._published_artifact(safe_change_id, artifact) for artifact in required_artifacts}
        if any(staged is None for staged in dependencies.values()):
            raise ArtifactDependencyError("OpenSpec artifact dependencies are not published")
        input_hashes = {artifact: staged.output_manifest_hash for artifact, staged in dependencies.items() if staged is not None}
        current = self._visible_change_pointer(safe_change_id)
        parent_output_manifest_hash = None if current is None else current.artifacts.get(safe_artifact)
        envelope_payload = safe_envelope.model_dump(mode="json", round_trip=True)
        staged = StagedArtifactManifest(
            change_id=safe_change_id,
            artifact=safe_artifact,
            envelope=safe_envelope,
            contract_hash=hash_json(envelope_payload),
            input_hashes=input_hashes,
            parent_output_manifest_hash=parent_output_manifest_hash,
            output_manifest_hash=hash_json(
                {
                    "change_id": safe_change_id,
                    "artifact": safe_artifact,
                    "envelope": envelope_payload,
                    "input_hashes": input_hashes,
                    "parent_output_manifest_hash": parent_output_manifest_hash,
                    "output_paths": instructions.output_paths,
                }
            ),
            output_paths=instructions.output_paths,
        )
        self._write_staged_artifact(staged)
        return staged

    def visible_path(self, staged: StagedArtifactManifest) -> Path | None:
        safe_staged = _validated_staged_artifact(staged)
        pointer = self._visible_change_pointer(safe_staged.change_id)
        if pointer is None:
            return None
        return self._revision_tree_root(pointer)

    def validate_artifact(self, staged: StagedArtifactManifest) -> ValidationReceipt:
        safe_staged = self._load_staged_artifact(staged)
        validation = self._parse_artifact_validation(
            self._run_json_command(
                ("validate", "--change", safe_staged.change_id, "--json"),
                cwd=self._staged_tree_root(safe_staged),
            )
        )
        if validation.change_id != safe_staged.change_id or validation.artifact != safe_staged.artifact:
            raise OpenSpecSchemaError("OpenSpec validation response is invalid")
        values = {
            "change_id": safe_staged.change_id,
            "artifact": safe_staged.artifact,
            "output_manifest_hash": safe_staged.output_manifest_hash,
            "validator": "openspec",
            "validator_version": "1.12.0",
            "validation_output_hash": hash_json(validation.model_dump(mode="json", round_trip=True)),
        }
        receipt = ValidationReceipt.model_validate({**values, "receipt_hash": hash_json(values)})
        try:
            if not _write_new_json(self._receipt_path(safe_staged), receipt.model_dump(mode="json", round_trip=True)):
                if self._load_validation_receipt(safe_staged) != receipt:
                    raise OpenSpecError("OpenSpec validation receipt is immutable")
        except (AuthoritativeStateCorrupt, OSError, ValueError):
            raise OpenSpecError("OpenSpec validation receipt cannot be written safely") from None
        return receipt

    def parse_task_definitions(self, staged: StagedArtifactManifest) -> TaskDefinitionManifest:
        definitions, _ = self._parse_task_manifest(staged)
        return definitions

    def parse_initial_task_status(
        self,
        staged: StagedArtifactManifest,
        definitions: TaskDefinitionManifest,
    ) -> TaskStatusManifest:
        parsed_definitions, initial_status = self._parse_task_manifest(staged)
        if _validated_task_definition_manifest(definitions) != parsed_definitions:
            raise TaskDefinitionChanged("OpenSpec task status definitions changed")
        return initial_status

    def _parse_task_manifest(
        self,
        staged: StagedArtifactManifest,
    ) -> tuple[TaskDefinitionManifest, TaskStatusManifest]:
        safe_staged = self._load_staged_artifact(staged)
        if safe_staged.artifact != "tasks":
            raise OpenSpecInputError("OpenSpec task definitions require a tasks artifact")
        tasks: list[TaskDefinition] = []
        statuses: list[TaskStatus] = []
        task_ids: set[str] = set()
        for artifact_file in safe_staged.envelope.files:
            for line in artifact_file.content.splitlines():
                checklist_item = _TASK_CHECKLIST_ITEM.fullmatch(line)
                if checklist_item is None:
                    continue
                definition = _TASK_DEFINITION.fullmatch(checklist_item.group("body"))
                if definition is None:
                    raise OpenSpecSchemaError("OpenSpec task definition is invalid")
                task_id = definition.group("task_id")
                text = definition.group("text").strip()
                if not text or task_id in task_ids:
                    raise OpenSpecSchemaError("OpenSpec task definition is invalid")
                task_ids.add(task_id)
                tasks.append(TaskDefinition(task_id=task_id, text=text))
                statuses.append(
                    TaskStatus(
                        task_id=task_id,
                        status=UnitStatus.CHECKED if checklist_item.group("checked").lower() == "x" else UnitStatus.UNCHECKED,
                    )
                )
        task_tuple = tuple(tasks)
        definitions = TaskDefinitionManifest(
            definition_hash=canonical_task_definition_hash(task_tuple),
            tasks=task_tuple,
        )
        return definitions, TaskStatusManifest(
            definition_hash=definitions.definition_hash,
            statuses=tuple(statuses),
        )

    def transition_task_status(
        self,
        definitions: TaskDefinitionManifest,
        before: TaskStatusManifest,
        completed_task_ids: tuple[str, ...],
    ) -> TaskStatusManifest:
        safe_definitions = _validated_task_definition_manifest(definitions)
        safe_before = _validated_task_status_manifest(before)
        if safe_before.definition_hash != safe_definitions.definition_hash:
            raise TaskDefinitionChanged("OpenSpec task status definitions changed")
        known_task_ids = tuple(task.task_id for task in safe_definitions.tasks)
        known_task_id_set = set(known_task_ids)
        before_statuses = {status.task_id: status.status for status in safe_before.statuses}
        if set(before_statuses) != known_task_id_set:
            raise TaskDefinitionChanged("OpenSpec task status definitions changed")
        if not isinstance(completed_task_ids, tuple) or any(not isinstance(task_id, str) for task_id in completed_task_ids):
            raise OpenSpecInputError("OpenSpec completed task IDs are invalid")
        if any(task_id not in known_task_id_set for task_id in completed_task_ids):
            raise UnknownTaskId("OpenSpec completed task ID is unknown")
        completed = set(completed_task_ids)
        return TaskStatusManifest(
            definition_hash=safe_definitions.definition_hash,
            statuses=tuple(
                TaskStatus(
                    task_id=task_id,
                    status=UnitStatus.CHECKED if task_id in completed else before_statuses[task_id],
                )
                for task_id in known_task_ids
            ),
        )

    def validate_complete_change(self, change_id: str) -> ValidationReceipt:
        safe_change_id = _validated_change_id(change_id)
        lock_descriptor = self._acquire_publication_lock(safe_change_id)
        try:
            pointer = self._visible_change_pointer(safe_change_id)
            if pointer is None:
                raise ArtifactDependencyError("OpenSpec full change validation requires all artifacts to be published")
            artifacts = self._published_artifacts(safe_change_id, pointer)
            if set(artifacts) != _ARTIFACT_KINDS:
                raise ArtifactDependencyError("OpenSpec full change validation requires all artifacts to be published")
            tasks = artifacts["tasks"]
            validation = self._parse_artifact_validation(
                self._run_json_command(
                    ("validate", "--change", safe_change_id, "--json"),
                    cwd=self._revision_root(pointer) / "tree",
                )
            )
            if validation.change_id != safe_change_id or validation.artifact != "tasks":
                raise OpenSpecSchemaError("OpenSpec validation response is invalid")
            values = {
                "change_id": safe_change_id,
                "artifact": "tasks",
                "output_manifest_hash": tasks.output_manifest_hash,
                "validator": "openspec",
                "validator_version": "1.12.0",
                "validation_output_hash": hash_json(validation.model_dump(mode="json", round_trip=True)),
            }
            return ValidationReceipt.model_validate({**values, "receipt_hash": hash_json(values)})
        finally:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            os.close(lock_descriptor)

    def publish_artifact(self, staged: StagedArtifactManifest, checkpoint: Checkpoint) -> tuple[Path, ...]:
        safe_staged = self._load_staged_artifact(staged)
        receipt = self._load_validation_receipt(safe_staged)
        safe_checkpoint = _validated_checkpoint(checkpoint)
        if (
            not self.checkpoint_authority.matches(
                safe_checkpoint,
                stage=_stage_for_artifact(safe_staged.artifact),
                contract_hash=safe_staged.contract_hash,
                input_hashes=safe_staged.input_hashes,
            )
            or safe_checkpoint.stage is not _stage_for_artifact(safe_staged.artifact)
            or safe_checkpoint.contract_hash.lower() != safe_staged.contract_hash.lower()
            or dict(safe_checkpoint.input_hashes) != dict(safe_staged.input_hashes)
            or safe_checkpoint.output_manifest_hash.lower() != safe_staged.output_manifest_hash.lower()
            or safe_checkpoint.validator != receipt.validator
            or safe_checkpoint.validator_version != receipt.validator_version
            or safe_checkpoint.validation_receipt_hash.lower() != receipt.receipt_hash.lower()
        ):
            raise CheckpointMismatch("OpenSpec checkpoint does not match staged artifact")
        lock_descriptor = self._acquire_publication_lock(safe_staged.change_id)
        try:
            self._revalidate_published_prerequisites(safe_staged)
            current = self._visible_change_pointer(safe_staged.change_id)
            current_artifact_hash = None if current is None else current.artifacts.get(safe_staged.artifact)
            if current_artifact_hash is not None and current_artifact_hash.lower() == safe_staged.output_manifest_hash.lower():
                visible_root = self._revision_tree_root(current)
                return tuple(visible_root / artifact_file.relative_path for artifact_file in safe_staged.envelope.files)
            if current_artifact_hash != safe_staged.parent_output_manifest_hash:
                raise CheckpointMismatch("OpenSpec publication cannot regress the visible version")
            if current is None and safe_staged.parent_output_manifest_hash is not None:
                raise CheckpointMismatch("OpenSpec publication cannot advance from a missing visible version")
            artifacts = self._published_artifacts(safe_staged.change_id)
            artifacts[safe_staged.artifact] = safe_staged
            self._reject_stale_published_dependents(safe_staged, artifacts)
            successor = self._successor_pointer(safe_staged.change_id, current, artifacts)
            self._write_complete_revision(successor, artifacts)
            if set(successor.artifacts) == _ARTIFACT_KINDS:
                self._validate_complete_revision(successor, safe_staged.artifact)
            self._fsync_complete_revision(successor, artifacts)
            _atomic_replace_json(
                self._current_pointer_path(safe_staged.change_id),
                successor.model_dump(mode="json", round_trip=True),
            )
        except (AuthoritativeStateCorrupt, OSError, ValueError, UnicodeEncodeError):
            raise OpenSpecError("OpenSpec artifact cannot be published safely") from None
        finally:
            fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
            os.close(lock_descriptor)
        visible_root = self.visible_path(safe_staged)
        if visible_root is None:
            raise OpenSpecError("OpenSpec visible pointer cannot be read safely")
        return tuple(visible_root / artifact_file.relative_path for artifact_file in safe_staged.envelope.files)

    def _write_staged_artifact(self, staged: StagedArtifactManifest) -> None:
        stage_root = self._staged_root(staged)
        try:
            _ensure_directory(self.root, stage_root)
            change_tree = self._change_tree_root(staged.change_id, staged.artifact, staged.output_manifest_hash)
            for artifact, published in self._published_artifacts(staged.change_id).items():
                if artifact == staged.artifact:
                    continue
                for artifact_file in published.envelope.files:
                    destination = change_tree / artifact_file.relative_path
                    _ensure_directory(self.root, destination.parent)
                    _write_immutable_file(destination, artifact_file.content.encode("utf-8"))
            for artifact_file in staged.envelope.files:
                destination = change_tree / artifact_file.relative_path
                _ensure_directory(self.root, destination.parent)
                _write_immutable_file(destination, artifact_file.content.encode("utf-8"))
            if not _write_new_json(stage_root / "manifest.json", staged.model_dump(mode="json", round_trip=True)):
                self._load_artifact_manifest(staged, stage_root, "OpenSpec staged manifest")
        except (AuthoritativeStateCorrupt, OSError, ValueError, UnicodeEncodeError):
            raise OpenSpecError("OpenSpec staged artifact cannot be written safely") from None

    def _staged_root(self, staged: StagedArtifactManifest) -> Path:
        return self.root / ".auto-code-openspec" / "versions" / staged.change_id / staged.output_manifest_hash

    def _staged_tree_root(self, staged: StagedArtifactManifest) -> Path:
        return self._staged_root(staged) / "tree"

    def _receipt_path(self, staged: StagedArtifactManifest) -> Path:
        return self._staged_root(staged) / "validation-receipt.json"

    def _current_pointer_path(self, change_id: str) -> Path:
        return self.root / ".auto-code-openspec" / "current" / change_id / "current.json"

    def _acquire_publication_lock(self, change_id: str) -> int:
        lock_path = self._current_pointer_path(change_id).with_name(".publish.lock")
        descriptor: int | None = None
        try:
            _ensure_directory(self.root, lock_path.parent)
            parent_fd, name = _open_parent(lock_path, description="OpenSpec publication lock")
            try:
                descriptor = os.open(
                    name,
                    os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                    0o600,
                    dir_fd=parent_fd,
                )
            finally:
                os.close(parent_fd)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            return descriptor
        except (AuthoritativeStateCorrupt, OSError, ValueError):
            if descriptor is not None:
                os.close(descriptor)
            raise OpenSpecError("OpenSpec publication lock cannot be acquired safely") from None

    def _version_root(self, change_id: str, output_manifest_hash: str) -> Path:
        return self.root / ".auto-code-openspec" / "versions" / change_id / output_manifest_hash

    def _change_tree_root(self, change_id: str, artifact: ArtifactKind, output_manifest_hash: str) -> Path:
        return self._version_root(change_id, output_manifest_hash) / "tree" / "openspec" / "changes" / change_id

    def _visible_change_pointer(self, change_id: str) -> _VisibleChangePointer | None:
        publication = self._current_pointer_path(change_id)
        try:
            _ensure_directory(self.root, publication.parent)
            if _path_lstat(publication, "OpenSpec visible pointer") is None:
                return None
            pointer = _VisibleChangePointer.model_validate(
                _read_canonical_json(publication, "OpenSpec visible pointer")
            )
        except (AuthoritativeStateCorrupt, OSError, ValueError, ValidationError):
            raise OpenSpecError("OpenSpec visible pointer cannot be read safely") from None
        if pointer.change_id != change_id:
            raise OpenSpecError("OpenSpec visible pointer is invalid")
        return pointer

    def _published_artifact(
        self,
        change_id: str,
        artifact: ArtifactKind,
        pointer: _VisibleChangePointer | None = None,
    ) -> StagedArtifactManifest | None:
        if pointer is None:
            pointer = self._visible_change_pointer(change_id)
        if pointer is None or artifact not in pointer.artifacts:
            return None
        output_manifest_hash = pointer.artifacts[artifact]
        version_root = self._version_root(change_id, output_manifest_hash)
        try:
            staged = StagedArtifactManifest.model_validate(
                _read_canonical_json(version_root / "manifest.json", "OpenSpec visible artifact")
            )
        except (AuthoritativeStateCorrupt, OSError, ValueError, ValidationError):
            raise OpenSpecError("OpenSpec visible artifact cannot be read safely") from None
        if (
            staged.change_id != change_id
            or staged.artifact != artifact
            or staged.output_manifest_hash.lower() != output_manifest_hash.lower()
        ):
            raise OpenSpecError("OpenSpec visible artifact is invalid")
        return self._load_artifact_manifest(staged, version_root, "OpenSpec visible artifact")

    def _published_artifacts(
        self,
        change_id: str,
        pointer: _VisibleChangePointer | None = None,
    ) -> dict[ArtifactKind, StagedArtifactManifest]:
        published: dict[ArtifactKind, StagedArtifactManifest] = {}
        if pointer is None:
            pointer = self._visible_change_pointer(change_id)
        if pointer is None:
            return published
        for artifact in pointer.artifacts:
            staged = self._published_artifact(change_id, artifact, pointer)
            if staged is not None:
                published[artifact] = staged
        return published

    def _revalidate_published_prerequisites(self, staged: StagedArtifactManifest) -> None:
        for artifact, expected_hash in staged.input_hashes.items():
            published = self._published_artifact(staged.change_id, artifact)
            if published is None or published.output_manifest_hash.lower() != expected_hash.lower():
                raise ArtifactDependencyError("OpenSpec artifact dependencies changed before publication")

    @staticmethod
    def _reject_stale_published_dependents(
        staged: StagedArtifactManifest,
        artifacts: Mapping[ArtifactKind, StagedArtifactManifest],
    ) -> None:
        for published in artifacts.values():
            expected_hash = published.input_hashes.get(staged.artifact)
            if expected_hash is not None and expected_hash.lower() != staged.output_manifest_hash.lower():
                raise ArtifactDependencyError("OpenSpec published dependents would become stale")

    def _successor_pointer(
        self,
        change_id: str,
        current: _VisibleChangePointer | None,
        artifacts: Mapping[ArtifactKind, StagedArtifactManifest],
    ) -> _VisibleChangePointer:
        revision = 1 if current is None else current.revision + 1
        artifact_hashes = {artifact: staged.output_manifest_hash for artifact, staged in artifacts.items()}
        values = {
            "change_id": change_id,
            "revision": revision,
            "artifacts": artifact_hashes,
        }
        return _VisibleChangePointer.model_validate({**values, "revision_hash": hash_json(values)})

    def _revision_root(self, pointer: _VisibleChangePointer) -> Path:
        return self.root / ".auto-code-openspec" / "revisions" / pointer.change_id / pointer.revision_hash

    def _revision_tree_root(self, pointer: _VisibleChangePointer) -> Path:
        return self._revision_root(pointer) / "tree" / "openspec" / "changes" / pointer.change_id

    def _write_complete_revision(
        self,
        pointer: _VisibleChangePointer,
        artifacts: Mapping[ArtifactKind, StagedArtifactManifest],
    ) -> None:
        revision_root = self._revision_root(pointer)
        tree_root = self._revision_tree_root(pointer)
        try:
            _ensure_directory(self.root, tree_root)
            for artifact in sorted(artifacts):
                staged = artifacts[artifact]
                if pointer.artifacts[artifact].lower() != staged.output_manifest_hash.lower():
                    raise OpenSpecError("OpenSpec revision artifacts are invalid")
                for artifact_file in staged.envelope.files:
                    destination = tree_root / artifact_file.relative_path
                    _ensure_directory(self.root, destination.parent)
                    _write_immutable_file(destination, artifact_file.content.encode("utf-8"))
            if not _write_new_json(revision_root / "manifest.json", pointer.model_dump(mode="json", round_trip=True)):
                persisted = _VisibleChangePointer.model_validate(
                    _read_canonical_json(revision_root / "manifest.json", "OpenSpec revision manifest")
                )
                if persisted != pointer:
                    raise OpenSpecError("OpenSpec revision is immutable")
        except (AuthoritativeStateCorrupt, OSError, ValueError, UnicodeEncodeError):
            raise OpenSpecError("OpenSpec revision cannot be written safely") from None

    def _validate_complete_revision(self, pointer: _VisibleChangePointer, artifact: ArtifactKind) -> None:
        validation = self._parse_artifact_validation(
            self._run_json_command(
                ("validate", "--change", pointer.change_id, "--json"),
                cwd=self._revision_root(pointer) / "tree",
            )
        )
        if validation.change_id != pointer.change_id or validation.artifact != artifact:
            raise OpenSpecSchemaError("OpenSpec validation response is invalid")

    def _fsync_complete_revision(
        self,
        pointer: _VisibleChangePointer,
        artifacts: Mapping[ArtifactKind, StagedArtifactManifest],
    ) -> None:
        revision_root = self._revision_root(pointer)
        change_tree = self._revision_tree_root(pointer)
        directories = {
            revision_root,
            revision_root / "tree",
            revision_root / "tree" / "openspec",
            revision_root / "tree" / "openspec" / "changes",
            change_tree,
        }
        for staged in artifacts.values():
            directories.update(change_tree / Path(artifact_file.relative_path).parent for artifact_file in staged.envelope.files)
        ancestor = revision_root.parent
        while ancestor != self.root:
            directories.add(ancestor)
            ancestor = ancestor.parent
        directories.add(self.root)
        for directory in sorted(directories, key=lambda path: len(path.parts), reverse=True):
            _ensure_directory(self.root, directory, create=False)
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                _fsync_directory_fd(descriptor)
            finally:
                os.close(descriptor)

    def _load_staged_artifact(self, staged: StagedArtifactManifest) -> StagedArtifactManifest:
        safe_staged = _validated_staged_artifact(staged)
        return self._load_artifact_manifest(safe_staged, self._staged_root(safe_staged), "OpenSpec staged manifest")

    def _load_artifact_manifest(
        self,
        staged: StagedArtifactManifest,
        root: Path,
        description: str,
    ) -> StagedArtifactManifest:
        safe_staged = _validated_staged_artifact(staged)
        try:
            persisted = StagedArtifactManifest.model_validate(
                _read_canonical_json(root / "manifest.json", description)
            )
            if persisted != safe_staged:
                raise OpenSpecError("OpenSpec staged artifact does not match its manifest")
            for artifact_file in persisted.envelope.files:
                if not hmac.compare_digest(
                    _read_regular_file(self._change_tree_root(
                        persisted.change_id,
                        persisted.artifact,
                        persisted.output_manifest_hash,
                    ) / artifact_file.relative_path),
                    artifact_file.content.encode("utf-8"),
                ):
                    raise OpenSpecError("OpenSpec staged artifact does not match its files")
            return persisted
        except (AuthoritativeStateCorrupt, OSError, ValueError, UnicodeEncodeError):
            raise OpenSpecError("OpenSpec staged artifact cannot be read safely") from None

    def _load_validation_receipt(self, staged: StagedArtifactManifest) -> ValidationReceipt:
        try:
            receipt = ValidationReceipt.model_validate(
                _read_canonical_json(self._receipt_path(staged), "OpenSpec validation receipt")
            )
        except (AuthoritativeStateCorrupt, OSError, ValueError, ValidationError):
            raise CheckpointMismatch("OpenSpec validation receipt is missing or invalid") from None
        if (
            receipt.change_id != staged.change_id
            or receipt.artifact != staged.artifact
            or receipt.output_manifest_hash.lower() != staged.output_manifest_hash.lower()
        ):
            raise CheckpointMismatch("OpenSpec validation receipt does not match staged artifact")
        return receipt

    def _run_json_command(self, argv: tuple[str, ...], *, cwd: Path | None = None) -> object:
        try:
            execution = self.process_runner.run_with_trusted_output(
                (self.openspec_executable, *argv),
                self.root if cwd is None else cwd,
                float(self.timeout),
                self.evidence_sink,
                self.environment,
                self.sandbox_policy,
                suppress_public_output=True,
            )
            if not isinstance(execution, CommandExecution):
                raise TypeError
            if not isinstance(execution.result, CommandResult) or not isinstance(execution.output, TrustedCommandOutput):
                raise TypeError
            execution.result.require_success()
            output = execution.output.read_stdout()
        except (CommandFailedError, ProcessBoundaryError, TypeError, ValueError):
            raise OpenSpecProcessError("OpenSpec command failed") from None
        try:
            digest = hashlib.sha256(output.encode("utf-8")).hexdigest()
        except UnicodeEncodeError:
            raise OpenSpecSchemaError("OpenSpec JSON response is invalid") from None
        if not hmac.compare_digest(digest, execution.output.stdout_sha256):
            raise OpenSpecSchemaError("OpenSpec JSON response is invalid")
        return _parse_trusted_json(output)

    def _require_existing_change(self, change_id: str) -> None:
        try:
            change = _ChangePresence.model_validate(
                self._run_json_command(("show", change_id, "--type", "change", "--json"))
            )
        except (TypeError, ValueError, ValidationError):
            raise OpenSpecSchemaError("OpenSpec change response is invalid") from None
        if change.change_id != change_id:
            raise OpenSpecSchemaError("OpenSpec change response is invalid")

    def _write_ownership_binding(self, change_id: str, ticket_id: str, run_id: str) -> _ChangeOwner:
        path = self._ownership_path(change_id)
        payload = {
            "schema": "spec-driven",
            "change_id": change_id,
            "ticket_id": ticket_id,
            "run_id": run_id,
        }
        encoded = json.dumps(payload, allow_nan=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("xb") as destination:
                destination.write(encoded)
        except FileExistsError:
            return self._read_ownership_binding(change_id)
        except OSError:
            raise ChangeOwnershipError("OpenSpec change ownership is invalid") from None
        return self._parse_owner(_parse_trusted_json(encoded))

    def _read_ownership_binding(self, change_id: str) -> _ChangeOwner:
        try:
            encoded = self._ownership_path(change_id).read_bytes()
            owner = self._parse_owner(_parse_trusted_json(encoded))
        except (OSError, OpenSpecSchemaError):
            raise ChangeOwnershipError("OpenSpec change ownership is invalid") from None
        if owner.change_id != change_id:
            raise ChangeOwnershipError("OpenSpec change ownership is invalid")
        return owner

    def _ownership_path(self, change_id: str) -> Path:
        return self.root / ".auto-code-openspec" / "ownership" / f"{change_id}.json"

    @staticmethod
    def _parse_owner(value: object) -> _ChangeOwner:
        try:
            return _ChangeOwner.model_validate(value)
        except (TypeError, ValueError, ValidationError):
            raise OpenSpecSchemaError("OpenSpec change response is invalid") from None

    @staticmethod
    def _parse_instructions(value: object) -> ArtifactInstructions:
        try:
            return ArtifactInstructions.model_validate(value)
        except (TypeError, ValueError, ValidationError):
            raise OpenSpecSchemaError("OpenSpec instruction response is invalid") from None

    @staticmethod
    def _parse_artifact_validation(value: object) -> _ArtifactValidation:
        try:
            return _ArtifactValidation.model_validate(value)
        except (TypeError, ValueError, ValidationError):
            raise OpenSpecSchemaError("OpenSpec validation response is invalid") from None


def _validated_envelope(value: object) -> ArtifactEnvelope:
    try:
        if not isinstance(value, ArtifactEnvelope):
            raise TypeError
        return ArtifactEnvelope.model_validate(value.model_dump(mode="json", round_trip=True))
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise OpenSpecSchemaError("OpenSpec artifact envelope is invalid") from None


def _validated_staged_artifact(value: object) -> StagedArtifactManifest:
    try:
        if not isinstance(value, StagedArtifactManifest):
            raise TypeError
        return StagedArtifactManifest.model_validate(value.model_dump(mode="json", round_trip=True))
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise OpenSpecSchemaError("OpenSpec staged artifact is invalid") from None


def _validated_task_definition_manifest(value: object) -> TaskDefinitionManifest:
    try:
        if not isinstance(value, TaskDefinitionManifest):
            raise TypeError
        manifest = TaskDefinitionManifest.model_validate(value.model_dump(mode="json", round_trip=True))
        if any(
            _TASK_DEFINITION.fullmatch(f"{task.task_id} {task.text.strip()}") is None
            for task in manifest.tasks
        ):
            raise ValueError
        return manifest
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise OpenSpecInputError("OpenSpec task definitions are invalid") from None


def _validated_task_status_manifest(value: object) -> TaskStatusManifest:
    try:
        if not isinstance(value, TaskStatusManifest):
            raise TypeError
        return TaskStatusManifest.model_validate(value.model_dump(mode="json", round_trip=True))
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise OpenSpecInputError("OpenSpec task status is invalid") from None


def _validated_checkpoint(value: object) -> Checkpoint:
    try:
        if not isinstance(value, Checkpoint):
            raise TypeError
        return Checkpoint.model_validate(value.model_dump(mode="json", round_trip=True))
    except (AttributeError, TypeError, ValueError, ValidationError):
        raise CheckpointMismatch("OpenSpec checkpoint is invalid") from None


def _stage_for_artifact(artifact: ArtifactKind) -> Stage:
    return {
        "proposal": Stage.ARCHITECT_PROPOSAL,
        "specs": Stage.ARCHITECT_SPECS,
        "design": Stage.ARCHITECT_DESIGN,
        "tasks": Stage.ARCHITECT_TASKS,
    }[artifact]


def _read_regular_file(path: Path) -> bytes:
    parent_fd, name = _open_parent(path, description="OpenSpec staged artifact")
    try:
        metadata = _lstat_at(parent_fd, name, "OpenSpec staged artifact")
        if metadata is None or not stat.S_ISREG(metadata.st_mode):
            raise AuthoritativeStateCorrupt("OpenSpec staged artifact is not a regular file")
        descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise AuthoritativeStateCorrupt("OpenSpec staged artifact is not a regular file")
            with os.fdopen(descriptor, "rb") as source:
                return source.read()
        except BaseException:
            try:
                os.close(descriptor)
            except OSError:
                pass
            raise
    finally:
        os.close(parent_fd)


def _visible_file_matches(path: Path, payload: bytes) -> bool:
    metadata = _path_lstat(path, "OpenSpec visible artifact")
    if metadata is None:
        return False
    if not stat.S_ISREG(metadata.st_mode):
        raise AuthoritativeStateCorrupt("OpenSpec visible artifact is not a regular file")
    if not hmac.compare_digest(_read_regular_file(path), payload):
        raise AuthoritativeStateCorrupt("OpenSpec visible artifact is immutable")
    return True


def _write_immutable_file(path: Path, payload: bytes) -> None:
    parent_fd, name = _open_parent(path, description="OpenSpec staged artifact")
    try:
        metadata = _lstat_at(parent_fd, name, "OpenSpec staged artifact")
        if metadata is not None:
            if not stat.S_ISREG(metadata.st_mode):
                raise AuthoritativeStateCorrupt("OpenSpec staged artifact is not a regular file")
            existing = _read_regular_file(path)
            if not hmac.compare_digest(existing, payload):
                raise AuthoritativeStateCorrupt("OpenSpec staged artifact is immutable")
            return
        _write_file_and_fsync_at(parent_fd, name, payload)
        _fsync_directory_fd(parent_fd)
    finally:
        os.close(parent_fd)


def _validated_change_id(value: object) -> str:
    if not isinstance(value, str) or _CHANGE_ID.fullmatch(value) is None:
        raise OpenSpecInputError("OpenSpec change ID is invalid")
    try:
        return reject_unsafe_persisted_value(value)
    except ValueError:
        raise OpenSpecInputError("OpenSpec change ID is invalid") from None


def _validated_owner_id(value: object) -> str:
    if not isinstance(value, str) or _OWNER_ID.fullmatch(value) is None:
        raise OpenSpecInputError("OpenSpec owner ID is invalid")
    try:
        return reject_unsafe_persisted_value(value)
    except ValueError:
        raise OpenSpecInputError("OpenSpec owner ID is invalid") from None


def _validated_artifact(value: object) -> ArtifactKind:
    if not isinstance(value, str) or value not in _ARTIFACT_KINDS:
        raise OpenSpecInputError("OpenSpec artifact is invalid")
    return value  # type: ignore[return-value]


def _validated_relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or "\\" in value or value.startswith("/"):
        raise ValueError("OpenSpec output path is invalid")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("OpenSpec output path is invalid")
    try:
        return reject_unsafe_persisted_value(value)
    except ValueError:
        raise ValueError("OpenSpec output path is invalid") from None


def _parse_trusted_json(value: str | bytes) -> dict[str, object]:
    def reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, item in pairs:
            if key in result:
                raise ValueError("duplicate JSON key")
            result[key] = item
        return result

    def reject_nonfinite_constant(value: str) -> object:
        raise ValueError(f"invalid JSON constant: {value}")

    try:
        if isinstance(value, bytes):
            value = value.decode("utf-8", errors="strict")
        if not isinstance(value, str):
            raise ValueError("JSON text is invalid")
        parsed = json.loads(
            value,
            object_pairs_hook=reject_duplicate_keys,
            parse_constant=reject_nonfinite_constant,
        )
        if not isinstance(parsed, dict):
            raise ValueError("JSON response must be an object")
        return parsed
    except (TypeError, UnicodeDecodeError, ValueError, json.JSONDecodeError):
        raise OpenSpecSchemaError("OpenSpec JSON response is invalid") from None
