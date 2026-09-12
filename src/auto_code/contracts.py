from __future__ import annotations

from datetime import datetime
from enum import StrEnum
import hashlib
import json
import re
from types import MappingProxyType
from typing import Annotated, Any, Literal, Mapping, Protocol, Self, TypeAlias
from urllib.parse import urlsplit, urlunsplit
import uuid

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_serializer,
    field_validator,
    model_validator,
    ValidationError,
    ValidationInfo,
)

from .hashing import canonical_json_bytes, hash_json
from .model_catalog import SUPPORTED_PROVIDERS, canonical_text, is_secret_like_identifier


class ContractModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    def model_copy(
        self,
        *,
        update: Mapping[str, Any] | None = None,
        deep: bool = False,
    ) -> Self:
        values = self.model_dump(round_trip=True)
        values.update(update or {})
        return type(self).model_validate(values)


class Stage(StrEnum):
    ANALYST = "analyst"
    ARCHITECT_OUTLINE = "architect_outline"
    ARCHITECT_PROPOSAL = "architect_proposal"
    ARCHITECT_SPECS = "architect_specs"
    ARCHITECT_DESIGN = "architect_design"
    ARCHITECT_TASKS = "architect_tasks"
    PROGRAMMER = "programmer"
    VERIFICATION = "verification"
    TESTER = "tester"
    REVIEWER = "reviewer"


class FailureClass(StrEnum):
    PRODUCT = "product"
    INVALID_OUTPUT = "invalid_output"
    ORCHESTRATION = "orchestration"
    AMBIGUITY = "ambiguity"
    BUDGET_EXHAUSTED = "budget_exhausted"


class FailureSource(StrEnum):
    PREFLIGHT = "preflight"
    TRANSPORT = "transport"
    ARTIFACT = "artifact"
    VERIFICATION = "verification"
    BROWSER = "browser"
    REVIEW = "review"
    FINALIZATION = "finalization"
    SUPERVISOR = "supervisor"


class FindingKind(StrEnum):
    IMPLEMENTATION_MISMATCH = "implementation_mismatch"
    SCENARIO_MISMATCH = "scenario_mismatch"
    ARTIFACT_MISMATCH = "artifact_mismatch"
    REQUIREMENTS_MISMATCH = "requirements_mismatch"
    INVALID_UNIT_OUTPUT = "invalid_unit_output"
    INVALID_ROUTING = "invalid_routing"


class RunDisposition(StrEnum):
    ACTIVE = "active"
    WAITING_MCP = "waiting_mcp"
    REPAIR_REQUIRED = "repair_required"
    HUMAN_REVIEW = "human_review"
    DONE = "done"
    ABANDONED = "abandoned"


class PreparationPhase(StrEnum):
    SELECTED = "selected"
    IN_PROGRESS_REQUESTED = "in_progress_requested"
    IN_PROGRESS_CONFIRMED = "in_progress_confirmed"
    BRANCH_CREATED = "branch_created"
    READY = "ready"
    COMPENSATION_REQUIRED = "compensation_required"


class UnitStatus(StrEnum):
    UNCHECKED = "unchecked"
    CHECKED = "checked"


Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9A-Fa-f]{64}$")]
CheckpointId = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{32}$")]
EvidenceMediaType = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,63}/[a-z0-9][a-z0-9!#$&^_.+-]{0,63}$"),
]
EvidenceCreator = Annotated[str, StringConstraints(pattern=r"^[a-z][a-z0-9_-]{0,63}$")]
_SAFE_REFERENCE_SEGMENT = r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}"
_SAFE_REFERENCE_PATH = rf"^{_SAFE_REFERENCE_SEGMENT}(?:/{_SAFE_REFERENCE_SEGMENT})*$"
_SAFE_IDENTIFIER = r"^[a-z][a-z0-9_-]{0,63}$"
EvidencePath = Annotated[
    str,
    StringConstraints(max_length=512, pattern=_SAFE_REFERENCE_PATH),
]
_JWT_LIKE_SEGMENT = re.compile(
    r"eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(?=$|\.)"
)
_CREDENTIAL_LIKE_SEGMENT = re.compile(r"sk-[A-Za-z0-9_-]{8,}(?=$|\.)", re.IGNORECASE)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b[A-Za-z0-9_-]*(?:api[_-]?key|token|password|secret|credential)[A-Za-z0-9_-]*\s*[:=]\s*\S+"
)
_SECRET_MAPPING_KEY = re.compile(
    r"(?:^|[_-])(?:api[_-]?keys?|access[_-]?keys?|private[_-]?keys?|tokens?|passwords?|secrets?|credentials?|authorizations?)(?:$|[_-])"
)
_INSTRUCTION_LIKE_VALUE = re.compile(
    r"(?i)(?:ignore[-_:\s]+(?:all[-_:\s]+)?(?:previous|prior)[-_:\s]+instructions|follow[-_:\s]+(?:these|the)[-_:\s]+instructions|system[-_:\s]+prompt|developer[-_:\s]+message|assistant[-_:\s]+instructions)"
)


def reject_unsafe_persisted_value(value: str) -> str:
    if any(
        _JWT_LIKE_SEGMENT.search(segment)
        or _CREDENTIAL_LIKE_SEGMENT.search(segment)
        or _INSTRUCTION_LIKE_VALUE.search(segment)
        for segment in value.split("/")
    ):
        raise ValueError("Persisted values cannot contain secrets or instructions")
    return value


class EvidenceRef(ContractModel):
    relative_path: EvidencePath
    sha256: Sha256
    media_type: EvidenceMediaType
    creator: EvidenceCreator

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        return reject_unsafe_persisted_value(value)

    @field_validator("creator")
    @classmethod
    def validate_creator(cls, value: str) -> str:
        return reject_unsafe_persisted_value(value)


_BOUNDED_TEXT = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=4_096),
]
_SHORT_TEXT = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=1, max_length=512),
]
_PYTHON_OBSERVED_VERSION = re.compile(r"3\.12\.(?:0|[1-9][0-9]{0,8})\Z")
_NODE_OBSERVED_VERSION = re.compile(
    r"v?(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\.(?:0|[1-9][0-9]{0,8})\Z"
)
_EXACT_COMPONENT_VERSIONS = MappingProxyType(
    {
        "crewai": "1.15.20",
        "openspec": "1.12.0",
        "ralph": "1.0.10",
        "playwright": "0.1.19",
    }
)
_REFERENCE_ID = Annotated[
    str,
    StringConstraints(max_length=256, pattern=_SAFE_REFERENCE_PATH),
]
TASK_ID_PATTERN = r"^[1-9][0-9]*(?:\.[1-9][0-9]*)*$"
_TASK_ID = Annotated[str, StringConstraints(max_length=256, pattern=TASK_ID_PATTERN)]
_CHANGE_ID = Annotated[
    str,
    StringConstraints(max_length=63, pattern=r"^[a-z][a-z0-9-]{0,62}$"),
]
_GIT_SHA = Annotated[str, StringConstraints(pattern=r"^[0-9A-Fa-f]{40}(?:[0-9A-Fa-f]{24})?$")]
_GIT_MODE = Annotated[str, StringConstraints(pattern=r"^(?:000000|100644|100755|120000|160000)$")]
_GIT_CHANGE_STATUS = Annotated[
    str,
    StringConstraints(pattern=r"^(?:[ADMTUXB]|[CR](?:0|[1-9][0-9]?|100))$"),
]
_FAILURE_KIND = Annotated[str, StringConstraints(max_length=64, pattern=_SAFE_IDENTIFIER)]
_SENSITIVE_PATH_PARTS = frozenset({".auto-code", ".env", ".git", "secrets"})
_ARCHITECT_STAGES = frozenset(
    {
        Stage.ARCHITECT_OUTLINE,
        Stage.ARCHITECT_PROPOSAL,
        Stage.ARCHITECT_SPECS,
        Stage.ARCHITECT_DESIGN,
        Stage.ARCHITECT_TASKS,
    }
)


class OutputContract(ContractModel):
    """Base for model-authored outputs that remain immutable after validation."""

    schema_version: Literal["v1"] = "v1"


class SourceCitation(ContractModel):
    source_id: _REFERENCE_ID
    locator: _REFERENCE_ID
    source_hash: Sha256

    @field_validator("source_id", "locator")
    @classmethod
    def validate_reference(cls, value: str) -> str:
        return reject_unsafe_persisted_value(value)


class SourceCitedRequirement(ContractModel):
    requirement_id: _REFERENCE_ID
    text: _BOUNDED_TEXT
    sources: tuple[SourceCitation, ...] = Field(min_length=1, max_length=8)

    @field_validator("requirement_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        return reject_unsafe_persisted_value(value)


class SourceCitedCriterion(ContractModel):
    criterion_id: _REFERENCE_ID
    text: _BOUNDED_TEXT
    sources: tuple[SourceCitation, ...] = Field(min_length=1, max_length=8)

    @field_validator("criterion_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        return reject_unsafe_persisted_value(value)


class AmbiguitySeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    BLOCKING = "blocking"


class Ambiguity(ContractModel):
    ambiguity_id: _REFERENCE_ID
    text: _BOUNDED_TEXT
    severity: AmbiguitySeverity
    sources: tuple[SourceCitation, ...] = Field(min_length=1, max_length=8)

    @field_validator("ambiguity_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        return reject_unsafe_persisted_value(value)


class RequirementsPackage(OutputContract):
    objective: _BOUNDED_TEXT
    in_scope: tuple[_BOUNDED_TEXT, ...] = Field(min_length=1, max_length=64)
    out_of_scope: tuple[_BOUNDED_TEXT, ...] = Field(min_length=1, max_length=64)
    requirements: tuple[SourceCitedRequirement, ...] = Field(min_length=1, max_length=128)
    acceptance_criteria: tuple[SourceCitedCriterion, ...] = Field(min_length=1, max_length=128)
    constraints: tuple[_BOUNDED_TEXT, ...] = Field(max_length=64)
    dependencies: tuple[_BOUNDED_TEXT, ...] = Field(max_length=64)
    ambiguities: tuple[Ambiguity, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def validate_unique_ids(self) -> RequirementsPackage:
        if len({item.requirement_id for item in self.requirements}) != len(self.requirements):
            raise ValueError("Requirement IDs must be unique")
        if len({item.criterion_id for item in self.acceptance_criteria}) != len(self.acceptance_criteria):
            raise ValueError("Acceptance criterion IDs must be unique")
        if len({item.ambiguity_id for item in self.ambiguities}) != len(self.ambiguities):
            raise ValueError("Ambiguity IDs must be unique")
        return self


class BrowserScenario(ContractModel):
    scenario_id: _REFERENCE_ID
    description: _BOUNDED_TEXT
    expected_result: _BOUNDED_TEXT

    @field_validator("scenario_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        return reject_unsafe_persisted_value(value)


class BrowserE2EDecision(OutputContract):
    required: bool
    reason: _BOUNDED_TEXT
    scenarios: tuple[BrowserScenario, ...] = Field(max_length=64)

    @model_validator(mode="after")
    def validate_scenarios(self) -> BrowserE2EDecision:
        if self.required and not self.scenarios:
            raise ValueError("Browser E2E decision requires at least one scenario")
        if not self.required and self.scenarios:
            raise ValueError("A skipped Browser E2E decision must not include scenarios")
        if len({scenario.scenario_id for scenario in self.scenarios}) != len(self.scenarios):
            raise ValueError("Browser scenario IDs must be unique")
        return self


class ArtifactUnitManifestEntry(ContractModel):
    artifact_id: _REFERENCE_ID
    stage: Stage
    output_contract: Annotated[
        str,
        StringConstraints(max_length=64, pattern=r"^[A-Z][A-Za-z0-9]{0,63}$"),
    ]

    @model_validator(mode="after")
    def validate_artifact_stage(self) -> ArtifactUnitManifestEntry:
        if self.stage not in _ARCHITECT_STAGES:
            raise ValueError("Artifact Unit stages must belong to Architect")
        return self


class ChangeOutline(OutputContract):
    change_id: _CHANGE_ID
    artifact_units: tuple[ArtifactUnitManifestEntry, ...] = Field(min_length=1, max_length=16)
    direct_dependency_hashes: Mapping[_REFERENCE_ID, Sha256] = Field(min_length=1, max_length=32)
    browser_e2e_decision: BrowserE2EDecision

    @field_validator("change_id")
    @classmethod
    def validate_change_id(cls, value: str) -> str:
        return reject_unsafe_persisted_value(value)

    @field_validator("direct_dependency_hashes")
    @classmethod
    def freeze_dependency_hashes(cls, value: Mapping[str, Sha256]) -> Mapping[str, Sha256]:
        for key in value:
            reject_unsafe_persisted_value(key)
        return MappingProxyType(dict(value))

    @field_serializer("direct_dependency_hashes")
    def serialize_dependency_hashes(self, value: Mapping[str, Sha256]) -> dict[str, Sha256]:
        return dict(value)

    @model_validator(mode="after")
    def validate_artifact_ids(self) -> ChangeOutline:
        if len({unit.artifact_id for unit in self.artifact_units}) != len(self.artifact_units):
            raise ValueError("Artifact Unit IDs must be unique")
        return self


class ArtifactFile(OutputContract):
    relative_path: EvidencePath
    content: Annotated[str, StringConstraints(max_length=262_144)]
    sha256: Sha256

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        return _validate_product_path(value)

    @model_validator(mode="after")
    def validate_content_hash(self) -> ArtifactFile:
        actual = hashlib.sha256(self.content.encode("utf-8")).hexdigest()
        if self.sha256.lower() != actual:
            raise ValueError("Artifact file content hash does not match content")
        return self


class ArtifactEnvelope(OutputContract):
    artifact_id: _REFERENCE_ID
    files: tuple[ArtifactFile, ...] = Field(min_length=1, max_length=64)

    @field_validator("artifact_id")
    @classmethod
    def validate_artifact_id(cls, value: str) -> str:
        return reject_unsafe_persisted_value(value)

    @model_validator(mode="after")
    def validate_file_paths(self) -> ArtifactEnvelope:
        if len({file.relative_path for file in self.files}) != len(self.files):
            raise ValueError("Artifact file paths must be unique")
        return self


class ImplementationResult(OutputContract):
    task_definition_hash: Sha256
    task_status_hash: Sha256
    completed_task_ids: tuple[_TASK_ID, ...] = Field(min_length=1, max_length=256)
    changed_paths: tuple[EvidencePath, ...] = Field(min_length=1, max_length=512)
    command_evidence: tuple[EvidenceRef, ...] = Field(min_length=1, max_length=64)
    latest_failure_resolution: _BOUNDED_TEXT

    @field_validator("completed_task_ids")
    @classmethod
    def validate_completed_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for task_id in value:
            reject_unsafe_persisted_value(task_id)
        if len(set(value)) != len(value):
            raise ValueError("Completed task IDs must be unique")
        return value

    @model_validator(mode="after")
    def validate_programmer_context(self, info: ValidationInfo) -> ImplementationResult:
        if not isinstance(info.context, Mapping):
            return self
        definition_hash = info.context.get("task_definition_hash")
        status_hash = info.context.get("task_status_hash")
        known_task_ids = info.context.get("known_task_ids")
        if definition_hash is None and status_hash is None and known_task_ids is None:
            return self
        if not isinstance(definition_hash, str) or not isinstance(status_hash, str) or not isinstance(
            known_task_ids, tuple
        ):
            raise ValueError("Implementation Result requires complete Programmer validation context")
        if self.task_definition_hash.lower() != definition_hash.lower():
            raise ValueError("Implementation Result task definition hash does not match its input")
        if self.task_status_hash.lower() != status_hash.lower():
            raise ValueError("Implementation Result task status hash does not match its input")
        if any(task_id not in known_task_ids for task_id in self.completed_task_ids):
            raise ValueError("Completed task IDs must be known task IDs")
        return self

    @field_validator("changed_paths")
    @classmethod
    def validate_changed_paths(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for path in value:
            _validate_product_path(path)
        if len(set(value)) != len(value):
            raise ValueError("Changed paths must be unique")
        return value


class BuildIdentity(OutputContract):
    baseline_sha: _GIT_SHA
    product_manifest_hash: Sha256
    project_policy_hash: Sha256
    command_hashes: Mapping[_REFERENCE_ID, Sha256] = Field(max_length=128)
    runtime_hash: Sha256

    @field_validator("command_hashes")
    @classmethod
    def freeze_command_hashes(cls, value: Mapping[str, Sha256]) -> Mapping[str, Sha256]:
        for key in value:
            reject_unsafe_persisted_value(key)
        return MappingProxyType(dict(value))

    @field_serializer("command_hashes")
    def serialize_command_hashes(self, value: Mapping[str, Sha256]) -> dict[str, Sha256]:
        return dict(value)


_PRODUCT_MANIFEST_HASH_CONSTRUCTION_CONTEXT = object()


class ProductChangeFile(OutputContract):
    path: EvidencePath
    status: _GIT_CHANGE_STATUS
    old_path: EvidencePath | None
    old_mode: _GIT_MODE
    mode: _GIT_MODE
    old_object_id: _GIT_SHA | None
    object_id: _GIT_SHA | None
    binary: bool
    untracked: bool

    @field_validator("path", "old_path")
    @classmethod
    def validate_product_paths(cls, value: str | None) -> str | None:
        if value is not None:
            _validate_product_path(value)
        return value

    @model_validator(mode="after")
    def validate_change_metadata(self) -> ProductChangeFile:
        kind = self.status[0]
        requires_old_entry = kind != "A"
        requires_current_entry = kind != "D"

        if requires_old_entry != (self.old_mode != "000000" and self.old_object_id is not None):
            raise ValueError("Product change old mode and object ID do not match status")
        if requires_current_entry != (self.mode != "000000" and self.object_id is not None):
            raise ValueError("Product change mode and object ID do not match status")

        if kind in {"R", "C"}:
            if self.old_path is None:
                raise ValueError("Renamed and copied product changes require an old path")
            if self.old_path == self.path:
                raise ValueError("Renamed and copied product paths must differ")
        elif self.old_path is not None:
            raise ValueError("Only renamed and copied product changes may contain an old path")

        if self.untracked and kind != "A":
            raise ValueError("Untracked product changes must be additions")
        return self


class ProductChangeManifest(OutputContract):
    baseline_sha: _GIT_SHA
    files: tuple[ProductChangeFile, ...] = Field(min_length=1, max_length=512)
    content_hash: Sha256

    @model_validator(mode="after")
    def validate_hash_and_paths(self, info: ValidationInfo) -> ProductChangeManifest:
        if len({entry.path for entry in self.files}) != len(self.files):
            raise ValueError("Product manifest paths must be unique")
        if info.context is _PRODUCT_MANIFEST_HASH_CONSTRUCTION_CONTEXT:
            return self
        if self.content_hash.lower() != hash_json(self._content_payload()):
            raise ValueError("Product manifest hash does not match content")
        return self

    def _content_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", round_trip=True, exclude={"content_hash"})

    @classmethod
    def from_files(
        cls,
        baseline_sha: str,
        files: tuple[ProductChangeFile, ...],
    ) -> ProductChangeManifest:
        unchecked = cls.model_validate(
            {"baseline_sha": baseline_sha, "files": files, "content_hash": "0" * 64},
            context=_PRODUCT_MANIFEST_HASH_CONSTRUCTION_CONTEXT,
        )
        payload = unchecked._content_payload()
        return cls.model_validate({**payload, "content_hash": hash_json(payload)})


class VerificationCheck(OutputContract):
    command_id: _REFERENCE_ID
    command_hash: Sha256
    returncode: int
    failure_kind: _FAILURE_KIND | None
    stdout_evidence: EvidenceRef
    stderr_evidence: EvidenceRef

    @field_validator("command_id", "failure_kind")
    @classmethod
    def validate_command_identifiers(cls, value: str | None) -> str | None:
        if value is not None:
            reject_unsafe_persisted_value(value)
        return value


class VerificationResult(OutputContract):
    build_identity_hash: Sha256
    checks: tuple[VerificationCheck, ...] = Field(max_length=128)
    passed: bool
    empty_authorized: bool

    @model_validator(mode="after")
    def validate_checks(self, info: ValidationInfo) -> VerificationResult:
        if not self.checks and not self.empty_authorized:
            raise ValueError("Empty verification result is not authorized")
        if self.passed != all(check.returncode == 0 for check in self.checks):
            raise ValueError("Verification pass state does not match checks")

        if not isinstance(info.context, Mapping):
            return self
        build = info.context.get("build_identity")
        if build is None:
            return self
        if not isinstance(build, BuildIdentity):
            raise ValueError("Verification Result requires a Build Identity validation context")
        if self.build_identity_hash.lower() != hash_json(build.model_dump(mode="json", round_trip=True)).lower():
            raise ValueError("Verification Result Build Identity hash does not match its input")
        actual_commands = tuple((check.command_id, check.command_hash) for check in self.checks)
        if actual_commands != tuple(build.command_hashes.items()):
            raise ValueError("Verification checks must match complete ordered Build Identity commands")
        return self


class BrowserResultStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"
    SKIPPED = "skipped"


class BrowserScenarioStatus(StrEnum):
    PASSED = "passed"
    FAILED = "failed"


class BrowserScenarioObservation(ContractModel):
    scenario_id: _REFERENCE_ID
    status: BrowserScenarioStatus
    observation: _BOUNDED_TEXT
    evidence: tuple[EvidenceRef, ...] = Field(min_length=1, max_length=16)

    @field_validator("scenario_id")
    @classmethod
    def validate_identifier(cls, value: str) -> str:
        return reject_unsafe_persisted_value(value)


class BrowserResult(OutputContract):
    status: BrowserResultStatus
    browser_e2e_decision_hash: Sha256
    build_identity_hash: Sha256
    reason: _BOUNDED_TEXT
    scenario_observations: tuple[BrowserScenarioObservation, ...] = Field(max_length=64)
    evidence: tuple[EvidenceRef, ...] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def validate_observations(self) -> BrowserResult:
        observations = self.scenario_observations
        if len({observation.scenario_id for observation in observations}) != len(observations):
            raise ValueError("Browser scenario observations must be unique")
        if self.status is BrowserResultStatus.SKIPPED:
            if observations:
                raise ValueError("Skipped Browser Result must not include scenario observations")
        elif not observations:
            raise ValueError("Browser Result requires scenario observations")
        elif self.status is BrowserResultStatus.PASSED and any(
            observation.status is not BrowserScenarioStatus.PASSED for observation in observations
        ):
            raise ValueError("Passed Browser Result cannot contain failed scenario observations")
        elif self.status is BrowserResultStatus.FAILED and not any(
            observation.status is BrowserScenarioStatus.FAILED for observation in observations
        ):
            raise ValueError("Failed Browser Result requires a failed scenario observation")
        return self

    @model_validator(mode="after")
    def validate_tester_context(self, info: ValidationInfo) -> BrowserResult:
        if not isinstance(info.context, Mapping):
            return self
        decision = info.context.get("browser_e2e_decision")
        build = info.context.get("build_identity")
        if decision is None and build is None:
            return self
        if not isinstance(decision, BrowserE2EDecision) or not isinstance(build, BuildIdentity):
            raise ValueError("Browser Result requires complete Tester validation context")
        if self.browser_e2e_decision_hash.lower() != hash_json(decision.model_dump(mode="json", round_trip=True)).lower():
            raise ValueError("Browser Result decision hash does not match declared Browser E2E decision")
        if self.build_identity_hash.lower() != hash_json(build.model_dump(mode="json", round_trip=True)).lower():
            raise ValueError("Browser Result Build Identity hash does not match its input")
        expected_ids = {scenario.scenario_id for scenario in decision.scenarios}
        actual_ids = {observation.scenario_id for observation in self.scenario_observations}
        if decision.required:
            if self.status is BrowserResultStatus.SKIPPED:
                raise ValueError("Required Browser E2E decision cannot be skipped")
            if actual_ids != expected_ids:
                raise ValueError("Browser Result scenario IDs do not match declared Browser E2E decision")
        else:
            if self.status is not BrowserResultStatus.SKIPPED:
                raise ValueError("Optional Browser E2E decision must be skipped")
            if self.reason != decision.reason:
                raise ValueError("Skipped Browser Result must use the declared reason")
        return self


class ReviewManifest(OutputContract):
    baseline_sha: _GIT_SHA
    requirements_package_hash: Sha256
    change_outline_hash: Sha256
    artifact_hashes: Mapping[_REFERENCE_ID, Sha256] = Field(min_length=1, max_length=128)
    task_definition_hash: Sha256
    task_status_hash: Sha256
    product_manifest_hash: Sha256
    build_identity_hash: Sha256
    project_policy_hash: Sha256
    verification_result_hash: Sha256
    browser_result_hash: Sha256

    @field_validator("artifact_hashes")
    @classmethod
    def freeze_artifact_hashes(cls, value: Mapping[str, Sha256]) -> Mapping[str, Sha256]:
        for key in value:
            reject_unsafe_persisted_value(key)
        return MappingProxyType(dict(value))

    @field_serializer("artifact_hashes")
    def serialize_artifact_hashes(self, value: Mapping[str, Sha256]) -> dict[str, Sha256]:
        return dict(value)

    @property
    def content_hash(self) -> str:
        return hash_json(self.model_dump(mode="json", round_trip=True))


class ReviewResult(OutputContract):
    approved: bool
    review_manifest_hash: Sha256
    failure_class: FailureClass | None = None
    failure_source: FailureSource | None = None
    finding_kind: FindingKind | None = None
    owner_stage: Stage | None = None
    cited_ids: tuple[_REFERENCE_ID, ...] = Field(max_length=128)
    blocking_findings: tuple[_BOUNDED_TEXT, ...] = Field(max_length=64)
    evidence: tuple[EvidenceRef, ...] = Field(max_length=64)
    next_action: _BOUNDED_TEXT

    @field_validator("cited_ids")
    @classmethod
    def validate_cited_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for identifier in value:
            reject_unsafe_persisted_value(identifier)
        if len(set(value)) != len(value):
            raise ValueError("Cited IDs must be unique")
        return value

    @model_validator(mode="after")
    def validate_review(self, info: ValidationInfo) -> ReviewResult:
        failure_values = (self.failure_class, self.failure_source, self.finding_kind, self.owner_stage)
        if self.approved:
            if any(value is not None for value in failure_values):
                raise ValueError("Approved Review Result cannot report a failure")
            if self.blocking_findings:
                raise ValueError("Approved Review Result cannot contain blocking findings")
        elif any(value is None for value in failure_values):
            raise ValueError("Rejected Review Result requires failure classification and ownership")
        elif not self.blocking_findings:
            raise ValueError("Rejected Review Result requires blocking findings")

        expected = None
        if isinstance(info.context, Mapping):
            expected = info.context.get("review_manifest_hash")
        if expected is not None and self.review_manifest_hash.lower() != str(expected).lower():
            raise ValueError("Review Result review manifest hash does not match its input manifest")
        return self


class ValidationIssue(ContractModel):
    location: tuple[_REFERENCE_ID, ...] = Field(min_length=1, max_length=16)
    message: _SHORT_TEXT
    error_type: Annotated[str, StringConstraints(max_length=128, pattern=_SAFE_IDENTIFIER)]

    @field_validator("location")
    @classmethod
    def validate_location(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for part in value:
            reject_unsafe_persisted_value(part)
        return value


class InvalidUnitOutput(OutputContract):
    stage: Stage
    output_hash: Sha256
    validation_errors: tuple[ValidationIssue, ...] = Field(min_length=1, max_length=32)

    @model_validator(mode="after")
    def validate_cognitive_stage(self) -> InvalidUnitOutput:
        if self.stage is Stage.VERIFICATION:
            raise ValueError("Verification is not a model-authored unit")
        return self


def sanitize_validation_errors(error: ValidationError) -> tuple[ValidationIssue, ...]:
    """Retain bounded validator metadata without retaining model-authored input."""

    issues: list[ValidationIssue] = []
    for detail in error.errors(include_url=False)[:32]:
        location = tuple(_sanitize_error_location(part) for part in detail.get("loc", ())) or ("root",)
        message = _sanitize_error_message(str(detail.get("msg", "Validation failed")))
        error_type = _sanitize_error_type(str(detail.get("type", "validation_error")))
        issues.append(ValidationIssue(location=location, message=message, error_type=error_type))
    if not issues:
        issues.append(ValidationIssue(location=("root",), message="Validation failed", error_type="validation_error"))
    return tuple(issues)


def hash_invalid_output(error: ValidationError) -> str:
    return hash_json([issue.model_dump(mode="json") for issue in sanitize_validation_errors(error)])


def _validate_product_path(value: str) -> str:
    reject_unsafe_persisted_value(value)
    if any(part in _SENSITIVE_PATH_PARTS or part.startswith(".env") for part in value.split("/")):
        raise ValueError("Product paths cannot reference state, Git, or secret files")
    return value


def _sanitize_error_location(value: object) -> str:
    candidate = str(value)
    if re.fullmatch(_SAFE_REFERENCE_SEGMENT, candidate) and not _looks_sensitive(candidate):
        return candidate
    return "invalid"


def _sanitize_error_message(value: str) -> str:
    candidate = value.strip()
    if not candidate or _looks_sensitive(candidate):
        return "Validation failed"
    return candidate[:512]


def _sanitize_error_type(value: str) -> str:
    candidate = value.strip().lower().replace("-", "_")
    if re.fullmatch(_SAFE_IDENTIFIER, candidate):
        return candidate
    return "validation_error"


def _looks_sensitive(value: str) -> bool:
    return bool(
        _JWT_LIKE_SEGMENT.search(value)
        or _CREDENTIAL_LIKE_SEGMENT.search(value)
        or _SECRET_ASSIGNMENT.search(value)
        or _BEARER_SECRET.search(value)
        or _INSTRUCTION_LIKE_VALUE.search(value)
    )


_URL_IN_TEXT = re.compile(
    r"(?:(?<![A-Za-z0-9])//|\b(?:[a-z][a-z0-9+.-]*://|mailto:))[^\s<>()\[\]{}\"']+",
    re.IGNORECASE,
)
_BEARER_SECRET = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{8,}")
_SECRET_LITERAL = re.compile(r"(?i)\bsk-[A-Za-z0-9_-]{8,}\b")
_MAX_UNTRUSTED_TEXT = 1_048_576
_MAX_UNTRUSTED_ITEMS = 512


class IdentityResolutionError(ValueError):
    pass


class TicketProjectionTooLargeError(ValueError):
    pass


_TICKET_HASH_CONSTRUCTION_CONTEXT = object()


def sanitize_url(value: str) -> str:
    """Remove URL credentials and volatile query/fragment data before persistence."""

    if not isinstance(value, str):
        raise ValueError("URL must be text")
    try:
        parsed = urlsplit(value)
        if not parsed.scheme and not parsed.netloc:
            return value
        scheme = parsed.scheme.lower()
        if not parsed.hostname:
            return urlunsplit((scheme, "", parsed.path, "", ""))
        hostname = parsed.hostname
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        netloc = hostname
        if parsed.port is not None:
            netloc = f"{netloc}:{parsed.port}"
        return urlunsplit((scheme, netloc, parsed.path, "", ""))
    except (TypeError, ValueError):
        return "[REDACTED]"


def sanitize_untrusted_text(value: str) -> str:
    """Keep requirement text while removing credentials and URL-sensitive components."""

    if not isinstance(value, str) or len(value) > _MAX_UNTRUSTED_TEXT:
        raise ValueError("Untrusted text is invalid")

    def replace_url(match: re.Match[str]) -> str:
        return sanitize_url(match.group(0))

    sanitized = _URL_IN_TEXT.sub(replace_url, value)
    sanitized = _SECRET_ASSIGNMENT.sub("[REDACTED]", sanitized)
    sanitized = _BEARER_SECRET.sub("[REDACTED]", sanitized)
    sanitized = _SECRET_LITERAL.sub("[REDACTED]", sanitized)
    sanitized = _JWT_LIKE_SEGMENT.sub("[REDACTED]", sanitized)
    return sanitized


def sanitize_untrusted_value(value: object, *, depth: int = 0) -> object:
    """Convert untrusted JSON-like input into a bounded, redacted value."""

    if depth > 32:
        raise ValueError("Untrusted data is too deeply nested")
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if value != value or value in {float("inf"), float("-inf")}:
            raise ValueError("Untrusted numeric data is invalid")
        return value
    if isinstance(value, str):
        return sanitize_untrusted_text(value)
    if isinstance(value, Mapping):
        if len(value) > _MAX_UNTRUSTED_ITEMS:
            raise ValueError("Untrusted mapping is too large")
        normalized: dict[str, object] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("Untrusted mapping keys must be text")
            clean_key = sanitize_untrusted_text(key)
            if clean_key in normalized:
                raise ValueError("Untrusted mapping contains duplicate keys")
            normalized[clean_key] = (
                "[REDACTED]" if _is_secret_mapping_key(clean_key) else sanitize_untrusted_value(item, depth=depth + 1)
            )
        return normalized
    if isinstance(value, (list, tuple)):
        if len(value) > _MAX_UNTRUSTED_ITEMS:
            raise ValueError("Untrusted collection is too large")
        return [sanitize_untrusted_value(item, depth=depth + 1) for item in value]
    raise ValueError("Untrusted data must be JSON-like")


def _is_secret_mapping_key(value: str) -> bool:
    normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", value).lower()
    return _SECRET_MAPPING_KEY.search(normalized) is not None


def _freeze_json(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType({str(key): _freeze_json(item) for key, item in value.items()})
    if isinstance(value, list):
        return tuple(_freeze_json(item) for item in value)
    if isinstance(value, tuple):
        return tuple(_freeze_json(item) for item in value)
    return value


def _thaw_json(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _thaw_json(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw_json(item) for item in value]
    return value


def _safe_snapshot_identifier(value: object, field: str, *, required: bool = True) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or not value or len(value) > 256 or "\x00" in value:
        raise ValueError(f"{field} must be a safe identifier")
    try:
        reject_unsafe_persisted_value(value)
    except ValueError as error:
        raise ValueError(f"{field} must be a safe identifier") from error
    return value


class IdentityResolutionStatus(StrEnum):
    RESOLVED = "resolved"
    NOT_FOUND = "not_found"
    AMBIGUOUS = "ambiguous"


class IdentityResolution(ContractModel):
    status: IdentityResolutionStatus
    resolved_id: str | None = None
    candidate_ids: tuple[str, ...] = Field(default=(), max_length=64)

    @field_validator("resolved_id")
    @classmethod
    def validate_resolved_id(cls, value: str | None) -> str | None:
        return _safe_snapshot_identifier(value, "Resolved identity", required=False)

    @field_validator("candidate_ids")
    @classmethod
    def validate_candidate_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        for identifier in value:
            _safe_snapshot_identifier(identifier, "Candidate identity")
        if len(set(value)) != len(value):
            raise ValueError("Candidate identities must be unique")
        return value

    @model_validator(mode="after")
    def validate_resolution(self) -> IdentityResolution:
        if self.status is IdentityResolutionStatus.RESOLVED:
            if self.resolved_id is None or self.candidate_ids:
                raise ValueError("Resolved identity must contain exactly one ID")
        elif self.status is IdentityResolutionStatus.NOT_FOUND:
            if self.resolved_id is not None or self.candidate_ids:
                raise ValueError("Not-found identity cannot contain IDs")
        elif self.resolved_id is not None or len(self.candidate_ids) < 2:
            raise ValueError("Ambiguous identity requires multiple candidate IDs")
        return self

    @classmethod
    def resolved(cls, identifier: str) -> IdentityResolution:
        return cls(status=IdentityResolutionStatus.RESOLVED, resolved_id=identifier)

    @classmethod
    def not_found(cls) -> IdentityResolution:
        return cls(status=IdentityResolutionStatus.NOT_FOUND)

    @classmethod
    def ambiguous(cls, identifiers: tuple[str, ...]) -> IdentityResolution:
        return cls(status=IdentityResolutionStatus.AMBIGUOUS, candidate_ids=identifiers)

    def require_resolved(self, subject: str) -> str:
        if self.status is not IdentityResolutionStatus.RESOLVED or self.resolved_id is None:
            raise IdentityResolutionError(f"{subject} identity is not uniquely resolved")
        return self.resolved_id


class CandidateTicket(ContractModel):
    id: str
    state_type: Literal["unstarted"]
    assignee_id: str
    milestone_id: str
    priority: int | None = None
    created_at: datetime
    title: str = ""

    @field_validator("id", "assignee_id", "milestone_id")
    @classmethod
    def validate_candidate_identifiers(cls, value: str) -> str:
        validated = _safe_snapshot_identifier(value, "Candidate ticket")
        assert validated is not None
        return validated

    @field_validator("title", mode="before")
    @classmethod
    def sanitize_candidate_title(cls, value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("Candidate title must be text")
        return sanitize_untrusted_text(value)

    @field_validator("priority")
    @classmethod
    def validate_candidate_priority(cls, value: int | None) -> int | None:
        if value is not None and (isinstance(value, bool) or value <= 0):
            raise ValueError("Candidate priority must be positive or absent")
        return value


class TicketComment(ContractModel):
    comment_id: str | None = None
    text: str

    @field_validator("comment_id")
    @classmethod
    def validate_comment_id(cls, value: str | None) -> str | None:
        return _safe_snapshot_identifier(value, "Comment ID", required=False)

    @field_validator("text", mode="before")
    @classmethod
    def sanitize_comment_text(cls, value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("Comment text must be text")
        return sanitize_untrusted_text(value)


class TicketAttachment(ContractModel):
    name: str | None = None
    url: str | None = None
    media_type: str | None = None
    safe_text: str | None = None
    metadata: Mapping[str, Any] = Field(default_factory=dict)

    @field_validator("name", "media_type", "safe_text", mode="before")
    @classmethod
    def sanitize_attachment_text(cls, value: object) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("Attachment text must be text")
        return sanitize_untrusted_text(value)

    @field_validator("url", mode="before")
    @classmethod
    def sanitize_attachment_url(cls, value: object) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str):
            raise ValueError("Attachment URL must be text")
        return sanitize_url(value)

    @field_validator("metadata", mode="before")
    @classmethod
    def sanitize_attachment_metadata(cls, value: object) -> Mapping[str, Any]:
        sanitized = sanitize_untrusted_value(value)
        if not isinstance(sanitized, Mapping):
            raise ValueError("Attachment metadata must be an object")
        return sanitized

    @field_validator("metadata")
    @classmethod
    def freeze_attachment_metadata(cls, value: Mapping[str, Any]) -> Mapping[str, Any]:
        return _freeze_json(value)  # type: ignore[return-value]

    @field_serializer("metadata")
    def serialize_attachment_metadata(self, value: Mapping[str, Any]) -> object:
        return _thaw_json(value)


class TicketConstraintProjection(ContractModel):
    schema_version: Literal["v1"] = "v1"
    ticket_id: str
    title: str
    description: str
    criteria: tuple[str, ...] = Field(max_length=_MAX_UNTRUSTED_ITEMS)
    comments: tuple[TicketComment, ...] = Field(max_length=_MAX_UNTRUSTED_ITEMS)
    labels: tuple[str, ...] = Field(max_length=_MAX_UNTRUSTED_ITEMS)
    relations: tuple[Mapping[str, Any], ...] = Field(max_length=_MAX_UNTRUSTED_ITEMS)
    subtickets: tuple[Mapping[str, Any], ...] = Field(max_length=_MAX_UNTRUSTED_ITEMS)
    attachments: tuple[TicketAttachment, ...] = Field(max_length=_MAX_UNTRUSTED_ITEMS)
    content_hash: Sha256

    @field_validator("relations", "subtickets", mode="before")
    @classmethod
    def sanitize_projection_records(cls, value: object) -> tuple[Mapping[str, Any], ...]:
        if not isinstance(value, (list, tuple)):
            raise ValueError("Ticket records must be a collection")
        sanitized = tuple(sanitize_untrusted_value(item) for item in value)
        if any(not isinstance(item, Mapping) for item in sanitized):
            raise ValueError("Ticket records must be objects")
        return sanitized  # type: ignore[return-value]

    @field_validator("relations", "subtickets")
    @classmethod
    def freeze_projection_records(cls, value: tuple[Mapping[str, Any], ...]) -> tuple[Mapping[str, Any], ...]:
        return tuple(_freeze_json(item) for item in value)  # type: ignore[return-value]

    @field_serializer("relations", "subtickets")
    def serialize_projection_records(self, value: tuple[Mapping[str, Any], ...]) -> object:
        return [_thaw_json(item) for item in value]

    @model_validator(mode="after")
    def validate_content_hash(self, info: ValidationInfo) -> TicketConstraintProjection:
        if info.context is _TICKET_HASH_CONSTRUCTION_CONTEXT:
            return self
        if self.content_hash.lower() != hash_json(self._content_payload()):
            raise ValueError("Ticket constraint projection hash does not match content")
        return self

    def _content_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", round_trip=True, exclude={"content_hash"})

    @classmethod
    def from_snapshot(cls, snapshot: TicketSnapshot) -> TicketConstraintProjection:
        values: dict[str, object] = {
            "ticket_id": snapshot.ticket_id,
            "title": snapshot.title,
            "description": snapshot.description,
            "criteria": snapshot.criteria,
            "comments": snapshot.comments,
            "labels": snapshot.labels,
            "relations": snapshot.relations,
            "subtickets": snapshot.subtickets,
            "attachments": snapshot.attachments,
        }
        unchecked = cls.model_validate(
            {"content_hash": "0" * 64, **values},
            context=_TICKET_HASH_CONSTRUCTION_CONTEXT,
        )
        payload = unchecked._content_payload()
        return cls.model_validate({**payload, "content_hash": hash_json(payload)})


class AnalystTicketProjection(TicketConstraintProjection):
    def to_prompt_text(self, *, max_chars: int = 32_768) -> str:
        if not isinstance(max_chars, int) or isinstance(max_chars, bool) or max_chars <= 0:
            raise ValueError("Analyst projection limit must be positive")
        encoded = canonical_json_bytes(self.model_dump(mode="json", round_trip=True)).decode("ascii")
        if len(encoded) > max_chars:
            raise TicketProjectionTooLargeError("Ticket requirements exceed the Analyst projection bound")
        return encoded


class TicketSnapshot(ContractModel):
    schema_version: Literal["v1"] = "v1"
    ticket_id: str
    title: str
    description: str = ""
    criteria: tuple[str, ...] = Field(max_length=_MAX_UNTRUSTED_ITEMS)
    comments: tuple[TicketComment, ...] = Field(max_length=_MAX_UNTRUSTED_ITEMS)
    labels: tuple[str, ...] = Field(max_length=_MAX_UNTRUSTED_ITEMS)
    relations: tuple[Mapping[str, Any], ...] = Field(max_length=_MAX_UNTRUSTED_ITEMS)
    subtickets: tuple[Mapping[str, Any], ...] = Field(max_length=_MAX_UNTRUSTED_ITEMS)
    attachments: tuple[TicketAttachment, ...] = Field(max_length=_MAX_UNTRUSTED_ITEMS)
    workspace_id: str | None = None
    team_id: str | None = None
    captured_at: datetime
    pagination_complete: bool
    source_page_hashes: Mapping[str, Sha256] = Field(min_length=1, max_length=_MAX_UNTRUSTED_ITEMS)
    content_hash: Sha256

    @field_validator("ticket_id")
    @classmethod
    def validate_ticket_id(cls, value: str) -> str:
        validated = _safe_snapshot_identifier(value, "Ticket ID")
        assert validated is not None
        return validated

    @field_validator("workspace_id", "team_id")
    @classmethod
    def validate_optional_ticket_ids(cls, value: str | None) -> str | None:
        return _safe_snapshot_identifier(value, "Ticket metadata ID", required=False)

    @field_validator("title", "description", mode="before")
    @classmethod
    def sanitize_ticket_text(cls, value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("Ticket text must be text")
        return sanitize_untrusted_text(value)

    @field_validator("criteria", "labels", mode="before")
    @classmethod
    def sanitize_ticket_text_collections(cls, value: object) -> tuple[str, ...]:
        if not isinstance(value, (list, tuple)):
            raise ValueError("Ticket text collection must be a collection")
        if any(not isinstance(item, str) for item in value):
            raise ValueError("Ticket text collection must contain text")
        return tuple(sanitize_untrusted_text(item) for item in value)

    @field_validator("relations", "subtickets", mode="before")
    @classmethod
    def sanitize_ticket_records(cls, value: object) -> tuple[Mapping[str, Any], ...]:
        if not isinstance(value, (list, tuple)):
            raise ValueError("Ticket records must be a collection")
        sanitized = tuple(sanitize_untrusted_value(item) for item in value)
        if any(not isinstance(item, Mapping) for item in sanitized):
            raise ValueError("Ticket records must be objects")
        return sanitized  # type: ignore[return-value]

    @field_validator("relations", "subtickets")
    @classmethod
    def freeze_ticket_records(cls, value: tuple[Mapping[str, Any], ...]) -> tuple[Mapping[str, Any], ...]:
        return tuple(_freeze_json(item) for item in value)  # type: ignore[return-value]

    @field_serializer("relations", "subtickets")
    def serialize_ticket_records(self, value: tuple[Mapping[str, Any], ...]) -> object:
        return [_thaw_json(item) for item in value]

    @field_validator("source_page_hashes")
    @classmethod
    def freeze_source_page_hashes(cls, value: Mapping[str, Sha256]) -> Mapping[str, Sha256]:
        normalized: dict[str, Sha256] = {}
        for key, page_hash in value.items():
            validated = _safe_snapshot_identifier(key, "Source page ID")
            assert validated is not None
            normalized[validated] = page_hash.lower()
        if len(normalized) != len(value):
            raise ValueError("Source page IDs must be unique")
        return MappingProxyType(normalized)

    @field_serializer("source_page_hashes")
    def serialize_source_page_hashes(self, value: Mapping[str, Sha256]) -> dict[str, Sha256]:
        return dict(value)

    @field_validator("captured_at")
    @classmethod
    def validate_capture_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Ticket capture time must include a timezone")
        return value

    @model_validator(mode="after")
    def validate_content_hash(self, info: ValidationInfo) -> TicketSnapshot:
        if info.context is _TICKET_HASH_CONSTRUCTION_CONTEXT:
            return self
        if self.content_hash.lower() != hash_json(self._content_payload()):
            raise ValueError("Ticket Snapshot hash does not match content")
        return self

    def _content_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", round_trip=True, exclude={"content_hash"})

    @classmethod
    def from_untrusted(
        cls,
        raw: object,
        *,
        captured_at: datetime,
        pagination_complete: bool,
        source_page_hashes: Mapping[str, str],
    ) -> TicketSnapshot:
        if not isinstance(raw, Mapping):
            raise ValueError("Ticket source must be an object")
        title = raw.get("title")
        ticket_id = raw.get("id", raw.get("identifier"))
        if not isinstance(title, str) or not title.strip():
            raise ValueError("Ticket source lacks a title")
        values: dict[str, object] = {
            "ticket_id": ticket_id,
            "title": title,
            "description": raw.get("description", ""),
            "criteria": _snapshot_text_values(raw.get("criteria", raw.get("acceptance_criteria", ()))),
            "comments": _snapshot_comments(raw.get("comments", ())),
            "labels": _snapshot_labels(raw.get("labels", ())),
            "relations": _snapshot_records(raw.get("relations", ())),
            "subtickets": _snapshot_records(raw.get("subtickets", ())),
            "attachments": _snapshot_attachments(raw.get("attachments", ())),
            "workspace_id": raw.get("workspace_id"),
            "team_id": raw.get("team_id"),
            "captured_at": captured_at,
            "pagination_complete": pagination_complete,
            "source_page_hashes": source_page_hashes,
        }
        unchecked = cls.model_validate(
            {"content_hash": "0" * 64, **values},
            context=_TICKET_HASH_CONSTRUCTION_CONTEXT,
        )
        payload = unchecked._content_payload()
        return cls.model_validate({**payload, "content_hash": hash_json(payload)})

    def constraint_projection(self) -> TicketConstraintProjection:
        return TicketConstraintProjection.from_snapshot(self)

    def analyst_projection(self, *, max_chars: int = 32_768) -> AnalystTicketProjection:
        values: dict[str, object] = {
            "ticket_id": self.ticket_id,
            "title": self.title,
            "description": self.description,
            "criteria": self.criteria,
            "comments": self.comments,
            "labels": self.labels,
            "relations": self.relations,
            "subtickets": self.subtickets,
            "attachments": self.attachments,
        }
        unchecked = AnalystTicketProjection.model_validate(
            {"content_hash": "0" * 64, **values},
            context=_TICKET_HASH_CONSTRUCTION_CONTEXT,
        )
        payload = unchecked._content_payload()
        projection = AnalystTicketProjection.model_validate({**payload, "content_hash": hash_json(payload)})
        projection.to_prompt_text(max_chars=max_chars)
        return projection


def _snapshot_text_values(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("Ticket text collection must be a collection")
    values: list[str] = []
    for item in value:
        if isinstance(item, str):
            values.append(item)
        elif isinstance(item, Mapping):
            text = next((item.get(name) for name in ("text", "description", "title", "body") if isinstance(item.get(name), str)), None)
            if text is None:
                values.append(canonical_json_bytes(sanitize_untrusted_value(item)).decode("ascii"))
            else:
                values.append(text)
        else:
            raise ValueError("Ticket text collection must contain text")
    return tuple(values)


def _snapshot_comments(value: object) -> tuple[TicketComment, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("Ticket comments must be a collection")
    comments: list[TicketComment] = []
    for item in value:
        if isinstance(item, str):
            comments.append(TicketComment(text=item))
        elif isinstance(item, Mapping):
            text = next((item.get(name) for name in ("body", "text", "content", "description") if isinstance(item.get(name), str)), None)
            if text is None:
                text = canonical_json_bytes(sanitize_untrusted_value(item)).decode("ascii")
            comment_id = item.get("id")
            comments.append(TicketComment(comment_id=comment_id if isinstance(comment_id, str) else None, text=text))
        else:
            raise ValueError("Ticket comments must contain text or objects")
    return tuple(comments)


def _snapshot_labels(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("Ticket labels must be a collection")
    labels: list[str] = []
    for item in value:
        if isinstance(item, str):
            labels.append(item)
        elif isinstance(item, Mapping) and isinstance(item.get("name"), str):
            labels.append(item["name"])
        else:
            labels.append(canonical_json_bytes(sanitize_untrusted_value(item)).decode("ascii"))
    return tuple(labels)


def _snapshot_records(value: object) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("Ticket records must be a collection")
    records = tuple(sanitize_untrusted_value(item) for item in value)
    if any(not isinstance(item, Mapping) for item in records):
        raise ValueError("Ticket records must contain objects")
    return records  # type: ignore[return-value]


def _snapshot_attachments(value: object) -> tuple[TicketAttachment, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("Ticket attachments must be a collection")
    attachments: list[TicketAttachment] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise ValueError("Ticket attachments must contain objects")
        attachments.append(
            TicketAttachment(
                name=item.get("name") if isinstance(item.get("name"), str) else item.get("title"),
                url=item.get("url") if isinstance(item.get("url"), str) else None,
                media_type=item.get("media_type") if isinstance(item.get("media_type"), str) else item.get("mime_type"),
                safe_text=next(
                    (item.get(name) for name in ("text", "content", "description") if isinstance(item.get(name), str)),
                    None,
                ),
                metadata={str(key): value for key, value in item.items() if key not in {"url", "text", "content", "description"}},
            )
        )
    return tuple(attachments)


class Checkpoint(ContractModel):
    checkpoint_id: CheckpointId | None = None
    stage: Stage
    contract_hash: Sha256
    input_hashes: Mapping[Annotated[str, StringConstraints(max_length=256, pattern=_SAFE_REFERENCE_PATH)], Sha256]
    output_manifest_hash: Sha256
    validator: Annotated[str, StringConstraints(pattern=_SAFE_IDENTIFIER)]
    validator_version: Annotated[str, StringConstraints(max_length=256, pattern=_SAFE_REFERENCE_PATH)]
    validation_receipt_hash: Sha256
    evidence: tuple[EvidenceRef, ...] = ()

    @field_validator("input_hashes")
    @classmethod
    def freeze_input_hashes(cls, value: Mapping[str, Sha256]) -> Mapping[str, Sha256]:
        for key in value:
            reject_unsafe_persisted_value(key)
        return MappingProxyType(dict(value))

    @field_validator("validator", "validator_version")
    @classmethod
    def reject_unsafe_metadata(cls, value: str) -> str:
        return reject_unsafe_persisted_value(value)

    @field_serializer("input_hashes")
    def serialize_input_hashes(self, value: Mapping[str, Sha256]) -> dict[str, Sha256]:
        return dict(value)


class FailureRecord(ContractModel):
    failure_class: FailureClass
    failure_source: FailureSource
    finding_kind: FindingKind
    owner_stage: Stage | None = None
    cited_ids: tuple[str, ...] = ()
    evidence_refs: tuple[EvidenceRef, ...] = ()
    observed_revision: int | None = Field(default=None, ge=0)


class EffectEventKind(StrEnum):
    INTENTION = "intention"
    INVOCATION = "invocation"
    OBSERVATION = "observation"
    RECONCILIATION = "reconciliation"


class EffectOutcome(StrEnum):
    SUCCESS = "success"
    FAILURE = "failure"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    UNKNOWN = "unknown"


EffectOperation = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z][a-z0-9_]{0,63}$"),
]
EffectReference = Annotated[
    str,
    StringConstraints(max_length=256, pattern=_SAFE_REFERENCE_PATH),
]
EffectHash = Sha256


_UUID_PATTERN = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)


def _canonical_uuid(value: object, field: str) -> str:
    if not isinstance(value, str) or _UUID_PATTERN.fullmatch(value) is None:
        raise ValueError(f"{field} must be a canonical UUID")
    try:
        parsed = str(uuid.UUID(value))
    except ValueError as error:
        raise ValueError(f"{field} must be a canonical UUID") from error
    if parsed != value:
        raise ValueError(f"{field} must be a canonical UUID")
    return value


def _action_arguments(value: object) -> Mapping[str, Any]:
    _reject_action_secrets(value)
    sanitized = sanitize_untrusted_value(value)
    if not isinstance(sanitized, Mapping):
        raise ValueError("MCP action arguments must be an object")
    for item in _walk_json_values(sanitized):
        if isinstance(item, str) and _looks_sensitive(item):
            raise ValueError("MCP action arguments cannot contain secrets")
    return _freeze_json(sanitized)  # type: ignore[return-value]


def _reject_action_secrets(value: object, *, depth: int = 0) -> None:
    if depth > 32:
        raise ValueError("MCP action arguments are too deeply nested")
    if isinstance(value, str):
        if sanitize_untrusted_text(value) != value:
            raise ValueError("MCP action arguments cannot contain secrets")
        return
    if value is None or isinstance(value, (bool, int, float)):
        return
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("MCP action arguments must use text keys")
            _reject_action_secrets(key, depth=depth + 1)
            _reject_action_secrets(item, depth=depth + 1)
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _reject_action_secrets(item, depth=depth + 1)
        return
    raise ValueError("MCP action arguments must be JSON-like")


def _walk_json_values(value: object) -> tuple[object, ...]:
    values: list[object] = [value]
    if isinstance(value, Mapping):
        for key, item in value.items():
            values.extend(_walk_json_values(key))
            values.extend(_walk_json_values(item))
    elif isinstance(value, (list, tuple)):
        for item in value:
            values.extend(_walk_json_values(item))
    return tuple(values)


_TICKET_MCP_OPERATIONS = frozenset(
    {
        "query_ticket_projection",
        "query_ticket_state",
        "compare_and_start_ticket",
        "compare_and_complete_ticket",
        "restore_ticket_state",
    }
)


class McpActionRequest(ContractModel):
    """A fully bound request that must be persisted before bridge execution."""

    schema_version: Literal["v1"] = "v1"
    request_id: str
    effect_id: EffectReference
    effect_hash: EffectHash
    operation: EffectOperation
    entity: EffectReference
    target: EffectReference
    expected_external_revision: str | None = None
    run_id: EffectReference
    expected_revision: int = Field(ge=1)
    expected_state_hash: Sha256
    arguments: Mapping[str, Any] = Field(default_factory=dict)
    request_hash: EffectHash

    @field_validator("request_id")
    @classmethod
    def validate_request_id(cls, value: str) -> str:
        return _canonical_uuid(value, "MCP request ID")

    @field_validator("effect_id", "entity", "target", "run_id")
    @classmethod
    def validate_request_references(cls, value: str) -> str:
        return reject_unsafe_persisted_value(value)

    @field_validator("expected_external_revision")
    @classmethod
    def validate_external_revision(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not value or len(value) > 256 or _looks_sensitive(value):
            raise ValueError("Expected external revision is invalid")
        return value

    @field_validator("effect_hash", "expected_state_hash", "request_hash")
    @classmethod
    def normalize_request_hashes(cls, value: str) -> str:
        return value.lower()

    @field_validator("arguments", mode="before")
    @classmethod
    def validate_action_arguments(cls, value: object) -> Mapping[str, Any]:
        return _action_arguments(value)

    @field_validator("arguments")
    @classmethod
    def freeze_action_arguments(cls, value: Mapping[str, Any]) -> Mapping[str, Any]:
        return _freeze_json(value)  # type: ignore[return-value]

    @field_serializer("arguments")
    def serialize_action_arguments(self, value: Mapping[str, Any]) -> object:
        return _thaw_json(value)

    @model_validator(mode="after")
    def validate_request_hashes(self) -> McpActionRequest:
        self.validated_ticket_target()
        if self.effect_hash != hash_json(self._effect_payload()):
            raise ValueError("MCP action effect hash does not match content")
        if self.request_hash != hash_json(self._request_payload()):
            raise ValueError("MCP action request hash does not match content")
        return self

    def validated_ticket_target(self) -> str | None:
        if self.operation not in _TICKET_MCP_OPERATIONS:
            return None
        ticket_id = self.arguments.get("ticket_id")
        if self.entity != "ticket" or not isinstance(ticket_id, str) or ticket_id != self.target:
            raise ValueError("MCP ticket target does not match ticket_id")
        return ticket_id

    @classmethod
    def snapshot(cls, value: object) -> McpActionRequest:
        """Return a fully revalidated request detached from caller-owned mappings."""
        if not isinstance(value, McpActionRequest):
            raise ValueError("MCP action request is invalid")
        try:
            return cls.model_validate(value.model_dump(round_trip=True))
        except ValidationError as error:
            if any(
                str(item.get("ctx", {}).get("error")) == "MCP ticket target does not match ticket_id"
                for item in error.errors(include_input=False)
            ):
                raise ValueError("MCP ticket target is invalid") from None
            raise ValueError("MCP action request is invalid") from None
        except Exception:
            raise ValueError("MCP action request is invalid") from None

    def _effect_payload(self) -> dict[str, object]:
        return {
            "effect_id": self.effect_id,
            "operation": self.operation,
            "entity": self.entity,
            "target": self.target,
            "expected_external_revision": self.expected_external_revision,
            "arguments": _thaw_json(self.arguments),
        }

    def _request_payload(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "effect_id": self.effect_id,
            "effect_hash": self.effect_hash,
            "operation": self.operation,
            "entity": self.entity,
            "target": self.target,
            "expected_external_revision": self.expected_external_revision,
            "run_id": self.run_id,
            "expected_revision": self.expected_revision,
            "expected_state_hash": self.expected_state_hash,
            "arguments": _thaw_json(self.arguments),
        }

    @property
    def payload_hash(self) -> str:
        return hash_json(_thaw_json(self.arguments))

    @classmethod
    def create(
        cls,
        *,
        operation: str,
        entity: str,
        target: str,
        expected_external_revision: str | None,
        run_id: str,
        expected_revision: int,
        expected_state_hash: str,
        arguments: Mapping[str, Any],
        effect_id: str | None = None,
    ) -> McpActionRequest:
        request_id = str(uuid.uuid4())
        action_effect_id = effect_id or f"linear-{operation}-{uuid.uuid4().hex}"
        effect_payload = {
            "effect_id": action_effect_id,
            "operation": operation,
            "entity": entity,
            "target": target,
            "expected_external_revision": expected_external_revision,
            "arguments": _thaw_json(_action_arguments(arguments)),
        }
        effect_hash = hash_json(effect_payload)
        request_payload = {
            "schema_version": "v1",
            "request_id": request_id,
            "effect_id": action_effect_id,
            "effect_hash": effect_hash,
            "operation": operation,
            "entity": entity,
            "target": target,
            "expected_external_revision": expected_external_revision,
            "run_id": run_id,
            "expected_revision": expected_revision,
            "expected_state_hash": expected_state_hash.lower(),
            "arguments": _thaw_json(_action_arguments(arguments)),
        }
        return cls(
            **request_payload,
            request_hash=hash_json(request_payload),
        )


class TrustedMcpReceipt(ContractModel):
    schema_version: Literal["v1"] = "v1"
    receipt_id: str
    request_id: str
    effect_id: EffectReference
    effect_hash: EffectHash
    request_hash: EffectHash
    operation: EffectOperation
    target: EffectReference
    run_id: EffectReference
    expected_revision: int = Field(ge=1)
    expected_state_hash: Sha256
    expected_external_revision: str | None = None
    payload_hash: Sha256
    result_hash: Sha256
    outcome: EffectOutcome
    external_revision: str | None = None
    bridge_identity: EffectReference
    mcp_server_identity: EffectReference
    tool_call_id: EffectReference
    observed_at: datetime
    observations: tuple[str, ...] = Field(max_length=32)
    relative_path: EvidencePath
    bridge_signature: str | None = None

    @field_validator("receipt_id", "request_id")
    @classmethod
    def validate_receipt_uuids(cls, value: str) -> str:
        return _canonical_uuid(value, "Trusted MCP receipt ID")

    @field_validator(
        "effect_id",
        "operation",
        "target",
        "run_id",
        "bridge_identity",
        "mcp_server_identity",
        "tool_call_id",
    )
    @classmethod
    def validate_receipt_references(cls, value: str) -> str:
        return reject_unsafe_persisted_value(value)

    @field_validator(
        "effect_hash",
        "request_hash",
        "expected_state_hash",
        "payload_hash",
        "result_hash",
    )
    @classmethod
    def normalize_receipt_hashes(cls, value: str) -> str:
        return value.lower()

    @field_validator("expected_external_revision", "external_revision")
    @classmethod
    def validate_receipt_revision(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not value or len(value) > 256 or _looks_sensitive(value):
            raise ValueError("Receipt revision is invalid")
        return value

    @field_validator("observations", mode="before")
    @classmethod
    def sanitize_receipt_observations(cls, value: object) -> tuple[str, ...]:
        if not isinstance(value, (list, tuple)):
            raise ValueError("Receipt observations must be a collection")
        observations = tuple(sanitize_untrusted_text(item) for item in value if isinstance(item, str))
        if len(observations) != len(value) or any(len(item) > 1_024 for item in observations):
            raise ValueError("Receipt observations are invalid")
        return observations

    @field_validator("relative_path")
    @classmethod
    def validate_receipt_path(cls, value: str) -> str:
        if not value.startswith("trusted-mcp/receipts/"):
            raise ValueError("Receipt must use a trusted bridge path")
        return value

    @field_validator("bridge_signature")
    @classmethod
    def validate_bridge_signature(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("Bridge signature is invalid")
        return value

    @field_validator("observed_at")
    @classmethod
    def validate_observed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Receipt timestamp must include a timezone")
        return value

    def signed_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", round_trip=True, exclude={"bridge_signature"})

    @property
    def content_hash(self) -> str:
        return hash_json(self.model_dump(mode="json", round_trip=True))


class PreparationBridgeAttestation(ContractModel):
    """Bridge provenance duplicated in a typed preparation input."""

    bridge_identity: EffectReference
    mcp_server_identity: EffectReference
    tool_call_id: EffectReference
    captured_at: datetime

    @field_validator("bridge_identity", "mcp_server_identity", "tool_call_id")
    @classmethod
    def validate_attestation_references(cls, value: str) -> str:
        return reject_unsafe_persisted_value(value)

    @field_validator("captured_at")
    @classmethod
    def validate_attestation_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Preparation attestation timestamp must include a timezone")
        return value


class PreparationInput(ContractModel):
    """The bridge-written, challenge-free input for ticket preparation."""

    schema_version: Literal["v1"] = "v1"
    repository_id: EffectReference
    max_crew_iterations: int = Field(gt=0)
    assignee_resolution: IdentityResolution
    milestone_resolution: IdentityResolution
    pages: tuple[Mapping[str, Any], ...] = Field(max_length=_MAX_UNTRUSTED_ITEMS)
    page_hashes: Mapping[str, Sha256] = Field(max_length=_MAX_UNTRUSTED_ITEMS)
    workflow_states: Mapping[str, EffectReference] = Field(min_length=1, max_length=_MAX_UNTRUSTED_ITEMS)
    bridge_attestation: PreparationBridgeAttestation

    @field_validator("repository_id")
    @classmethod
    def validate_preparation_repository(cls, value: str) -> str:
        return reject_unsafe_persisted_value(value)

    @field_validator("pages", mode="before")
    @classmethod
    def sanitize_preparation_pages(cls, value: object) -> tuple[Mapping[str, Any], ...]:
        if not isinstance(value, (list, tuple)):
            raise ValueError("Preparation pages must be a collection")
        pages = tuple(sanitize_untrusted_value(page) for page in value)
        if any(not isinstance(page, Mapping) for page in pages):
            raise ValueError("Preparation pages must contain objects")
        return pages  # type: ignore[return-value]

    @field_validator("pages")
    @classmethod
    def freeze_preparation_pages(cls, value: tuple[Mapping[str, Any], ...]) -> tuple[Mapping[str, Any], ...]:
        return tuple(_freeze_json(page) for page in value)  # type: ignore[return-value]

    @field_serializer("pages")
    def serialize_preparation_pages(self, value: tuple[Mapping[str, Any], ...]) -> object:
        return [_thaw_json(page) for page in value]

    @field_validator("page_hashes")
    @classmethod
    def freeze_preparation_page_hashes(cls, value: Mapping[str, Sha256]) -> Mapping[str, Sha256]:
        normalized: dict[str, Sha256] = {}
        for key, page_hash in value.items():
            validated = _safe_snapshot_identifier(key, "Preparation page ID")
            assert validated is not None
            normalized[validated] = page_hash.lower()
        return MappingProxyType(normalized)

    @field_serializer("page_hashes")
    def serialize_preparation_page_hashes(self, value: Mapping[str, Sha256]) -> dict[str, Sha256]:
        return dict(value)

    @field_validator("workflow_states")
    @classmethod
    def freeze_workflow_states(cls, value: Mapping[str, EffectReference]) -> Mapping[str, EffectReference]:
        normalized: dict[str, EffectReference] = {}
        for key, state_id in value.items():
            validated = _safe_snapshot_identifier(key, "Workflow state")
            assert validated is not None
            normalized[validated] = reject_unsafe_persisted_value(state_id)
        return MappingProxyType(normalized)

    @field_serializer("workflow_states")
    def serialize_workflow_states(self, value: Mapping[str, EffectReference]) -> dict[str, EffectReference]:
        return dict(value)

    @model_validator(mode="after")
    def validate_page_hashes(self) -> PreparationInput:
        expected = {
            f"page-{index}": hash_json(_thaw_json(page))
            for index, page in enumerate(self.pages, start=1)
        }
        if dict(self.page_hashes) != expected:
            raise ValueError("Preparation input page hashes do not match the typed pages")
        return self


class TrustedPreparationInputRef(ContractModel):
    schema_version: Literal["v1"] = "v1"
    input_id: str
    relative_path: EvidencePath
    repository_id: EffectReference
    reservation_id: EffectReference
    challenge_hash: Sha256
    input_hash: Sha256
    query_hash: Sha256
    payload_hash: Sha256
    result_hash: Sha256
    source_page_hashes: Mapping[str, Sha256] = Field(max_length=_MAX_UNTRUSTED_ITEMS)
    pagination_complete: bool
    max_crew_iterations: int = Field(gt=0)
    bridge_identity: EffectReference
    mcp_server_identity: EffectReference
    tool_call_id: EffectReference
    captured_at: datetime
    observations: tuple[str, ...] = Field(max_length=32)
    bridge_signature: str | None = None

    @field_validator("input_id")
    @classmethod
    def validate_preparation_uuid(cls, value: str) -> str:
        return _canonical_uuid(value, "Trusted preparation input ID")

    @field_validator("relative_path")
    @classmethod
    def validate_preparation_path(cls, value: str) -> str:
        if not value.startswith("trusted-mcp/preparation/"):
            raise ValueError("Preparation input must use a trusted bridge path")
        return value

    @field_validator("challenge_hash", "input_hash", "query_hash", "payload_hash", "result_hash")
    @classmethod
    def normalize_preparation_hashes(cls, value: str) -> str:
        return value.lower()

    @field_validator("source_page_hashes")
    @classmethod
    def freeze_preparation_hashes(cls, value: Mapping[str, Sha256]) -> Mapping[str, Sha256]:
        normalized: dict[str, Sha256] = {}
        for key, page_hash in value.items():
            validated = _safe_snapshot_identifier(key, "Preparation page ID")
            assert validated is not None
            normalized[validated] = page_hash.lower()
        return MappingProxyType(normalized)

    @field_serializer("source_page_hashes")
    def serialize_preparation_hashes(self, value: Mapping[str, Sha256]) -> dict[str, Sha256]:
        return dict(value)

    @field_validator("repository_id", "reservation_id", "bridge_identity", "mcp_server_identity", "tool_call_id")
    @classmethod
    def validate_preparation_references(cls, value: str) -> str:
        return reject_unsafe_persisted_value(value)

    @field_validator("captured_at")
    @classmethod
    def validate_preparation_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Preparation timestamp must include a timezone")
        return value

    @field_validator("observations", mode="before")
    @classmethod
    def sanitize_preparation_observations(cls, value: object) -> tuple[str, ...]:
        if not isinstance(value, (list, tuple)):
            raise ValueError("Preparation observations must be a collection")
        observations = tuple(sanitize_untrusted_text(item) for item in value if isinstance(item, str))
        if len(observations) != len(value) or any(len(item) > 1_024 for item in observations):
            raise ValueError("Preparation observations are invalid")
        return observations

    @field_validator("bridge_signature")
    @classmethod
    def validate_preparation_signature(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("Bridge signature is invalid")
        return value

    def signed_payload(self) -> dict[str, object]:
        return self.model_dump(mode="json", round_trip=True, exclude={"bridge_signature"})

    @property
    def content_hash(self) -> str:
        return hash_json(self.model_dump(mode="json", round_trip=True))


def preparation_input_envelope_hash(reference: TrustedPreparationInputRef, preparation_input: PreparationInput) -> str:
    """Hash the canonical trusted envelope without its self-authenticating fields."""

    return hash_json(
        {
            "reference": reference.model_dump(
                mode="json",
                round_trip=True,
                exclude={"input_hash", "bridge_signature"},
            ),
            "input": preparation_input.model_dump(mode="json", round_trip=True),
        }
    )


class EffectIntentionPayload(ContractModel):
    operation: EffectOperation
    target: EffectReference
    request_hash: EffectHash

    @field_validator("operation", "target", "request_hash")
    @classmethod
    def reject_secret_like_values(cls, value: str) -> str:
        return reject_unsafe_persisted_value(value)


class EffectInvocationPayload(ContractModel):
    wait_seconds: float = Field(default=0, ge=0)


class EffectObservationPayload(ContractModel):
    outcome: EffectOutcome
    external_revision: str | None = None
    evidence_refs: tuple[EvidenceRef, ...] = ()

    @field_validator("external_revision")
    @classmethod
    def reject_secret_like_values(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not value or len(value) > 256 or _looks_sensitive(value):
            raise ValueError("External revision is invalid")
        return reject_unsafe_persisted_value(value)


class EffectReconciliationPayload(ContractModel):
    outcome: EffectOutcome
    evidence_refs: tuple[EvidenceRef, ...] = ()
    receipt_hash: Sha256 | None = None

    @field_validator("receipt_hash")
    @classmethod
    def normalize_receipt_hash(cls, value: str | None) -> str | None:
        return value.lower() if value is not None else None


class EffectEventBase(ContractModel):
    effect_id: EffectReference
    sequence: int = Field(gt=0)
    timestamp: datetime

    @field_validator("effect_id")
    @classmethod
    def reject_secret_like_values(cls, value: str) -> str:
        return reject_unsafe_persisted_value(value)


class EffectIntention(EffectEventBase):
    kind: Literal[EffectEventKind.INTENTION] = EffectEventKind.INTENTION
    payload: EffectIntentionPayload


class EffectInvocation(EffectEventBase):
    kind: Literal[EffectEventKind.INVOCATION] = EffectEventKind.INVOCATION
    payload: EffectInvocationPayload


class EffectObservation(EffectEventBase):
    kind: Literal[EffectEventKind.OBSERVATION] = EffectEventKind.OBSERVATION
    payload: EffectObservationPayload


class EffectReconciliation(EffectEventBase):
    kind: Literal[EffectEventKind.RECONCILIATION] = EffectEventKind.RECONCILIATION
    payload: EffectReconciliationPayload


EffectEvent: TypeAlias = Annotated[
    EffectIntention | EffectInvocation | EffectObservation | EffectReconciliation,
    Field(discriminator="kind"),
]


class TaskDefinition(ContractModel):
    task_id: str
    text: str


class TaskDefinitionManifest(ContractModel):
    definition_hash: Sha256
    tasks: tuple[TaskDefinition, ...]

    @model_validator(mode="after")
    def unique_task_ids(self) -> TaskDefinitionManifest:
        if len({task.task_id for task in self.tasks}) != len(self.tasks):
            raise ValueError("Task definition IDs must be unique")
        if self.definition_hash != canonical_task_definition_hash(self.tasks):
            raise ValueError("Task definition hash does not match canonical task content")
        return self


class TaskStatus(ContractModel):
    task_id: str
    status: UnitStatus


class TaskStatusManifest(ContractModel):
    definition_hash: Sha256
    statuses: tuple[TaskStatus, ...]

    @model_validator(mode="after")
    def unique_task_ids(self) -> TaskStatusManifest:
        if len({status.task_id for status in self.statuses}) != len(self.statuses):
            raise ValueError("Task status IDs must be unique")
        return self


class HumanAuthorizationAction(StrEnum):
    RESUME = "resume"
    ABANDON = "abandon"


class HumanAuthorization(ContractModel):
    authorization_id: str
    action: HumanAuthorizationAction
    run_id: str
    challenge: str
    actor: str
    reason: str
    issued_at: datetime
    expires_at: datetime
    key_id: str
    signature: str
    additional_iterations: int = Field(default=0, ge=0)
    consumed_at: datetime | None = None

    @model_validator(mode="after")
    def validate_budget(self) -> HumanAuthorization:
        if self.action is HumanAuthorizationAction.RESUME and self.additional_iterations == 0:
            raise ValueError("Resume authorization requires additional iterations")
        if self.action is HumanAuthorizationAction.ABANDON and self.additional_iterations:
            raise ValueError("Abandon authorization cannot grant iterations")
        return self

    @property
    def consumed_resume_grant(self) -> int:
        if (
            self.action is HumanAuthorizationAction.RESUME
            and self.consumed_at is not None
            and self.issued_at <= self.consumed_at <= self.expires_at
        ):
            return self.additional_iterations
        return 0


class AuthorizationVerifier(Protocol):
    def verify(self, authorization: HumanAuthorization, action: HumanAuthorizationAction) -> bool: ...


class RunnerIdentity(ContractModel):
    content_hash: Sha256
    source_sha: Sha256
    dependency_lock_hash: Sha256
    contract_bundle_hash: Sha256
    built_at: datetime

    @field_validator("content_hash", "source_sha", "dependency_lock_hash", "contract_bundle_hash")
    @classmethod
    def normalize_runner_hashes(cls, value: str) -> str:
        return canonical_text(value, "Runner identity hash").lower()

    @field_validator("built_at")
    @classmethod
    def validate_runner_built_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Runner identity time must be timezone-aware")
        return value


class CatalogObservation(ContractModel):
    provider: str
    endpoint_identity: str
    credential_scope_hash: Sha256
    fetched_at: datetime
    expires_at: datetime
    model_set_hash: Sha256
    profile_bundle_hash: Sha256
    response_evidence_hash: Sha256

    @field_validator("provider")
    @classmethod
    def validate_catalog_provider(cls, value: str) -> str:
        provider = canonical_text(value, "Catalog provider")
        if provider not in SUPPORTED_PROVIDERS:
            raise ValueError("Catalog provider is invalid")
        return provider

    @field_validator("endpoint_identity")
    @classmethod
    def validate_catalog_endpoint_identity(cls, value: str) -> str:
        endpoint_identity = canonical_text(value, "Catalog endpoint identity")
        if (
            re.fullmatch(_SAFE_IDENTIFIER, endpoint_identity) is None
            or is_secret_like_identifier(endpoint_identity)
            or _looks_sensitive(endpoint_identity)
        ):
            raise ValueError("Catalog endpoint identity is invalid")
        return endpoint_identity

    @field_validator(
        "credential_scope_hash",
        "model_set_hash",
        "profile_bundle_hash",
        "response_evidence_hash",
    )
    @classmethod
    def normalize_catalog_hashes(cls, value: str) -> str:
        return canonical_text(value, "Catalog hash").lower()

    @field_validator("fetched_at", "expires_at")
    @classmethod
    def validate_catalog_timestamps(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Catalog timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_catalog_expiry(self) -> CatalogObservation:
        if self.fetched_at >= self.expires_at:
            raise ValueError("Catalog expiry must follow its fetch timestamp")
        return self

    @property
    def content_hash(self) -> str:
        return hash_json(self.model_dump(mode="json", round_trip=True))


class BrowserPreflightStatus(StrEnum):
    NOT_CONFIGURED = "not_configured"
    VERIFIED = "verified"


class CompatibilityComponentObservation(ContractModel):
    component: Literal["python", "crewai", "openspec", "node", "ralph", "playwright"]
    expected_constraint: _SHORT_TEXT
    observed_version: _SHORT_TEXT
    verified_identity_hash: Sha256
    evidence_hashes: tuple[Sha256, ...] = Field(max_length=64)

    @field_validator("component")
    @classmethod
    def normalize_component(cls, value: str) -> str:
        return canonical_text(value, "Compatibility component")

    @field_validator("expected_constraint", "observed_version")
    @classmethod
    def validate_component_text(cls, value: str) -> str:
        text = canonical_text(value, "Compatibility component text")
        if _looks_sensitive(text) or is_secret_like_identifier(text):
            raise ValueError("Compatibility component text is invalid")
        return reject_unsafe_persisted_value(text)

    @field_validator("verified_identity_hash")
    @classmethod
    def normalize_component_identity_hash(cls, value: str) -> str:
        return canonical_text(value, "Compatibility component identity hash").lower()

    @field_validator("evidence_hashes")
    @classmethod
    def normalize_component_evidence_hashes(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        return tuple(canonical_text(item, "Compatibility component evidence hash").lower() for item in value)

    @model_validator(mode="after")
    def validate_component_version_text(self) -> CompatibilityComponentObservation:
        if self.component == "python":
            valid = self.expected_constraint == "3.12.x" and _PYTHON_OBSERVED_VERSION.fullmatch(
                self.observed_version
            ) is not None
        elif self.component == "node":
            valid = self.expected_constraint == ">=20.19.0" and _NODE_OBSERVED_VERSION.fullmatch(
                self.observed_version
            ) is not None
        else:
            version = _EXACT_COMPONENT_VERSIONS[self.component]
            valid = self.expected_constraint == version and self.observed_version == version
        if not valid:
            raise ValueError("Compatibility component version is invalid")
        return self


class CompatibilityReceipt(ContractModel):
    schema_version: Literal["v1"] = "v1"
    receipt_id: str
    issued_at: datetime
    launcher_identity: EffectReference
    runner_identity: RunnerIdentity
    runner_content_hash: Sha256
    project_policy_hash: Sha256
    selected_role_models_hash: Sha256
    profile_bundle_hash: Sha256
    catalog_receipt_hashes: Mapping[str, Sha256] = Field(max_length=len(SUPPORTED_PROVIDERS))
    catalog_observations: tuple[CatalogObservation, ...] = Field(max_length=len(SUPPORTED_PROVIDERS))
    browser_preflight_status: BrowserPreflightStatus
    component_observations: tuple[CompatibilityComponentObservation, ...] = Field(min_length=5, max_length=6)
    relative_path: EvidencePath

    @field_validator("runner_identity", mode="before")
    @classmethod
    def revalidate_runner_identity(cls, value: object) -> object:
        if isinstance(value, RunnerIdentity):
            return value.model_dump(mode="json", round_trip=True)
        return value

    @field_validator("catalog_observations", mode="before")
    @classmethod
    def revalidate_catalog_observations(cls, value: object) -> object:
        if isinstance(value, (tuple, list)):
            return tuple(
                observation.model_dump(mode="json", round_trip=True)
                if isinstance(observation, CatalogObservation)
                else observation
                for observation in value
            )
        return value

    @field_validator("component_observations", mode="before")
    @classmethod
    def revalidate_component_observations(cls, value: object) -> object:
        if isinstance(value, (tuple, list)):
            return tuple(
                observation.model_dump(mode="json", round_trip=True)
                if isinstance(observation, CompatibilityComponentObservation)
                else observation
                for observation in value
            )
        return value

    @field_validator("receipt_id")
    @classmethod
    def validate_receipt_id(cls, value: str) -> str:
        return _canonical_uuid(value, "Compatibility receipt ID")

    @field_validator("issued_at")
    @classmethod
    def validate_issued_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Compatibility receipt time must be timezone-aware")
        return value

    @field_validator("launcher_identity")
    @classmethod
    def validate_launcher_identity(cls, value: str) -> str:
        identity = canonical_text(value, "Compatibility launcher identity")
        if _looks_sensitive(identity) or is_secret_like_identifier(identity):
            raise ValueError("Compatibility launcher identity is invalid")
        return reject_unsafe_persisted_value(identity)

    @field_validator(
        "runner_content_hash",
        "project_policy_hash",
        "selected_role_models_hash",
        "profile_bundle_hash",
    )
    @classmethod
    def normalize_receipt_hashes(cls, value: str) -> str:
        return canonical_text(value, "Compatibility receipt hash").lower()

    @field_validator("catalog_receipt_hashes")
    @classmethod
    def freeze_catalog_receipt_hashes(cls, value: Mapping[str, Sha256]) -> Mapping[str, Sha256]:
        normalized: dict[str, Sha256] = {}
        for source_provider, source_hash in value.items():
            provider = canonical_text(source_provider, "Compatibility catalog provider")
            if provider not in SUPPORTED_PROVIDERS or provider in normalized:
                raise ValueError("Compatibility catalog receipt hashes are invalid")
            normalized[provider] = canonical_text(source_hash, "Compatibility catalog receipt hash").lower()
        return MappingProxyType(normalized)

    @field_serializer("catalog_receipt_hashes")
    def serialize_catalog_receipt_hashes(self, value: Mapping[str, Sha256]) -> dict[str, Sha256]:
        return dict(value)

    @field_validator("relative_path")
    @classmethod
    def validate_receipt_path(cls, value: str) -> str:
        path = canonical_text(value, "Compatibility receipt path")
        if _looks_sensitive(path) or is_secret_like_identifier(path):
            raise ValueError("Compatibility receipt path is invalid")
        return reject_unsafe_persisted_value(path)

    @model_validator(mode="after")
    def validate_receipt_bindings(self) -> CompatibilityReceipt:
        expected_path = f"trusted-launcher/compatibility/{self.receipt_id}.json"
        if self.relative_path != expected_path:
            raise ValueError("Compatibility receipt path does not match its ID")
        if self.runner_content_hash != self.runner_identity.content_hash:
            raise ValueError("Compatibility receipt runner content hash does not match its identity")

        catalog_providers = tuple(observation.provider for observation in self.catalog_observations)
        if catalog_providers != tuple(sorted(catalog_providers)) or len(set(catalog_providers)) != len(catalog_providers):
            raise ValueError("Compatibility catalog observations must be sorted and unique")
        if set(catalog_providers) != set(self.catalog_receipt_hashes):
            raise ValueError("Compatibility catalog receipt hashes do not match observations")
        if any(
            self.catalog_receipt_hashes[observation.provider] != observation.content_hash
            for observation in self.catalog_observations
        ):
            raise ValueError("Compatibility catalog receipt hash does not match observation")
        if any(
            observation.profile_bundle_hash != self.profile_bundle_hash
            for observation in self.catalog_observations
        ):
            raise ValueError("Compatibility catalog profile bundle hash does not match receipt")

        components = tuple(observation.component for observation in self.component_observations)
        if components != tuple(sorted(components)) or len(set(components)) != len(components):
            raise ValueError("Compatibility component observations must be sorted and unique")
        required_components = {"python", "crewai", "openspec", "node", "ralph"}
        if self.browser_preflight_status is BrowserPreflightStatus.VERIFIED:
            required_components.add("playwright")
        if set(components) != required_components:
            raise ValueError("Compatibility component observations do not match browser status")
        return self

    @property
    def content_hash(self) -> str:
        return hash_json(self.model_dump(mode="json", round_trip=True))


class RepairRunnerIdentity(RunnerIdentity):
    pass


class PendingExternalRequest(ContractModel):
    request_id: EffectReference
    effect_id: EffectReference
    request_hash: EffectHash
    operation: EffectOperation
    entity: EffectReference | None = None
    target: EffectReference | None = None
    arguments: Mapping[str, Any] | None = None
    effect_hash: EffectHash | None = None
    expected_revision: int | None = Field(default=None, ge=1)
    expected_state_hash: Sha256 | None = None
    expected_external_revision: str | None = None
    payload_hash: Sha256 | None = None

    @field_validator("request_id", "effect_id", "request_hash", "operation")
    @classmethod
    def reject_secret_like_values(cls, value: str) -> str:
        return reject_unsafe_persisted_value(value)

    @field_validator("entity", "target")
    @classmethod
    def reject_optional_secret_like_values(cls, value: str | None) -> str | None:
        return reject_unsafe_persisted_value(value) if value is not None else None

    @field_validator("arguments", mode="before")
    @classmethod
    def validate_pending_arguments(cls, value: object) -> Mapping[str, Any] | None:
        return _action_arguments(value) if value is not None else None

    @field_validator("arguments")
    @classmethod
    def freeze_pending_arguments(cls, value: Mapping[str, Any] | None) -> Mapping[str, Any] | None:
        return _freeze_json(value) if value is not None else None  # type: ignore[return-value]

    @field_serializer("arguments")
    def serialize_pending_arguments(self, value: Mapping[str, Any] | None) -> object:
        return _thaw_json(value) if value is not None else None

    @field_validator("effect_hash", "expected_state_hash", "payload_hash")
    @classmethod
    def normalize_pending_hashes(cls, value: str | None) -> str | None:
        return value.lower() if value is not None else None

    @field_validator("expected_external_revision")
    @classmethod
    def validate_pending_external_revision(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not isinstance(value, str) or not value or len(value) > 256 or _looks_sensitive(value):
            raise ValueError("Pending external revision is invalid")
        return value

    def reconstruct_request(self, run_id: str) -> McpActionRequest:
        if self.entity is None or self.target is None or self.arguments is None or self.effect_hash is None:
            raise ValueError("Pending request cannot be reconstructed")
        try:
            request = McpActionRequest(
                request_id=self.request_id,
                effect_id=self.effect_id,
                effect_hash=self.effect_hash,
                operation=self.operation,
                entity=self.entity,
                target=self.target,
                expected_external_revision=self.expected_external_revision,
                run_id=run_id,
                expected_revision=self.expected_revision,
                expected_state_hash=self.expected_state_hash,
                arguments=self.arguments,
                request_hash=self.request_hash,
            )
        except Exception:
            raise ValueError("Pending request cannot be reconstructed") from None
        if request.payload_hash != self.payload_hash:
            raise ValueError("Pending request payload hash does not match")
        return request


class PersistedBranchBinding(ContractModel):
    """Immutable branch lineage captured before the branch creation effect."""

    ticket_id: str
    branch: str
    base_sha: str
    repository_identity: Sha256
    remote_fingerprint: Sha256
    default_branch: str
    checkpoint_lineage: str

    @model_validator(mode="after")
    def validate_binding(self) -> PersistedBranchBinding:
        if (
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", self.ticket_id) is None
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", self.branch) is None
            or not self.branch.startswith(f"{self.ticket_id}-")
            or re.fullmatch(r"[0-9a-f]{40}(?:[0-9a-f]{24})?", self.base_sha) is None
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}", self.default_branch) is None
            or not self.checkpoint_lineage
        ):
            raise ValueError("Branch binding is invalid")
        return self


RestartReceiptHash: TypeAlias = Sha256


class FinalizationEvidence(ContractModel):
    prefinalization_ticket_projection: EffectReference
    commit_sha: EffectReference
    pushed_sha: EffectReference
    linear_done_receipt: EffectReference

    @field_validator(
        "prefinalization_ticket_projection",
        "commit_sha",
        "pushed_sha",
        "linear_done_receipt",
    )
    @classmethod
    def reject_secret_like_values(cls, value: str) -> str:
        return reject_unsafe_persisted_value(value)


class StageOutput(ContractModel):
    stage: Stage
    content_hash: Sha256


class RunState(ContractModel):
    run_id: str
    ticket_id: str
    repository_id: str
    max_crew_iterations: int = Field(gt=0)
    branch: str | None = None
    branch_binding: PersistedBranchBinding | None = None
    preparation_phase: PreparationPhase = PreparationPhase.SELECTED
    project_policy_hash: Sha256 | None = None
    preparation_input_ref: TrustedPreparationInputRef | None = None
    preparation_input_hash: Sha256 | None = None
    ticket_snapshot_hash: Sha256 | None = None
    compatibility_receipt_hash: Sha256 | None = None
    compatibility_receipt_ref: EvidenceRef | None = None
    disposition: RunDisposition = RunDisposition.ACTIVE
    compensated: bool = False
    crew_iteration_count: int = Field(default=0, ge=0)
    iteration_open: bool = False
    current_stage: Stage = Stage.ANALYST
    requirements_package: str | None = None
    change_outline: str | None = None
    stage_outputs: tuple[StageOutput, ...] = ()
    task_definition_manifest: TaskDefinitionManifest | None = None
    task_status_manifest: TaskStatusManifest | None = None
    product_change_manifest: str | None = None
    build_identity: str | None = None
    verification_result: str | None = None
    browser_result: str | None = None
    review_manifest: str | None = None
    review_result: str | None = None
    checkpoints: Mapping[Stage, Checkpoint] = Field(default_factory=dict)
    failure_history: tuple[FailureRecord, ...] = ()
    effect_ledger: tuple[EffectEvent, ...] = ()
    human_authorizations: tuple[HumanAuthorization, ...] = ()
    runner_identity: RunnerIdentity | None = None
    repair_runner_identity: RepairRunnerIdentity | None = None
    restart_receipt_hash: RestartReceiptHash | None = None
    pending_external_request: PendingExternalRequest | None = None
    prefinalization_ticket_projection: str | None = None
    commit_sha: str | None = None
    pushed_sha: str | None = None
    linear_done_receipt: str | None = None
    finalization_eligible: bool = False
    finalization: str | None = None
    finalization_evidence: FinalizationEvidence | None = None

    @field_validator(
        "project_policy_hash",
        "preparation_input_hash",
        "ticket_snapshot_hash",
        "compatibility_receipt_hash",
    )
    @classmethod
    def normalize_preparation_binding_hashes(cls, value: str | None) -> str | None:
        return value.lower() if value is not None else None

    @field_validator("checkpoints")
    @classmethod
    def freeze_checkpoints(
        cls,
        value: Mapping[Stage, Checkpoint],
    ) -> Mapping[Stage, Checkpoint]:
        return MappingProxyType(dict(value))

    @field_serializer("checkpoints")
    def serialize_checkpoints(self, value: Mapping[Stage, Checkpoint]) -> dict[Stage, Checkpoint]:
        return dict(value)

    @model_validator(mode="after")
    def validate_state(self) -> RunState:
        binding_fields = (
            self.project_policy_hash,
            self.preparation_input_ref,
            self.preparation_input_hash,
            self.ticket_snapshot_hash,
            self.compatibility_receipt_hash,
            self.compatibility_receipt_ref,
        )
        if any(field is not None for field in binding_fields):
            if not self.has_preparation_binding:
                raise ValueError("Preparation binding must be complete")
            assert self.preparation_input_ref is not None
            assert self.preparation_input_hash is not None
            assert self.compatibility_receipt_hash is not None
            assert self.compatibility_receipt_ref is not None
            if self.preparation_input_ref.repository_id != self.repository_id:
                raise ValueError("Preparation input repository does not match the run")
            if self.preparation_input_ref.max_crew_iterations != self.max_crew_iterations:
                raise ValueError("Preparation crew iteration budget does not match its trusted input")
            if self.preparation_input_ref.input_hash != self.preparation_input_hash:
                raise ValueError("Preparation input hash does not match its trusted reference")
            if self.compatibility_receipt_ref.sha256 != self.compatibility_receipt_hash:
                raise ValueError("Compatibility receipt hash does not match its reference")
        elif self.preparation_phase is not PreparationPhase.SELECTED or self.compensated:
            raise ValueError("Preparation state requires a complete preparation binding")
        if self.crew_iteration_count > self.authorized_iteration_limit:
            raise ValueError("Crew Iteration count exceeds authorized limit")
        if self.iteration_open and self.crew_iteration_count == 0:
            raise ValueError("An open Crew Iteration must be counted")
        if self.finalization_eligible and self.iteration_open:
            raise ValueError("Finalization cannot be eligible during an open iteration")
        if self.finalization_eligible and (self.review_manifest is None or self.review_result is None):
            raise ValueError("Finalization eligibility requires an approved review binding")
        if any(authorization.run_id != self.run_id for authorization in self.human_authorizations):
            raise ValueError("Human Authorization belongs to another run")
        if len({authorization.authorization_id for authorization in self.human_authorizations}) != len(
            self.human_authorizations
        ):
            raise ValueError("Human Authorization IDs must be unique")
        if self.task_status_manifest is not None:
            if self.task_definition_manifest is None:
                raise ValueError("Task status requires an active task definition")
            if self.task_status_manifest.definition_hash != self.task_definition_manifest.definition_hash:
                raise ValueError("Task status definition hash does not match")
            task_ids = {task.task_id for task in self.task_definition_manifest.tasks}
            status_ids = {status.task_id for status in self.task_status_manifest.statuses}
            if status_ids != task_ids:
                raise ValueError("Task statuses must cover exactly the active task definitions")
        if any(checkpoint.stage is not stage for stage, checkpoint in self.checkpoints.items()):
            raise ValueError("Checkpoint stage does not match its key")
        if len({output.stage for output in self.stage_outputs}) != len(self.stage_outputs):
            raise ValueError("Stage output references must be unique")
        outputs = {output.stage: output for output in self.stage_outputs}
        if set(outputs) != set(self.checkpoints):
            raise ValueError("Stage outputs must match checkpoints exactly")
        for stage, checkpoint in self.checkpoints.items():
            output = outputs[stage]
            if output.content_hash != checkpoint.output_manifest_hash:
                raise ValueError("Checkpoint output manifest does not match its Stage output")
        intentions, phases = self.validate_effect_ledger()
        if self.pending_external_request is not None:
            pending = self.pending_external_request
            intention = intentions.get(pending.effect_id)
            if intention is None:
                raise ValueError("Pending request references an unknown effect")
            if phases[pending.effect_id] == "reconciled":
                raise ValueError("Pending request references a reconciled effect")
            if (
                intention.payload.request_hash != pending.request_hash
                or intention.payload.operation != pending.operation
            ):
                raise ValueError("Pending request does not match its effect intention")
            if pending.entity is not None or pending.target is not None or pending.arguments is not None:
                try:
                    request = pending.reconstruct_request(self.run_id)
                except ValueError:
                    raise ValueError("Pending request cannot be reconstructed") from None
                if intention.payload.target != request.target:
                    raise ValueError("Pending request does not match its effect intention")
        return self

    @property
    def has_preparation_binding(self) -> bool:
        return all(
            field is not None
            for field in (
                self.project_policy_hash,
                self.preparation_input_ref,
                self.preparation_input_hash,
                self.ticket_snapshot_hash,
                self.compatibility_receipt_hash,
                self.compatibility_receipt_ref,
                self.runner_identity,
            )
        )

    def validate_effect_ledger(self) -> tuple[dict[str, EffectIntention], dict[str, str]]:
        intentions: dict[str, EffectIntention] = {}
        phases: dict[str, str] = {}
        previous_sequence = 0
        for event in self.effect_ledger:
            if event.sequence <= previous_sequence:
                raise ValueError("Effect Ledger sequences must be globally increasing")
            previous_sequence = event.sequence
            phase = phases.get(event.effect_id)
            if event.kind is EffectEventKind.INTENTION:
                if phase is not None:
                    raise ValueError("Effect may have only one intention")
                if not isinstance(event, EffectIntention):
                    raise ValueError("Effect intention payload is invalid")
                intentions[event.effect_id] = event
                phases[event.effect_id] = "ready"
            elif event.kind is EffectEventKind.INVOCATION:
                if phase != "ready":
                    raise ValueError("Effect invocation requires an unreconciled intention")
                phases[event.effect_id] = "awaiting_observation"
            elif event.kind is EffectEventKind.OBSERVATION:
                if phase != "awaiting_observation":
                    raise ValueError("Effect observation requires an invocation")
                phases[event.effect_id] = "ready"
            elif phase == "awaiting_observation" or phase is None:
                raise ValueError("Effect reconciliation requires completed invocation pairs")
            elif phase == "reconciled":
                raise ValueError("Effect may have only one reconciliation")
            else:
                phases[event.effect_id] = "reconciled"
        return intentions, phases

    @property
    def authorized_iteration_limit(self) -> int:
        return self.max_crew_iterations + sum(
            authorization.consumed_resume_grant for authorization in self.human_authorizations
        )

    def can_start_iteration(self) -> bool:
        return (
            self.disposition is RunDisposition.ACTIVE
            and not self.iteration_open
            and not self.finalization_eligible
            and self.crew_iteration_count < self.authorized_iteration_limit
        )

    def begin_iteration(self) -> RunState:
        if not self.can_start_iteration():
            raise ValueError("Crew Iteration cannot start")
        return self.model_copy(
            update={
                "crew_iteration_count": self.crew_iteration_count + 1,
                "iteration_open": True,
            }
        )


def canonical_task_definition_hash(tasks: tuple[TaskDefinition, ...]) -> str:
    return hash_json([task.model_dump(mode="json", round_trip=True) for task in tasks])


class PreparationContextPayload(ContractModel):
    """Typed immutable context published only by the ActiveRunIndex activation transaction."""

    run_id: str
    repository_id: str
    ticket_snapshot: TicketSnapshot
    ticket_snapshot_hash: Sha256
    original_state_id: str
    original_external_revision: str
    preparation_input_ref: TrustedPreparationInputRef
    preparation_input_hash: Sha256
    compatibility_receipt_hash: Sha256
    compatibility_receipt_ref: EvidenceRef
    runner_identity: RunnerIdentity

    @model_validator(mode="after")
    def validate_bindings(self) -> PreparationContextPayload:
        if (
            _safe_snapshot_identifier(self.run_id, "Preparation context run") is None
            or _safe_snapshot_identifier(self.repository_id, "Preparation context repository") is None
            or _safe_snapshot_identifier(self.original_state_id, "Preparation context state") is None
            or not isinstance(self.original_external_revision, str)
        ):
            raise ValueError("Preparation context payload is invalid")
        try:
            reject_unsafe_persisted_value(self.original_external_revision)
        except ValueError:
            raise ValueError("Preparation context payload is invalid") from None
        if (
            self.ticket_snapshot.content_hash != self.ticket_snapshot_hash
            or self.preparation_input_ref.input_hash != self.preparation_input_hash
            or self.preparation_input_ref.repository_id != self.repository_id
            or self.compatibility_receipt_ref.sha256 != self.compatibility_receipt_hash
            or self.compatibility_receipt_ref.creator != "trusted-launcher"
            or self.compatibility_receipt_ref.media_type != "application/json"
        ):
            raise ValueError("Preparation context payload is invalid")
        return self


class CompatibilityClaimBinding(ContractModel):
    """The receipt-only compatibility binding retained by a selected activation claim."""

    compatibility_receipt_hash: Sha256
    compatibility_receipt_ref: EvidenceRef
    project_policy_hash: Sha256
    runner_identity: RunnerIdentity

    @model_validator(mode="after")
    def validate_receipt_binding(self) -> CompatibilityClaimBinding:
        if (
            self.compatibility_receipt_ref.sha256 != self.compatibility_receipt_hash
            or self.compatibility_receipt_ref.creator != "trusted-launcher"
            or self.compatibility_receipt_ref.media_type != "application/json"
        ):
            raise ValueError("Compatibility claim receipt binding is invalid")
        return self


class SelectedActivationClaimRequest(ContractModel):
    """Trusted selection facts that the Active Run index must claim before preflight."""

    reservation_id: str
    repository_id: str
    expected_index_revision: int = Field(ge=1)
    expected_index_hash: Sha256
    preparation_input_ref: TrustedPreparationInputRef
    ticket_snapshot: TicketSnapshot
    original_state_id: str
    original_external_revision: str

    @field_validator("expected_index_hash")
    @classmethod
    def normalize_claim_index_hash(cls, value: str) -> str:
        return value.lower()

    @model_validator(mode="after")
    def validate_selection_binding(self) -> SelectedActivationClaimRequest:
        if (
            self.preparation_input_ref.bridge_signature is None
            or not self.preparation_input_ref.pagination_complete
            or self.preparation_input_ref.repository_id != self.repository_id
            or self.preparation_input_ref.reservation_id != self.reservation_id
            or self.ticket_snapshot.pagination_complete is not True
            or dict(self.ticket_snapshot.source_page_hashes) != dict(self.preparation_input_ref.source_page_hashes)
            or _safe_snapshot_identifier(self.original_state_id, "Selected activation state") is None
            or not isinstance(self.original_external_revision, str)
            or len(self.original_external_revision) > 256
            or _looks_sensitive(self.original_external_revision)
            or self.original_external_revision == "[REDACTED]"
        ):
            raise ValueError("Selected activation claim is invalid")
        try:
            reject_unsafe_persisted_value(self.original_external_revision)
        except ValueError:
            raise ValueError("Selected activation claim is invalid") from None
        return self


class ActivationRequest(ContractModel):
    reservation_id: str
    repository_id: str
    expected_index_revision: int = Field(ge=1)
    expected_index_hash: Sha256
    preparation_input_ref: TrustedPreparationInputRef
    run_id: str | None = None
    initial_state: RunState | None = None
    initial_state_hash: Sha256 | None = None
    preparation_context_payload: PreparationContextPayload | None = None
    preparation_context_hash: Sha256 | None = None

    @field_validator("expected_index_hash")
    @classmethod
    def normalize_expected_index_hash(cls, value: str) -> str:
        return value.lower()

    @model_validator(mode="after")
    def validate_initial_state(self) -> ActivationRequest:
        if self.preparation_input_ref.bridge_signature is None:
            raise ValueError("Activation requires a signed preparation input reference")
        if not self.preparation_input_ref.pagination_complete:
            raise ValueError("Activation requires complete preparation input pagination")
        if self.preparation_input_ref.repository_id != self.repository_id:
            raise ValueError("Preparation input repository does not match activation")
        if self.preparation_input_ref.reservation_id != self.reservation_id:
            raise ValueError("Preparation input reservation does not match activation")
        if self.run_id is None:
            if (
                self.initial_state is not None
                or self.initial_state_hash is not None
                or self.preparation_context_payload is not None
                or self.preparation_context_hash is not None
            ):
                raise ValueError("No-candidate activation cannot include an initial state")
            return self
        if self.initial_state is None or self.initial_state_hash is None:
            raise ValueError("Active activation requires an initial state and hash")
        if self.initial_state.run_id != self.run_id or self.initial_state.repository_id != self.repository_id:
            raise ValueError("Initial state identity does not match activation")
        from .hashing import hash_json

        if hash_json(self.initial_state.model_dump(mode="json", round_trip=True)) != self.initial_state_hash.lower():
            raise ValueError("Initial state hash does not match activation")
        if (self.preparation_context_payload is None) != (self.preparation_context_hash is None):
            raise ValueError("Preparation context activation binding is incomplete")
        if self.preparation_context_payload is not None:
            context = self.preparation_context_payload
            if (
                hash_json(context.model_dump(mode="json", round_trip=True)) != self.preparation_context_hash.lower()
                or context.run_id != self.run_id
                or context.repository_id != self.repository_id
                or context.preparation_input_ref != self.preparation_input_ref
                or context.ticket_snapshot_hash != self.initial_state.ticket_snapshot_hash
                or context.preparation_input_hash != self.initial_state.preparation_input_hash
                or context.compatibility_receipt_hash != self.initial_state.compatibility_receipt_hash
                or context.compatibility_receipt_ref != self.initial_state.compatibility_receipt_ref
                or context.runner_identity != self.initial_state.runner_identity
                or context.ticket_snapshot.ticket_id != self.initial_state.ticket_id
            ):
                raise ValueError("Preparation context activation binding does not match initial state")
        return self

    @property
    def challenge_hash(self) -> str:
        return self.preparation_input_ref.challenge_hash

    @property
    def preparation_input_hash(self) -> str:
        return self.preparation_input_ref.input_hash
