from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
import socket
from typing import Protocol

from .contracts import (
    BrowserResult,
    BuildIdentity,
    ChangeOutline,
    ProductChangeManifest,
    RequirementsPackage,
    ReviewManifest,
    ReviewResult,
    RunState,
    Stage,
    StepResult,
    VerificationResult,
)
from .finalization_service import (
    FinalizationCapabilityDescriptor,
    FinalizationKeyAuthority,
    FinalizationRequest,
    _FinalizationHandlers,
    _LauncherFinalizationService,
)
from .finalizer import _FinalizationArtifacts, _Finalizer, _FinalizerDependencies
from .hashing import hash_json
from .linear import LinearGateway
from .prepare import PreparationContextAuthority
from .project_config import ProjectConfig
from .state import RunStateStore, StateGeneration, _read_canonical_json


class FinalizationArtifactError(RuntimeError):
    pass


class FinalizationLauncherError(RuntimeError):
    pass


class _ArtifactStore(Protocol):
    def load(self, content_hash: str, model: type[object]) -> object: ...


class _StateArtifactStore:
    """Read hash-addressed finalization artifacts from launcher-owned storage."""

    def __init__(self, state_root: Path) -> None:
        self._root = state_root / "finalization-artifacts"

    def load(self, content_hash: str, model: type[object]) -> object:
        try:
            payload = _read_canonical_json(self._root / f"{content_hash}.json", "finalization artifact")
            validator = getattr(model, "model_validate")
            value = validator(payload)
            dump = getattr(value, "model_dump")
            if hash_json(dump(mode="json", round_trip=True)) != content_hash:
                raise ValueError
            return value
        except Exception:
            raise FinalizationArtifactError("finalization artifact is unavailable") from None


class FinalizationArtifactAuthority:
    """Load finalization inputs solely from the Active Run and prepared baseline."""

    def __init__(self, state_root: Path, *, artifacts: _ArtifactStore | None = None) -> None:
        self._state_root = Path(state_root)
        self._artifacts = _StateArtifactStore(self._state_root) if artifacts is None else artifacts

    def load_for(self, state: RunState) -> _FinalizationArtifacts:
        if not isinstance(state, RunState):
            raise FinalizationArtifactError("finalization state is invalid")
        try:
            context = PreparationContextAuthority(self._state_root).load_verified(state.run_id)
            if (
                context.repository_id != state.repository_id
                or context.ticket_snapshot.ticket_id != state.ticket_id
                or state.ticket_snapshot_hash != context.ticket_snapshot_hash
            ):
                raise FinalizationArtifactError("ticket baseline changed")
            requirements = self._load(state.requirements_package, RequirementsPackage)
            outline = self._load(state.change_outline, ChangeOutline)
            product = self._load(state.product_change_manifest_hash, ProductChangeManifest)
            build = self._load(state.build_identity, BuildIdentity)
            verification = self._load(state.verification_result, VerificationResult)
            browser = self._load(state.browser_result, BrowserResult)
            review_manifest = self._load(state.review_manifest, ReviewManifest)
            review_result = self._load(state.review_result, ReviewResult)
            policy = self._load(state.project_policy_hash, ProjectConfig)
            if state.task_definition_manifest is None or state.task_status_manifest is None:
                raise FinalizationArtifactError("task manifests are unavailable")
            artifact_hashes = self._artifact_hashes(state, review_manifest)
            return _FinalizationArtifacts(
                ticket_snapshot=context.ticket_snapshot,
                original_state_id=context.original_state_id,
                original_external_revision=context.original_external_revision,
                project_policy=policy,
                requirements=requirements,
                change_outline=outline,
                artifact_hashes=artifact_hashes,
                task_definition=state.task_definition_manifest,
                task_status=state.task_status_manifest,
                product_manifest=product,
                build_identity=build,
                verification_result=verification,
                browser_result=browser,
                review_manifest=review_manifest,
                review_result=review_result,
            )
        except FinalizationArtifactError:
            raise
        except Exception:
            raise FinalizationArtifactError("finalization artifacts are unavailable") from None

    def _load(self, content_hash: str | None, model: type[object]) -> object:
        if not isinstance(content_hash, str):
            raise FinalizationArtifactError("finalization artifact is unavailable")
        return self._artifacts.load(content_hash, model)

    @staticmethod
    def _artifact_hashes(state: RunState, review: ReviewManifest) -> dict[str, str]:
        stages = {
            "proposal": Stage.ARCHITECT_PROPOSAL,
            "specs": Stage.ARCHITECT_SPECS,
            "design": Stage.ARCHITECT_DESIGN,
            "tasks": Stage.ARCHITECT_TASKS,
        }
        outputs = {output.stage: output.content_hash for output in state.stage_outputs}
        artifact_hashes = {name: outputs.get(stage) for name, stage in stages.items()}
        if any(value is None for value in artifact_hashes.values()) or artifact_hashes != dict(review.artifact_hashes):
            raise FinalizationArtifactError("OpenSpec artifact bindings changed")
        return {name: value for name, value in artifact_hashes.items() if value is not None}


@dataclass(frozen=True)
class FinalizationLauncherRuntime:
    """Launcher-owned capabilities; never constructed by the target CLI."""

    state_root: Path
    linear: LinearGateway | None = None
    git_guard: object | None = None
    active_run_index: object | None = None
    artifact_authority: FinalizationArtifactAuthority | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "state_root", Path(self.state_root))


class FinalizationLauncher:
    """Compose finalization only from launcher-held state and capabilities."""

    def __init__(self, runtime: FinalizationLauncherRuntime) -> None:
        if not isinstance(runtime, FinalizationLauncherRuntime):
            raise ValueError("finalization launcher runtime is invalid")
        self._runtime = runtime
        self._state_root = runtime.state_root
        self._keys = FinalizationKeyAuthority(self._state_root)
        self._artifacts = runtime.artifact_authority or FinalizationArtifactAuthority(self._state_root)
        self._services: dict[str, _LauncherFinalizationService] = {}

    @classmethod
    def from_runtime(cls, runtime: FinalizationLauncherRuntime) -> FinalizationLauncher:
        return cls(runtime)

    def serve_descriptor(
        self,
        run_id: str,
        expected_revision: int,
        expected_generation_hash: str,
        *,
        socket_path: Path,
    ) -> FinalizationCapabilityDescriptor:
        generation = self._load_exact(run_id, expected_revision, expected_generation_hash)
        service = self._service_for(generation)
        descriptor = service.issue_descriptor(
            operation="finalize",
            run_id=run_id,
            expected_revision=expected_revision,
            expected_state_hash=expected_generation_hash,
            request_id=None,
            socket_path=socket_path,
            expires_at=datetime.now(UTC) + timedelta(minutes=1),
            timeout_seconds=1.0,
        )
        self._services[descriptor.nonce] = service
        return descriptor

    def serve(self, run_id: str, expected_revision: int, expected_generation_hash: str) -> None:
        generation = self._load_exact(run_id, expected_revision, expected_generation_hash)
        self._finalizer_for(generation).advance(generation)

    def _service_for(self, generation: StateGeneration) -> _LauncherFinalizationService:
        key_hash = generation.state.finalization_public_key_hash
        if key_hash is None or generation.state.finalization_public_key is None:
            raise FinalizationLauncherError("finalization trust is unavailable")
        key = self._keys.load_private_key(key_hash)
        public_key = key.public_key().public_bytes_raw().hex()
        if public_key != generation.state.finalization_public_key:
            raise FinalizationLauncherError("finalization trust is invalid")
        return _LauncherFinalizationService(
            signing_key=key,
            state_root=self._state_root,
            handlers=_FinalizationHandlers(
                finalize=lambda request: self._handle_finalize(generation, request),
                receipt=lambda request: self._handle_receipt(generation, request),
            ),
        )

    def _handle_finalize(self, generation: StateGeneration, request: FinalizationRequest) -> StepResult:
        self._require_request(generation, request)
        return self._finalizer_for(generation).advance(generation)

    def _handle_receipt(self, generation: StateGeneration, request: FinalizationRequest) -> StepResult:
        self._require_request(generation, request)
        raise FinalizationLauncherError("finalization receipt composition is unavailable")

    def _finalizer_for(self, generation: StateGeneration) -> _Finalizer:
        if (
            not isinstance(self._runtime.linear, LinearGateway)
            or self._runtime.git_guard is None
            or self._runtime.active_run_index is None
        ):
            raise FinalizationLauncherError("finalization launcher capabilities are unavailable")
        store = RunStateStore(
            self._state_root,
            generation.state.run_id,
            receipt_authority=self._runtime.linear._receipt_authority,
        )
        artifacts = self._artifacts.load_for(generation.state)
        return _Finalizer(
            _FinalizerDependencies(
                store=store,
                linear=self._runtime.linear,
                git_guard=self._runtime.git_guard,
                active_run_index=self._runtime.active_run_index,
                project_policy=artifacts.project_policy,
                artifacts=artifacts,
            )
        )

    @staticmethod
    def _require_request(generation: StateGeneration, request: FinalizationRequest) -> None:
        if request != FinalizationRequest(
            operation=request.operation,
            run_id=generation.state.run_id,
            expected_revision=generation.revision,
            expected_state_hash=generation.state_hash,
            request_id=request.request_id,
            nonce=request.nonce,
        ):
            raise FinalizationLauncherError("finalization request does not match the Active Run")

    def _load_exact(self, run_id: str, expected_revision: int, expected_generation_hash: str) -> StateGeneration:
        try:
            generation = RunStateStore.load_read_only(self._state_root, run_id)
            if generation.revision != expected_revision or generation.state_hash != expected_generation_hash:
                raise ValueError
            return generation
        except Exception:
            raise FinalizationLauncherError("finalization state does not match the Active Run") from None


__all__ = [
    "FinalizationArtifactAuthority",
    "FinalizationArtifactError",
    "FinalizationLauncher",
    "FinalizationLauncherError",
    "FinalizationLauncherRuntime",
]
