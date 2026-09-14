from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import os
from pathlib import Path
import socket
import tempfile
from typing import Protocol

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auto_code.contracts import (
    BrowserResult,
    BuildIdentity,
    ChangeOutline,
    FailureClass,
    FailureRecord,
    FailureSource,
    FindingKind,
    ProductChangeManifest,
    RequirementsPackage,
    ReviewManifest,
    ReviewResult,
    RunDisposition,
    RunState,
    Stage,
    StepKind,
    StepResult,
    VerificationResult,
)
from auto_code.finalization_service import (
    FinalizationCapabilityBinding,
    FinalizationCapabilityDescriptor,
    FinalizationParentCapability,
    FinalizationRequest,
    FinalizationTrustMaterial,
    _FinalizationHandlersInternal,
    _LauncherFinalizationServiceInternal,
)
from auto_code.finalizer import _FinalizationArtifacts, _Finalizer, _FinalizerDependencies
from auto_code.hashing import hash_json
from auto_code.hashing import canonical_json_bytes
from auto_code.linear import LinearGateway
from auto_code.mcp_bridge import TrustedLinearBridge
from auto_code.process import LauncherSocketSandbox, ProcessConfigurationError, SandboxChildEvidence, SandboxChildHandle
from auto_code.prepare import PreparationContextAuthority
from auto_code.project_config import ProjectConfig
from auto_code.state import RunStateStore, StateGeneration, _read_canonical_json


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
        if len({output.stage for output in state.stage_outputs}) != len(state.stage_outputs):
            raise FinalizationArtifactError("duplicate OpenSpec stage outputs")
        outputs = {output.stage: output.content_hash for output in state.stage_outputs}
        artifact_hashes = {name: outputs.get(stage) for name, stage in stages.items()}
        if any(value is None for value in artifact_hashes.values()) or artifact_hashes != dict(review.artifact_hashes):
            raise FinalizationArtifactError("OpenSpec artifact bindings changed")
        return {name: value for name, value in artifact_hashes.items() if value is not None}


@dataclass(frozen=True)
class _LauncherRuntime:
    """Launcher-owned capabilities; never constructed by the target CLI."""

    state_root: Path
    linear: LinearGateway | None = None
    bridge: TrustedLinearBridge | None = None
    git_guard: object | None = None
    active_run_index: object | None = None
    artifact_authority: FinalizationArtifactAuthority | None = None
    signing_key: Ed25519PrivateKey | None = None
    finalization_parent: FinalizationParentCapability | None = None
    sandbox: LauncherSocketSandbox | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "state_root", Path(self.state_root))


class FinalizationLauncher:
    """Compose finalization only from launcher-held state and capabilities."""

    def __init__(self, runtime: _LauncherRuntime) -> None:
        if not isinstance(runtime, _LauncherRuntime):
            raise ValueError("finalization launcher runtime is invalid")
        self._runtime = runtime
        self._state_root = runtime.state_root
        self._artifacts = runtime.artifact_authority or FinalizationArtifactAuthority(self._state_root)
        self._services: dict[str, _LauncherFinalizationServiceInternal] = {}

    def serve_descriptor(
        self,
        run_id: str,
        expected_revision: int,
        expected_generation_hash: str,
        *,
        socket_path: Path,
        operation: str = "finalize",
        request_id: str | None = None,
    ) -> FinalizationCapabilityDescriptor:
        generation = self._load_exact(run_id, expected_revision, expected_generation_hash)
        service = self._service_for(generation)
        descriptor = service.issue_descriptor(
            operation=operation,
            run_id=run_id,
            expected_revision=expected_revision,
            expected_state_hash=expected_generation_hash,
            request_id=request_id,
            socket_path=socket_path,
            expires_at=datetime.now(UTC) + timedelta(minutes=1),
            timeout_seconds=5.0,
        )
        self._services[descriptor.nonce] = service
        return descriptor

    def serve_ticket_process(
        self,
        run_id: str,
        expected_revision: int,
        expected_generation_hash: str,
        ticket_argv: tuple[str, ...],
        *,
        operation: str = "finalize",
        request_id: str | None = None,
    ) -> int:
        """Run one ticket command against one launcher-owned IPC capability."""

        if not ticket_argv or any(not isinstance(argument, str) or not argument for argument in ticket_argv):
            raise FinalizationLauncherError("ticket command is invalid")
        sandbox = self._runtime.sandbox
        if not isinstance(sandbox, LauncherSocketSandbox):
            raise FinalizationLauncherError("finalization sandbox isolation is unavailable")
        socket_directory = Path(tempfile.mkdtemp(prefix="auto-code-finalization-"))
        socket_directory.chmod(0o700)
        socket_path = socket_directory / "service.sock"
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        descriptors: list[int] = []
        process: SandboxChildHandle | None = None
        try:
            listener.bind(str(socket_path))
            listener.listen(1)
            process = sandbox.prepare_finalization_child(ticket_argv)
            descriptor = self.serve_descriptor(
                run_id,
                expected_revision,
                expected_generation_hash,
                socket_path=socket_path,
                operation=operation,
                request_id=request_id,
            )
            service = self._services[descriptor.nonce]
            parent = self._runtime.finalization_parent
            if not isinstance(parent, FinalizationParentCapability) or not isinstance(self._runtime.signing_key, Ed25519PrivateKey):
                raise FinalizationLauncherError("finalization parent capability is unavailable")
            descriptor_bytes = descriptor.to_bytes()
            trust = FinalizationTrustMaterial(
                public_key=service.public_key,
                descriptor_hash=hashlib.sha256(descriptor_bytes).hexdigest(),
                parent=parent,
            )
            trust_bytes = trust.to_bytes()
            binding = FinalizationCapabilityBinding.issue(
                descriptor,
                trust,
                descriptor_bytes,
                trust_bytes,
                self._runtime.signing_key,
            )
            descriptors = [
                _sealed_descriptor(descriptor_bytes),
                _sealed_descriptor(trust_bytes),
                _sealed_descriptor(binding.to_bytes()),
            ]
            post_transfer_evidence = process.transfer_finalization_fds((descriptors[0], descriptors[1], descriptors[2]))
            if not isinstance(post_transfer_evidence, SandboxChildEvidence) or post_transfer_evidence.fd_numbers != (0, 1, 2, 4, 5, 6):
                raise FinalizationLauncherError("finalization child post-transfer evidence is invalid")
            service._peer_pid = process.pid
            service.serve_once(listener)
            return process.wait(timeout=descriptor.timeout_seconds).returncode
        except Exception as error:
            cleanup_errors: list[Exception] = []
            if process is not None:
                try:
                    process.kill_group()
                except Exception as cleanup:
                    cleanup_errors.append(cleanup)
                try:
                    process.wait()
                except Exception as cleanup:
                    cleanup_errors.append(cleanup)
            if len(cleanup_errors) == 1:
                raise FinalizationLauncherError("finalization child cleanup failed") from cleanup_errors[0]
            if cleanup_errors:
                raise FinalizationLauncherError("finalization child cleanup failed") from ExceptionGroup(
                    "Finalization child cleanup failures", cleanup_errors
                )
            raise FinalizationLauncherError("finalization launcher lifecycle failed") from error
        finally:
            for descriptor_fd in descriptors:
                os.close(descriptor_fd)
            listener.close()
            try:
                socket_path.unlink()
            except FileNotFoundError:
                pass
            socket_directory.rmdir()

    def _service_for(self, generation: StateGeneration) -> _LauncherFinalizationServiceInternal:
        self._require_active_run(generation)
        key_hash = generation.state.finalization_public_key_hash
        if key_hash is None or generation.state.finalization_public_key is None:
            raise FinalizationLauncherError("finalization trust is unavailable")
        key = self._runtime.signing_key
        if not isinstance(key, Ed25519PrivateKey):
            raise FinalizationLauncherError("finalization signing credential is unavailable")
        public_key = key.public_key().public_bytes_raw().hex()
        if public_key != generation.state.finalization_public_key:
            raise FinalizationLauncherError("finalization trust is invalid")
        return _LauncherFinalizationServiceInternal(
            signing_key=key,
            state_root=self._state_root,
            handlers=_FinalizationHandlersInternal(
                finalize=lambda request: self._handle_finalize(generation, request),
                receipt=lambda request: self._handle_receipt(generation, request),
            ),
        )

    def _require_active_run(self, generation: StateGeneration) -> None:
        index = self._runtime.active_run_index
        lookup = getattr(index, "lookup", None)
        if not callable(lookup):
            raise FinalizationLauncherError("Active Run Index is unavailable")
        active = lookup(generation.state.repository_id)
        index_hash = getattr(active, "index_hash", None)
        if (
            active is None
            or getattr(active, "repository_id", None) != generation.state.repository_id
            or getattr(active, "run_id", None) != generation.state.run_id
            or not isinstance(getattr(active, "index_revision", None), int)
            or getattr(active, "index_revision") < 1
            or not isinstance(index_hash, str)
            or len(index_hash) != 64
            or any(character not in "0123456789abcdef" for character in index_hash)
            or Path(getattr(active, "state_root", "")) != self._state_root
        ):
            raise FinalizationLauncherError("Active Run Index does not match finalization state")

    def _handle_finalize(self, generation: StateGeneration, request: FinalizationRequest) -> StepResult:
        self._require_request(generation, request)
        if generation.state.disposition is RunDisposition.HUMAN_REVIEW:
            failure = generation.state.failure_history[-1] if generation.state.failure_history else FailureRecord(
                failure_class=FailureClass.ORCHESTRATION,
                failure_source=FailureSource.FINALIZATION,
                finding_kind=FindingKind.INVALID_ROUTING,
            )
            return StepResult(
                kind=StepKind.HUMAN_REVIEW,
                run_id=generation.state.run_id,
                state_revision=generation.revision,
                state_hash=generation.state_hash,
                failure=failure,
            )
        return self._finalizer_for(generation).advance(generation)

    def _handle_receipt(self, generation: StateGeneration, request: FinalizationRequest) -> StepResult:
        self._require_request(generation, request)
        if request.request_id is None or not isinstance(self._runtime.bridge, TrustedLinearBridge):
            raise FinalizationLauncherError("finalization receipt composition is unavailable")
        linear = self._linear_for(generation)
        pending = linear.replay_pending(generation)
        if pending is None or pending.request_id != request.request_id:
            raise FinalizationLauncherError("finalization receipt does not match the Active Run")
        receipt = self._runtime.bridge.execute(pending)
        accepted = self._finalizer_for(generation).accept_trusted_receipt(generation, receipt)
        return self._finalizer_for(accepted).advance(accepted)

    def _finalizer_for(self, generation: StateGeneration) -> _Finalizer:
        if (
            not isinstance(self._runtime.bridge, TrustedLinearBridge)
            or self._runtime.git_guard is None
            or self._runtime.active_run_index is None
        ):
            raise FinalizationLauncherError("finalization launcher capabilities are unavailable")
        store = RunStateStore(self._state_root, generation.state.run_id, receipt_authority=self._runtime.bridge.receipt_authority)
        artifacts = self._artifacts.load_for(generation.state)
        return _Finalizer(
            _FinalizerDependencies(
                store=store,
                linear=self._linear_for(generation),
                git_guard=self._runtime.git_guard,
                active_run_index=self._runtime.active_run_index,
                project_policy=artifacts.project_policy,
                artifacts=artifacts,
            )
        )

    def _linear_for(self, generation: StateGeneration) -> LinearGateway:
        if not isinstance(self._runtime.bridge, TrustedLinearBridge):
            raise FinalizationLauncherError("finalization bridge capability is unavailable")
        return LinearGateway(
            RunStateStore(
                self._state_root,
                generation.state.run_id,
                receipt_authority=self._runtime.bridge.receipt_authority,
            ),
            self._runtime.bridge.receipt_authority,
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


def generation_key_hash(generation: StateGeneration) -> str:
    key_hash = generation.state.finalization_public_key_hash
    if not isinstance(key_hash, str):
        raise FinalizationLauncherError("finalization trust is unavailable")
    return key_hash


def _sealed_descriptor(payload: bytes) -> int:
    temporary, path = tempfile.mkstemp(prefix="auto-code-finalization-")
    try:
        os.write(temporary, payload)
    finally:
        os.close(temporary)
    descriptor = os.open(path, os.O_RDONLY)
    os.unlink(path)
    return descriptor


__all__ = [
    "FinalizationArtifactAuthority",
    "FinalizationArtifactError",
    "FinalizationLauncher",
    "FinalizationLauncherError",
]
