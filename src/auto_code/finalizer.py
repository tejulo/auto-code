from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from datetime import timedelta
import re
import uuid

from .contracts import (
    BrowserResult,
    BuildIdentity,
    ChangeOutline,
    EffectIntention,
    EffectIntentionPayload,
    EffectInvocation,
    EffectInvocationPayload,
    EffectObservation,
    EffectObservationPayload,
    EffectOutcome,
    EffectReconciliation,
    EffectReconciliationPayload,
    FailureClass,
    FailureRecord,
    FailureSource,
    FinalizationEvidence,
    FindingKind,
    IndexReleaseBinding,
    IndexReleaseReceipt,
    McpActionRequest,
    ProductChangeManifest,
    RequirementsPackage,
    ReviewManifest,
    ReviewResult,
    RunDisposition,
    RunState,
    Stage,
    StepKind,
    StepResult,
    TaskDefinitionManifest,
    TaskStatusManifest,
    TicketConstraintProjection,
    TicketSnapshot,
    TrustedMcpReceipt,
    UnitStatus,
    VerificationResult,
)
from .hashing import hash_json
from .linear import LinearGateway
from .project_config import ProjectConfig
from .state import CompareAndSwapConflict, RunStateStore, StateGeneration


class FinalizationError(RuntimeError):
    pass


@dataclass(frozen=True)
class _FinalizationArtifacts:
    """The immutable artifacts that were reviewed for one finalization."""

    ticket_snapshot: TicketSnapshot
    original_state_id: str
    original_external_revision: str
    project_policy: ProjectConfig
    requirements: RequirementsPackage
    change_outline: ChangeOutline
    artifact_hashes: Mapping[str, str]
    task_definition: TaskDefinitionManifest
    task_status: TaskStatusManifest
    product_manifest: ProductChangeManifest
    build_identity: BuildIdentity
    verification_result: VerificationResult
    browser_result: BrowserResult
    review_manifest: ReviewManifest
    review_result: ReviewResult


@dataclass(frozen=True)
class _FinalizerDependencies:
    store: RunStateStore
    linear: LinearGateway
    git_guard: object
    active_run_index: object
    project_policy: ProjectConfig
    artifacts: _FinalizationArtifacts

    def __post_init__(self) -> None:
        if not isinstance(self.store, RunStateStore) or not isinstance(self.linear, LinearGateway):
            raise ValueError("Finalizer requires a state store and Linear gateway")
        if not isinstance(self.project_policy, ProjectConfig) or not isinstance(self.artifacts, _FinalizationArtifacts):
            raise ValueError("Finalizer requires trusted approval inputs")


class _Finalizer:
    """Advance approved work through durable, one-way finalization effects."""

    def __init__(self, dependencies: _FinalizerDependencies) -> None:
        if not isinstance(dependencies, _FinalizerDependencies):
            raise ValueError("Finalizer requires typed dependencies")
        self.dependencies = dependencies
        self.store = dependencies.store

    def advance(self, generation: StateGeneration) -> StepResult:
        self._require_generation(generation)
        while True:
            state = generation.state
            if state.disposition is RunDisposition.WAITING_MCP:
                return self._pending_result(generation)
            if state.disposition is not RunDisposition.ACTIVE:
                return self._gated_result(generation)
            if state.finalization_next_eligible_at is not None and datetime.now(UTC) < state.finalization_next_eligible_at:
                return self._ready_result(generation)
            try:
                artifacts = self._verify_approval(state)
            except Exception:
                return self._human_review(generation)

            if state.prefinalization_ticket_projection is None:
                request = self.dependencies.linear.request_ticket_projection(
                    generation,
                    state.ticket_id,
                    expected_external_revision=artifacts.original_external_revision,
                    expected_state_id=artifacts.original_state_id,
                )
                persisted = self.dependencies.linear.persist_pending(generation, request)
                return self._action_result(persisted, request)
            if state.prefinalization_ticket_projection != self._projection_hash(artifacts.ticket_snapshot):
                return self._human_review(generation)
            try:
                self._verify_git_position(state, artifacts)
            except Exception:
                return self._human_review(generation)

            if state.commit_sha is None:
                reconciled = self._reconcile_local_effect(generation, "commit", artifacts)
                if reconciled is not generation:
                    generation = reconciled
                    continue
                if self._attempts(state, "commit") >= artifacts.project_policy.finalization.max_invocations_per_effect:
                    return self._human_review(generation)
                generation = self._invoke_commit(generation, artifacts)
                if generation.state.commit_sha is None:
                    return self._ready_result(generation)
                continue

            if state.pushed_sha is None:
                reconciled = self._reconcile_local_effect(generation, "push", artifacts)
                if reconciled is not generation:
                    generation = reconciled
                    continue
                if self._attempts(state, "push") >= artifacts.project_policy.finalization.max_invocations_per_effect:
                    return self._human_review(generation)
                generation = self._invoke_push(generation, artifacts)
                if generation.state.pushed_sha is None:
                    return self._ready_result(generation)
                continue

            if state.linear_done_receipt is None:
                if self._attempts(state, "compare_and_complete_ticket") >= artifacts.project_policy.finalization.max_invocations_per_effect:
                    return self._human_review(generation)
                request = self.dependencies.linear.request_action(
                    generation,
                    operation="compare_and_complete_ticket",
                    entity="ticket",
                    target=state.ticket_id,
                    expected_external_revision=artifacts.original_external_revision,
                    arguments={"ticket_id": state.ticket_id, "state_id": artifacts.project_policy.linear.completed_state_id},
                )
                persisted = self.dependencies.linear.persist_pending(generation, request)
                return self._action_result(persisted, request)

            try:
                self._verify_approval(state)
                self._verify_git_position(state, artifacts)
            except Exception:
                return self._human_review(generation)
            evidence = FinalizationEvidence(
                prefinalization_ticket_projection=state.prefinalization_ticket_projection,
                commit_sha=state.commit_sha,
                pushed_sha=state.pushed_sha,
                linear_done_receipt=state.linear_done_receipt,
            )
            try:
                release_binding = self._active_index_release_binding(generation)
            except Exception:
                return self._human_review(generation)
            done = self.store.compare_and_swap(
                generation.revision,
                generation.state_hash,
                state.model_copy(
                    update={
                        "disposition": RunDisposition.DONE,
                        "finalization": "approved-finalization",
                        "finalization_evidence": evidence,
                        "finalization_index_release_binding": release_binding,
                    }
                ),
            )
            try:
                released = self._release_active_run(done)
            except Exception:
                return self._human_review(done)
            return self._result(StepKind.DONE, released)

    def accept_trusted_receipt(self, generation: StateGeneration, receipt: TrustedMcpReceipt) -> StateGeneration:
        """Consume only bridge-authenticated receipts matched by the pending request."""

        self._require_generation(generation)
        pending = generation.state.pending_external_request
        if pending is None:
            return self.dependencies.linear.consume_receipt(generation, receipt)
        artifacts = self._verify_approval(generation.state)

        def update(state: RunState, accepted: TrustedMcpReceipt) -> RunState:
            if pending.operation == "query_ticket_projection":
                if (
                    accepted.outcome is not EffectOutcome.SUCCESS
                    or accepted.external_revision != artifacts.original_external_revision
                    or accepted.observed_state_id != artifacts.original_state_id
                    or accepted.result_hash != self._projection_hash(artifacts.ticket_snapshot)
                ):
                    return self._failed_state(state)
                return state.model_copy(update={"prefinalization_ticket_projection": accepted.result_hash})
            if pending.operation == "compare_and_complete_ticket" and accepted.outcome is EffectOutcome.SUCCESS:
                if accepted.observed_state_id != artifacts.project_policy.linear.completed_state_id:
                    return self._failed_state(state)
                return state.model_copy(update={"linear_done_receipt": accepted.content_hash})
            if accepted.outcome is not EffectOutcome.SUCCESS and wait_seconds:
                cumulative_wait = state.finalization_retry_wait_seconds + wait_seconds
                if cumulative_wait > artifacts.project_policy.finalization.total_retry_wait_seconds:
                    return self._failed_state(state)
                return state.model_copy(
                    update={
                        "finalization_retry_wait_seconds": cumulative_wait,
                        "finalization_next_eligible_at": accepted.observed_at + timedelta(seconds=wait_seconds),
                    }
                )
            return state

        wait_seconds = self._retry_after_seconds(receipt)
        return self.dependencies.linear.consume_receipt(
            generation,
            receipt,
            state_update=update,
            wait_seconds=wait_seconds,
        )

    def _verify_approval(self, state: RunState) -> _FinalizationArtifacts:
        artifacts = self.dependencies.artifacts
        if not isinstance(artifacts, _FinalizationArtifacts):
            raise FinalizationError("finalization artifacts are unavailable")
        if artifacts.ticket_snapshot.ticket_id != state.ticket_id:
            raise FinalizationError("ticket baseline changed")
        if state.has_preparation_binding:
            from .prepare import PreparationContextAuthority

            context = PreparationContextAuthority(self.store.root).load_verified(state.run_id)
            if (
                context.ticket_snapshot != artifacts.ticket_snapshot
                or context.ticket_snapshot_hash != state.ticket_snapshot_hash
                or context.original_state_id != artifacts.original_state_id
                or context.original_external_revision != artifacts.original_external_revision
            ):
                raise FinalizationError("ticket baseline changed")
        review = artifacts.review_manifest
        if (
            not state.finalization_eligible
            or state.iteration_open
            or not artifacts.review_result.approved
            or state.review_manifest != review.content_hash
            or state.review_result != hash_json(artifacts.review_result.model_dump(mode="json", round_trip=True))
            or artifacts.review_result.review_manifest_hash != review.content_hash
            or artifacts.project_policy.policy_hash != self.dependencies.project_policy.policy_hash
            or review.project_policy_hash != self.dependencies.project_policy.policy_hash
            or review.baseline_sha != artifacts.product_manifest.baseline_sha
            or review.requirements_package_hash != hash_json(artifacts.requirements.model_dump(mode="json", round_trip=True))
            or review.change_outline_hash != hash_json(artifacts.change_outline.model_dump(mode="json", round_trip=True))
            or dict(review.artifact_hashes) != dict(artifacts.artifact_hashes)
            or review.task_definition_hash != artifacts.task_definition.definition_hash
            or review.task_status_hash != hash_json(artifacts.task_status.model_dump(mode="json", round_trip=True))
            or review.product_manifest_hash != artifacts.product_manifest.content_hash
            or review.build_identity_hash != hash_json(artifacts.build_identity.model_dump(mode="json", round_trip=True))
            or review.verification_result_hash != hash_json(artifacts.verification_result.model_dump(mode="json", round_trip=True))
            or review.browser_result_hash != hash_json(artifacts.browser_result.model_dump(mode="json", round_trip=True))
            or state.requirements_package != review.requirements_package_hash
            or state.change_outline != review.change_outline_hash
            or state.product_change_manifest_hash != review.product_manifest_hash
            or state.build_identity != review.build_identity_hash
            or state.verification_result != review.verification_result_hash
            or state.browser_result != review.browser_result_hash
            or state.task_definition_manifest != artifacts.task_definition
            or state.task_status_manifest != artifacts.task_status
            or any(status.status is not UnitStatus.CHECKED for status in artifacts.task_status.statuses)
        ):
            raise FinalizationError("review bindings changed")
        if artifacts.build_identity.baseline_sha != artifacts.product_manifest.baseline_sha:
            raise FinalizationError("Build Identity baseline changed")
        if artifacts.build_identity.product_manifest_hash != artifacts.product_manifest.content_hash:
            raise FinalizationError("Build Identity product changed")
        if artifacts.build_identity.project_policy_hash != self.dependencies.project_policy.policy_hash:
            raise FinalizationError("Build Identity policy changed")
        VerificationResult.model_validate(
            artifacts.verification_result.model_dump(mode="json", round_trip=True),
            context={"build_identity": artifacts.build_identity},
        )
        if not artifacts.verification_result.passed:
            raise FinalizationError("verification failed")
        BrowserResult.model_validate(
            artifacts.browser_result.model_dump(mode="json", round_trip=True),
            context={"browser_e2e_decision": artifacts.change_outline.browser_e2e_decision, "build_identity": artifacts.build_identity},
        )
        checkpoint = state.checkpoints.get(Stage.REVIEWER)
        if checkpoint is None or checkpoint.output_manifest_hash != state.review_result:
            raise FinalizationError("Reviewer checkpoint changed")
        return artifacts

    def _verify_git_position(self, state: RunState, artifacts: _FinalizationArtifacts) -> None:
        git = self.dependencies.git_guard
        if not state.branch or self._call(git, "refresh_finalization", state.branch, artifacts.product_manifest.baseline_sha) is not True:
            raise FinalizationError("ticket branch or remote base changed")
        if state.commit_sha is not None and self._call(git, "reconcile_product_commit", artifacts.product_manifest, state.commit_sha) != state.commit_sha:
            raise FinalizationError("local commit changed")
        if state.pushed_sha is not None and self._call(git, "reconcile_product_push", state.branch, state.pushed_sha) != state.pushed_sha:
            raise FinalizationError("remote ticket branch changed")

    def _invoke_commit(self, generation: StateGeneration, artifacts: _FinalizationArtifacts) -> StateGeneration:
        intended, effect_id = self._intend(generation, "commit", generation.state.ticket_id)
        try:
            commit = self._call(
                self.dependencies.git_guard,
                "commit_product_manifest",
                artifacts.product_manifest,
                f"{generation.state.ticket_id}: {artifacts.ticket_snapshot.title}",
            )
            if not isinstance(commit, str) or len(commit) not in {40, 64}:
                raise FinalizationError("Git commit result is invalid")
            return self._record_local_result(intended, effect_id, "commit", EffectOutcome.SUCCESS, commit, {"commit_sha": commit})
        except Exception:
            return self._record_local_result(intended, effect_id, "commit", EffectOutcome.FAILURE, None, {})

    def _invoke_push(self, generation: StateGeneration, artifacts: _FinalizationArtifacts) -> StateGeneration:
        del artifacts
        intended, effect_id = self._intend(generation, "push", generation.state.ticket_id)
        try:
            pushed = self._call(self.dependencies.git_guard, "push_product_commit", generation.state.commit_sha)
            if pushed != generation.state.commit_sha:
                raise FinalizationError("Git push result is invalid")
            return self._record_local_result(intended, effect_id, "push", EffectOutcome.SUCCESS, pushed, {"pushed_sha": pushed})
        except Exception:
            return self._record_local_result(intended, effect_id, "push", EffectOutcome.FAILURE, None, {})

    def _reconcile_local_effect(
        self,
        generation: StateGeneration,
        operation: str,
        artifacts: _FinalizationArtifacts,
    ) -> StateGeneration:
        intentions, phases = generation.state.validate_effect_ledger()
        unresolved = [
            (effect_id, intention)
            for effect_id, intention in intentions.items()
            if intention.payload.operation == operation and phases[effect_id] != "reconciled"
        ]
        if not unresolved:
            return generation
        effect_id, _ = unresolved[-1]
        observed = (
            self._call(self.dependencies.git_guard, "reconcile_product_commit", artifacts.product_manifest, generation.state.commit_sha)
            if operation == "commit"
            else self._call(
                self.dependencies.git_guard,
                "reconcile_product_push",
                generation.state.branch,
                generation.state.commit_sha,
            )
        )
        expected = generation.state.commit_sha
        if observed is not None and (operation == "commit" or observed == expected):
            updates = {"commit_sha": observed} if operation == "commit" else {"pushed_sha": observed}
            return self._record_local_result(generation, effect_id, operation, EffectOutcome.SUCCESS, observed, updates)
        return self._record_local_result(generation, effect_id, operation, EffectOutcome.UNKNOWN, None, {})

    def _intend(self, generation: StateGeneration, operation: str, target: str) -> tuple[StateGeneration, str]:
        effect_id = f"{operation}-{uuid.uuid4().hex}"
        sequence = generation.state.effect_ledger[-1].sequence + 1 if generation.state.effect_ledger else 1
        state = generation.state.model_copy(
            update={
                "effect_ledger": (
                    *generation.state.effect_ledger,
                    EffectIntention(
                        effect_id=effect_id,
                        sequence=sequence,
                        timestamp=datetime.now(UTC),
                        payload=EffectIntentionPayload(
                            operation=operation,
                            target=target,
                            request_hash=hash_json({"effect_id": effect_id, "operation": operation, "target": target}),
                        ),
                    ),
                )
            }
        )
        return self.store.compare_and_swap(generation.revision, generation.state_hash, state), effect_id

    def _record_local_result(
        self,
        generation: StateGeneration,
        effect_id: str,
        operation: str,
        outcome: EffectOutcome,
        external_revision: str | None,
        updates: Mapping[str, object],
    ) -> StateGeneration:
        del operation
        sequence = generation.state.effect_ledger[-1].sequence + 1
        now = datetime.now(UTC)
        state = generation.state.model_copy(
            update={
                **updates,
                "effect_ledger": (
                    *generation.state.effect_ledger,
                    EffectInvocation(effect_id=effect_id, sequence=sequence, timestamp=now, payload=EffectInvocationPayload()),
                    EffectObservation(
                        effect_id=effect_id,
                        sequence=sequence + 1,
                        timestamp=now,
                        payload=EffectObservationPayload(outcome=outcome, external_revision=external_revision, evidence_refs=()),
                    ),
                    EffectReconciliation(
                        effect_id=effect_id,
                        sequence=sequence + 2,
                        timestamp=now,
                        payload=EffectReconciliationPayload(
                            outcome=outcome,
                            evidence_refs=(),
                            receipt_hash=hash_json({"effect_id": effect_id, "outcome": outcome.value, "revision": external_revision}),
                        ),
                    ),
                ),
            }
        )
        return self.store.compare_and_swap(generation.revision, generation.state_hash, state)

    def _human_review(self, generation: StateGeneration) -> StepResult:
        if generation.state.disposition is RunDisposition.HUMAN_REVIEW:
            return self._gated_result(generation)
        persisted = self.store.compare_and_swap(
            generation.revision,
            generation.state_hash,
            self._failed_state(generation.state),
        )
        return self._result(StepKind.HUMAN_REVIEW, persisted, failure=persisted.state.failure_history[-1])

    @staticmethod
    def _failed_state(state: RunState) -> RunState:
        failure = FailureRecord(
            failure_class=FailureClass.ORCHESTRATION,
            failure_source=FailureSource.FINALIZATION,
            finding_kind=FindingKind.ARTIFACT_MISMATCH,
        )
        return state.model_copy(update={"disposition": RunDisposition.HUMAN_REVIEW, "failure_history": (*state.failure_history, failure)})

    @staticmethod
    def _projection_hash(snapshot: TicketSnapshot) -> str:
        projection = TicketConstraintProjection.from_snapshot(snapshot)
        return hash_json(projection.model_dump(mode="json", round_trip=True))

    @staticmethod
    def _retry_after_seconds(receipt: TrustedMcpReceipt) -> float:
        for observation in receipt.observations:
            matched = re.fullmatch(r"retry-after=([0-9]+(?:\.[0-9]+)?)", observation.strip().lower())
            if matched is not None:
                return float(matched.group(1))
        return 0

    @staticmethod
    def _attempts(state: RunState, operation: str) -> int:
        return sum(
            isinstance(event, EffectIntention) and event.payload.operation == operation
            for event in state.effect_ledger
        )

    def _pending_result(self, generation: StateGeneration) -> StepResult:
        action = self.dependencies.linear.replay_pending(generation)
        if action is None:
            return self._human_review(generation)
        return self._action_result(generation, action)

    def _gated_result(self, generation: StateGeneration) -> StepResult:
        if generation.state.disposition is RunDisposition.DONE:
            if not generation.state.finalization_index_released:
                try:
                    generation = self._release_active_run(generation)
                except Exception:
                    return self._human_review(generation)
            return self._result(StepKind.DONE, generation)
        failure = generation.state.failure_history[-1] if generation.state.failure_history else FailureRecord(
            failure_class=FailureClass.ORCHESTRATION,
            failure_source=FailureSource.FINALIZATION,
            finding_kind=FindingKind.INVALID_ROUTING,
        )
        return self._result(StepKind.HUMAN_REVIEW, generation, failure=failure)

    def _ready_result(self, generation: StateGeneration) -> StepResult:
        return self._result(StepKind.READY_TO_FINALIZE, generation)

    @staticmethod
    def _action_result(generation: StateGeneration, action: McpActionRequest) -> StepResult:
        return StepResult(
            kind=StepKind.MCP_ACTION,
            run_id=generation.state.run_id,
            state_revision=generation.revision,
            state_hash=generation.state_hash,
            request_id=action.request_id,
            action=action,
        )

    @staticmethod
    def _result(kind: StepKind, generation: StateGeneration, *, failure: FailureRecord | None = None) -> StepResult:
        return StepResult(
            kind=kind,
            run_id=generation.state.run_id,
            state_revision=generation.revision,
            state_hash=generation.state_hash,
            failure=failure,
        )

    def _release_active_run(self, generation: StateGeneration) -> StateGeneration:
        index = self.dependencies.active_run_index
        lookup = getattr(index, "lookup", None)
        if not callable(lookup):
            raise FinalizationError("Active Run Index is unavailable")
        active = lookup(generation.state.repository_id)
        if active is None:
            return self._reconcile_released_index(generation, index)
        if getattr(active, "run_id", None) != generation.state.run_id:
            raise FinalizationError("Active Run Index entry belongs to another run")
        binding = generation.state.finalization_index_release_binding
        if not isinstance(binding, IndexReleaseBinding) or binding != IndexReleaseBinding(
            repository_id=generation.state.repository_id,
            run_id=generation.state.run_id,
            prior_revision=active.index_revision,
            prior_hash=active.index_hash,
        ):
            raise FinalizationError("Active Run Index release binding is unavailable")
        try:
            receipt = index.release(
                generation.state.repository_id,
                generation.state.run_id,
                active.index_revision,
                active.index_hash,
                generation.state_hash,
            )
        except Exception:
            if lookup(generation.state.repository_id) is not None:
                raise
            return self._reconcile_released_index(generation, index)
        if not isinstance(receipt, IndexReleaseReceipt) or receipt != binding.receipt_for(generation.state_hash):
            raise FinalizationError("Active Run Index release receipt is invalid")
        verifier = getattr(index, "verify_release", None)
        if not callable(verifier):
            raise FinalizationError("Active Run Index receipt verifier is unavailable")
        verifier(receipt)
        return self._mark_index_released(generation, receipt)

    def _reconcile_released_index(self, generation: StateGeneration, index: object) -> StateGeneration:
        if generation.state.disposition is not RunDisposition.DONE:
            raise FinalizationError("Active Run Index entry is missing")
        binding = generation.state.finalization_index_release_binding
        if not isinstance(binding, IndexReleaseBinding):
            raise FinalizationError("Active Run Index release binding is unavailable")
        receipt = binding.receipt_for(generation.state_hash)
        verifier = getattr(index, "verify_release", None)
        if not callable(verifier):
            raise FinalizationError("Active Run Index receipt verifier is unavailable")
        verifier(receipt)
        return self._mark_index_released(generation, receipt)

    def _mark_index_released(self, generation: StateGeneration, receipt: IndexReleaseReceipt) -> StateGeneration:
        return self.store.compare_and_swap(
            generation.revision,
            generation.state_hash,
            generation.state.model_copy(
                update={
                    "finalization_index_released": True,
                    "finalization_index_release_receipt": receipt,
                }
            ),
        )

    def _active_index_release_binding(self, generation: StateGeneration) -> IndexReleaseBinding:
        index = self.dependencies.active_run_index
        lookup = getattr(index, "lookup", None)
        if not callable(lookup):
            raise FinalizationError("Active Run Index is unavailable")
        active = lookup(generation.state.repository_id)
        if active is None or getattr(active, "run_id", None) != generation.state.run_id:
            raise FinalizationError("Active Run Index entry is unavailable")
        return IndexReleaseBinding(
            repository_id=generation.state.repository_id,
            run_id=generation.state.run_id,
            prior_revision=active.index_revision,
            prior_hash=active.index_hash,
        )

    def _require_generation(self, generation: StateGeneration) -> None:
        if not isinstance(generation, StateGeneration) or generation.state.run_id != self.store.run_id:
            raise FinalizationError("finalization generation belongs to another run")
        current = self.store.load()
        if current != generation:
            raise CompareAndSwapConflict("finalization generation is stale")

    @staticmethod
    def _call(target: object, method: str, *args: object) -> object:
        callback = getattr(target, method, None)
        if not callable(callback):
            raise FinalizationError(f"Git finalization capability {method} is unavailable")
        return callback(*args)


__all__ = ["FinalizationError"]
