from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .checkpoint import CheckpointAuthority
from .contracts import (
    EvidenceRef,
    FailureClass,
    FailureRecord,
    FailureSource,
    FindingKind,
    InvalidUnitOutput,
    McpActionRequest,
    ReviewResult,
    RunDisposition,
    RunState,
    Stage,
    StageOutput,
    StepKind,
    StepResult,
)
from .router import CheckpointExpectation, apply_route, next_stage, route_failure
from .state import RunStateStore, StateGeneration


class SupervisorError(RuntimeError):
    pass


class SupervisorStateMismatch(SupervisorError):
    pass


class StageExecutor(Protocol):
    def execute(self, stage: Stage, state: RunState) -> StageExecution | FailureRecord | InvalidUnitOutput: ...


@dataclass(frozen=True)
class StageExecution:
    """Validated local stage material ready for checkpointing by the supervisor."""

    output_manifest_hash: str
    validator: str
    validator_version: str
    validation_receipt_hash: str
    evidence: tuple[EvidenceRef, ...] = ()
    review: ReviewResult | None = None


@dataclass(frozen=True)
class SupervisorDependencies:
    store: RunStateStore
    checkpoint_authority: CheckpointAuthority
    expectations: Mapping[Stage, CheckpointExpectation]
    executor: StageExecutor

    def __post_init__(self) -> None:
        if not isinstance(self.store, RunStateStore):
            raise ValueError("Supervisor requires a run state store")
        if not isinstance(self.checkpoint_authority, CheckpointAuthority):
            raise ValueError("Supervisor requires a checkpoint authority")
        if set(self.expectations) != set(Stage):
            raise ValueError("Supervisor requires an expectation for every stage")
        if not callable(getattr(self.executor, "execute", None)):
            raise ValueError("Supervisor requires a deterministic stage executor")


class Supervisor:
    """Own one Crew Iteration and all transitions between its cognitive stages."""

    def __init__(self, dependencies: SupervisorDependencies) -> None:
        if not isinstance(dependencies, SupervisorDependencies):
            raise ValueError("Supervisor requires typed dependencies")
        self.dependencies = dependencies
        self.store = dependencies.store

    def step(self, run_id: str, expected_revision: int, expected_hash: str) -> StepResult:
        if run_id != self.store.run_id:
            raise SupervisorStateMismatch("run ID does not match this supervisor")
        generation = self.store.load()
        self._require_expected(generation, expected_revision, expected_hash)
        state = generation.state

        if state.disposition is not RunDisposition.ACTIVE:
            return self._gated_result(generation)

        stage = next_stage(state, self.dependencies.expectations, self.dependencies.checkpoint_authority)
        if stage is None:
            if not state.iteration_open and state.finalization_eligible:
                return self._result(StepKind.READY_TO_FINALIZE, generation)
            return self._human_review(generation, self._supervisor_failure(FindingKind.INVALID_ROUTING))

        if not state.iteration_open:
            if not state.can_start_iteration():
                return self._human_review(
                    generation,
                    FailureRecord(
                        failure_class=FailureClass.BUDGET_EXHAUSTED,
                        failure_source=FailureSource.SUPERVISOR,
                        finding_kind=FindingKind.REQUIREMENTS_MISMATCH,
                    ),
                )
            generation = self.store.compare_and_swap(
                generation.revision,
                generation.state_hash,
                state.begin_iteration(),
            )
        return self.execute_and_checkpoint(generation, stage)

    def record_failure(
        self,
        failure_class: FailureClass,
        owner_stage: Stage,
        evidence: object = (),
    ) -> StepResult:
        """Record a known product result without accepting model-authored routing."""

        if failure_class is FailureClass.PRODUCT:
            failure = FailureRecord(
                failure_class=failure_class,
                failure_source=FailureSource.REVIEW,
                finding_kind=FindingKind.IMPLEMENTATION_MISMATCH,
                owner_stage=owner_stage,
                evidence_refs=self._evidence_refs(evidence),
            )
        elif failure_class is FailureClass.INVALID_OUTPUT:
            failure = FailureRecord(
                failure_class=failure_class,
                failure_source=FailureSource.ARTIFACT,
                finding_kind=FindingKind.INVALID_UNIT_OUTPUT,
                owner_stage=owner_stage,
                evidence_refs=self._evidence_refs(evidence),
            )
        else:
            raise ValueError("Supervisor records only product defects and invalid unit output")
        generation = self.store.load()
        routed = apply_route(generation.state, route_failure(generation.state, failure))
        persisted = self.store.compare_and_swap(generation.revision, generation.state_hash, routed)
        return self._failure_result(persisted, persisted.state.failure_history[-1])

    def execute_and_checkpoint(self, generation: StateGeneration, stage: Stage) -> StepResult:
        if generation.state.current_stage is not stage or not generation.state.iteration_open:
            return self._human_review(generation, self._supervisor_failure(FindingKind.INVALID_ROUTING))
        try:
            outcome = self.dependencies.executor.execute(stage, generation.state)
        except Exception:
            return self._route_failure(generation, self._orchestration_failure(stage))
        if isinstance(outcome, InvalidUnitOutput):
            failure = FailureRecord(
                failure_class=FailureClass.INVALID_OUTPUT,
                failure_source=FailureSource.ARTIFACT,
                finding_kind=FindingKind.INVALID_UNIT_OUTPUT,
                owner_stage=stage,
            )
            return self._route_failure(generation, failure)
        if isinstance(outcome, FailureRecord):
            return self._route_failure(generation, outcome)
        if not isinstance(outcome, StageExecution):
            return self._route_failure(generation, self._orchestration_failure(stage))
        if stage is Stage.REVIEWER:
            return self._checkpoint_reviewer(generation, outcome)

        expectation = self.dependencies.expectations[stage]
        try:
            checkpoint = self.dependencies.checkpoint_authority.issue(
                stage=stage,
                contract_hash=expectation.contract_hash,
                input_hashes=expectation.input_hashes,
                output_manifest_hash=outcome.output_manifest_hash,
                validator=outcome.validator,
                validator_version=outcome.validator_version,
                validation_receipt_hash=outcome.validation_receipt_hash,
                evidence=outcome.evidence,
            )
            updates = {
                "checkpoints": {**generation.state.checkpoints, stage: checkpoint},
                "stage_outputs": (*generation.state.stage_outputs, StageOutput(stage=stage, content_hash=checkpoint.output_manifest_hash)),
                "current_stage": stage,
            }
            persisted = self.store.compare_and_swap(
                generation.revision,
                generation.state_hash,
                generation.state.model_copy(update=updates),
            )
        except Exception:
            return self._route_failure(generation, self._orchestration_failure(stage))
        return self._result(StepKind.CONTINUE, persisted, stage=stage, evidence=outcome.evidence)

    def _checkpoint_reviewer(self, generation: StateGeneration, outcome: StageExecution) -> StepResult:
        review = outcome.review
        if review is None:
            return self._route_failure(generation, self._orchestration_failure(Stage.REVIEWER))
        if review.review_manifest_hash != generation.state.review_manifest:
            return self._route_failure(generation, self._supervisor_failure(FindingKind.INVALID_ROUTING))
        if not review.approved:
            failure = FailureRecord(
                failure_class=review.failure_class,
                failure_source=review.failure_source,
                finding_kind=review.finding_kind,
                owner_stage=review.owner_stage,
                cited_ids=review.cited_ids,
                evidence_refs=review.evidence,
            )
            return self._route_failure(generation, failure)
        expectation = self.dependencies.expectations[Stage.REVIEWER]
        try:
            checkpoint = self.dependencies.checkpoint_authority.issue(
                stage=Stage.REVIEWER,
                contract_hash=expectation.contract_hash,
                input_hashes=expectation.input_hashes,
                output_manifest_hash=outcome.output_manifest_hash,
                validator=outcome.validator,
                validator_version=outcome.validator_version,
                validation_receipt_hash=outcome.validation_receipt_hash,
                evidence=outcome.evidence,
            )
            persisted = self.store.compare_and_swap(
                generation.revision,
                generation.state_hash,
                generation.state.model_copy(
                    update={
                        "checkpoints": {**generation.state.checkpoints, Stage.REVIEWER: checkpoint},
                        "stage_outputs": (
                            *generation.state.stage_outputs,
                            StageOutput(stage=Stage.REVIEWER, content_hash=checkpoint.output_manifest_hash),
                        ),
                        "current_stage": Stage.REVIEWER,
                        "review_result": outcome.output_manifest_hash,
                        "iteration_open": False,
                        "finalization_eligible": True,
                    }
                ),
            )
        except Exception:
            return self._route_failure(generation, self._orchestration_failure(Stage.REVIEWER))
        return self._result(StepKind.READY_TO_FINALIZE, persisted, evidence=outcome.evidence)

    def _route_failure(self, generation: StateGeneration, failure: FailureRecord) -> StepResult:
        routed = apply_route(generation.state, route_failure(generation.state, failure))
        persisted = self.store.compare_and_swap(generation.revision, generation.state_hash, routed)
        return self._failure_result(persisted, persisted.state.failure_history[-1])

    def _human_review(self, generation: StateGeneration, failure: FailureRecord) -> StepResult:
        return self._route_failure(generation, failure)

    def _gated_result(self, generation: StateGeneration) -> StepResult:
        state = generation.state
        if state.disposition is RunDisposition.WAITING_MCP:
            action = self._pending_action(state)
            if action is not None:
                return StepResult(
                    kind=StepKind.MCP_ACTION,
                    run_id=state.run_id,
                    state_revision=generation.revision,
                    state_hash=generation.state_hash,
                    request_id=action.request_id,
                    action=action,
                )
            return self._route_failure(generation, self._supervisor_failure(FindingKind.INVALID_ROUTING))
        if state.disposition is RunDisposition.REPAIR_REQUIRED:
            return self._result(StepKind.REPAIR_REQUIRED, generation, failure=self._latest_failure(state))
        if state.disposition is RunDisposition.HUMAN_REVIEW:
            return self._result(StepKind.HUMAN_REVIEW, generation, failure=self._latest_failure(state))
        if state.disposition in {RunDisposition.DONE, RunDisposition.ABANDONED}:
            return self._result(StepKind.DONE, generation)
        return self._result(StepKind.HUMAN_REVIEW, generation, failure=self._supervisor_failure(FindingKind.INVALID_ROUTING))

    @staticmethod
    def _pending_action(state: RunState) -> McpActionRequest | None:
        if state.pending_external_request is None:
            return None
        try:
            return state.pending_external_request.reconstruct_request(state.run_id)
        except ValueError:
            return None

    @staticmethod
    def _latest_failure(state: RunState) -> FailureRecord:
        if state.failure_history:
            return state.failure_history[-1]
        return Supervisor._supervisor_failure(FindingKind.INVALID_ROUTING)

    @staticmethod
    def _supervisor_failure(finding_kind: FindingKind) -> FailureRecord:
        return FailureRecord(
            failure_class=FailureClass.ORCHESTRATION,
            failure_source=FailureSource.SUPERVISOR,
            finding_kind=finding_kind,
        )

    @staticmethod
    def _orchestration_failure(stage: Stage) -> FailureRecord:
        return FailureRecord(
            failure_class=FailureClass.ORCHESTRATION,
            failure_source=FailureSource.ARTIFACT,
            finding_kind=FindingKind.INVALID_UNIT_OUTPUT,
            owner_stage=stage,
        )

    @staticmethod
    def _evidence_refs(value: object) -> tuple[EvidenceRef, ...]:
        if not isinstance(value, (tuple, list)):
            return ()
        return tuple(item for item in value if isinstance(item, EvidenceRef))

    @staticmethod
    def _require_expected(generation: StateGeneration, expected_revision: int, expected_hash: str) -> None:
        if generation.revision != expected_revision or generation.state_hash != expected_hash.lower():
            raise SupervisorStateMismatch("expected state does not match")

    @staticmethod
    def _failure_result(generation: StateGeneration, failure: FailureRecord) -> StepResult:
        kind = {
            RunDisposition.ACTIVE: StepKind.ITERATION_FAILED,
            RunDisposition.REPAIR_REQUIRED: StepKind.REPAIR_REQUIRED,
            RunDisposition.HUMAN_REVIEW: StepKind.HUMAN_REVIEW,
        }.get(generation.state.disposition, StepKind.HUMAN_REVIEW)
        return Supervisor._result(kind, generation, failure=failure, evidence=failure.evidence_refs)

    @staticmethod
    def _result(
        kind: StepKind,
        generation: StateGeneration,
        *,
        stage: Stage | None = None,
        failure: FailureRecord | None = None,
        evidence: tuple[EvidenceRef, ...] = (),
    ) -> StepResult:
        return StepResult(
            kind=kind,
            run_id=generation.state.run_id,
            state_revision=generation.revision,
            state_hash=generation.state_hash,
            stage=stage,
            failure=failure,
            evidence=evidence,
        )


__all__ = ["StageExecution", "StepKind", "Supervisor", "SupervisorDependencies", "SupervisorError", "SupervisorStateMismatch"]
