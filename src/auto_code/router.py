from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from .checkpoint import CheckpointAuthority
from .contracts import (
    FailureClass,
    FailureRecord,
    FailureSource,
    FindingKind,
    RunDisposition,
    RunState,
    Stage,
)


DEPENDENCIES: Mapping[Stage, frozenset[Stage]] = MappingProxyType(
    {
        Stage.ANALYST: frozenset(),
        Stage.ARCHITECT_OUTLINE: frozenset({Stage.ANALYST}),
        Stage.ARCHITECT_PROPOSAL: frozenset({Stage.ARCHITECT_OUTLINE}),
        Stage.ARCHITECT_SPECS: frozenset({Stage.ARCHITECT_PROPOSAL}),
        Stage.ARCHITECT_DESIGN: frozenset({Stage.ARCHITECT_PROPOSAL}),
        Stage.ARCHITECT_TASKS: frozenset({Stage.ARCHITECT_SPECS, Stage.ARCHITECT_DESIGN}),
        Stage.PROGRAMMER: frozenset({Stage.ARCHITECT_TASKS}),
        Stage.VERIFICATION: frozenset({Stage.PROGRAMMER}),
        Stage.TESTER: frozenset({Stage.VERIFICATION}),
        Stage.REVIEWER: frozenset({Stage.TESTER}),
    }
)

_ARCHITECT_STAGES = frozenset(
    {
        Stage.ARCHITECT_OUTLINE,
        Stage.ARCHITECT_PROPOSAL,
        Stage.ARCHITECT_SPECS,
        Stage.ARCHITECT_DESIGN,
        Stage.ARCHITECT_TASKS,
    }
)
_PRODUCT_EXECUTION_SOURCES = frozenset(
    {FailureSource.VERIFICATION, FailureSource.BROWSER, FailureSource.REVIEW}
)
_REPAIR_SOURCES = frozenset(
    {
        FailureSource.TRANSPORT,
        FailureSource.ARTIFACT,
        FailureSource.VERIFICATION,
        FailureSource.BROWSER,
        FailureSource.REVIEW,
    }
)
_HUMAN_REVIEW_ORCHESTRATION_SOURCES = frozenset(
    {FailureSource.PREFLIGHT, FailureSource.FINALIZATION, FailureSource.SUPERVISOR}
)


@dataclass(frozen=True)
class CheckpointExpectation:
    contract_hash: str
    input_hashes: Mapping[str, str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "input_hashes", MappingProxyType(dict(self.input_hashes)))


@dataclass(frozen=True)
class RouteDecision:
    disposition: RunDisposition
    invalidation_roots: tuple[Stage, ...]
    next_stage: Stage | None
    failure: FailureRecord
    original_failure: FailureRecord | None = None


def next_stage(
    state: RunState,
    expectations: Mapping[Stage, CheckpointExpectation],
    checkpoint_authority: CheckpointAuthority,
) -> Stage | None:
    """Return the earliest cognitive stage without a matching checkpoint binding."""
    if state.disposition is not RunDisposition.ACTIVE:
        return None
    outputs = {output.stage: output for output in state.stage_outputs}
    for stage in Stage:
        expectation = expectations.get(stage)
        checkpoint = state.checkpoints.get(stage)
        if expectation is None or checkpoint is None:
            return stage
        output = outputs.get(stage)
        if output is None or output.content_hash != checkpoint.output_manifest_hash:
            return stage
        if not checkpoint_authority.is_reusable(
            checkpoint,
            stage=stage,
            contract_hash=expectation.contract_hash,
            input_hashes=expectation.input_hashes,
        ):
            return stage
    return None


def invalidate_from(state: RunState, owner: Stage) -> RunState:
    """Remove one stage and all graph descendants while safely closing an iteration."""
    invalid = _descendants(owner)
    updates: dict[str, object] = {
        "checkpoints": {
            stage: checkpoint for stage, checkpoint in state.checkpoints.items() if stage not in invalid
        },
        "stage_outputs": tuple(output for output in state.stage_outputs if output.stage not in invalid),
        "current_stage": owner,
        "iteration_open": False,
    }

    if Stage.ANALYST in invalid:
        updates["requirements_package"] = None
    if Stage.ARCHITECT_OUTLINE in invalid:
        updates["change_outline"] = None
    if Stage.ARCHITECT_TASKS in invalid:
        updates["task_definition_manifest"] = None
        updates["task_status_manifest"] = None
    if Stage.PROGRAMMER in invalid:
        updates["product_change_manifest"] = None
        updates["build_identity"] = None
    if Stage.VERIFICATION in invalid:
        updates["verification_result"] = None
    if Stage.TESTER in invalid:
        updates["browser_result"] = None
    if Stage.REVIEWER in invalid:
        updates.update(
            {
                "review_manifest": None,
                "review_result": None,
                "prefinalization_ticket_projection": None,
                "commit_sha": None,
                "pushed_sha": None,
                "linear_done_receipt": None,
                "finalization_eligible": False,
                "finalization": None,
                "finalization_evidence": None,
            }
        )
    return state.model_copy(update=updates)


def route_failure(state: RunState, failure: FailureRecord) -> RouteDecision:
    """Classify every failure without calling external systems or recursively rerouting."""
    if state.disposition is not RunDisposition.ACTIVE:
        return _gated_state_route(state, failure)

    if failure.failure_class is FailureClass.AMBIGUITY:
        return _human_review(failure)

    if (
        failure.failure_class is FailureClass.BUDGET_EXHAUSTED
        and failure.failure_source is FailureSource.SUPERVISOR
    ):
        return _human_review(failure)

    if failure.failure_class is FailureClass.INVALID_OUTPUT:
        if _is_retryable_invalid_output(state, failure):
            return _active_retry(failure, failure.owner_stage)

    if failure.failure_class is FailureClass.PRODUCT:
        if failure.owner_stage is Stage.ANALYST:
            return _human_review(failure)
        if (
            failure.owner_stage is Stage.PROGRAMMER
            and failure.failure_source in _PRODUCT_EXECUTION_SOURCES
            and failure.finding_kind in {FindingKind.IMPLEMENTATION_MISMATCH, FindingKind.SCENARIO_MISMATCH}
        ):
            return _active_retry(failure, Stage.PROGRAMMER)
        if (
            failure.failure_source is FailureSource.REVIEW
            and failure.finding_kind is FindingKind.ARTIFACT_MISMATCH
            and failure.owner_stage in _ARCHITECT_STAGES
            and failure.cited_ids
            and failure.evidence_refs
        ):
            return _active_retry(failure, failure.owner_stage)

    if failure.failure_class is FailureClass.ORCHESTRATION:
        if failure.failure_source in _REPAIR_SOURCES:
            return RouteDecision(
                disposition=RunDisposition.REPAIR_REQUIRED,
                invalidation_roots=(),
                next_stage=None,
                failure=failure,
            )
        if failure.failure_source in _HUMAN_REVIEW_ORCHESTRATION_SOURCES:
            return _human_review(failure)

    if _is_terminal_invalid_routing(failure):
        return _human_review(failure)
    return _human_review(_invalid_routing_failure(failure), original_failure=failure)


def apply_route(state: RunState, decision: RouteDecision) -> RunState:
    """Apply a pure routing decision, preserving failure history and closing the iteration."""
    if state.disposition is not RunDisposition.ACTIVE:
        gate = _gated_state_route(state, decision.failure)
        return state.model_copy(
            update={
                "disposition": gate.disposition,
                "iteration_open": False,
                "failure_history": (*state.failure_history, gate.failure),
            }
        )
    routed = state
    for owner in decision.invalidation_roots:
        routed = invalidate_from(routed, owner)
    failures = (*routed.failure_history,)
    if decision.original_failure is not None:
        failures = (*failures, decision.original_failure)
    updates: dict[str, object] = {
        "disposition": decision.disposition,
        "iteration_open": False,
        "failure_history": (*failures, decision.failure),
    }
    if decision.next_stage is not None:
        updates["current_stage"] = decision.next_stage
    return routed.model_copy(update=updates)


def _descendants(owner: Stage) -> frozenset[Stage]:
    invalid = {owner}
    while added := {
        stage for stage, requirements in DEPENDENCIES.items() if requirements.intersection(invalid)
    }.difference(invalid):
        invalid.update(added)
    return frozenset(invalid)


def _active_retry(failure: FailureRecord, stage: Stage) -> RouteDecision:
    return RouteDecision(
        disposition=RunDisposition.ACTIVE,
        invalidation_roots=(stage,),
        next_stage=stage,
        failure=failure,
    )


def _is_retryable_invalid_output(state: RunState, failure: FailureRecord) -> bool:
    return (
        state.iteration_open
        and failure.failure_source is FailureSource.ARTIFACT
        and failure.finding_kind is FindingKind.INVALID_UNIT_OUTPUT
        and failure.owner_stage is state.current_stage
    )


def _gated_state_route(state: RunState, failure: FailureRecord) -> RouteDecision:
    if state.disposition is RunDisposition.WAITING_MCP:
        return _human_review(failure)
    return RouteDecision(
        disposition=state.disposition,
        invalidation_roots=(),
        next_stage=None,
        failure=failure,
    )


def _human_review(
    failure: FailureRecord,
    *,
    original_failure: FailureRecord | None = None,
) -> RouteDecision:
    return RouteDecision(
        disposition=RunDisposition.HUMAN_REVIEW,
        invalidation_roots=(),
        next_stage=None,
        failure=failure,
        original_failure=original_failure,
    )


def _invalid_routing_failure(failure: FailureRecord) -> FailureRecord:
    return FailureRecord(
        failure_class=FailureClass.ORCHESTRATION,
        failure_source=FailureSource.SUPERVISOR,
        finding_kind=FindingKind.INVALID_ROUTING,
        cited_ids=failure.cited_ids,
        evidence_refs=failure.evidence_refs,
        observed_revision=failure.observed_revision,
    )


def _is_terminal_invalid_routing(failure: FailureRecord) -> bool:
    return (
        failure.failure_class is FailureClass.ORCHESTRATION
        and failure.failure_source is FailureSource.SUPERVISOR
        and failure.finding_kind is FindingKind.INVALID_ROUTING
    )
