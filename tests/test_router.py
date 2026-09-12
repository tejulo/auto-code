from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from auto_code.checkpoint import CheckpointAuthority
from auto_code.contracts import (
    Checkpoint,
    EvidenceRef,
    FailureClass,
    FailureRecord,
    FailureSource,
    FindingKind,
    RunDisposition,
    RunState,
    Stage,
    StageOutput,
    TaskDefinition,
    TaskDefinitionManifest,
    TaskStatus,
    TaskStatusManifest,
    UnitStatus,
)
from auto_code.router import (
    CheckpointExpectation,
    apply_route,
    invalidate_from,
    next_stage,
    route_failure,
)
from auto_code.state import EMPTY_STATE_HASH, InvalidStateTransition, RunStateStore


def digest(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def expectation_for(stage: Stage) -> CheckpointExpectation:
    return CheckpointExpectation(
        contract_hash=digest(f"contract:{stage.value}"),
        input_hashes={"upstream": digest(f"input:{stage.value}")},
    )


def all_expectations() -> dict[Stage, CheckpointExpectation]:
    return {stage: expectation_for(stage) for stage in Stage}


@pytest.fixture
def checkpoint_authority(tmp_path: Path) -> CheckpointAuthority:
    return CheckpointAuthority(tmp_path)


def approved(
    authority: CheckpointAuthority,
    stage: Stage,
    *,
    contract_hash: str | None = None,
    input_hashes: dict[str, str] | None = None,
) -> Checkpoint:
    expectation = expectation_for(stage)
    return authority.issue(
        stage=stage,
        contract_hash=contract_hash or expectation.contract_hash,
        input_hashes=input_hashes if input_hashes is not None else expectation.input_hashes,
        output_manifest_hash=digest(f"output:{stage.value}"),
        validator="test-validator",
        validator_version="1",
        validation_receipt_hash=digest(f"receipt:{stage.value}"),
    )


def unissued_checkpoint(stage: Stage) -> Checkpoint:
    expectation = expectation_for(stage)
    return Checkpoint(
        stage=stage,
        contract_hash=expectation.contract_hash,
        input_hashes=expectation.input_hashes,
        output_manifest_hash=digest(f"unissued-output:{stage.value}"),
        validator="test-validator",
        validator_version="1",
        validation_receipt_hash=digest(f"unissued-receipt:{stage.value}"),
    )


def stage_outputs_for(checkpoints: dict[Stage, Checkpoint]) -> tuple[StageOutput, ...]:
    return tuple(
        StageOutput(stage=stage, content_hash=checkpoint.output_manifest_hash)
        for stage, checkpoint in checkpoints.items()
    )


def evidence() -> EvidenceRef:
    return EvidenceRef(
        relative_path="evidence/review/finding.json",
        sha256=digest("review-finding"),
        media_type="application/json",
        creator="reviewer",
    )


def empty_state() -> RunState:
    return RunState(
        run_id="run-1",
        ticket_id="ENG-1",
        repository_id="repo-1",
        max_crew_iterations=3,
    )


def fully_approved_state(
    authority: CheckpointAuthority,
    *,
    iteration_open: bool = False,
    finalization_eligible: bool = False,
) -> RunState:
    tasks = (TaskDefinition(task_id="1.1", text="Implement routing"),)
    definition = TaskDefinitionManifest(
        definition_hash=hashlib.sha256(
            b'[{"task_id":"1.1","text":"Implement routing"}]'
        ).hexdigest(),
        tasks=tasks,
    )
    statuses = TaskStatusManifest(
        definition_hash=definition.definition_hash,
        statuses=(TaskStatus(task_id="1.1", status=UnitStatus.CHECKED),),
    )
    checkpoints = {stage: approved(authority, stage) for stage in Stage}
    return RunState(
        run_id="run-1",
        ticket_id="ENG-1",
        repository_id="repo-1",
        max_crew_iterations=3,
        crew_iteration_count=1 if iteration_open else 0,
        iteration_open=iteration_open,
        current_stage=Stage.REVIEWER,
        requirements_package="requirements-v1",
        change_outline="change-outline-v1",
        stage_outputs=stage_outputs_for(checkpoints),
        task_definition_manifest=definition,
        task_status_manifest=statuses,
        product_change_manifest="product-change-v1",
        build_identity="build-v1",
        verification_result="verification-v1",
        browser_result="browser-v1",
        review_manifest="review-manifest-v1",
        review_result="review-result-v1",
        checkpoints=checkpoints,
        prefinalization_ticket_projection="ticket-projection-v1",
        commit_sha="commit-v1",
        pushed_sha="pushed-v1",
        linear_done_receipt="linear-done-v1",
        finalization_eligible=finalization_eligible,
        finalization="finalization-v1",
    )


def test_next_stage_follows_cognitive_order_and_stops_before_finalization(
    checkpoint_authority: CheckpointAuthority,
) -> None:
    state = empty_state()
    expectations = all_expectations()

    for stage in Stage:
        assert next_stage(state, expectations, checkpoint_authority) is stage
        checkpoint = approved(checkpoint_authority, stage)
        state = state.model_copy(
            update={
                "checkpoints": {**state.checkpoints, stage: checkpoint},
                "stage_outputs": (*state.stage_outputs, StageOutput(stage=stage, content_hash=checkpoint.output_manifest_hash)),
            }
        )

    assert next_stage(state, expectations, checkpoint_authority) is None


def test_next_stage_restarts_at_checkpoint_without_mandatory_expectation(
    checkpoint_authority: CheckpointAuthority,
) -> None:
    checkpoints = {Stage.ANALYST: approved(checkpoint_authority, Stage.ANALYST)}
    state = empty_state().model_copy(update={"checkpoints": checkpoints, "stage_outputs": stage_outputs_for(checkpoints)})
    expectations = all_expectations()
    del expectations[Stage.ANALYST]

    assert next_stage(state, expectations, checkpoint_authority) is Stage.ANALYST


def test_next_stage_restarts_at_first_checkpoint_with_stale_input_binding(
    checkpoint_authority: CheckpointAuthority,
) -> None:
    checkpoints = {
        Stage.ANALYST: approved(checkpoint_authority, Stage.ANALYST),
        Stage.ARCHITECT_OUTLINE: approved(checkpoint_authority, Stage.ARCHITECT_OUTLINE),
        Stage.ARCHITECT_PROPOSAL: approved(
            checkpoint_authority,
            Stage.ARCHITECT_PROPOSAL,
            input_hashes={"upstream": digest("stale-proposal-input")},
        ),
        Stage.ARCHITECT_SPECS: approved(checkpoint_authority, Stage.ARCHITECT_SPECS),
    }
    state = empty_state().model_copy(update={"checkpoints": checkpoints, "stage_outputs": stage_outputs_for(checkpoints)})

    assert next_stage(state, all_expectations(), checkpoint_authority) is Stage.ARCHITECT_PROPOSAL


def test_next_stage_rejects_a_matching_but_unissued_checkpoint(
    checkpoint_authority: CheckpointAuthority,
) -> None:
    checkpoints = {Stage.ANALYST: unissued_checkpoint(Stage.ANALYST)}
    state = empty_state().model_copy(update={"checkpoints": checkpoints, "stage_outputs": stage_outputs_for(checkpoints)})

    assert next_stage(state, all_expectations(), checkpoint_authority) is Stage.ANALYST


def test_next_stage_rejects_an_issued_checkpoint_without_a_matching_output_binding(
    checkpoint_authority: CheckpointAuthority,
) -> None:
    checkpoint = approved(checkpoint_authority, Stage.ANALYST)
    state = RunState.model_construct(
        run_id="run-1",
        ticket_id="ENG-1",
        repository_id="repo-1",
        max_crew_iterations=3,
        checkpoints={Stage.ANALYST: checkpoint},
        stage_outputs=(),
    )

    assert next_stage(state, all_expectations(), checkpoint_authority) is Stage.ANALYST


def test_invalidating_tasks_clears_task_manifests_and_every_descendant_output(
    checkpoint_authority: CheckpointAuthority,
) -> None:
    routed = invalidate_from(fully_approved_state(checkpoint_authority, iteration_open=True), Stage.ARCHITECT_TASKS)

    assert set(routed.checkpoints) == {
        Stage.ANALYST,
        Stage.ARCHITECT_OUTLINE,
        Stage.ARCHITECT_PROPOSAL,
        Stage.ARCHITECT_SPECS,
        Stage.ARCHITECT_DESIGN,
    }
    assert {output.stage for output in routed.stage_outputs} == set(routed.checkpoints)
    assert routed.task_definition_manifest is None
    assert routed.task_status_manifest is None
    assert routed.product_change_manifest is None
    assert routed.build_identity is None
    assert routed.verification_result is None
    assert routed.browser_result is None
    assert routed.review_manifest is None
    assert routed.review_result is None
    assert routed.prefinalization_ticket_projection is None
    assert routed.commit_sha is None
    assert routed.pushed_sha is None
    assert routed.linear_done_receipt is None
    assert routed.finalization is None
    assert routed.finalization_eligible is False
    assert routed.current_stage is Stage.ARCHITECT_TASKS
    assert routed.iteration_open is False


def test_replacing_task_definitions_requires_clearing_task_checkpoint_and_restarts_there(
    tmp_path: Path,
    checkpoint_authority: CheckpointAuthority,
) -> None:
    first_definition = TaskDefinitionManifest(
        definition_hash=hashlib.sha256(b'[{"task_id":"1.1","text":"Implement routing"}]').hexdigest(),
        tasks=(TaskDefinition(task_id="1.1", text="Implement routing"),),
    )
    replacement_definition = TaskDefinitionManifest(
        definition_hash=hashlib.sha256(b'[{"task_id":"1.1","text":"Implement safer routing"}]').hexdigest(),
        tasks=(TaskDefinition(task_id="1.1", text="Implement safer routing"),),
    )
    task_stages = tuple(Stage)[: tuple(Stage).index(Stage.ARCHITECT_TASKS) + 1]
    checkpoints = {stage: approved(checkpoint_authority, stage) for stage in task_stages}
    store = RunStateStore(tmp_path, "run-1")
    initial = store.compare_and_swap(0, EMPTY_STATE_HASH, empty_state())
    defined = store.compare_and_swap(
        initial.revision,
        initial.state_hash,
        initial.state.model_copy(
            update={
                "task_definition_manifest": first_definition,
            }
        ),
    )
    first = store.compare_and_swap(
        defined.revision,
        defined.state_hash,
        defined.state.model_copy(
            update={
                "checkpoints": checkpoints,
                "stage_outputs": stage_outputs_for(checkpoints),
                "task_status_manifest": TaskStatusManifest(
                    definition_hash=first_definition.definition_hash,
                    statuses=(TaskStatus(task_id="1.1", status=UnitStatus.UNCHECKED),),
                ),
            }
        ),
    )
    stale = first.state.model_copy(
        update={
            "task_definition_manifest": replacement_definition,
            "task_status_manifest": None,
        }
    )

    assert Stage.ARCHITECT_TASKS in stale.checkpoints
    assert any(output.stage is Stage.ARCHITECT_TASKS for output in stale.stage_outputs)
    with pytest.raises(InvalidStateTransition, match="Task definition"):
        store.compare_and_swap(first.revision, first.state_hash, stale)

    assert store.load() == first
    cleared = stale.model_copy(
        update={
            "checkpoints": {
                stage: checkpoint for stage, checkpoint in stale.checkpoints.items() if stage is not Stage.ARCHITECT_TASKS
            },
            "stage_outputs": tuple(
                output for output in stale.stage_outputs if output.stage is not Stage.ARCHITECT_TASKS
            ),
        }
    )
    persisted = store.compare_and_swap(first.revision, first.state_hash, cleared)

    assert Stage.ARCHITECT_TASKS not in persisted.state.checkpoints
    assert all(output.stage is not Stage.ARCHITECT_TASKS for output in persisted.state.stage_outputs)
    assert next_stage(persisted.state, all_expectations(), checkpoint_authority) is Stage.ARCHITECT_TASKS


def test_invalidating_reviewer_clears_finalization_eligibility(
    checkpoint_authority: CheckpointAuthority,
) -> None:
    routed = invalidate_from(
        fully_approved_state(checkpoint_authority, finalization_eligible=True),
        Stage.REVIEWER,
    )

    assert routed.finalization_eligible is False
    assert routed.finalization is None


def test_product_implementation_mismatch_reroutes_to_programmer_and_preserves_planning(
    checkpoint_authority: CheckpointAuthority,
) -> None:
    state = fully_approved_state(checkpoint_authority, iteration_open=True)
    failure = FailureRecord(
        failure_class=FailureClass.PRODUCT,
        failure_source=FailureSource.REVIEW,
        finding_kind=FindingKind.IMPLEMENTATION_MISMATCH,
        owner_stage=Stage.PROGRAMMER,
        cited_ids=("REQ-1",),
        evidence_refs=(evidence(),),
    )

    decision = route_failure(state, failure)
    routed = apply_route(state, decision)

    assert decision.disposition is RunDisposition.ACTIVE
    assert decision.invalidation_roots == (Stage.PROGRAMMER,)
    assert decision.next_stage is Stage.PROGRAMMER
    assert set(routed.checkpoints) == {
        Stage.ANALYST,
        Stage.ARCHITECT_OUTLINE,
        Stage.ARCHITECT_PROPOSAL,
        Stage.ARCHITECT_SPECS,
        Stage.ARCHITECT_DESIGN,
        Stage.ARCHITECT_TASKS,
    }
    assert routed.task_definition_manifest is not None
    assert routed.task_status_manifest is not None
    assert routed.product_change_manifest is None
    assert routed.build_identity is None
    assert routed.verification_result is None
    assert routed.browser_result is None
    assert routed.review_manifest is None
    assert routed.review_result is None
    assert routed.finalization is None
    assert routed.current_stage is Stage.PROGRAMMER
    assert routed.iteration_open is False
    assert routed.failure_history[-1] == failure


def test_browser_scenario_failure_routes_to_programmer(
    checkpoint_authority: CheckpointAuthority,
) -> None:
    state = fully_approved_state(checkpoint_authority, iteration_open=True)
    failure = FailureRecord(
        failure_class=FailureClass.PRODUCT,
        failure_source=FailureSource.BROWSER,
        finding_kind=FindingKind.SCENARIO_MISMATCH,
        owner_stage=Stage.PROGRAMMER,
        cited_ids=("BROWSER-1",),
        evidence_refs=(evidence(),),
    )

    decision = route_failure(state, failure)

    assert decision.disposition is RunDisposition.ACTIVE
    assert decision.invalidation_roots == (Stage.PROGRAMMER,)
    assert decision.next_stage is Stage.PROGRAMMER


def test_browser_cleanup_orchestration_failure_requires_repair(
    checkpoint_authority: CheckpointAuthority,
) -> None:
    state = fully_approved_state(checkpoint_authority, iteration_open=True)
    failure = FailureRecord(
        failure_class=FailureClass.ORCHESTRATION,
        failure_source=FailureSource.BROWSER,
        finding_kind=FindingKind.INVALID_UNIT_OUTPUT,
    )

    decision = route_failure(state, failure)

    assert decision.disposition is RunDisposition.REPAIR_REQUIRED
    assert decision.invalidation_roots == ()
    assert decision.next_stage is None


def test_cited_architect_artifact_finding_reroutes_to_the_cited_artifact(
    checkpoint_authority: CheckpointAuthority,
) -> None:
    state = fully_approved_state(checkpoint_authority, iteration_open=True)
    failure = FailureRecord(
        failure_class=FailureClass.PRODUCT,
        failure_source=FailureSource.REVIEW,
        finding_kind=FindingKind.ARTIFACT_MISMATCH,
        owner_stage=Stage.ARCHITECT_DESIGN,
        cited_ids=("DESIGN-1",),
        evidence_refs=(evidence(),),
    )

    decision = route_failure(state, failure)
    routed = apply_route(state, decision)

    assert decision.invalidation_roots == (Stage.ARCHITECT_DESIGN,)
    assert decision.next_stage is Stage.ARCHITECT_DESIGN
    assert Stage.ARCHITECT_SPECS in routed.checkpoints
    assert Stage.ARCHITECT_DESIGN not in routed.checkpoints
    assert Stage.ARCHITECT_TASKS not in routed.checkpoints
    assert Stage.PROGRAMMER not in routed.checkpoints
    assert routed.current_stage is Stage.ARCHITECT_DESIGN


@pytest.mark.parametrize(
    ("cited_ids", "evidence_refs"),
    (((), (evidence(),)), (("DESIGN-1",), ())),
)
def test_uncorroborated_architect_artifact_finding_enters_invalid_routing_review(
    checkpoint_authority: CheckpointAuthority,
    cited_ids: tuple[str, ...],
    evidence_refs: tuple[EvidenceRef, ...],
) -> None:
    decision = route_failure(
        fully_approved_state(checkpoint_authority),
        FailureRecord(
            failure_class=FailureClass.PRODUCT,
            failure_source=FailureSource.REVIEW,
            finding_kind=FindingKind.ARTIFACT_MISMATCH,
            owner_stage=Stage.ARCHITECT_DESIGN,
            cited_ids=cited_ids,
            evidence_refs=evidence_refs,
        ),
    )

    assert decision.disposition is RunDisposition.HUMAN_REVIEW
    assert decision.invalidation_roots == ()
    assert decision.next_stage is None
    assert decision.failure.failure_class is FailureClass.ORCHESTRATION
    assert decision.failure.failure_source is FailureSource.SUPERVISOR
    assert decision.failure.finding_kind is FindingKind.INVALID_ROUTING


@pytest.mark.parametrize("stage", list(Stage))
def test_invalid_unit_output_repeats_the_same_cognitive_stage_and_closes_iteration(
    checkpoint_authority: CheckpointAuthority,
    stage: Stage,
) -> None:
    state = fully_approved_state(checkpoint_authority, iteration_open=True).model_copy(
        update={"current_stage": stage}
    )
    failure = FailureRecord(
        failure_class=FailureClass.INVALID_OUTPUT,
        failure_source=FailureSource.ARTIFACT,
        finding_kind=FindingKind.INVALID_UNIT_OUTPUT,
        owner_stage=stage,
    )

    decision = route_failure(state, failure)
    routed = apply_route(state, decision)

    assert decision.disposition is RunDisposition.ACTIVE
    assert decision.invalidation_roots == (stage,)
    assert decision.next_stage is stage
    assert routed.disposition is RunDisposition.ACTIVE
    assert routed.current_stage is stage
    assert routed.iteration_open is False
    assert stage not in routed.checkpoints
    assert routed.failure_history[-1] == failure


@pytest.mark.parametrize(
    "source",
    (
        FailureSource.PREFLIGHT,
        FailureSource.FINALIZATION,
        FailureSource.TRANSPORT,
        FailureSource.SUPERVISOR,
    ),
)
def test_invalid_unit_output_from_a_non_cognitive_source_enters_human_review_without_invalidation(
    checkpoint_authority: CheckpointAuthority,
    source: FailureSource,
) -> None:
    state = fully_approved_state(checkpoint_authority, iteration_open=True).model_copy(
        update={"current_stage": Stage.PROGRAMMER}
    )
    routed = apply_route(
        state,
        route_failure(
            state,
            FailureRecord(
                failure_class=FailureClass.INVALID_OUTPUT,
                failure_source=source,
                finding_kind=FindingKind.INVALID_UNIT_OUTPUT,
                owner_stage=Stage.PROGRAMMER,
            ),
        ),
    )

    assert routed.disposition is RunDisposition.HUMAN_REVIEW
    assert routed.current_stage is Stage.PROGRAMMER
    assert routed.iteration_open is False
    assert routed.checkpoints == state.checkpoints
    assert routed.failure_history[-1].failure_class is FailureClass.ORCHESTRATION
    assert routed.failure_history[-1].failure_source is FailureSource.SUPERVISOR
    assert next_stage(routed, all_expectations(), checkpoint_authority) is None


@pytest.mark.parametrize(
    ("current_stage", "owner_stage"),
    ((Stage.ARCHITECT_DESIGN, Stage.PROGRAMMER), (Stage.PROGRAMMER, Stage.TESTER)),
)
def test_invalid_unit_output_with_a_mismatched_owner_preserves_valid_units_and_enters_human_review(
    checkpoint_authority: CheckpointAuthority,
    current_stage: Stage,
    owner_stage: Stage,
) -> None:
    state = fully_approved_state(checkpoint_authority, iteration_open=True).model_copy(
        update={"current_stage": current_stage}
    )
    routed = apply_route(
        state,
        route_failure(
            state,
            FailureRecord(
                failure_class=FailureClass.INVALID_OUTPUT,
                failure_source=FailureSource.ARTIFACT,
                finding_kind=FindingKind.INVALID_UNIT_OUTPUT,
                owner_stage=owner_stage,
            ),
        ),
    )

    assert routed.disposition is RunDisposition.HUMAN_REVIEW
    assert routed.current_stage is current_stage
    assert routed.iteration_open is False
    assert routed.checkpoints == state.checkpoints
    assert routed.failure_history[-1].finding_kind is FindingKind.INVALID_ROUTING


@pytest.mark.parametrize(
    "disposition",
    (
        RunDisposition.HUMAN_REVIEW,
        RunDisposition.REPAIR_REQUIRED,
    ),
)
def test_persisted_gated_state_cannot_be_reactivated_by_an_ordinary_failure(
    tmp_path: Path,
    checkpoint_authority: CheckpointAuthority,
    disposition: RunDisposition,
) -> None:
    iteration_open = disposition in {RunDisposition.HUMAN_REVIEW, RunDisposition.REPAIR_REQUIRED}
    state = RunState(
        run_id=f"run-{disposition.value}",
        ticket_id="ENG-1",
        repository_id="repo-1",
        max_crew_iterations=3,
        disposition=disposition,
        crew_iteration_count=1 if iteration_open else 0,
        iteration_open=iteration_open,
        current_stage=Stage.PROGRAMMER,
    )
    store = RunStateStore(tmp_path, state.run_id)
    initial = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(
            run_id=state.run_id,
            ticket_id=state.ticket_id,
            repository_id=state.repository_id,
            max_crew_iterations=state.max_crew_iterations,
        ),
    )
    gated = store.compare_and_swap(initial.revision, initial.state_hash, state)
    failure = FailureRecord(
        failure_class=FailureClass.PRODUCT,
        failure_source=FailureSource.REVIEW,
        finding_kind=FindingKind.IMPLEMENTATION_MISMATCH,
        owner_stage=Stage.PROGRAMMER,
    )

    decision = route_failure(gated.state, failure)
    routed = apply_route(gated.state, decision)
    persisted = store.compare_and_swap(gated.revision, gated.state_hash, routed).state

    assert decision.disposition is disposition
    assert decision.invalidation_roots == ()
    assert decision.next_stage is None
    assert persisted.disposition is disposition
    assert persisted.current_stage is Stage.PROGRAMMER
    assert persisted.iteration_open is False
    assert persisted.failure_history[-1] == failure
    assert next_stage(persisted, all_expectations(), checkpoint_authority) is None


@pytest.mark.parametrize(
    "source",
    (
        FailureSource.TRANSPORT,
        FailureSource.ARTIFACT,
        FailureSource.VERIFICATION,
        FailureSource.BROWSER,
        FailureSource.REVIEW,
    ),
)
def test_orchestration_execution_failures_require_repair(
    checkpoint_authority: CheckpointAuthority,
    source: FailureSource,
) -> None:
    state = fully_approved_state(checkpoint_authority, iteration_open=True)
    decision = route_failure(
        state,
        FailureRecord(
            failure_class=FailureClass.ORCHESTRATION,
            failure_source=source,
            finding_kind=FindingKind.INVALID_UNIT_OUTPUT,
            owner_stage=Stage.PROGRAMMER,
        ),
    )
    routed = apply_route(state, decision)

    assert decision.disposition is RunDisposition.REPAIR_REQUIRED
    assert decision.invalidation_roots == ()
    assert decision.next_stage is None
    assert routed.disposition is RunDisposition.REPAIR_REQUIRED
    assert routed.iteration_open is False
    assert set(routed.checkpoints) == set(Stage)


@pytest.mark.parametrize(
    "source",
    (FailureSource.PREFLIGHT, FailureSource.FINALIZATION, FailureSource.SUPERVISOR),
)
def test_orchestration_preflight_finalization_and_repair_failures_enter_human_review(
    checkpoint_authority: CheckpointAuthority,
    source: FailureSource,
) -> None:
    decision = route_failure(
        fully_approved_state(checkpoint_authority),
        FailureRecord(
            failure_class=FailureClass.ORCHESTRATION,
            failure_source=source,
            finding_kind=FindingKind.INVALID_UNIT_OUTPUT,
        ),
    )

    assert decision.disposition is RunDisposition.HUMAN_REVIEW
    assert decision.invalidation_roots == ()
    assert decision.next_stage is None


@pytest.mark.parametrize("source", list(FailureSource))
def test_ambiguity_from_any_source_enters_human_review(
    checkpoint_authority: CheckpointAuthority,
    source: FailureSource,
) -> None:
    decision = route_failure(
        fully_approved_state(checkpoint_authority),
        FailureRecord(
            failure_class=FailureClass.AMBIGUITY,
            failure_source=source,
            finding_kind=FindingKind.REQUIREMENTS_MISMATCH,
            owner_stage=Stage.ANALYST,
        ),
    )

    assert decision.disposition is RunDisposition.HUMAN_REVIEW
    assert decision.invalidation_roots == ()
    assert decision.next_stage is None


def test_budget_exhaustion_from_supervisor_enters_human_review(
    checkpoint_authority: CheckpointAuthority,
) -> None:
    decision = route_failure(
        fully_approved_state(checkpoint_authority),
        FailureRecord(
            failure_class=FailureClass.BUDGET_EXHAUSTED,
            failure_source=FailureSource.SUPERVISOR,
            finding_kind=FindingKind.REQUIREMENTS_MISMATCH,
        ),
    )

    assert decision.disposition is RunDisposition.HUMAN_REVIEW
    assert decision.invalidation_roots == ()
    assert decision.next_stage is None


def test_product_analyst_attribution_enters_human_review_without_invalidating_planning(
    checkpoint_authority: CheckpointAuthority,
) -> None:
    state = fully_approved_state(checkpoint_authority, iteration_open=True)
    decision = route_failure(
        state,
        FailureRecord(
            failure_class=FailureClass.PRODUCT,
            failure_source=FailureSource.REVIEW,
            finding_kind=FindingKind.REQUIREMENTS_MISMATCH,
            owner_stage=Stage.ANALYST,
            cited_ids=("REQ-1",),
            evidence_refs=(evidence(),),
        ),
    )
    routed = apply_route(state, decision)

    assert decision.disposition is RunDisposition.HUMAN_REVIEW
    assert decision.invalidation_roots == ()
    assert routed.checkpoints == state.checkpoints
    assert routed.iteration_open is False


def test_unlisted_failure_converts_once_to_terminal_invalid_routing_review(
    checkpoint_authority: CheckpointAuthority,
) -> None:
    state = fully_approved_state(checkpoint_authority, iteration_open=True)
    unlisted = FailureRecord(
        failure_class=FailureClass.PRODUCT,
        failure_source=FailureSource.TRANSPORT,
        finding_kind=FindingKind.ARTIFACT_MISMATCH,
        owner_stage=Stage.TESTER,
    )

    decision = route_failure(state, unlisted)
    routed = apply_route(state, decision)
    repeated = route_failure(state, decision.failure)

    assert decision.disposition is RunDisposition.HUMAN_REVIEW
    assert decision.invalidation_roots == ()
    assert decision.next_stage is None
    assert decision.failure.failure_class is FailureClass.ORCHESTRATION
    assert decision.failure.failure_source is FailureSource.SUPERVISOR
    assert decision.failure.finding_kind is FindingKind.INVALID_ROUTING
    assert routed.disposition is RunDisposition.HUMAN_REVIEW
    assert routed.iteration_open is False
    assert routed.failure_history[-2:] == (unlisted, decision.failure)
    assert routed.failure_history[-1] == decision.failure
    assert repeated.disposition is RunDisposition.HUMAN_REVIEW
    assert repeated.failure == decision.failure
