from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
import json
from pathlib import Path

from pydantic import ValidationError
import pytest

from auto_code.checkpoint import CheckpointAuthority
from auto_code.cli import TrustedRuntimeConfig, main
from auto_code.contracts import (
    FailureClass,
    FailureRecord,
    FailureSource,
    FindingKind,
    EffectIntention,
    EffectIntentionPayload,
    McpActionRequest,
    PendingExternalRequest,
    ReviewResult,
    RunDisposition,
    RunState,
    RunnerIdentity,
    Stage,
    StageOutput,
    StepResult,
    TaskDefinition,
    TaskDefinitionManifest,
    TaskStatus,
    TaskStatusManifest,
    UnitStatus,
)
from auto_code.router import CheckpointExpectation
from auto_code.state import EMPTY_STATE_HASH, RunStateStore, StateGeneration
from auto_code.supervisor import StageExecution, StepKind, Supervisor, SupervisorDependencies


def digest(value: str) -> str:
    return sha256(value.encode("ascii")).hexdigest()


def runner_identity() -> RunnerIdentity:
    return RunnerIdentity(
        content_hash="a" * 64,
        source_sha="b" * 64,
        dependency_lock_hash="c" * 64,
        contract_bundle_hash="d" * 64,
        runner_archive_hash="e" * 64,
        built_at="2026-09-12T00:00:00Z",
    )


def expectations() -> dict[Stage, CheckpointExpectation]:
    return {
        stage: CheckpointExpectation(
            contract_hash=digest(f"contract:{stage.value}"),
            input_hashes={"upstream": digest(f"input:{stage.value}")},
        )
        for stage in Stage
    }


def task_definition() -> TaskDefinitionManifest:
    task = TaskDefinition(task_id="1.1", text="Implement the requested behavior")
    return TaskDefinitionManifest(definition_hash=digest('[{"task_id":"1.1","text":"Implement the requested behavior"}]'), tasks=(task,))


def task_status(definition: TaskDefinitionManifest) -> TaskStatusManifest:
    return TaskStatusManifest(
        definition_hash=definition.definition_hash,
        statuses=(TaskStatus(task_id="1.1", status=UnitStatus.UNCHECKED),),
    )


def approved_planning_state(authority: CheckpointAuthority, expected: dict[Stage, CheckpointExpectation]) -> RunState:
    planning = tuple(Stage)[: tuple(Stage).index(Stage.PROGRAMMER)]
    checkpoints = {
        stage: authority.issue(
            stage=stage,
            contract_hash=expected[stage].contract_hash,
            input_hashes=expected[stage].input_hashes,
            output_manifest_hash=digest(f"output:{stage.value}"),
            validator="test_validator",
            validator_version="1",
            validation_receipt_hash=digest(f"receipt:{stage.value}"),
        )
        for stage in planning
    }
    definitions = task_definition()
    return RunState(
        run_id="run-1",
        ticket_id="ENG-1",
        repository_id="repo-1",
        max_crew_iterations=3,
        current_stage=Stage.PROGRAMMER,
        stage_outputs=tuple(
            StageOutput(stage=stage, content_hash=checkpoint.output_manifest_hash)
            for stage, checkpoint in checkpoints.items()
        ),
        task_definition_manifest=definitions,
        task_status_manifest=task_status(definitions),
        checkpoints=checkpoints,
    )


@dataclass
class FakeExecutor:
    results: dict[Stage, StageExecution | FailureRecord]

    def execute(self, stage: Stage, state: RunState) -> StageExecution | FailureRecord:
        del state
        return self.results[stage]


@dataclass(frozen=True)
class Dependencies:
    store: RunStateStore
    checkpoint_authority: CheckpointAuthority
    expectations: dict[Stage, CheckpointExpectation]
    executor: FakeExecutor

    def as_supervisor_dependencies(self) -> SupervisorDependencies:
        return SupervisorDependencies(
            store=self.store,
            checkpoint_authority=self.checkpoint_authority,
            expectations=self.expectations,
            executor=self.executor,
        )


@pytest.fixture
def dependencies(tmp_path: Path) -> Dependencies:
    store = RunStateStore(tmp_path, "run-1")
    authority = CheckpointAuthority(tmp_path)
    expected = expectations()
    return Dependencies(
        store=store,
        checkpoint_authority=authority,
        expectations=expected,
        executor=FakeExecutor(
            {
                Stage.PROGRAMMER: StageExecution(
                    output_manifest_hash=digest("programmer-output"),
                    validator="test_validator",
                    validator_version="1",
                    validation_receipt_hash=digest("programmer-receipt"),
                )
            }
        ),
    )


def persist(store: RunStateStore, state: RunState) -> StateGeneration:
    initial = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id=state.run_id, ticket_id=state.ticket_id, repository_id=state.repository_id, max_crew_iterations=3),
    )
    if state.task_status_manifest is None:
        return store.compare_and_swap(initial.revision, initial.state_hash, state)
    definitions = state.model_copy(update={"task_status_manifest": None})
    defined = store.compare_and_swap(initial.revision, initial.state_hash, definitions)
    return store.compare_and_swap(defined.revision, defined.state_hash, state)


def persist_exhausted(store: RunStateStore, state: RunState) -> StateGeneration:
    generation = persist(store, state)
    for _ in range(3):
        opened = store.compare_and_swap(
            generation.revision,
            generation.state_hash,
            generation.state.begin_iteration(),
        )
        generation = store.compare_and_swap(
            opened.revision,
            opened.state_hash,
            opened.state.model_copy(update={"iteration_open": False}),
        )
    return generation


def persist_reviewer(store: RunStateStore, state: RunState, review_manifest: str | None = None) -> StateGeneration:
    generation = persist(store, state)
    opened = generation.state.begin_iteration().model_copy(
        update={"current_stage": Stage.REVIEWER, "review_manifest": review_manifest}
    )
    return store.compare_and_swap(generation.revision, generation.state_hash, opened)


def test_product_defect_next_iteration_starts_at_programmer(
    dependencies: Dependencies,
) -> None:
    """Fails if product routing invalidates reusable planning checkpoints."""
    state = approved_planning_state(dependencies.checkpoint_authority, dependencies.expectations)
    persist(dependencies.store, state)
    supervisor = Supervisor(dependencies.as_supervisor_dependencies())

    supervisor.record_failure(FailureClass.PRODUCT, Stage.PROGRAMMER)
    generation = dependencies.store.load()
    result = supervisor.step(generation.state.run_id, generation.revision, generation.state_hash)

    assert result.kind is StepKind.CONTINUE
    assert result.stage is Stage.PROGRAMMER
    assert dependencies.checkpoint_authority.matches(
        dependencies.store.load().state.checkpoints[Stage.ARCHITECT_TASKS],
        stage=Stage.ARCHITECT_TASKS,
        contract_hash=dependencies.expectations[Stage.ARCHITECT_TASKS].contract_hash,
        input_hashes=dependencies.expectations[Stage.ARCHITECT_TASKS].input_hashes,
    )


def test_exhausted_budget_requires_human_review(dependencies: Dependencies) -> None:
    """Fails if an exhausted iteration budget starts another cognitive unit."""
    state = approved_planning_state(dependencies.checkpoint_authority, dependencies.expectations)
    persist_exhausted(dependencies.store, state)
    supervisor = Supervisor(dependencies.as_supervisor_dependencies())
    generation = dependencies.store.load()

    result = supervisor.step(generation.state.run_id, generation.revision, generation.state_hash)

    assert result.kind is StepKind.HUMAN_REVIEW
    assert result.failure is not None
    assert result.failure.failure_class is FailureClass.BUDGET_EXHAUSTED
    assert dependencies.store.load().state.finalization_eligible is False


def test_reviewer_checkpoint_and_iteration_close_are_one_generation(dependencies: Dependencies) -> None:
    """Fails if reviewer approval can persist a reusable checkpoint before closure."""
    state = approved_planning_state(dependencies.checkpoint_authority, dependencies.expectations)
    generation = persist_reviewer(dependencies.store, state, "a" * 64)
    dependencies.executor.results[Stage.REVIEWER] = StageExecution(
        output_manifest_hash=digest("reviewer-output"),
        validator="test_validator",
        validator_version="1",
        validation_receipt_hash=digest("reviewer-receipt"),
        review=ReviewResult(
            approved=True,
            review_manifest_hash="a" * 64,
            cited_ids=(),
            blocking_findings=(),
            evidence=(),
            next_action="Proceed to finalization.",
        ),
    )
    supervisor = Supervisor(dependencies.as_supervisor_dependencies())

    result = supervisor.execute_and_checkpoint(generation, Stage.REVIEWER)
    reloaded = dependencies.store.load()

    assert result.state_revision == generation.revision + 1
    assert Stage.REVIEWER in reloaded.state.checkpoints
    assert reloaded.state.iteration_open is False
    assert reloaded.state.finalization_eligible is True


def test_reviewer_rejection_closes_and_routes_in_one_generation(dependencies: Dependencies) -> None:
    """Fails if a rejected review leaves a reusable reviewer checkpoint or open iteration."""
    state = approved_planning_state(dependencies.checkpoint_authority, dependencies.expectations)
    generation = persist_reviewer(dependencies.store, state)
    dependencies.executor.results[Stage.REVIEWER] = FailureRecord(
        failure_class=FailureClass.PRODUCT,
        failure_source=FailureSource.REVIEW,
        finding_kind=FindingKind.IMPLEMENTATION_MISMATCH,
        owner_stage=Stage.PROGRAMMER,
    )
    supervisor = Supervisor(dependencies.as_supervisor_dependencies())

    result = supervisor.execute_and_checkpoint(generation, Stage.REVIEWER)
    reloaded = dependencies.store.load().state

    assert result.kind is StepKind.ITERATION_FAILED
    assert reloaded.iteration_open is False
    assert reloaded.finalization_eligible is False
    assert reloaded.current_stage is Stage.PROGRAMMER
    assert Stage.REVIEWER not in reloaded.checkpoints


def test_reviewer_approval_requires_the_persisted_review_manifest_hash(dependencies: Dependencies) -> None:
    """Fails if a reviewer can approve a result for another review manifest."""
    persisted_manifest = digest("persisted-review-manifest")
    state = approved_planning_state(dependencies.checkpoint_authority, dependencies.expectations)
    generation = persist_reviewer(dependencies.store, state, persisted_manifest)
    dependencies.executor.results[Stage.REVIEWER] = StageExecution(
        output_manifest_hash=digest("reviewer-output"),
        validator="test_validator",
        validator_version="1",
        validation_receipt_hash=digest("reviewer-receipt"),
        review=ReviewResult(
            approved=True,
            review_manifest_hash=digest("other-review-manifest"),
            cited_ids=(),
            blocking_findings=(),
            evidence=(),
            next_action="Proceed to finalization.",
        ),
    )

    result = Supervisor(dependencies.as_supervisor_dependencies()).execute_and_checkpoint(generation, Stage.REVIEWER)
    reloaded = dependencies.store.load().state

    assert result.kind is StepKind.HUMAN_REVIEW
    assert reloaded.review_manifest == persisted_manifest
    assert reloaded.finalization_eligible is False
    assert Stage.REVIEWER not in reloaded.checkpoints


def test_stage_execution_rejects_arbitrary_lifecycle_updates() -> None:
    """Fails if an executor can request a supervisor-owned disposition transition."""
    with pytest.raises(TypeError):
        StageExecution(
            output_manifest_hash=digest("output"),
            validator="test_validator",
            validator_version="1",
            validation_receipt_hash=digest("receipt"),
            state_updates={"disposition": RunDisposition.HUMAN_REVIEW},
        )


def test_mcp_step_result_requires_the_action_run_binding() -> None:
    """Fails if a correlated MCP action can target another run."""
    action = McpActionRequest.create(
        operation="query_repository",
        entity="repository",
        target="repo-1",
        expected_external_revision=None,
        run_id="run-2",
        expected_revision=1,
        expected_state_hash="a" * 64,
        arguments={},
    )

    with pytest.raises(ValidationError, match="run"):
        StepResult(
            kind=StepKind.MCP_ACTION,
            run_id="run-1",
            state_revision=1,
            state_hash="a" * 64,
            request_id=action.request_id,
            action=action,
        )


def test_unreconstructable_waiting_mcp_request_enters_persisted_human_review(dependencies: Dependencies) -> None:
    """Fails if malformed pending MCP state returns an unpersisted synthetic result."""
    state = approved_planning_state(dependencies.checkpoint_authority, dependencies.expectations)
    generation = persist(dependencies.store, state)
    pending = PendingExternalRequest(
        request_id="request-1",
        effect_id="effect-1",
        request_hash="a" * 64,
        operation="query_ticket_state",
        expected_revision=generation.revision,
        expected_state_hash=generation.state_hash,
    )
    waiting = generation.state.model_copy(
        update={
            "disposition": RunDisposition.WAITING_MCP,
            "pending_external_request": pending,
            "effect_ledger": (
                EffectIntention(
                    effect_id="effect-1",
                    sequence=1,
                    timestamp=datetime(2026, 9, 12, tzinfo=UTC),
                    payload=EffectIntentionPayload(
                        operation="query_ticket_state",
                        target="ENG-1",
                        request_hash="a" * 64,
                    ),
                ),
            ),
        }
    )
    waiting_generation = dependencies.store.compare_and_swap(generation.revision, generation.state_hash, waiting)

    result = Supervisor(dependencies.as_supervisor_dependencies()).step(
        waiting_generation.state.run_id,
        waiting_generation.revision,
        waiting_generation.state_hash,
    )
    reloaded = dependencies.store.load().state

    assert result.kind is StepKind.HUMAN_REVIEW
    assert result.failure is not None
    assert result.failure.failure_class is FailureClass.ORCHESTRATION
    assert result.failure.failure_source is FailureSource.SUPERVISOR
    assert reloaded.disposition is RunDisposition.HUMAN_REVIEW
    assert reloaded.failure_history[-1] == result.failure


def test_step_cli_dispatches_a_cas_bound_json_result(
    dependencies: Dependencies,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    """Fails if the public step command can dispatch without the exact state binding."""
    state = approved_planning_state(dependencies.checkpoint_authority, dependencies.expectations)
    generation = persist(dependencies.store, state)
    supervisor = Supervisor(dependencies.as_supervisor_dependencies())
    runtime = TrustedRuntimeConfig(
        state_root=tmp_path,
        project_root=tmp_path,
        project_policy_path=tmp_path / "auto-code.yaml",
        project_policy_hash="0" * 64,
        runner_identity=runner_identity(),
    )

    assert main(
        [
            "step",
            "--run",
            "run-1",
            "--expected-revision",
            str(generation.revision),
            "--expected-hash",
            generation.state_hash,
            "--json",
        ],
        runtime=runtime,
        supervisor_factory=lambda _: supervisor,
    ) == 0

    payload = json.loads(capsys.readouterr().out)
    assert payload["kind"] == "continue"
    assert payload["run_id"] == "run-1"
    assert payload["stage"] == "programmer"
