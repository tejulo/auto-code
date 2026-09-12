from datetime import UTC, datetime

from pydantic import BaseModel, ValidationError, field_validator
import pytest

from auto_code.contracts import (
    ActivationRequest,
    ArtifactEnvelope,
    ArtifactFile,
    BrowserE2EDecision,
    BrowserResult,
    BrowserScenario,
    BrowserScenarioObservation,
    BuildIdentity,
    ChangeOutline,
    Checkpoint,
    EvidenceRef,
    EffectIntention,
    EffectIntentionPayload,
    EffectObservationPayload,
    EffectReconciliation,
    EffectReconciliationPayload,
    HumanAuthorization,
    HumanAuthorizationAction,
    IdentityResolution,
    ImplementationResult,
    InvalidUnitOutput,
    McpActionRequest,
    PendingExternalRequest,
    PreparationBridgeAttestation,
    PreparationInput,
    ProductChangeFile,
    ProductChangeManifest,
    RequirementsPackage,
    ReviewManifest,
    ReviewResult,
    RunnerIdentity,
    RunDisposition,
    RunState,
    Stage,
    StageOutput,
    TaskDefinition,
    TaskDefinitionManifest,
    TaskStatus,
    TaskStatusManifest,
    TrustedPreparationInputRef,
    UnitStatus,
    VerificationCheck,
    VerificationResult,
    sanitize_validation_errors,
)
from auto_code.hashing import hash_json


NOW = datetime(2026, 1, 1, tzinfo=UTC)
FUTURE = datetime(2099, 1, 1, tzinfo=UTC)
REQUEST_HASH = "a" * 64
CHECKPOINT_CONTRACT_HASH = "b" * 64
CHECKPOINT_INPUT_HASH = "c" * 64
CHECKPOINT_OUTPUT_HASH = "d" * 64
CHECKPOINT_RECEIPT_HASH = "e" * 64
TASK_DEFINITION_HASH = hash_json(
    [
        {"task_id": "1.1", "text": "First task"},
        {"task_id": "1.2", "text": "Second task"},
    ]
)
OTHER_TASK_DEFINITION_HASH = "0" * 64
RUNNER_CONTENT_HASH = "1" * 64
RUNNER_SOURCE_HASH = "2" * 64
RUNNER_LOCK_HASH = "3" * 64
RUNNER_CONTRACT_BUNDLE_HASH = "4" * 64
ACTIVATION_CHALLENGE_HASH = "5" * 64
ACTIVATION_PREPARATION_HASH = "6" * 64
STAGE_OUTPUT_HASH = "7" * 64
OTHER_REQUEST_HASH = "8" * 64
UPPERCASE_HASH = "A" * 64
INVALID_HASH = "not-a-sha256"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.c2lnbmF0dXJl"
SHORT_JWT = "eyJhbGciOiJIUzI1NiJ9.e30.sig"


def sha(char: str) -> str:
    return char * 64


def source_citation() -> dict[str, object]:
    return {"source_id": "ticket-description", "locator": "line-1", "source_hash": sha("9")}


def requirements_package() -> RequirementsPackage:
    return RequirementsPackage(
        objective="Deliver the approved change.",
        in_scope=("Implement the requested behavior.",),
        out_of_scope=("Do not change deployment.",),
        requirements=(
            {
                "requirement_id": "REQ-1",
                "text": "The change is observable.",
                "sources": (source_citation(),),
            },
        ),
        acceptance_criteria=(
            {
                "criterion_id": "AC-1",
                "text": "The observable behavior is verified.",
                "sources": (source_citation(),),
            },
        ),
        constraints=("Preserve the public API.",),
        dependencies=("An approved artifact is available.",),
        ambiguities=(),
    )


def browser_decision() -> BrowserE2EDecision:
    return BrowserE2EDecision(
        required=True,
        reason="The requested flow changes browser behavior.",
        scenarios=(
            BrowserScenario(
                scenario_id="BROWSER-1",
                description="Open the changed flow.",
                expected_result="The requested result is visible.",
            ),
        ),
    )


def review_manifest() -> ReviewManifest:
    return ReviewManifest(
        baseline_sha="a" * 40,
        requirements_package_hash=sha("b"),
        change_outline_hash=sha("c"),
        artifact_hashes={"proposal": sha("d")},
        task_definition_hash=sha("e"),
        task_status_hash=sha("f"),
        product_manifest_hash=sha("0"),
        build_identity_hash=sha("1"),
        project_policy_hash=sha("2"),
        verification_result_hash=sha("3"),
        browser_result_hash=sha("4"),
    )


def resume_authorization(
    authorization_id: str,
    *,
    issued_at: datetime = NOW,
    expires_at: datetime = FUTURE,
    consumed_at: datetime | None = NOW,
) -> HumanAuthorization:
    return HumanAuthorization(
        authorization_id=authorization_id,
        action=HumanAuthorizationAction.RESUME,
        run_id="run-1",
        challenge=f"challenge-{authorization_id}",
        actor="operator",
        reason="continue work",
        issued_at=issued_at,
        expires_at=expires_at,
        key_id="key-1",
        signature="signature",
        additional_iterations=2,
        consumed_at=consumed_at,
    )


def checkpoint() -> Checkpoint:
    return Checkpoint(
        stage=Stage.ANALYST,
        contract_hash=CHECKPOINT_CONTRACT_HASH,
        input_hashes={"requirements": CHECKPOINT_INPUT_HASH},
        output_manifest_hash=CHECKPOINT_OUTPUT_HASH,
        validator="validator",
        validator_version="1",
        validation_receipt_hash=CHECKPOINT_RECEIPT_HASH,
    )


def evidence_ref(**changes: str) -> EvidenceRef:
    values = {
        "relative_path": "evidence/linear/receipt.json",
        "sha256": REQUEST_HASH,
        "media_type": "application/json",
        "creator": "trusted-bridge",
    }
    values.update(changes)
    return EvidenceRef(**values)


def implementation_result_data(**changes: object) -> dict[str, object]:
    values: dict[str, object] = {
        "task_definition_hash": sha("a"),
        "task_status_hash": sha("b"),
        "completed_task_ids": ("1.1",),
        "changed_paths": ("src/auto_code/crew.py",),
        "command_evidence": (evidence_ref().model_dump(),),
        "latest_failure_resolution": "Implemented the cited correction.",
    }
    values.update(changes)
    return values


def implementation_validation_context() -> dict[str, object]:
    return {
        "task_definition_hash": sha("a"),
        "task_status_hash": sha("b"),
        "known_task_ids": ("1.1", "1.2"),
    }


def build_identity() -> BuildIdentity:
    return BuildIdentity(
        baseline_sha="a" * 40,
        product_manifest_hash=sha("b"),
        project_policy_hash=sha("c"),
        command_hashes={"pytest": sha("d")},
        runtime_hash=sha("e"),
    )


def task_definitions() -> TaskDefinitionManifest:
    return TaskDefinitionManifest(
        definition_hash=TASK_DEFINITION_HASH,
        tasks=(
            TaskDefinition(task_id="1.1", text="First task"),
            TaskDefinition(task_id="1.2", text="Second task"),
        ),
    )


def task_statuses(
    definition_hash: str = TASK_DEFINITION_HASH,
    task_ids: tuple[str, ...] = ("1.1", "1.2"),
) -> TaskStatusManifest:
    return TaskStatusManifest(
        definition_hash=definition_hash,
        statuses=tuple(TaskStatus(task_id=task_id, status=UnitStatus.UNCHECKED) for task_id in task_ids),
    )


def runner_identity() -> RunnerIdentity:
    return RunnerIdentity(
        content_hash=RUNNER_CONTENT_HASH,
        source_sha=RUNNER_SOURCE_HASH,
        dependency_lock_hash=RUNNER_LOCK_HASH,
        contract_bundle_hash=RUNNER_CONTRACT_BUNDLE_HASH,
        built_at=NOW,
    )


def activation_request() -> ActivationRequest:
    reference = TrustedPreparationInputRef(
        input_id="44444444-4444-4444-8444-444444444444",
        relative_path="trusted-mcp/preparation/44444444-4444-4444-8444-444444444444.json",
        repository_id="repo",
        reservation_id="reservation-1",
        challenge_hash=ACTIVATION_CHALLENGE_HASH,
        input_hash=ACTIVATION_PREPARATION_HASH,
        query_hash=sha("1"),
        payload_hash=sha("2"),
        result_hash=sha("3"),
        source_page_hashes={"page-1": sha("4")},
        pagination_complete=True,
        max_crew_iterations=3,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        tool_call_id="tool-call-1",
        captured_at=NOW,
        observations=("Trusted preparation input captured.",),
        bridge_signature=sha("5"),
    )
    return ActivationRequest(
        reservation_id="reservation-1",
        repository_id="repo",
        expected_index_revision=1,
        expected_index_hash=sha("6"),
        preparation_input_ref=reference,
    )


def preparation_input(*, page_hash: str | None = None) -> PreparationInput:
    page = {"tickets": []}
    return PreparationInput(
        repository_id="repo",
        max_crew_iterations=3,
        assignee_resolution=IdentityResolution.resolved("user-1"),
        milestone_resolution=IdentityResolution.resolved("milestone-1"),
        pages=(page,),
        page_hashes={"page-1": page_hash or hash_json(page)},
        workflow_states={"started": "state-1"},
        bridge_attestation=PreparationBridgeAttestation(
            bridge_identity="launcher-bridge",
            mcp_server_identity="linear-mcp",
            tool_call_id="tool-call-1",
            captured_at=NOW,
        ),
    )


def intention(
    *,
    operation: str = "mcp_action",
    request_hash: str = REQUEST_HASH,
) -> EffectIntention:
    return EffectIntention(
        effect_id="effect-1",
        sequence=1,
        timestamp=NOW,
        payload=EffectIntentionPayload(
            operation=operation,
            target="ENG-1",
            request_hash=request_hash,
        ),
    )


def reconciliation() -> EffectReconciliation:
    return EffectReconciliation(
        effect_id="effect-1",
        sequence=2,
        timestamp=NOW,
        payload=EffectReconciliationPayload(outcome="success"),
    )


def pending_request(
    *,
    effect_id: str = "effect-1",
    operation: str = "mcp_action",
    request_hash: str = REQUEST_HASH,
) -> PendingExternalRequest:
    return PendingExternalRequest(
        request_id="request-1",
        effect_id=effect_id,
        request_hash=request_hash,
        operation=operation,
    )


def test_attempt_budget_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo", max_crew_iterations=0)


def test_preparation_input_rejects_page_hashes_that_do_not_match_the_typed_pages() -> None:
    with pytest.raises(ValidationError, match="page hashes"):
        preparation_input(page_hash=sha("f"))


def test_begin_iteration_is_immutable_and_budgeted() -> None:
    state = RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo", max_crew_iterations=1)
    started = state.begin_iteration()
    assert state.crew_iteration_count == 0
    assert started.crew_iteration_count == 1
    assert started.iteration_open is True
    assert started.can_start_iteration() is False
    assert started.current_stage is Stage.ANALYST


def test_authorized_iteration_limit_ignores_unconsumed_resume_grants() -> None:
    state = RunState(
        run_id="run-1",
        ticket_id="ENG-1",
        repository_id="repo",
        max_crew_iterations=3,
        human_authorizations=(
            resume_authorization("authorization-1"),
            resume_authorization("authorization-2", consumed_at=None),
        ),
    )
    assert state.authorized_iteration_limit == 5


def test_rejects_duplicate_human_authorization_ids() -> None:
    with pytest.raises(ValidationError):
        RunState(
            run_id="run-1",
            ticket_id="ENG-1",
            repository_id="repo",
            max_crew_iterations=3,
            human_authorizations=(
                resume_authorization("authorization-1"),
                resume_authorization("authorization-1"),
            ),
        )


def test_future_consumption_does_not_increase_capacity() -> None:
    state = RunState(
        run_id="run-1",
        ticket_id="ENG-1",
        repository_id="repo",
        max_crew_iterations=3,
        human_authorizations=(
            resume_authorization(
                "authorization-1",
                expires_at=datetime(2027, 1, 1, tzinfo=UTC),
                consumed_at=datetime(2098, 1, 1, tzinfo=UTC),
            ),
        ),
    )
    assert state.authorized_iteration_limit == 3


def test_preissue_consumption_does_not_increase_capacity() -> None:
    state = RunState(
        run_id="run-1",
        ticket_id="ENG-1",
        repository_id="repo",
        max_crew_iterations=3,
        human_authorizations=(
            resume_authorization(
                "authorization-1",
                consumed_at=datetime(2025, 1, 1, tzinfo=UTC),
            ),
        ),
    )
    assert state.authorized_iteration_limit == 3


def test_historical_consumed_grant_remains_valid_after_expiry() -> None:
    state = RunState(
        run_id="run-1",
        ticket_id="ENG-1",
        repository_id="repo",
        max_crew_iterations=3,
        disposition=RunDisposition.DONE,
        human_authorizations=(
            resume_authorization(
                "authorization-1",
                issued_at=datetime(2020, 1, 1, tzinfo=UTC),
                expires_at=datetime(2021, 1, 1, tzinfo=UTC),
                consumed_at=datetime(2020, 6, 1, tzinfo=UTC),
            ),
        ),
    )
    assert state.authorized_iteration_limit == 5


@pytest.mark.parametrize(
    "changes",
    (
        {"relative_path": "../receipt.json"},
        {"relative_path": "evidence/../receipt.json"},
        {"relative_path": "/receipt.json"},
        {"sha256": INVALID_HASH},
        {"media_type": "provider response"},
        {"creator": "creator with whitespace"},
    ),
)
def test_evidence_references_require_safe_structured_values(changes: dict[str, str]) -> None:
    with pytest.raises(ValidationError):
        evidence_ref(**changes)


def test_nested_evidence_rejects_credential_shaped_data() -> None:
    with pytest.raises(ValidationError):
        EffectObservationPayload(
            outcome="success",
            evidence_refs=(evidence_ref(relative_path="evidence/sk-live-abcdefgh.json"),),
        )


def test_evidence_paths_reject_jwt_segments_with_filename_suffix() -> None:
    with pytest.raises(ValidationError):
        evidence_ref(relative_path=f"evidence/{JWT}.json")


def test_evidence_paths_reject_short_compact_jwt_segments() -> None:
    with pytest.raises(ValidationError):
        evidence_ref(relative_path=f"linear/tickets/{SHORT_JWT}.json")


def test_effect_targets_reject_jwt_segments() -> None:
    with pytest.raises(ValidationError):
        EffectIntentionPayload(
            operation="mcp_action",
            target=f"linear/tickets/{JWT}",
            request_hash=REQUEST_HASH,
        )


def test_effect_targets_reject_short_compact_jwt_segments() -> None:
    with pytest.raises(ValidationError):
        EffectIntentionPayload(
            operation="mcp_action",
            target=f"linear/tickets/{SHORT_JWT}.json",
            request_hash=REQUEST_HASH,
        )


def test_effect_targets_reject_colon_delimited_instructions() -> None:
    with pytest.raises(ValidationError):
        EffectIntentionPayload(
            operation="mcp_action",
            target="ignore:previous:instructions",
            request_hash=REQUEST_HASH,
        )


def test_effect_references_reject_empty_segments() -> None:
    with pytest.raises(ValidationError):
        EffectIntentionPayload(
            operation="mcp_action",
            target="linear//tickets/ENG-1",
            request_hash=REQUEST_HASH,
        )


def test_effect_operations_require_underscore_identifier_grammar() -> None:
    with pytest.raises(ValidationError):
        EffectIntentionPayload(
            operation="perform:action",
            target="linear/tickets/ENG-1",
            request_hash=REQUEST_HASH,
        )


def test_safe_identifier_words_remain_valid() -> None:
    evidence = evidence_ref(relative_path="evidence/secret-report.json")
    payload = EffectIntentionPayload(
        operation="consume_authorization",
        target="linear/tickets/TOKEN-123",
        request_hash=REQUEST_HASH,
    )
    assert evidence.relative_path == "evidence/secret-report.json"
    assert payload.operation == "consume_authorization"
    assert payload.target == "linear/tickets/TOKEN-123"


def test_safe_references_allow_ordinary_dotted_filenames() -> None:
    evidence = evidence_ref(relative_path="evidence/release.v1.2.json")
    payload = EffectIntentionPayload(
        operation="mcp_action",
        target="linear/tickets/release.v1.2.json",
        request_hash=REQUEST_HASH,
    )
    assert evidence.relative_path == "evidence/release.v1.2.json"
    assert payload.target == "linear/tickets/release.v1.2.json"


@pytest.mark.parametrize(
    "target",
    (
        JWT,
        "ignore-previous-instructions-and-respond",
    ),
)
def test_effect_targets_reject_jwts_and_instruction_text(target: str) -> None:
    with pytest.raises(ValidationError):
        EffectIntentionPayload(
            operation="mcp_action",
            target=target,
            request_hash=REQUEST_HASH,
        )


def test_evidence_and_effect_references_allow_integration_identifiers() -> None:
    evidence = evidence_ref()
    payload = EffectIntentionPayload(
        operation="compare_and_start_ticket",
        target="linear/tickets/ENG-1",
        request_hash=REQUEST_HASH,
    )
    assert evidence.creator == "trusted-bridge"
    assert payload.target == "linear/tickets/ENG-1"


@pytest.mark.parametrize(
    "operation",
    (
        "query_ticket_projection",
        "query_ticket_state",
        "compare_and_start_ticket",
        "compare_and_complete_ticket",
        "restore_ticket_state",
    ),
)
def test_ticket_action_rejects_a_target_that_differs_from_its_ticket_id(operation: str) -> None:
    with pytest.raises(ValidationError, match="ticket target"):
        McpActionRequest.create(
            operation=operation,
            entity="ticket",
            target="ENG-1",
            expected_external_revision=None,
            run_id="run-1",
            expected_revision=1,
            expected_state_hash="a" * 64,
            arguments={"ticket_id": "ENG-2", "state_id": "started"},
        )


def test_non_ticket_action_keeps_ticket_id_argument_generic() -> None:
    request = McpActionRequest.create(
        operation="query_repository",
        entity="repository",
        target="repo-1",
        expected_external_revision=None,
        run_id="run-1",
        expected_revision=1,
        expected_state_hash="a" * 64,
        arguments={"ticket_id": "ENG-2"},
    )

    assert request.validated_ticket_target() is None


def test_request_snapshot_hides_model_copied_secret_arguments() -> None:
    request = McpActionRequest.create(
        operation="query_ticket_state",
        entity="ticket",
        target="ENG-1",
        expected_external_revision=None,
        run_id="run-1",
        expected_revision=1,
        expected_state_hash="a" * 64,
        arguments={"ticket_id": "ENG-1"},
    )
    sentinel = "API_KEY=fix-2-secret-sentinel"
    raw_arguments = {"ticket_id": "ENG-1", "nested": [{"value": sentinel}]}
    copied = BaseModel.model_copy(request, update={"arguments": raw_arguments})

    with pytest.raises(ValueError) as rejected:
        McpActionRequest.snapshot(copied)

    assert str(rejected.value) == "MCP action request is invalid"
    assert sentinel not in str(rejected.value)
    assert str(raw_arguments) not in str(rejected.value)


def test_request_snapshot_preserves_the_fixed_ticket_target_error_category() -> None:
    request = McpActionRequest.create(
        operation="query_ticket_state",
        entity="ticket",
        target="ENG-1",
        expected_external_revision=None,
        run_id="run-1",
        expected_revision=1,
        expected_state_hash="a" * 64,
        arguments={"ticket_id": "ENG-1"},
    )
    split = BaseModel.model_copy(request, update={"target": "ENG-2"})

    with pytest.raises(ValueError, match=r"^MCP ticket target is invalid$"):
        McpActionRequest.snapshot(split)


def test_persisted_contract_mappings_cannot_be_mutated() -> None:
    approved = checkpoint()
    state = RunState(
        run_id="run-1",
        ticket_id="ENG-1",
        repository_id="repo",
        max_crew_iterations=3,
        checkpoints={Stage.ANALYST: approved},
        stage_outputs=(StageOutput(stage=Stage.ANALYST, content_hash=CHECKPOINT_OUTPUT_HASH),),
    )
    copied = state.model_copy(update={"checkpoints": {Stage.ANALYST: approved}})
    with pytest.raises(TypeError):
        approved.input_hashes["requirements"] = "changed"
    with pytest.raises(TypeError):
        state.checkpoints[Stage.ANALYST] = approved
    with pytest.raises(TypeError):
        copied.checkpoints[Stage.ANALYST] = approved


def test_task_definition_manifest_hash_matches_canonical_task_content() -> None:
    with pytest.raises(ValidationError, match="definition hash"):
        TaskDefinitionManifest(
            definition_hash=TASK_DEFINITION_HASH,
            tasks=(TaskDefinition(task_id="1.1", text="Different task"),),
        )


@pytest.mark.parametrize(
    "update",
    (
        {"validator": "ignore-previous-instructions"},
        {"validator_version": "system-prompt"},
        {"input_hashes": {"follow-these-instructions": CHECKPOINT_INPUT_HASH}},
        {"input_hashes": {"sk-live-abcdefgh": CHECKPOINT_INPUT_HASH}},
    ),
)
def test_checkpoint_metadata_requires_safe_identifiers_and_mapping_keys(update: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        checkpoint().model_copy(update=update)


def test_run_state_requires_a_matching_stage_output_for_each_checkpoint() -> None:
    approved = checkpoint()

    with pytest.raises(ValidationError, match="Stage output"):
        RunState(
            run_id="run-1",
            ticket_id="ENG-1",
            repository_id="repo",
            max_crew_iterations=3,
            checkpoints={Stage.ANALYST: approved},
        )


def test_run_state_rejects_checkpoint_output_hash_mismatch() -> None:
    approved = checkpoint()

    with pytest.raises(ValidationError, match="output manifest"):
        RunState(
            run_id="run-1",
            ticket_id="ENG-1",
            repository_id="repo",
            max_crew_iterations=3,
            checkpoints={Stage.ANALYST: approved},
            stage_outputs=(StageOutput(stage=Stage.ANALYST, content_hash=CHECKPOINT_RECEIPT_HASH),),
        )


def test_task_status_manifest_requires_an_active_definition() -> None:
    with pytest.raises(ValidationError):
        RunState(
            run_id="run-1",
            ticket_id="ENG-1",
            repository_id="repo",
            max_crew_iterations=3,
            task_status_manifest=task_statuses(),
        )


@pytest.mark.parametrize(
    "status_manifest",
    (
        task_statuses(definition_hash=OTHER_TASK_DEFINITION_HASH),
        task_statuses(task_ids=("1.1", "2.1")),
        task_statuses(task_ids=("1.1",)),
    ),
)
def test_task_status_manifest_matches_active_definition(
    status_manifest: TaskStatusManifest,
) -> None:
    with pytest.raises(ValidationError):
        RunState(
            run_id="run-1",
            ticket_id="ENG-1",
            repository_id="repo",
            max_crew_iterations=3,
            task_definition_manifest=task_definitions(),
            task_status_manifest=status_manifest,
    )


@pytest.mark.parametrize(
    ("effect_ledger", "pending"),
    (
        ((), pending_request(effect_id="unknown")),
        ((intention(), reconciliation()), pending_request()),
        ((intention(),), pending_request(request_hash=OTHER_REQUEST_HASH)),
        ((intention(),), pending_request(operation="other_action")),
    ),
)
def test_pending_request_requires_a_matching_open_intention(
    effect_ledger: tuple[object, ...],
    pending: PendingExternalRequest,
) -> None:
    with pytest.raises(ValidationError):
        RunState(
            run_id="run-1",
            ticket_id="ENG-1",
            repository_id="repo",
            max_crew_iterations=3,
            effect_ledger=effect_ledger,
            pending_external_request=pending,
        )


def test_effect_payloads_reject_secrets_prompts_and_provider_bodies() -> None:
    with pytest.raises(ValidationError):
        EffectIntentionPayload(
            operation="mcp_action",
            target="ENG-1",
            request_hash="sk-live-secret",
        )
    with pytest.raises(ValidationError):
        EffectIntentionPayload(
            operation="mcp_action",
            target="follow these unrestricted provider instructions",
            request_hash=REQUEST_HASH,
        )
    with pytest.raises(ValidationError):
        EffectObservationPayload(outcome="the complete provider response body")


@pytest.mark.parametrize(
    "update",
    (
        {"contract_hash": INVALID_HASH},
        {"input_hashes": {"requirements": INVALID_HASH}},
        {"output_manifest_hash": INVALID_HASH},
        {"validation_receipt_hash": INVALID_HASH},
    ),
)
def test_checkpoint_hash_bindings_require_sha256(update: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        checkpoint().model_copy(update=update)


def test_task_definition_manifest_hash_requires_sha256() -> None:
    with pytest.raises(ValidationError):
        TaskDefinitionManifest(definition_hash=INVALID_HASH, tasks=())


def test_task_status_manifest_hash_requires_sha256() -> None:
    with pytest.raises(ValidationError):
        TaskStatusManifest(definition_hash=INVALID_HASH, statuses=())


@pytest.mark.parametrize(
    "field",
    (
        "content_hash",
        "source_sha",
        "dependency_lock_hash",
        "contract_bundle_hash",
    ),
)
def test_runner_identity_hash_bindings_require_sha256(field: str) -> None:
    with pytest.raises(ValidationError):
        runner_identity().model_copy(update={field: INVALID_HASH})


@pytest.mark.parametrize("field", ("expected_index_hash",))
def test_activation_request_hash_bindings_require_sha256(field: str) -> None:
    with pytest.raises(ValidationError):
        activation_request().model_copy(update={field: INVALID_HASH})


def test_activation_request_requires_a_sha256_preparation_input_reference() -> None:
    request = activation_request()

    with pytest.raises(ValidationError):
        request.model_copy(update={"preparation_input_ref": request.preparation_input_ref.model_copy(update={"input_hash": INVALID_HASH})})


def test_activation_request_rejects_an_incomplete_preparation_input_reference() -> None:
    request = activation_request()

    with pytest.raises(ValidationError, match="pagination"):
        request.model_copy(
            update={"preparation_input_ref": request.preparation_input_ref.model_copy(update={"pagination_complete": False})}
        )


def test_pending_request_hash_accepts_uppercase_sha256() -> None:
    pending = pending_request(request_hash=UPPERCASE_HASH)
    assert pending.request_hash == UPPERCASE_HASH


def test_stage_output_hash_requires_sha256() -> None:
    with pytest.raises(ValidationError):
        StageOutput(stage=Stage.ANALYST, content_hash=INVALID_HASH)


def test_requirements_package_requires_traceable_cited_requirements_and_forbids_extra_fields() -> None:
    package = requirements_package()

    assert package.requirements[0].requirement_id == "REQ-1"
    with pytest.raises(ValidationError, match="sources"):
        RequirementsPackage(
            objective="Deliver the approved change.",
            in_scope=("Implement the requested behavior.",),
            out_of_scope=("Do not change deployment.",),
            requirements=({"requirement_id": "REQ-1", "text": "The change is observable.", "sources": ()},),
            acceptance_criteria=(
                {
                    "criterion_id": "AC-1",
                    "text": "The observable behavior is verified.",
                    "sources": (source_citation(),),
                },
            ),
            constraints=(),
            dependencies=(),
            ambiguities=(),
        )
    with pytest.raises(ValidationError, match="Extra inputs"):
        RequirementsPackage.model_validate({**package.model_dump(), "unbounded_context": "forbidden"})


def test_browser_e2e_decision_requires_scenarios_exactly_when_browser_validation_is_required() -> None:
    assert browser_decision().scenarios[0].scenario_id == "BROWSER-1"

    with pytest.raises(ValidationError, match="scenario"):
        BrowserE2EDecision(required=True, reason="A browser flow changed.", scenarios=())
    with pytest.raises(ValidationError, match="must not include scenarios"):
        BrowserE2EDecision(
            required=False,
            reason="No browser behavior changed.",
            scenarios=browser_decision().scenarios,
        )


def test_change_outline_binds_direct_dependencies_and_a_required_browser_decision() -> None:
    outline = ChangeOutline(
        change_id="add-bounded-runner",
        artifact_units=(
            {"artifact_id": "proposal", "stage": Stage.ARCHITECT_PROPOSAL, "output_contract": "ArtifactEnvelope"},
        ),
        direct_dependency_hashes={"requirements": sha("a")},
        browser_e2e_decision=browser_decision(),
    )

    assert outline.direct_dependency_hashes["requirements"] == sha("a")
    with pytest.raises(ValidationError):
        ChangeOutline(
            change_id="add-bounded-runner",
            artifact_units=outline.artifact_units,
            direct_dependency_hashes={"requirements": INVALID_HASH},
            browser_e2e_decision=browser_decision(),
        )


def test_artifact_envelope_validates_content_hashes_and_unique_relative_paths() -> None:
    content = "# Proposal\n"
    file = ArtifactFile(relative_path="proposal.md", content=content, sha256="03862585012a9c8e770ee36871f6483b00d93503a33b6f66acfd564dc1a64910")

    envelope = ArtifactEnvelope(artifact_id="proposal", files=(file,))
    assert envelope.files == (file,)
    with pytest.raises(ValidationError, match="content hash"):
        ArtifactFile(relative_path="proposal.md", content=content, sha256=sha("a"))
    with pytest.raises(ValidationError, match="unique"):
        ArtifactEnvelope(artifact_id="proposal", files=(file, file))


def test_implementation_result_binds_input_hashes_and_claims_only_safe_paths() -> None:
    result = ImplementationResult.model_validate(
        implementation_result_data(),
        context=implementation_validation_context(),
    )

    assert result.completed_task_ids == ("1.1",)
    with pytest.raises(ValidationError):
        result.model_copy(update={"changed_paths": ("../state.json",)})


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        ({"completed_task_ids": ("task-one",)}, "completed_task_ids"),
        ({"completed_task_ids": ("9.9",)}, "(?i)known task"),
        ({"task_definition_hash": sha("c")}, "definition hash"),
        ({"task_status_hash": sha("c")}, "status hash"),
    ),
)
def test_implementation_result_requires_known_numeric_tasks_and_bound_hashes(
    changes: dict[str, object],
    message: str,
) -> None:
    with pytest.raises(ValidationError, match=message):
        ImplementationResult.model_validate(
            implementation_result_data(**changes),
            context=implementation_validation_context(),
        )


def test_build_identity_and_browser_result_bind_all_verification_inputs() -> None:
    identity = BuildIdentity(
        baseline_sha="a" * 40,
        product_manifest_hash=sha("b"),
        project_policy_hash=sha("c"),
        command_hashes={"pytest": sha("d")},
        runtime_hash=sha("e"),
    )
    result = BrowserResult(
        status="passed",
        browser_e2e_decision_hash=sha("f"),
        build_identity_hash=sha("0"),
        reason="All required scenarios passed.",
        scenario_observations=(
            BrowserScenarioObservation(
                scenario_id="BROWSER-1",
                status="passed",
                observation="The requested result was visible.",
                evidence=(evidence_ref(),),
            ),
        ),
        evidence=(evidence_ref(),),
    )

    assert identity.command_hashes["pytest"] == sha("d")
    assert result.status == "passed"
    with pytest.raises(ValidationError, match="observations"):
        BrowserResult(
            status="failed",
            browser_e2e_decision_hash=sha("f"),
            build_identity_hash=sha("0"),
            reason="A required scenario failed.",
            scenario_observations=(),
            evidence=(evidence_ref(),),
        )


def test_product_change_manifest_binds_modes_renames_objects_and_untracked_entries() -> None:
    manifest = ProductChangeManifest.from_files(
        "a" * 40,
        (
            ProductChangeFile(
                path="new.py",
                status="R100",
                old_path="old.py",
                old_mode="100644",
                mode="100755",
                old_object_id="b" * 40,
                object_id="c" * 40,
                binary=False,
                untracked=False,
            ),
            ProductChangeFile(
                path="generated/data.bin",
                status="A",
                old_path=None,
                old_mode="000000",
                mode="100644",
                old_object_id=None,
                object_id="d" * 40,
                binary=True,
                untracked=True,
            ),
        ),
    )

    assert manifest.content_hash == hash_json(manifest.model_dump(mode="json", exclude={"content_hash"}))
    with pytest.raises(ValidationError, match="unique"):
        manifest.model_copy(update={"files": (manifest.files[0], manifest.files[0])})


@pytest.mark.parametrize(
    "changes",
    (
        {"path": ".git/config"},
        {"status": "R100", "old_path": None},
        {"status": "A", "old_mode": "100644"},
        {"status": "D", "mode": "100644"},
    ),
)
def test_product_change_file_rejects_unsafe_or_inconsistent_git_metadata(changes: dict[str, object]) -> None:
    values: dict[str, object] = {
        "path": "src/auto_code/contracts.py",
        "status": "M",
        "old_path": None,
        "old_mode": "100644",
        "mode": "100644",
        "old_object_id": "a" * 40,
        "object_id": "b" * 40,
        "binary": False,
        "untracked": False,
    }
    values.update(changes)

    with pytest.raises(ValidationError):
        ProductChangeFile(**values)


def test_verification_result_requires_exact_build_hash_and_complete_command_evidence() -> None:
    build = build_identity()
    check = VerificationCheck(
        command_id="pytest",
        command_hash=sha("f"),
        returncode=0,
        failure_kind=None,
        stdout_evidence=evidence_ref(),
        stderr_evidence=evidence_ref(),
    )
    result = VerificationResult(
        build_identity_hash=hash_json(build.model_dump(mode="json")),
        checks=(check,),
        passed=True,
        empty_authorized=False,
    )

    assert result.checks == (check,)
    with pytest.raises(ValidationError, match="(?i)empty"):
        VerificationResult(
            build_identity_hash=result.build_identity_hash,
            checks=(),
            passed=True,
            empty_authorized=False,
        )


def test_verification_result_requires_its_pass_state_to_match_command_return_codes() -> None:
    check = VerificationCheck(
        command_id="pytest",
        command_hash=sha("f"),
        returncode=1,
        failure_kind="exit",
        stdout_evidence=evidence_ref(),
        stderr_evidence=evidence_ref(),
    )

    with pytest.raises(ValidationError, match="pass state"):
        VerificationResult(
            build_identity_hash=sha("a"),
            checks=(check,),
            passed=True,
            empty_authorized=False,
        )


def test_verification_result_rejects_a_mismatched_bound_build_identity_hash() -> None:
    build = build_identity()
    check = VerificationCheck(
        command_id="pytest",
        command_hash=sha("d"),
        returncode=0,
        failure_kind=None,
        stdout_evidence=evidence_ref(),
        stderr_evidence=evidence_ref(),
    )

    with pytest.raises(ValidationError, match="Build Identity hash"):
        VerificationResult.model_validate(
            {
                "build_identity_hash": sha("f"),
                "checks": (check,),
                "passed": True,
                "empty_authorized": False,
            },
            context={"build_identity": build},
        )


def test_verification_result_rejects_a_command_not_authorized_by_the_bound_build_identity() -> None:
    build = build_identity()
    check = VerificationCheck(
        command_id="pytest",
        command_hash=sha("f"),
        returncode=0,
        failure_kind=None,
        stdout_evidence=evidence_ref(),
        stderr_evidence=evidence_ref(),
    )

    with pytest.raises(ValidationError, match="complete ordered"):
        VerificationResult.model_validate(
            {
                "build_identity_hash": hash_json(build.model_dump(mode="json")),
                "checks": (check,),
                "passed": True,
                "empty_authorized": False,
            },
            context={"build_identity": build},
        )


def test_verification_result_requires_complete_ordered_build_commands_in_context() -> None:
    build = BuildIdentity(
        baseline_sha="a" * 40,
        product_manifest_hash=sha("b"),
        project_policy_hash=sha("c"),
        command_hashes={"check-1": sha("d"), "check-2": sha("e")},
        runtime_hash=sha("f"),
    )
    first = VerificationCheck(
        command_id="check-1",
        command_hash=sha("d"),
        returncode=0,
        failure_kind=None,
        stdout_evidence=evidence_ref(),
        stderr_evidence=evidence_ref(),
    )
    second = VerificationCheck(
        command_id="check-2",
        command_hash=sha("e"),
        returncode=0,
        failure_kind=None,
        stdout_evidence=evidence_ref(),
        stderr_evidence=evidence_ref(),
    )
    extra = VerificationCheck(
        command_id="check-3",
        command_hash=sha("f"),
        returncode=0,
        failure_kind=None,
        stdout_evidence=evidence_ref(),
        stderr_evidence=evidence_ref(),
    )

    for checks in ((), (second, first), (first, first), (first, second, extra)):
        with pytest.raises(ValidationError, match="complete ordered"):
            VerificationResult.model_validate(
                {
                    "build_identity_hash": hash_json(build.model_dump(mode="json", round_trip=True)),
                    "checks": checks,
                    "passed": True,
                    "empty_authorized": not checks,
                },
                context={"build_identity": build},
            )


def test_browser_result_rejects_mismatched_tester_decision_and_build_hashes() -> None:
    decision = browser_decision()
    build = BuildIdentity(
        baseline_sha="a" * 40,
        product_manifest_hash=sha("b"),
        project_policy_hash=sha("c"),
        command_hashes={"pytest": sha("d")},
        runtime_hash=sha("e"),
    )
    decision_hash = hash_json(decision.model_dump(mode="json", round_trip=True))
    build_hash = hash_json(build.model_dump(mode="json", round_trip=True))
    data = {
        "status": "passed",
        "browser_e2e_decision_hash": decision_hash,
        "build_identity_hash": build_hash,
        "reason": "The declared scenario passed.",
        "scenario_observations": (
            {
                "scenario_id": "BROWSER-1",
                "status": "passed",
                "observation": "The requested result was visible.",
                "evidence": (evidence_ref().model_dump(),),
            },
        ),
        "evidence": (evidence_ref().model_dump(),),
    }
    context = {"browser_e2e_decision": decision, "build_identity": build}

    with pytest.raises(ValidationError, match="decision hash"):
        BrowserResult.model_validate({**data, "browser_e2e_decision_hash": sha("f")}, context=context)
    with pytest.raises(ValidationError, match="Build Identity hash"):
        BrowserResult.model_validate({**data, "build_identity_hash": sha("0")}, context=context)


def test_browser_result_requires_the_declared_required_scenarios() -> None:
    decision = BrowserE2EDecision(
        required=True,
        reason="The changed browser flows must be verified.",
        scenarios=(
            BrowserScenario(
                scenario_id="BROWSER-1",
                description="Open the first changed flow.",
                expected_result="The first result is visible.",
            ),
            BrowserScenario(
                scenario_id="BROWSER-2",
                description="Open the second changed flow.",
                expected_result="The second result is visible.",
            ),
        ),
    )
    build = BuildIdentity(
        baseline_sha="a" * 40,
        product_manifest_hash=sha("b"),
        project_policy_hash=sha("c"),
        command_hashes={"pytest": sha("d")},
        runtime_hash=sha("e"),
    )
    context = {"browser_e2e_decision": decision, "build_identity": build}
    hashes = {
        "browser_e2e_decision_hash": hash_json(decision.model_dump(mode="json", round_trip=True)),
        "build_identity_hash": hash_json(build.model_dump(mode="json", round_trip=True)),
    }
    observation = {
        "scenario_id": "BROWSER-1",
        "status": "passed",
        "observation": "The first result was visible.",
        "evidence": (evidence_ref().model_dump(),),
    }
    data = {
        "status": "passed",
        **hashes,
        "reason": "The declared scenarios passed.",
        "scenario_observations": (observation,),
        "evidence": (evidence_ref().model_dump(),),
    }

    with pytest.raises(ValidationError, match="cannot be skipped"):
        BrowserResult.model_validate(
            {**data, "status": "skipped", "scenario_observations": ()},
            context=context,
        )
    with pytest.raises(ValidationError, match="scenario IDs"):
        BrowserResult.model_validate(
            {
                **data,
                "scenario_observations": (
                    observation,
                    {**observation, "scenario_id": "BROWSER-3"},
                ),
            },
            context=context,
        )
    with pytest.raises(ValidationError, match="scenario IDs"):
        BrowserResult.model_validate(data, context=context)


def test_browser_result_accepts_an_optional_decision_only_when_skipped_for_its_declared_reason() -> None:
    decision = BrowserE2EDecision(required=False, reason="No browser behavior changed.", scenarios=())
    build = BuildIdentity(
        baseline_sha="a" * 40,
        product_manifest_hash=sha("b"),
        project_policy_hash=sha("c"),
        command_hashes={"pytest": sha("d")},
        runtime_hash=sha("e"),
    )
    data = {
        "status": "skipped",
        "browser_e2e_decision_hash": hash_json(decision.model_dump(mode="json", round_trip=True)),
        "build_identity_hash": hash_json(build.model_dump(mode="json", round_trip=True)),
        "reason": decision.reason,
        "scenario_observations": (),
        "evidence": (evidence_ref().model_dump(),),
    }
    context = {"browser_e2e_decision": decision, "build_identity": build}

    assert BrowserResult.model_validate(data, context=context).status == "skipped"
    with pytest.raises(ValidationError, match="declared reason"):
        BrowserResult.model_validate({**data, "reason": "Not the declared reason."}, context=context)


def test_review_result_must_repeat_the_review_manifest_hash_and_a_rejection_is_actionable() -> None:
    manifest = review_manifest()
    result = ReviewResult.model_validate(
        {
            "approved": False,
            "review_manifest_hash": manifest.content_hash,
            "failure_class": "product",
            "failure_source": "review",
            "finding_kind": "implementation_mismatch",
            "owner_stage": "programmer",
            "cited_ids": ["REQ-1"],
            "blocking_findings": ["The implementation misses REQ-1."],
            "evidence": [evidence_ref().model_dump()],
            "next_action": "Resume at programmer.",
        },
        context={"review_manifest_hash": manifest.content_hash},
    )

    assert result.review_manifest_hash == manifest.content_hash
    with pytest.raises(ValidationError, match="review manifest hash"):
        ReviewResult.model_validate(
            {**result.model_dump(), "review_manifest_hash": sha("f")},
            context={"review_manifest_hash": manifest.content_hash},
        )


def test_invalid_unit_output_exposes_only_hashed_sanitized_validation_evidence() -> None:
    output = InvalidUnitOutput(
        stage=Stage.ANALYST,
        output_hash=sha("a"),
        validation_errors=(
            {"location": ("objective",), "message": "Field required", "error_type": "missing"},
        ),
    )

    assert output.validation_errors[0].location == ("objective",)
    with pytest.raises(ValidationError):
        output.model_copy(update={"validation_errors": ({"location": (), "message": "x" * 10_000, "error_type": "bad"},)})


def test_invalid_unit_output_sanitizer_does_not_retain_secret_like_validator_messages() -> None:
    class LeakingOutput(BaseModel):
        value: str

        @field_validator("value")
        @classmethod
        def reject_value(cls, value: str) -> str:
            raise ValueError("OPENCODE_API_KEY=leaked-secret-value")

    with pytest.raises(ValidationError) as error:
        LeakingOutput.model_validate_json('{"value":"unsafe"}')

    issues = sanitize_validation_errors(error.value)

    assert "leaked-secret-value" not in " ".join(issue.message for issue in issues)
