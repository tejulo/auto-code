from __future__ import annotations

import json
from multiprocessing import get_context
import os
from pathlib import Path
from queue import Empty
from threading import Event, Thread
from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

import auto_code.run_index as run_index_module
from auto_code.checkpoint import CheckpointAuthority
from auto_code.contracts import (
    ActivationRequest,
    Checkpoint,
    EvidenceRef,
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
    FindingKind,
    HumanAuthorization,
    HumanAuthorizationAction,
    PreparationPhase,
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
)
from auto_code.hashing import hash_json
from auto_code.linear import LinearGateway
from auto_code.mcp_bridge import McpToolResult, TrustedLinearBridge
from auto_code.run_index import (
    ActivationReservationMismatch,
    ActivationStateMismatch,
    ActivationReplayMismatch,
    ActiveRunExists,
    AuthoritativeIndexCorrupt,
    IndexProbeResult,
    NonTerminalRunRelease,
    ReservationOwner,
    RunIdAlreadyUsed,
)
from auto_code.state import (
    EMPTY_STATE_HASH,
    AuthoritativeStateCorrupt,
    InvalidStateTransition,
    RunStateStore,
    StateGeneration,
    StateStoreError,
)
from tests.state_fixtures import (
    CONTRACT_HASH,
    INPUT_HASH,
    OTHER_PREPARATION_INPUT_HASH,
    OUTPUT_HASH,
    PREPARATION_INPUT_HASH,
    RECEIPT_HASH,
    abandoned_state,
    activated_index,
    activation_request,
    competing_cas_in_process,
    persist_generation,
    persist_terminal_generation,
    preparation_index,
    reserve_and_activate_in_process,
    run_concurrently,
    state_with_effect,
    transition_away_in_process,
)


NOW = datetime(2026, 1, 1, tzinfo=UTC)


class TrustedAuthorizations:
    def __init__(self, *authorization_ids: str) -> None:
        self.authorization_ids = frozenset(authorization_ids)

    def verify(self, authorization: HumanAuthorization, action: HumanAuthorizationAction) -> bool:
        return authorization.action is action and authorization.authorization_id in self.authorization_ids


class RecordingAuthorizations(TrustedAuthorizations):
    def __init__(self, *authorization_ids: str) -> None:
        super().__init__(*authorization_ids)
        self.calls: list[tuple[str, HumanAuthorizationAction]] = []

    def verify(self, authorization: HumanAuthorization, action: HumanAuthorizationAction) -> bool:
        self.calls.append((authorization.authorization_id, action))
        return super().verify(authorization, action)


class StaticLinearMcp:
    def __init__(self) -> None:
        self.call_count = 0

    def call(self, server_identity: str, tool_name: str, arguments: object) -> McpToolResult:
        self.call_count += 1
        return McpToolResult(
            tool_call_id=f"tool-call-{self.call_count}",
            result={"state": "started"},
            external_revision="revision-1",
        )


def consumed_authorization(
    run_id: str,
    action: HumanAuthorizationAction,
    authorization_id: str,
) -> HumanAuthorization:
    return HumanAuthorization(
        authorization_id=authorization_id,
        action=action,
        run_id=run_id,
        challenge="operator-challenge",
        actor="operator",
        reason="operator authorized this transition",
        issued_at=NOW,
        expires_at=datetime(2027, 1, 1, tzinfo=UTC),
        key_id="operator-key",
        signature="signature-shaped-data",
        additional_iterations=1 if action is HumanAuthorizationAction.RESUME else 0,
        consumed_at=NOW,
    )


def runner_identity(content_hash: str) -> RunnerIdentity:
    return RunnerIdentity(
        content_hash=content_hash,
        source_sha="b" * 64,
        dependency_lock_hash="c" * 64,
        contract_bundle_hash="d" * 64,
        built_at=NOW,
    )


def preparation_input_ref(reservation_id: str, repository_id: str, challenge_hash: str) -> TrustedPreparationInputRef:
    return TrustedPreparationInputRef(
        input_id="11111111-1111-4111-8111-111111111111",
        relative_path="trusted-mcp/preparation/11111111-1111-4111-8111-111111111111.json",
        repository_id=repository_id,
        reservation_id=reservation_id,
        challenge_hash=challenge_hash,
        input_hash="a" * 64,
        query_hash="b" * 64,
        payload_hash="c" * 64,
        result_hash="d" * 64,
        source_page_hashes={"page-1": "e" * 64},
        pagination_complete=True,
        max_crew_iterations=3,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        tool_call_id="tool-call-1",
        captured_at=NOW,
        observations=("Trusted preparation input captured.",),
        bridge_signature="f" * 64,
    )


def preparation_bound_state(
    *,
    run_id: str = "run-1",
    repository_id: str = "repo-1",
    preparation_phase: PreparationPhase = PreparationPhase.SELECTED,
    preparation_input_reference: TrustedPreparationInputRef | None = None,
) -> RunState:
    reference = preparation_input_reference or preparation_input_ref("reservation-1", repository_id, "9" * 64)
    return RunState(
        run_id=run_id,
        ticket_id="ENG-1",
        repository_id=repository_id,
        max_crew_iterations=3,
        preparation_phase=preparation_phase,
        project_policy_hash="1" * 64,
        preparation_input_ref=reference,
        preparation_input_hash=reference.input_hash,
        ticket_snapshot_hash="2" * 64,
        compatibility_receipt_hash="3" * 64,
        compatibility_receipt_ref=EvidenceRef(
            relative_path="preflight/compatibility.json",
            sha256="3" * 64,
            media_type="application/json",
            creator="trusted-launcher",
        ),
        runner_identity=runner_identity("4" * 64),
    )


def reconciled_effect_events(
    effect_id: str,
    sequence: int,
    operation: str,
    outcome: EffectOutcome,
) -> tuple[EffectIntention, EffectInvocation, EffectObservation, EffectReconciliation]:
    return (
        EffectIntention(
            effect_id=effect_id,
            sequence=sequence,
            timestamp=NOW,
            payload=EffectIntentionPayload(
                operation=operation,
                target="ENG-1",
                request_hash="a" * 64,
            ),
        ),
        EffectInvocation(
            effect_id=effect_id,
            sequence=sequence + 1,
            timestamp=NOW,
            payload=EffectInvocationPayload(),
        ),
        EffectObservation(
            effect_id=effect_id,
            sequence=sequence + 2,
            timestamp=NOW,
            payload=EffectObservationPayload(outcome=outcome),
        ),
        EffectReconciliation(
            effect_id=effect_id,
            sequence=sequence + 3,
            timestamp=NOW,
            payload=EffectReconciliationPayload(outcome=outcome),
        ),
    )


def preparation_receipt_boundary(
    tmp_path: Path,
    *,
    authorization_verifier: TrustedAuthorizations | None = None,
) -> tuple[RunStateStore, TrustedLinearBridge, LinearGateway, StateGeneration]:
    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=StaticLinearMcp(),
    )
    store = RunStateStore(
        tmp_path,
        "run-1",
        authorization_verifier=authorization_verifier,
        receipt_authority=bridge.receipt_authority,
    )
    initial = store.compare_and_swap(0, EMPTY_STATE_HASH, preparation_bound_state())
    requested = store.compare_and_swap(
        initial.revision,
        initial.state_hash,
        initial.state.model_copy(update={"preparation_phase": PreparationPhase.IN_PROGRESS_REQUESTED}),
    )
    return store, bridge, LinearGateway(store, bridge.receipt_authority), requested


def pending_ticket_request(
    tmp_path: Path,
    *,
    authorization_verifier: TrustedAuthorizations | None = None,
) -> tuple[RunStateStore, TrustedLinearBridge, LinearGateway, StateGeneration, object]:
    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=StaticLinearMcp(),
    )
    store = RunStateStore(
        tmp_path,
        "run-1",
        authorization_verifier=authorization_verifier,
        receipt_authority=bridge.receipt_authority,
    )
    initial = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3),
    )
    gateway = LinearGateway(store, bridge.receipt_authority)
    request = gateway.request_state(initial, "ENG-1")
    return store, bridge, gateway, gateway.persist_pending(initial, request), request


def confirm_preparation(
    bridge: TrustedLinearBridge,
    gateway: LinearGateway,
    generation: StateGeneration,
) -> StateGeneration:
    request = gateway.request_action(
        generation,
        operation="compare_and_start_ticket",
        entity="ticket",
        target=generation.state.ticket_id,
        expected_external_revision=None,
        arguments={"ticket_id": generation.state.ticket_id, "state_id": "state-1"},
    )
    pending = gateway.persist_pending(generation, request)
    return gateway.consume_receipt(
        pending,
        bridge.execute(request),
        state_update=lambda state, _: state.model_copy(
            update={"preparation_phase": PreparationPhase.IN_PROGRESS_CONFIRMED}
        ),
    )


def restore_preparation(
    bridge: TrustedLinearBridge,
    gateway: LinearGateway,
    generation: StateGeneration,
) -> StateGeneration:
    request = gateway.request_action(
        generation,
        operation="restore_ticket_state",
        entity="ticket",
        target=generation.state.ticket_id,
        expected_external_revision=None,
        arguments={"ticket_id": generation.state.ticket_id, "state_id": "state-1"},
    )
    pending = gateway.persist_pending(generation, request)
    return gateway.consume_receipt(
        pending,
        bridge.execute(request),
        state_update=lambda state, _: state.model_copy(
            update={"compensated": True, "disposition": RunDisposition.HUMAN_REVIEW}
        ),
    )


def restored_compensation_preparation(
    tmp_path: Path,
) -> tuple[RunStateStore, StateGeneration, StateGeneration]:
    verifier = TrustedAuthorizations("resume-1")
    store, bridge, gateway, requested = preparation_receipt_boundary(
        tmp_path,
        authorization_verifier=verifier,
    )
    confirmed = confirm_preparation(bridge, gateway, requested)
    compensation = store.compare_and_swap(
        confirmed.revision,
        confirmed.state_hash,
        confirmed.state.model_copy(
            update={
                "preparation_phase": PreparationPhase.COMPENSATION_REQUIRED,
                "effect_ledger": (
                    *confirmed.state.effect_ledger,
                    *reconciled_effect_events(
                        "branch-effect",
                        confirmed.state.effect_ledger[-1].sequence + 1,
                        "create_ticket_branch",
                        EffectOutcome.FAILURE,
                    ),
                ),
            }
        ),
    )
    return store, compensation, restore_preparation(bridge, gateway, compensation)


def task_definition_manifest(*texts: str) -> TaskDefinitionManifest:
    tasks = tuple(TaskDefinition(task_id=f"1.{number}", text=text) for number, text in enumerate(texts, start=1))
    return TaskDefinitionManifest(
        definition_hash=hash_json([task.model_dump(mode="json", round_trip=True) for task in tasks]),
        tasks=tasks,
    )


def task_status_manifest(definition: TaskDefinitionManifest, status: UnitStatus) -> TaskStatusManifest:
    return TaskStatusManifest(
        definition_hash=definition.definition_hash,
        statuses=tuple(TaskStatus(task_id=task.task_id, status=status) for task in definition.tasks),
    )


def complete_finalization_evidence() -> object:
    from auto_code.contracts import FinalizationEvidence

    return FinalizationEvidence(
        prefinalization_ticket_projection="ticket-projection-1",
        commit_sha="a" * 40,
        pushed_sha="a" * 40,
        linear_done_receipt="linear-receipt-1",
    )


def finalization_ready_state() -> RunState:
    return RunState(
        run_id="run-1",
        ticket_id="ENG-1",
        repository_id="repo-1",
        max_crew_iterations=3,
        review_manifest="review-manifest-1",
        review_result="approved-review-result-1",
        finalization_eligible=True,
        prefinalization_ticket_projection="ticket-projection-1",
        commit_sha="a" * 40,
        pushed_sha="a" * 40,
        linear_done_receipt="linear-receipt-1",
        finalization_evidence=complete_finalization_evidence(),
    )


def persist_after_initial(store: RunStateStore, state: RunState) -> StateGeneration:
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
    return store.compare_and_swap(initial.revision, initial.state_hash, state)


def test_hash_json_uses_canonical_mapping_order() -> None:
    assert hash_json({"a": 1, "b": 2}) == "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777"
    assert hash_json({"a": 1, "b": 2}) == hash_json({"b": 2, "a": 1})


def test_checkpoint_authority_reuses_matching_checkpoint_bindings(tmp_path: Path) -> None:
    authority = CheckpointAuthority(tmp_path)
    issued = authority.issue(
        stage=Stage.ANALYST,
        contract_hash=CONTRACT_HASH,
        input_hashes={"requirements": INPUT_HASH},
        output_manifest_hash=OUTPUT_HASH,
        validator="contract-validator",
        validator_version="1",
        validation_receipt_hash=RECEIPT_HASH,
        evidence=(),
    )
    assert authority.is_reusable(
        issued,
        stage=Stage.ANALYST,
        contract_hash=CONTRACT_HASH,
        input_hashes={"requirements": INPUT_HASH},
    )
    assert not authority.is_reusable(
        issued,
        stage=Stage.ANALYST,
        contract_hash=CONTRACT_HASH,
        input_hashes={"requirements": RECEIPT_HASH},
    )


def test_checkpoint_authority_refuses_unsafe_metadata_before_registry_persistence(tmp_path: Path) -> None:
    authority = CheckpointAuthority(tmp_path)

    with pytest.raises(ValidationError):
        authority.issue(
            stage=Stage.ANALYST,
            contract_hash=CONTRACT_HASH,
            input_hashes={"system-prompt": INPUT_HASH},
            output_manifest_hash=OUTPUT_HASH,
            validator="contract-validator",
            validator_version="1",
            validation_receipt_hash=RECEIPT_HASH,
        )

    assert list(authority.registry_dir.iterdir()) == []


def test_checkpoint_authority_reuses_issued_checkpoint_after_state_round_trip(tmp_path: Path) -> None:
    authority = CheckpointAuthority(tmp_path)
    issued = authority.issue(
        stage=Stage.ANALYST,
        contract_hash=CONTRACT_HASH,
        input_hashes={"requirements": INPUT_HASH},
        output_manifest_hash=OUTPUT_HASH,
        validator="contract-validator",
        validator_version="1",
        validation_receipt_hash=RECEIPT_HASH,
        evidence=(),
    )
    store = RunStateStore(tmp_path, "run-1")
    persist_after_initial(
        store,
        RunState(
            run_id="run-1",
            ticket_id="ENG-1",
            repository_id="repo-1",
            max_crew_iterations=3,
            checkpoints={Stage.ANALYST: issued},
            stage_outputs=(StageOutput(stage=Stage.ANALYST, content_hash=OUTPUT_HASH),),
        ),
    )

    reloaded = store.load().state.checkpoints[Stage.ANALYST]

    assert authority.is_reusable(
        reloaded,
        stage=Stage.ANALYST,
        contract_hash=CONTRACT_HASH,
        input_hashes={"requirements": INPUT_HASH},
    )


def test_checkpoint_authority_registry_rehydrates_exact_copy_and_rejects_forgery(tmp_path: Path) -> None:
    authority = CheckpointAuthority(tmp_path)
    issued = authority.issue(
        stage=Stage.ANALYST,
        contract_hash=CONTRACT_HASH,
        input_hashes={"requirements": INPUT_HASH},
        output_manifest_hash=OUTPUT_HASH,
        validator="contract-validator",
        validator_version="1",
        validation_receipt_hash=RECEIPT_HASH,
        evidence=(),
    )
    exact_copy = Checkpoint.model_validate(issued.model_dump(mode="json", round_trip=True))
    restarted = CheckpointAuthority(tmp_path)
    forged = exact_copy.model_copy(update={"output_manifest_hash": RECEIPT_HASH})
    unissued = Checkpoint(
        checkpoint_id="f" * 32,
        stage=Stage.ANALYST,
        contract_hash=CONTRACT_HASH,
        input_hashes={"requirements": INPUT_HASH},
        output_manifest_hash=OUTPUT_HASH,
        validator="contract-validator",
        validator_version="1",
        validation_receipt_hash=RECEIPT_HASH,
    )

    assert issued.checkpoint_id is not None
    assert restarted.matches(
        exact_copy,
        stage=Stage.ANALYST,
        contract_hash=CONTRACT_HASH,
        input_hashes={"requirements": INPUT_HASH},
    )
    assert not restarted.matches(
        forged,
        stage=Stage.ANALYST,
        contract_hash=CONTRACT_HASH,
        input_hashes={"requirements": INPUT_HASH},
    )
    assert not restarted.matches(
        unissued,
        stage=Stage.ANALYST,
        contract_hash=CONTRACT_HASH,
        input_hashes={"requirements": INPUT_HASH},
    )


def test_store_writes_immutable_generation_and_current_pointer(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")
    state = RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3)

    first = store.compare_and_swap(0, EMPTY_STATE_HASH, state)

    assert first.revision == 1
    assert first.state == state
    assert store.load() == first
    assert store.generation_path(1, first.state_hash).is_file()
    assert json.loads(store.current_path.read_text(encoding="utf-8")) == {
        "revision": 1,
        "state_hash": first.state_hash,
    }


def test_read_only_load_does_not_create_missing_state_paths(tmp_path: Path) -> None:
    state_root = tmp_path / "missing-state-root"

    with pytest.raises(StateStoreError):
        RunStateStore.load_read_only(state_root, "run-1")

    assert not state_root.exists()


def test_read_only_load_does_not_recreate_lock_or_unneeded_directories(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")
    state = RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3)
    persisted = store.compare_and_swap(0, EMPTY_STATE_HASH, state)
    store.lock_path.unlink()
    store.locks_dir.rmdir()
    bindings_dir = tmp_path / "active-run-bindings"
    bindings_dir.rmdir()

    assert RunStateStore.load_read_only(tmp_path, "run-1") == persisted
    assert not store.locks_dir.exists()
    assert not bindings_dir.exists()


@pytest.mark.parametrize("component", ["runs", "run", "generations"])
def test_replaced_state_directory_symlink_is_refused(tmp_path: Path, component: str) -> None:
    store = RunStateStore(tmp_path, "run-1")
    state = RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3)
    store.compare_and_swap(0, EMPTY_STATE_HASH, state)
    target = {
        "runs": store.runs_dir,
        "run": store.run_dir,
        "generations": store.generations_dir,
    }[component]
    preserved = target.with_name(f"{target.name}-preserved")
    target.rename(preserved)
    target.symlink_to(preserved, target_is_directory=True)

    with pytest.raises(AuthoritativeStateCorrupt):
        store.load()


def test_current_pointer_symlink_is_refused(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")
    state = RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3)
    store.compare_and_swap(0, EMPTY_STATE_HASH, state)
    preserved = store.current_path.with_name("current-preserved.json")
    store.current_path.rename(preserved)
    store.current_path.symlink_to(preserved)

    with pytest.raises(AuthoritativeStateCorrupt):
        store.load()


def test_dangling_active_index_symlink_is_refused(tmp_path: Path) -> None:
    index = preparation_index(tmp_path)
    index.reserve("repo-1")
    entry_path = index._index_path("repo-1")
    entry_path.unlink()
    entry_path.symlink_to(tmp_path / "missing-index.json")

    with pytest.raises(AuthoritativeIndexCorrupt):
        index.lookup("repo-1")


def test_normal_load_refuses_an_orphan_after_interrupted_pointer_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = RunStateStore(tmp_path, "run-1")
    original = RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3)
    first = persist_after_initial(store, original)
    monkeypatch.setattr(os, "replace", lambda *_, **__: (_ for _ in ()).throw(OSError("interrupted")))

    with pytest.raises(OSError, match="interrupted"):
        store.compare_and_swap(first.revision, first.state_hash, original.begin_iteration())

    with pytest.raises(AuthoritativeStateCorrupt, match="unreferenced"):
        store.load()


def test_cas_recovers_only_the_exact_orphaned_generation_after_pointer_interruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = RunStateStore(tmp_path, "run-1")
    original = RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3)
    first = store.compare_and_swap(0, EMPTY_STATE_HASH, original)
    expected = original.begin_iteration()
    original_replace = os.replace
    monkeypatch.setattr(os, "replace", lambda *_, **__: (_ for _ in ()).throw(OSError("interrupted")))

    with pytest.raises(OSError, match="interrupted"):
        store.compare_and_swap(first.revision, first.state_hash, expected)

    monkeypatch.setattr(os, "replace", original_replace)
    conflicting = first.state.model_copy(update={"current_stage": Stage.PROGRAMMER})
    with pytest.raises(AuthoritativeStateCorrupt, match="conflicting generation"):
        store.compare_and_swap(first.revision, first.state_hash, conflicting)

    recovered = store.compare_and_swap(first.revision, first.state_hash, expected)
    assert recovered.state == expected


def test_missing_current_pointer_with_prior_generation_is_refused(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")
    original = RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3)
    store.compare_and_swap(0, EMPTY_STATE_HASH, original)
    store.current_path.unlink()

    with pytest.raises(AuthoritativeStateCorrupt, match="current state pointer is missing"):
        store.load()


def test_retry_recovers_exact_initial_generation_after_interrupted_pointer_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = RunStateStore(tmp_path, "run-1")
    original = RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3)
    original_replace = os.replace
    monkeypatch.setattr(os, "replace", lambda *_, **__: (_ for _ in ()).throw(OSError("interrupted")))

    with pytest.raises(OSError, match="interrupted"):
        store.compare_and_swap(0, EMPTY_STATE_HASH, original)

    monkeypatch.setattr(os, "replace", original_replace)
    recovered = store.compare_and_swap(0, EMPTY_STATE_HASH, original)

    assert recovered.revision == 1
    assert store.load().state == original


def test_cas_rejects_non_prefix_effect_ledger(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")
    first = persist_after_initial(store, state_with_effect("effect-1"))
    rewritten = first.state.model_copy(update={"effect_ledger": ()})

    with pytest.raises(InvalidStateTransition, match="effect_ledger"):
        store.compare_and_swap(first.revision, first.state_hash, rewritten)


def test_cas_rejects_immutable_ticket_identity_changes(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")
    original = RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3)
    first = store.compare_and_swap(0, EMPTY_STATE_HASH, original)

    with pytest.raises(InvalidStateTransition, match="ticket_id"):
        store.compare_and_swap(
            first.revision,
            first.state_hash,
            original.model_copy(update={"ticket_id": "ENG-2"}),
        )


def test_cas_rejects_immutable_budget_changes(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")
    original = RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3)
    first = store.compare_and_swap(0, EMPTY_STATE_HASH, original)

    with pytest.raises(InvalidStateTransition, match="max_crew_iterations"):
        store.compare_and_swap(
            first.revision,
            first.state_hash,
            original.model_copy(update={"max_crew_iterations": 4}),
        )


def test_cas_rejects_rewritten_failure_history_prefix(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")
    original = RunState(
        run_id="run-1",
        ticket_id="ENG-1",
        repository_id="repo-1",
        max_crew_iterations=3,
        failure_history=(
            FailureRecord(
                failure_class=FailureClass.PRODUCT,
                failure_source=FailureSource.REVIEW,
                finding_kind=FindingKind.IMPLEMENTATION_MISMATCH,
            ),
        ),
    )
    first = persist_after_initial(store, original)

    with pytest.raises(InvalidStateTransition, match="failure_history"):
        store.compare_and_swap(
            first.revision,
            first.state_hash,
            original.model_copy(update={"failure_history": ()}),
        )


def test_cas_rejects_untrusted_resume_from_human_review(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")
    first = persist_after_initial(
        store,
        RunState(
            run_id="run-1",
            ticket_id="ENG-1",
            repository_id="repo-1",
            max_crew_iterations=3,
            disposition=RunDisposition.HUMAN_REVIEW,
        ),
    )
    resumed = first.state.model_copy(
        update={
            "disposition": RunDisposition.ACTIVE,
            "human_authorizations": (
                consumed_authorization("run-1", HumanAuthorizationAction.RESUME, "resume-1"),
            ),
        }
    )

    with pytest.raises(InvalidStateTransition, match="resume"):
        store.compare_and_swap(first.revision, first.state_hash, resumed)


def test_cas_accepts_only_verifier_approved_resume_from_human_review(tmp_path: Path) -> None:
    store = RunStateStore(
        tmp_path,
        "run-1",
        authorization_verifier=TrustedAuthorizations("resume-1"),
    )
    first = persist_after_initial(
        store,
        RunState(
            run_id="run-1",
            ticket_id="ENG-1",
            repository_id="repo-1",
            max_crew_iterations=3,
            disposition=RunDisposition.HUMAN_REVIEW,
        ),
    )
    resumed = first.state.model_copy(
        update={
            "disposition": RunDisposition.ACTIVE,
            "human_authorizations": (
                consumed_authorization("run-1", HumanAuthorizationAction.RESUME, "resume-1"),
            ),
        }
    )

    assert store.compare_and_swap(first.revision, first.state_hash, resumed).state == resumed


def test_cas_rejects_inapplicable_authorization_before_verifying_it(tmp_path: Path) -> None:
    verifier = RecordingAuthorizations("resume-1")
    store = RunStateStore(tmp_path, "run-1", authorization_verifier=verifier)
    first = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3),
    )
    inapplicable = first.state.model_copy(
        update={
            "disposition": RunDisposition.HUMAN_REVIEW,
            "human_authorizations": (
                consumed_authorization("run-1", HumanAuthorizationAction.RESUME, "resume-1"),
            ),
        }
    )

    with pytest.raises(InvalidStateTransition, match="Human Authorization"):
        store.compare_and_swap(first.revision, first.state_hash, inapplicable)

    assert verifier.calls == []
    assert store.load() == first


def test_cas_rejects_trusted_abandon_outside_human_review_and_preserves_generation(tmp_path: Path) -> None:
    verifier = TrustedAuthorizations("abandon-1")
    store = RunStateStore(tmp_path, "run-1", authorization_verifier=verifier)
    first = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3),
    )
    abandoned = first.state.model_copy(
        update={
            "disposition": RunDisposition.ABANDONED,
            "human_authorizations": (
                consumed_authorization("run-1", HumanAuthorizationAction.ABANDON, "abandon-1"),
            ),
        }
    )

    with pytest.raises(InvalidStateTransition, match="Human Authorization"):
        store.compare_and_swap(first.revision, first.state_hash, abandoned)

    assert store.load() == first


def test_cas_rejects_repair_restart_without_a_new_runner_and_receipt(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")
    first = persist_after_initial(
        store,
        RunState(
            run_id="run-1",
            ticket_id="ENG-1",
            repository_id="repo-1",
            max_crew_iterations=3,
            disposition=RunDisposition.REPAIR_REQUIRED,
            runner_identity=runner_identity("a" * 64),
        ),
    )
    restarted = first.state.model_copy(
        update={
            "disposition": RunDisposition.ACTIVE,
            "runner_identity": runner_identity("b" * 64),
        }
    )

    with pytest.raises(InvalidStateTransition, match="repair"):
        store.compare_and_swap(first.revision, first.state_hash, restarted)


def test_cas_accepts_repair_restart_with_changed_runner_and_receipt(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")
    first = persist_after_initial(
        store,
        RunState(
            run_id="run-1",
            ticket_id="ENG-1",
            repository_id="repo-1",
            max_crew_iterations=3,
            disposition=RunDisposition.REPAIR_REQUIRED,
            runner_identity=runner_identity("a" * 64),
        ),
    )
    restarted = first.state.model_copy(
        update={
            "disposition": RunDisposition.ACTIVE,
            "runner_identity": runner_identity("b" * 64),
            "restart_receipt_hash": "e" * 64,
        }
    )

    assert store.compare_and_swap(first.revision, first.state_hash, restarted).state == restarted


def test_cas_rejects_waiting_mcp_resume_before_pending_effect_reconciles(tmp_path: Path) -> None:
    store, _, _, first, _ = pending_ticket_request(tmp_path)
    resumed = first.state.model_copy(
        update={"disposition": RunDisposition.ACTIVE, "pending_external_request": None}
    )

    with pytest.raises(InvalidStateTransition, match="pending request"):
        store.compare_and_swap(first.revision, first.state_hash, resumed)


def test_cas_accepts_waiting_mcp_resume_after_pending_effect_reconciles(tmp_path: Path) -> None:
    _, bridge, gateway, first, request = pending_ticket_request(tmp_path)
    resumed = gateway.consume_receipt(first, bridge.execute(request))

    assert resumed.state.pending_external_request is None
    assert resumed.state.disposition is RunDisposition.ACTIVE


def test_cas_rejects_resume_authorization_during_waiting_mcp_reactivation(tmp_path: Path) -> None:
    verifier = TrustedAuthorizations("resume-1")
    store, bridge, gateway, first, request = pending_ticket_request(
        tmp_path,
        authorization_verifier=verifier,
    )

    with pytest.raises(InvalidStateTransition, match="Human Authorization"):
        gateway.consume_receipt(
            first,
            bridge.execute(request),
            state_update=lambda state, _: state.model_copy(
                update={
                    "human_authorizations": (
                        consumed_authorization("run-1", HumanAuthorizationAction.RESUME, "resume-1"),
                    ),
                }
            ),
        )

    assert store.load() == first
    assert store.load().state.authorized_iteration_limit == 3


def test_cas_rejects_resume_authorization_during_repair_reactivation(tmp_path: Path) -> None:
    verifier = TrustedAuthorizations("resume-1")
    store = RunStateStore(tmp_path, "run-1", authorization_verifier=verifier)
    initial = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3),
    )
    repair = initial.state.model_copy(
        update={
            "disposition": RunDisposition.REPAIR_REQUIRED,
            "runner_identity": runner_identity("a" * 64),
        }
    )
    first = store.compare_and_swap(initial.revision, initial.state_hash, repair)
    restarted = first.state.model_copy(
        update={
            "disposition": RunDisposition.ACTIVE,
            "runner_identity": runner_identity("b" * 64),
            "restart_receipt_hash": "e" * 64,
            "human_authorizations": (
                consumed_authorization("run-1", HumanAuthorizationAction.RESUME, "resume-1"),
            ),
        }
    )

    assert restarted.authorized_iteration_limit == first.state.authorized_iteration_limit + 1
    with pytest.raises(InvalidStateTransition, match="Human Authorization"):
        store.compare_and_swap(first.revision, first.state_hash, restarted)

    assert store.load() == first
    assert store.load().state.authorized_iteration_limit == 3


def test_cas_rejects_crew_count_changes_without_a_legitimate_opening(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")
    first = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3),
    )
    forged_increment = first.state.model_copy(update={"crew_iteration_count": 1, "iteration_open": False})

    with pytest.raises(InvalidStateTransition, match="Crew Iteration"):
        store.compare_and_swap(first.revision, first.state_hash, forged_increment)

    second_store = RunStateStore(tmp_path, "run-2")
    initial = second_store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-2", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3),
    )
    opened = second_store.compare_and_swap(
        initial.revision,
        initial.state_hash,
        initial.state.begin_iteration(),
    )
    second = second_store.compare_and_swap(
        opened.revision,
        opened.state_hash,
        opened.state.model_copy(update={"iteration_open": False}),
    )

    with pytest.raises(InvalidStateTransition, match="opening"):
        second_store.compare_and_swap(
            second.revision,
            second.state_hash,
            second.state.model_copy(update={"iteration_open": True}),
        )


def test_cas_rejects_checked_task_status_regression(tmp_path: Path) -> None:
    definition = task_definition_manifest("Implement state validation")
    store = RunStateStore(tmp_path, "run-1")
    initial = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3),
    )
    defined = store.compare_and_swap(
        initial.revision,
        initial.state_hash,
        initial.state.model_copy(update={"task_definition_manifest": definition}),
    )
    unchecked = store.compare_and_swap(
        defined.revision,
        defined.state_hash,
        defined.state.model_copy(
            update={"task_status_manifest": task_status_manifest(definition, UnitStatus.UNCHECKED)}
        ),
    )
    first = store.compare_and_swap(
        unchecked.revision,
        unchecked.state_hash,
        unchecked.state.model_copy(
            update={"task_status_manifest": task_status_manifest(definition, UnitStatus.CHECKED)}
        ),
    )
    reopened = first.state.model_copy(
        update={"task_status_manifest": task_status_manifest(definition, UnitStatus.UNCHECKED)}
    )

    with pytest.raises(InvalidStateTransition, match="Task status"):
        store.compare_and_swap(first.revision, first.state_hash, reopened)


def test_cas_requires_definition_change_to_clear_dependent_state(tmp_path: Path) -> None:
    first_definition = task_definition_manifest("Implement state validation")
    second_definition = task_definition_manifest("Implement causal state validation")
    store = RunStateStore(tmp_path, "run-1")
    initial = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3),
    )
    defined = store.compare_and_swap(
        initial.revision,
        initial.state_hash,
        initial.state.model_copy(update={"task_definition_manifest": first_definition}),
    )
    first = store.compare_and_swap(
        defined.revision,
        defined.state_hash,
        defined.state.model_copy(
            update={
                "task_status_manifest": task_status_manifest(first_definition, UnitStatus.UNCHECKED),
                "product_change_manifest": "product-change-1",
                "build_identity": "build-1",
                "verification_result": "verification-1",
                "browser_result": "browser-1",
                "review_manifest": "review-manifest-1",
                "review_result": "review-result-1",
                "prefinalization_ticket_projection": "ticket-projection-1",
                "commit_sha": "commit-1",
                "pushed_sha": "push-1",
                "linear_done_receipt": "linear-receipt-1",
                "finalization": "finalization-1",
            }
        ),
    )
    stale = first.state.model_copy(
        update={"task_definition_manifest": second_definition, "task_status_manifest": None}
    )

    with pytest.raises(InvalidStateTransition, match="definition"):
        store.compare_and_swap(first.revision, first.state_hash, stale)

    reset = first.state.model_copy(
        update={
            "task_definition_manifest": second_definition,
            "task_status_manifest": None,
            "product_change_manifest": None,
            "build_identity": None,
            "verification_result": None,
            "browser_result": None,
            "review_manifest": None,
            "review_result": None,
            "prefinalization_ticket_projection": None,
            "commit_sha": None,
            "pushed_sha": None,
            "linear_done_receipt": None,
            "finalization": None,
        }
    )

    assert store.compare_and_swap(first.revision, first.state_hash, reset).state == reset


def test_cas_rejects_unbound_checkpoint_even_for_a_constructed_snapshot(tmp_path: Path) -> None:
    authority = CheckpointAuthority(tmp_path)
    checkpoint = authority.issue(
        stage=Stage.ANALYST,
        contract_hash=CONTRACT_HASH,
        input_hashes={"requirements": INPUT_HASH},
        output_manifest_hash=OUTPUT_HASH,
        validator="contract-validator",
        validator_version="1",
        validation_receipt_hash=RECEIPT_HASH,
    )
    state = RunState.model_construct(
        run_id="run-1",
        ticket_id="ENG-1",
        repository_id="repo-1",
        max_crew_iterations=3,
        checkpoints={Stage.ANALYST: checkpoint},
        stage_outputs=(),
    )

    with pytest.raises(InvalidStateTransition, match="persisted contract"):
        RunStateStore(tmp_path, "run-1").compare_and_swap(0, EMPTY_STATE_HASH, state)


def test_cas_rejects_checkpoint_with_a_mismatched_stage_output(tmp_path: Path) -> None:
    authority = CheckpointAuthority(tmp_path)
    checkpoint = authority.issue(
        stage=Stage.ANALYST,
        contract_hash=CONTRACT_HASH,
        input_hashes={"requirements": INPUT_HASH},
        output_manifest_hash=OUTPUT_HASH,
        validator="contract-validator",
        validator_version="1",
        validation_receipt_hash=RECEIPT_HASH,
    )
    state = RunState.model_construct(
        run_id="run-1",
        ticket_id="ENG-1",
        repository_id="repo-1",
        max_crew_iterations=3,
        checkpoints={Stage.ANALYST: checkpoint},
        stage_outputs=(StageOutput(stage=Stage.ANALYST, content_hash=RECEIPT_HASH),),
    )

    with pytest.raises(InvalidStateTransition, match="persisted contract"):
        RunStateStore(tmp_path, "run-1").compare_and_swap(0, EMPTY_STATE_HASH, state)


def test_cas_rejects_unsafe_checkpoint_mapping_keys_in_constructed_state(tmp_path: Path) -> None:
    checkpoint = Checkpoint.model_construct(
        checkpoint_id="a" * 32,
        stage=Stage.ANALYST,
        contract_hash=CONTRACT_HASH,
        input_hashes={"sk-live-abcdefgh": INPUT_HASH},
        output_manifest_hash=OUTPUT_HASH,
        validator="contract-validator",
        validator_version="1",
        validation_receipt_hash=RECEIPT_HASH,
        evidence=(),
    )
    state = RunState.model_construct(
        run_id="run-1",
        ticket_id="ENG-1",
        repository_id="repo-1",
        max_crew_iterations=3,
        checkpoints={Stage.ANALYST: checkpoint},
        stage_outputs=(StageOutput(stage=Stage.ANALYST, content_hash=OUTPUT_HASH),),
    )

    with pytest.raises(InvalidStateTransition, match="unsafe"):
        RunStateStore(tmp_path, "run-1").compare_and_swap(0, EMPTY_STATE_HASH, state)


def test_cas_rejects_initial_done_snapshot(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")
    arbitrary_done = RunState(
        run_id="run-1",
        ticket_id="ENG-1",
        repository_id="repo-1",
        max_crew_iterations=3,
        disposition=RunDisposition.DONE,
    )

    with pytest.raises(InvalidStateTransition, match="initial"):
        store.compare_and_swap(0, EMPTY_STATE_HASH, arbitrary_done)


def test_cas_rejects_completed_initial_state_without_writing_a_generation(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")

    with pytest.raises(InvalidStateTransition, match="initial"):
        store.compare_and_swap(0, EMPTY_STATE_HASH, finalization_ready_state())

    assert not store.current_path.exists()
    assert list(store.generations_dir.iterdir()) == []


def test_cas_rejects_done_without_finalization_evidence(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")
    first = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3),
    )

    with pytest.raises(InvalidStateTransition, match="finalization"):
        store.compare_and_swap(
            first.revision,
            first.state_hash,
            first.state.model_copy(update={"disposition": RunDisposition.DONE}),
        )


def test_cas_accepts_done_only_from_a_closed_finalization_eligible_state(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")
    first = persist_after_initial(store, finalization_ready_state())
    done = first.state.model_copy(update={"disposition": RunDisposition.DONE})

    assert store.compare_and_swap(first.revision, first.state_hash, done).state == done


def test_terminal_states_are_immutable(tmp_path: Path) -> None:
    done_store = RunStateStore(tmp_path, "run-1")
    ready = persist_after_initial(done_store, finalization_ready_state())
    done = done_store.compare_and_swap(
        ready.revision,
        ready.state_hash,
        ready.state.model_copy(update={"disposition": RunDisposition.DONE}),
    )

    with pytest.raises(InvalidStateTransition, match="terminal state"):
        done_store.compare_and_swap(
            done.revision,
            done.state_hash,
            done.state.model_copy(update={"current_stage": Stage.PROGRAMMER}),
        )

    verifier = TrustedAuthorizations("abandon-1")
    abandoned_store = RunStateStore(tmp_path, "run-2", authorization_verifier=verifier)
    active = abandoned_store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-2", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3),
    )
    human_review = abandoned_store.compare_and_swap(
        active.revision,
        active.state_hash,
        active.state.model_copy(update={"disposition": RunDisposition.HUMAN_REVIEW}),
    )
    abandoned = abandoned_store.compare_and_swap(
        human_review.revision,
        human_review.state_hash,
        human_review.state.model_copy(
            update={
                "disposition": RunDisposition.ABANDONED,
                "human_authorizations": (
                    consumed_authorization("run-2", HumanAuthorizationAction.ABANDON, "abandon-1"),
                ),
            }
        ),
    )

    with pytest.raises(InvalidStateTransition, match="terminal state"):
        abandoned_store.compare_and_swap(
            abandoned.revision,
            abandoned.state_hash,
            abandoned.state.model_copy(update={"current_stage": Stage.PROGRAMMER}),
        )


def test_state_and_index_accept_uppercase_hash_bindings(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")
    original = RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3)
    first = store.compare_and_swap(0, EMPTY_STATE_HASH, original)

    second = store.compare_and_swap(
        first.revision,
        first.state_hash.upper(),
        original.begin_iteration(),
    )

    index = preparation_index(tmp_path)
    reservation = index.reserve("repo-2")
    active = index.activate_reservation(
        activation_request(
            reservation,
            run_id="run-2",
            preparation_input_hash=PREPARATION_INPUT_HASH.upper(),
        ).model_copy(update={"expected_index_hash": reservation.index_hash.upper()})
    )

    assert second.revision == 2
    assert active.run_id == "run-2"


def test_store_refuses_path_escape_and_secret_like_values(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        RunStateStore(tmp_path, "../outside")

    store = RunStateStore(tmp_path, "run-1")
    state = RunState(
        run_id="run-1",
        ticket_id="sk-live-abcdefgh",
        repository_id="repo-1",
        max_crew_iterations=3,
    )
    with pytest.raises(InvalidStateTransition, match="unsafe"):
        store.compare_and_swap(0, EMPTY_STATE_HASH, state)


def test_only_one_concurrent_cas_writer_succeeds(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")
    first = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3),
    )

    results = run_concurrently(
        2,
        lambda: store.compare_and_swap(
            first.revision,
            first.state_hash,
            first.state.begin_iteration(),
        ),
    )

    assert sum(result.succeeded for result in results) == 1


def test_only_one_cross_process_cas_writer_succeeds(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")
    store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3),
    )
    context = get_context("spawn")
    ready = [context.Event(), context.Event()]
    proceed = context.Event()
    results = context.Queue()
    writers = [
        context.Process(target=competing_cas_in_process, args=(str(tmp_path), "run-1", event, proceed, results))
        for event in ready
    ]
    for writer in writers:
        writer.start()
    assert all(event.wait(10) for event in ready)
    proceed.set()
    observed = [results.get(timeout=10), results.get(timeout=10)]
    for writer in writers:
        writer.join(timeout=10)

    assert [writer.exitcode for writer in writers] == [0, 0]
    assert observed.count(("ok", "")) == 1
    assert observed.count(("error", "CompareAndSwapConflict")) == 1


def test_only_one_cross_process_reservation_activation_succeeds(tmp_path: Path) -> None:
    context = get_context("spawn")
    ready = [context.Event(), context.Event()]
    proceed = context.Event()
    results = context.Queue()
    workers = [
        context.Process(
            target=reserve_and_activate_in_process,
            args=(str(tmp_path), "repo-1", f"run-{number}", event, proceed, results),
        )
        for number, event in enumerate(ready, start=1)
    ]
    for worker in workers:
        worker.start()
    assert all(event.wait(10) for event in ready)
    proceed.set()
    observed = [results.get(timeout=10), results.get(timeout=10)]
    for worker in workers:
        worker.join(timeout=10)

    assert [worker.exitcode for worker in workers] == [0, 0]
    active = [result for result in observed if result[0] == "active"]
    blocked = [result for result in observed if result[0] == "error"]
    assert len(active) == 1
    assert blocked[0][1] in {"PreparationReservationExists", "ActiveRunExists"}
    assert preparation_index(tmp_path).lookup("repo-1").run_id == active[0][1]


def test_corrupt_referenced_generation_never_rewinds(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")
    first = persist_after_initial(store, state_with_effect("effect-1"))
    store.generation_path(first.revision, first.state_hash).write_text("{corrupt", encoding="utf-8")

    with pytest.raises(AuthoritativeStateCorrupt):
        store.load()


def test_active_run_blocks_new_claim_until_done(tmp_path: Path) -> None:
    index = preparation_index(tmp_path)
    reservation = index.reserve("repo-1")
    active = index.activate_reservation(activation_request(reservation, run_id="run-1"))

    with pytest.raises(ActiveRunExists):
        index.reserve("repo-1")

    done = persist_terminal_generation(active, RunDisposition.DONE)
    index.release("repo-1", "run-1", active.index_revision, active.index_hash, done.state_hash)

    assert index.reserve("repo-1").repository_id == "repo-1"


def test_activation_rejects_a_stale_reservation_cas_before_writing_a_journal(tmp_path: Path) -> None:
    index = preparation_index(tmp_path)
    reservation = index.reserve("repo-1")
    request = ActivationRequest(
        reservation_id=reservation.reservation_id,
        repository_id=reservation.repository_id,
        expected_index_revision=reservation.index_revision + 1,
        expected_index_hash=reservation.index_hash,
        preparation_input_ref=preparation_input_ref(
            reservation.reservation_id,
            reservation.repository_id,
            reservation.challenge_hash,
        ),
    )

    with pytest.raises(ActivationReservationMismatch, match="CAS"):
        index.activate_reservation(request)

    assert not index._journal_path(reservation.reservation_id).exists()


def test_activation_journal_binds_the_reservation_cas_and_trusted_input_provenance(tmp_path: Path) -> None:
    index = preparation_index(tmp_path)
    reservation = index.reserve("repo-1")
    reference = preparation_input_ref(
        reservation.reservation_id,
        reservation.repository_id,
        reservation.challenge_hash,
    )
    request = ActivationRequest(
        reservation_id=reservation.reservation_id,
        repository_id=reservation.repository_id,
        expected_index_revision=reservation.index_revision,
        expected_index_hash=reservation.index_hash,
        preparation_input_ref=reference,
    )

    index.activate_reservation(request)

    journal = index._load_journal_locked(reservation.reservation_id)
    assert journal is not None
    assert journal["expected_index_revision"] == reservation.index_revision
    assert journal["expected_index_hash"] == reservation.index_hash
    assert journal["preparation_input_ref"] == reference.model_dump(mode="json", round_trip=True)


def test_prepared_activation_replay_rechecks_the_reservation_cas_before_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    index = preparation_index(tmp_path)
    reservation = index.reserve("repo-1")
    request = ActivationRequest(
        reservation_id=reservation.reservation_id,
        repository_id=reservation.repository_id,
        expected_index_revision=reservation.index_revision,
        expected_index_hash=reservation.index_hash,
        preparation_input_ref=preparation_input_ref(
            reservation.reservation_id,
            reservation.repository_id,
            reservation.challenge_hash,
        ),
    )
    original_complete = index._complete_prepared_activation_locked
    monkeypatch.setattr(
        index,
        "_complete_prepared_activation_locked",
        lambda *_: (_ for _ in ()).throw(OSError("interrupted after journal")),
    )

    with pytest.raises(OSError, match="interrupted after journal"):
        index.activate_reservation(request)

    monkeypatch.setattr(index, "_complete_prepared_activation_locked", original_complete)
    with index._repository_lock(reservation.repository_id):
        entry = index._load_entry_locked(reservation.repository_id)
        assert entry is not None
        index._save_entry_locked(
            reservation.repository_id,
            index._new_entry(entry.revision + 1, dict(entry.record)),
        )

    with pytest.raises(ActivationReservationMismatch, match="CAS"):
        index.activate_reservation(request)

    assert index.lookup(reservation.repository_id) is None


def test_activation_requires_a_complete_preparation_binding_without_rejecting_generic_initial_states(
    tmp_path: Path,
) -> None:
    generic = RunState(run_id="generic-run", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3)
    assert RunStateStore(tmp_path, generic.run_id).compare_and_swap(0, EMPTY_STATE_HASH, generic).state == generic

    index = preparation_index(tmp_path)
    reservation = index.reserve("prep-repo")
    initial = RunState(
        run_id="prep-run",
        ticket_id="ENG-2",
        repository_id=reservation.repository_id,
        max_crew_iterations=3,
    )
    request = ActivationRequest(
        reservation_id=reservation.reservation_id,
        repository_id=reservation.repository_id,
        expected_index_revision=reservation.index_revision,
        expected_index_hash=reservation.index_hash,
        preparation_input_ref=preparation_input_ref(
            reservation.reservation_id,
            reservation.repository_id,
            reservation.challenge_hash,
        ),
        run_id=initial.run_id,
        initial_state=initial,
        initial_state_hash=hash_json(initial.model_dump(mode="json", round_trip=True)),
    )

    with pytest.raises(InvalidStateTransition, match="preparation binding"):
        index.activate_reservation(request)

    assert not index._journal_path(reservation.reservation_id).exists()


def test_preparation_phase_cannot_reset_after_a_linear_start_was_requested(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")
    initial = store.compare_and_swap(0, EMPTY_STATE_HASH, preparation_bound_state())
    requested = store.compare_and_swap(
        initial.revision,
        initial.state_hash,
        initial.state.model_copy(update={"preparation_phase": PreparationPhase.IN_PROGRESS_REQUESTED}),
    )

    with pytest.raises(InvalidStateTransition, match="preparation phase"):
        store.compare_and_swap(
            requested.revision,
            requested.state_hash,
            requested.state.model_copy(update={"preparation_phase": PreparationPhase.SELECTED}),
        )


def test_preparation_runner_identity_is_pinned_outside_an_authorized_repair_restart(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")
    initial = store.compare_and_swap(0, EMPTY_STATE_HASH, preparation_bound_state())

    with pytest.raises(InvalidStateTransition, match="runner_identity"):
        store.compare_and_swap(
            initial.revision,
            initial.state_hash,
            initial.state.model_copy(update={"runner_identity": runner_identity("8" * 64)}),
        )


def test_preparation_state_budget_must_match_its_trusted_input_reference() -> None:
    state = preparation_bound_state()

    with pytest.raises(ValidationError, match="crew iteration budget"):
        state.model_copy(update={"max_crew_iterations": 4})


def test_preparation_requires_a_persisted_compensation_phase_before_a_restore_can_mark_it_compensated(
    tmp_path: Path,
) -> None:
    store, bridge, gateway, requested = preparation_receipt_boundary(tmp_path)
    confirmed = confirm_preparation(bridge, gateway, requested)
    combined = confirmed.state.model_copy(
        update={
            "preparation_phase": PreparationPhase.COMPENSATION_REQUIRED,
            "disposition": RunDisposition.HUMAN_REVIEW,
            "compensated": True,
            "effect_ledger": (
                *confirmed.state.effect_ledger,
                *reconciled_effect_events(
                    "branch-effect",
                    5,
                    "create_ticket_branch",
                    EffectOutcome.FAILURE,
                ),
                *reconciled_effect_events(
                    "restore-effect",
                    9,
                    "restore_ticket_state",
                    EffectOutcome.SUCCESS,
                ),
            ),
        }
    )

    with pytest.raises(InvalidStateTransition, match="persisted compensation"):
        store.compare_and_swap(confirmed.revision, confirmed.state_hash, combined)


def test_compensation_restore_proof_rejects_a_receipt_created_before_compensation(tmp_path: Path) -> None:
    store, bridge, gateway, requested = preparation_receipt_boundary(tmp_path)
    confirmed = confirm_preparation(bridge, gateway, requested)
    request = gateway.request_action(
        confirmed,
        operation="restore_ticket_state",
        entity="ticket",
        target=confirmed.state.ticket_id,
        expected_external_revision=None,
        arguments={"ticket_id": confirmed.state.ticket_id, "state_id": "state-1"},
    )
    pending = gateway.persist_pending(confirmed, request)
    receipt = bridge.execute(request)
    sequence = pending.state.effect_ledger[-1].sequence + 1
    evidence = EvidenceRef(
        relative_path=receipt.relative_path,
        sha256=receipt.content_hash,
        media_type="application/json",
        creator="trusted-mcp-bridge",
    )
    reconciled = pending.state.model_copy(
        update={
            "preparation_phase": PreparationPhase.COMPENSATION_REQUIRED,
            "disposition": RunDisposition.HUMAN_REVIEW,
            "compensated": True,
            "pending_external_request": None,
            "effect_ledger": (
                *pending.state.effect_ledger,
                EffectInvocation(
                    effect_id=request.effect_id,
                    sequence=sequence,
                    timestamp=receipt.observed_at,
                    payload=EffectInvocationPayload(),
                ),
                EffectObservation(
                    effect_id=request.effect_id,
                    sequence=sequence + 1,
                    timestamp=receipt.observed_at,
                    payload=EffectObservationPayload(
                        outcome=receipt.outcome,
                        external_revision=receipt.external_revision,
                        evidence_refs=(evidence,),
                    ),
                ),
                EffectReconciliation(
                    effect_id=request.effect_id,
                    sequence=sequence + 2,
                    timestamp=receipt.observed_at,
                    payload=EffectReconciliationPayload(
                        outcome=receipt.outcome,
                        evidence_refs=(evidence,),
                        receipt_hash=receipt.content_hash,
                    ),
                ),
            ),
        }
    )

    assert not store._has_authenticated_receipt_reconciliation(
        pending.state,
        reconciled,
        "restore_ticket_state",
        EffectOutcome.SUCCESS,
    )


def test_confirmed_restore_pending_cannot_enter_compensation_after_human_review_resume(tmp_path: Path) -> None:
    verifier = TrustedAuthorizations("resume-1")
    store, bridge, gateway, requested = preparation_receipt_boundary(
        tmp_path,
        authorization_verifier=verifier,
    )
    confirmed = confirm_preparation(bridge, gateway, requested)
    request = gateway.request_action(
        confirmed,
        operation="restore_ticket_state",
        entity="ticket",
        target=confirmed.state.ticket_id,
        expected_external_revision=None,
        arguments={"ticket_id": confirmed.state.ticket_id, "state_id": "state-1"},
    )
    pending = gateway.persist_pending(confirmed, request)
    receipt = bridge.execute(request)
    human_review = store.compare_and_swap(
        pending.revision,
        pending.state_hash,
        pending.state.model_copy(update={"disposition": RunDisposition.HUMAN_REVIEW}),
    )
    resumed = store.compare_and_swap(
        human_review.revision,
        human_review.state_hash,
        human_review.state.model_copy(
            update={
                "disposition": RunDisposition.ACTIVE,
                "human_authorizations": (
                    consumed_authorization("run-1", HumanAuthorizationAction.RESUME, "resume-1"),
                ),
            }
        ),
    )

    with pytest.raises(InvalidStateTransition, match="pending request"):
        store.compare_and_swap(
            resumed.revision,
            resumed.state_hash,
            resumed.state.model_copy(
                update={
                    "preparation_phase": PreparationPhase.COMPENSATION_REQUIRED,
                    "effect_ledger": (
                        *resumed.state.effect_ledger,
                        *reconciled_effect_events(
                            "branch-effect",
                            resumed.state.effect_ledger[-1].sequence + 1,
                            "create_ticket_branch",
                            EffectOutcome.FAILURE,
                        ),
                    ),
                }
            ),
        )

    assert store.load() == resumed
    with pytest.raises(InvalidStateTransition, match="persisted compensation"):
        gateway.consume_receipt(
            resumed,
            receipt,
            state_update=lambda state, _: state.model_copy(
                update={
                    "preparation_phase": PreparationPhase.COMPENSATION_REQUIRED,
                    "compensated": True,
                    "disposition": RunDisposition.HUMAN_REVIEW,
                }
            ),
        )

    assert store.load() == resumed
    with pytest.raises(InvalidStateTransition, match="preparation phase"):
        store.compare_and_swap(
            resumed.revision,
            resumed.state_hash,
            resumed.state.model_copy(update={"preparation_phase": PreparationPhase.SELECTED}),
        )

    assert store.load() == resumed


def test_preparation_compensation_rejects_a_branch_failure_from_an_earlier_transition(tmp_path: Path) -> None:
    store, bridge, gateway, requested = preparation_receipt_boundary(tmp_path)
    confirmed = confirm_preparation(bridge, gateway, requested)
    with_old_branch_failure = store.compare_and_swap(
        confirmed.revision,
        confirmed.state_hash,
        confirmed.state.model_copy(
            update={
                "effect_ledger": (
                    *confirmed.state.effect_ledger,
                    *reconciled_effect_events(
                        "old-branch-effect",
                        5,
                        "create_ticket_branch",
                        EffectOutcome.FAILURE,
                    ),
                )
            }
        ),
    )

    with pytest.raises(InvalidStateTransition, match="branch failure"):
        store.compare_and_swap(
            with_old_branch_failure.revision,
            with_old_branch_failure.state_hash,
            with_old_branch_failure.state.model_copy(
                update={"preparation_phase": PreparationPhase.COMPENSATION_REQUIRED}
            ),
        )


def test_successful_compensation_rejects_a_restore_success_from_an_earlier_transition(tmp_path: Path) -> None:
    store, bridge, gateway, requested = preparation_receipt_boundary(tmp_path)
    confirmed = confirm_preparation(bridge, gateway, requested)
    compensation_required = store.compare_and_swap(
        confirmed.revision,
        confirmed.state_hash,
        confirmed.state.model_copy(
            update={
                "preparation_phase": PreparationPhase.COMPENSATION_REQUIRED,
                "effect_ledger": (
                    *confirmed.state.effect_ledger,
                    *reconciled_effect_events(
                        "branch-effect",
                        5,
                        "create_ticket_branch",
                        EffectOutcome.FAILURE,
                    ),
                ),
            }
        ),
    )
    with_old_restore_success = store.compare_and_swap(
        compensation_required.revision,
        compensation_required.state_hash,
        compensation_required.state.model_copy(
            update={
                "effect_ledger": (
                    *compensation_required.state.effect_ledger,
                    *reconciled_effect_events(
                        "old-restore-effect",
                        9,
                        "restore_ticket_state",
                        EffectOutcome.SUCCESS,
                    ),
                )
            }
        ),
    )

    with pytest.raises(InvalidStateTransition, match="restore reconciliation"):
        store.compare_and_swap(
            with_old_restore_success.revision,
            with_old_restore_success.state_hash,
            with_old_restore_success.state.model_copy(
                update={
                    "compensated": True,
                    "disposition": RunDisposition.HUMAN_REVIEW,
                }
            ),
        )


def resumed_and_reconfirmed_preparation(
    tmp_path: Path,
) -> tuple[RunStateStore, TrustedLinearBridge, LinearGateway, StateGeneration]:
    verifier = TrustedAuthorizations("resume-1", "resume-2")
    store, bridge, gateway, requested = preparation_receipt_boundary(
        tmp_path,
        authorization_verifier=verifier,
    )
    confirmed = confirm_preparation(bridge, gateway, requested)
    first_compensation = store.compare_and_swap(
        confirmed.revision,
        confirmed.state_hash,
        confirmed.state.model_copy(
            update={
                "preparation_phase": PreparationPhase.COMPENSATION_REQUIRED,
                "effect_ledger": (
                    *confirmed.state.effect_ledger,
                    *reconciled_effect_events(
                        "first-branch-effect",
                        confirmed.state.effect_ledger[-1].sequence + 1,
                        "create_ticket_branch",
                        EffectOutcome.FAILURE,
                    ),
                ),
            }
        ),
    )
    restored = restore_preparation(bridge, gateway, first_compensation)
    resumed = store.compare_and_swap(
        restored.revision,
        restored.state_hash,
        restored.state.model_copy(
            update={
                "preparation_phase": PreparationPhase.SELECTED,
                "disposition": RunDisposition.ACTIVE,
                "human_authorizations": (
                    consumed_authorization("run-1", HumanAuthorizationAction.RESUME, "resume-1"),
                ),
            }
        ),
    )
    second_requested = store.compare_and_swap(
        resumed.revision,
        resumed.state_hash,
        resumed.state.model_copy(update={"preparation_phase": PreparationPhase.IN_PROGRESS_REQUESTED}),
    )
    return store, bridge, gateway, confirm_preparation(bridge, gateway, second_requested)


def test_compensation_resume_requires_restore_after_the_latest_successful_start(tmp_path: Path) -> None:
    store, _, _, second_confirmed = resumed_and_reconfirmed_preparation(tmp_path)

    assert not store._has_current_preparation_restore(second_confirmed.state)


def test_resumed_preparation_cannot_stage_human_review_before_a_second_compensation(tmp_path: Path) -> None:
    store, _, _, second_confirmed = resumed_and_reconfirmed_preparation(tmp_path)
    staged = store.compare_and_swap(
        second_confirmed.revision,
        second_confirmed.state_hash,
        second_confirmed.state.model_copy(update={"disposition": RunDisposition.HUMAN_REVIEW}),
    )
    assert staged.state.disposition is RunDisposition.HUMAN_REVIEW

    with pytest.raises(InvalidStateTransition, match="active confirmation"):
        store.compare_and_swap(
            staged.revision,
            staged.state_hash,
            staged.state.model_copy(
                update={
                    "preparation_phase": PreparationPhase.COMPENSATION_REQUIRED,
                    "effect_ledger": (
                        *staged.state.effect_ledger,
                        *reconciled_effect_events(
                            "second-branch-effect",
                            staged.state.effect_ledger[-1].sequence + 1,
                            "create_ticket_branch",
                            EffectOutcome.FAILURE,
                        ),
                    ),
                }
            ),
        )


def test_compensation_human_review_cannot_resume_without_resetting_its_phase(tmp_path: Path) -> None:
    verifier = TrustedAuthorizations("resume-1")
    store, bridge, gateway, requested = preparation_receipt_boundary(
        tmp_path,
        authorization_verifier=verifier,
    )
    confirmed = confirm_preparation(bridge, gateway, requested)
    compensation = store.compare_and_swap(
        confirmed.revision,
        confirmed.state_hash,
        confirmed.state.model_copy(
            update={
                "preparation_phase": PreparationPhase.COMPENSATION_REQUIRED,
                "effect_ledger": (
                    *confirmed.state.effect_ledger,
                    *reconciled_effect_events(
                        "branch-effect",
                        confirmed.state.effect_ledger[-1].sequence + 1,
                        "create_ticket_branch",
                        EffectOutcome.FAILURE,
                    ),
                ),
            }
        ),
    )
    restored = restore_preparation(bridge, gateway, compensation)

    with pytest.raises(InvalidStateTransition, match="reset the compensation phase"):
        store.compare_and_swap(
            restored.revision,
            restored.state_hash,
            restored.state.model_copy(
                update={
                    "disposition": RunDisposition.ACTIVE,
                    "human_authorizations": (
                        consumed_authorization("run-1", HumanAuthorizationAction.RESUME, "resume-1"),
                    ),
                }
            ),
        )


def test_consumed_authenticated_resume_resets_compensation_and_preserves_ledger_and_history(tmp_path: Path) -> None:
    """An unverified resume or replacement history could erase the only evidence authorizing a retried preparation."""
    store, _, restored = restored_compensation_preparation(tmp_path)
    ledger = restored.state.effect_ledger
    history = restored.state.failure_history

    resumed = store.compare_and_swap(
        restored.revision,
        restored.state_hash,
        restored.state.model_copy(
            update={
                "preparation_phase": PreparationPhase.SELECTED,
                "disposition": RunDisposition.ACTIVE,
                "human_authorizations": (
                    consumed_authorization("run-1", HumanAuthorizationAction.RESUME, "resume-1"),
                ),
            }
        ),
    )

    assert resumed.state.preparation_phase is PreparationPhase.SELECTED
    assert resumed.state.disposition is RunDisposition.ACTIVE
    assert resumed.state.human_authorizations[-1].action is HumanAuthorizationAction.RESUME
    assert resumed.state.effect_ledger == ledger
    assert resumed.state.failure_history == history


def test_compensation_reset_rechecks_a_corrupt_restore_source_before_publication(tmp_path: Path) -> None:
    store, source, restored = restored_compensation_preparation(tmp_path)
    current_pointer = store.current_path.read_bytes()
    store.generation_path(source.revision, source.state_hash).write_text("{}", encoding="ascii")

    with pytest.raises(StateStoreError):
        store.compare_and_swap(
            restored.revision,
            restored.state_hash,
            restored.state.model_copy(
                update={
                    "preparation_phase": PreparationPhase.SELECTED,
                    "disposition": RunDisposition.ACTIVE,
                    "human_authorizations": (
                        consumed_authorization("run-1", HumanAuthorizationAction.RESUME, "resume-1"),
                    ),
                }
            ),
        )

    assert store.current_path.read_bytes() == current_pointer


def test_compensation_reset_rechecks_a_missing_restore_source_before_publication(tmp_path: Path) -> None:
    store, source, restored = restored_compensation_preparation(tmp_path)
    current_pointer = store.current_path.read_bytes()
    store.generation_path(source.revision, source.state_hash).unlink()

    assert not store._has_current_preparation_restore(restored.state)
    with pytest.raises(StateStoreError):
        store.compare_and_swap(
            restored.revision,
            restored.state_hash,
            restored.state.model_copy(
                update={
                    "preparation_phase": PreparationPhase.SELECTED,
                    "disposition": RunDisposition.ACTIVE,
                    "human_authorizations": (
                        consumed_authorization("run-1", HumanAuthorizationAction.RESUME, "resume-1"),
                    ),
                }
            ),
        )

    assert store.current_path.read_bytes() == current_pointer


def test_resumed_preparation_requires_a_new_restore_before_reentering_human_review(tmp_path: Path) -> None:
    verifier = TrustedAuthorizations("resume-1")
    store, bridge, gateway, requested = preparation_receipt_boundary(
        tmp_path,
        authorization_verifier=verifier,
    )
    confirmed = confirm_preparation(bridge, gateway, requested)
    first_compensation = store.compare_and_swap(
        confirmed.revision,
        confirmed.state_hash,
        confirmed.state.model_copy(
            update={
                "preparation_phase": PreparationPhase.COMPENSATION_REQUIRED,
                "effect_ledger": (
                    *confirmed.state.effect_ledger,
                    *reconciled_effect_events(
                        "first-branch-effect",
                        5,
                        "create_ticket_branch",
                        EffectOutcome.FAILURE,
                    ),
                ),
            }
        ),
    )
    restored = restore_preparation(bridge, gateway, first_compensation)
    resumed = store.compare_and_swap(
        restored.revision,
        restored.state_hash,
        restored.state.model_copy(
            update={
                "preparation_phase": PreparationPhase.SELECTED,
                "disposition": RunDisposition.ACTIVE,
                "human_authorizations": (
                    consumed_authorization("run-1", HumanAuthorizationAction.RESUME, "resume-1"),
                ),
            }
        ),
    )
    second_requested = store.compare_and_swap(
        resumed.revision,
        resumed.state_hash,
        resumed.state.model_copy(update={"preparation_phase": PreparationPhase.IN_PROGRESS_REQUESTED}),
    )
    second_confirmed = confirm_preparation(bridge, gateway, second_requested)
    with pytest.raises(InvalidStateTransition, match="restore reconciliation"):
        store.compare_and_swap(
            second_confirmed.revision,
            second_confirmed.state_hash,
            second_confirmed.state.model_copy(
                update={
                    "preparation_phase": PreparationPhase.COMPENSATION_REQUIRED,
                    "disposition": RunDisposition.HUMAN_REVIEW,
                    "effect_ledger": (
                        *second_confirmed.state.effect_ledger,
                        *reconciled_effect_events(
                            "direct-branch-effect",
                            17,
                            "create_ticket_branch",
                            EffectOutcome.FAILURE,
                        ),
                    ),
                }
            ),
        )

    second_compensation = store.compare_and_swap(
        second_confirmed.revision,
        second_confirmed.state_hash,
        second_confirmed.state.model_copy(
            update={
                "preparation_phase": PreparationPhase.COMPENSATION_REQUIRED,
                "effect_ledger": (
                    *second_confirmed.state.effect_ledger,
                    *reconciled_effect_events(
                        "second-branch-effect",
                        17,
                        "create_ticket_branch",
                        EffectOutcome.FAILURE,
                    ),
                ),
            }
        ),
    )

    with pytest.raises(InvalidStateTransition, match="restore reconciliation"):
        store.compare_and_swap(
            second_compensation.revision,
            second_compensation.state_hash,
            second_compensation.state.model_copy(update={"disposition": RunDisposition.HUMAN_REVIEW}),
        )


def test_probe_or_reserve_returns_a_live_reservation_without_issuing_another_challenge(tmp_path: Path) -> None:
    index = preparation_index(tmp_path)
    owner = ReservationOwner(host="launcher-host", pid=1234)

    first = index.probe_or_reserve("repo-1", owner)
    second = index.probe_or_reserve("repo-1", owner)

    assert isinstance(first, IndexProbeResult)
    assert first.outcome == "reserved"
    assert first.reservation is not None
    assert first.reservation.challenge is not None
    assert second.outcome == "blocked"
    assert second.reservation is not None
    assert second.reservation.reservation_id == first.reservation.reservation_id
    assert second.reservation.challenge is None


def test_activation_rejects_an_initial_state_bound_to_a_different_trusted_input(tmp_path: Path) -> None:
    index = preparation_index(tmp_path)
    reservation = index.reserve("repo-1")
    initial = preparation_bound_state(run_id="run-1", repository_id=reservation.repository_id)
    request = ActivationRequest(
        reservation_id=reservation.reservation_id,
        repository_id=reservation.repository_id,
        expected_index_revision=reservation.index_revision,
        expected_index_hash=reservation.index_hash,
        preparation_input_ref=preparation_input_ref(
            reservation.reservation_id,
            reservation.repository_id,
            reservation.challenge_hash,
        ),
        run_id=initial.run_id,
        initial_state=initial,
        initial_state_hash=hash_json(initial.model_dump(mode="json", round_trip=True)),
    )

    with pytest.raises(ActivationStateMismatch, match="trusted preparation input"):
        index.activate_reservation(request)

    assert index.lookup(reservation.repository_id) is None


def test_probe_or_reserve_returns_an_active_run_before_creating_another_reservation(tmp_path: Path) -> None:
    index = preparation_index(tmp_path)
    reservation = index.reserve("repo-1")
    reference = preparation_input_ref(
        reservation.reservation_id,
        reservation.repository_id,
        reservation.challenge_hash,
    )
    initial = preparation_bound_state(
        run_id="run-1",
        repository_id=reservation.repository_id,
        preparation_input_reference=reference,
    )
    active = index.activate_reservation(
        ActivationRequest(
            reservation_id=reservation.reservation_id,
            repository_id=reservation.repository_id,
            expected_index_revision=reservation.index_revision,
            expected_index_hash=reservation.index_hash,
            preparation_input_ref=reference,
            run_id=initial.run_id,
            initial_state=initial,
            initial_state_hash=hash_json(initial.model_dump(mode="json", round_trip=True)),
        )
    )

    result = index.probe_or_reserve("repo-1", ReservationOwner(host="launcher-host", pid=1234))

    assert result.outcome == "active"
    assert result.active_run == active
    assert result.reservation is None


def test_probe_or_reserve_reclaims_only_a_proven_dead_same_host_reservation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    index = preparation_index(tmp_path)
    owner = ReservationOwner(host="launcher-host", pid=1234)
    first = index.probe_or_reserve("repo-1", owner)
    assert first.reservation is not None
    monkeypatch.setattr(index, "_now", lambda: first.reservation.expires_at)
    monkeypatch.setattr(index, "_local_host", lambda: "other-host")

    blocked = index.probe_or_reserve("repo-1", owner)

    assert blocked.outcome == "blocked"
    monkeypatch.setattr(index, "_local_host", lambda: "launcher-host")
    monkeypatch.setattr(index, "_same_host_owner_is_dead", lambda host, pid: host == "launcher-host" and pid == 1234)

    reclaimed = index.probe_or_reserve("repo-1", owner)

    assert reclaimed.outcome == "reserved"
    assert reclaimed.reservation is not None
    assert reclaimed.reservation.reservation_id != first.reservation.reservation_id


def test_activation_persists_matching_initial_state_before_publishing_active_run(tmp_path: Path) -> None:
    index = preparation_index(tmp_path)
    reservation = index.reserve("repo-1")
    request = activation_request(reservation)

    active = index.activate_reservation(request)

    generation = RunStateStore(tmp_path, "run-1").load()
    assert generation.state == request.initial_state
    assert active.initial_generation_hash == generation.state_hash
    assert index.lookup("repo-1") == active


def test_activation_rejects_completed_initial_state_without_publishing_an_active_run(tmp_path: Path) -> None:
    index = preparation_index(tmp_path)
    reservation = index.reserve("repo-1")
    initial = finalization_ready_state()

    with pytest.raises(InvalidStateTransition, match="initial"):
        index.activate_reservation(activation_request(reservation, initial_state=initial))

    store = RunStateStore(tmp_path, "run-1")
    assert not store.current_path.exists()
    assert list(store.generations_dir.iterdir()) == []
    assert index.lookup("repo-1") is None


def test_malformed_activation_leaves_no_prepared_journal_and_reservation_is_reusable(tmp_path: Path) -> None:
    index = preparation_index(tmp_path)
    reservation = index.reserve("repo-1")

    with pytest.raises(InvalidStateTransition, match="initial"):
        index.activate_reservation(activation_request(reservation, initial_state=finalization_ready_state()))

    assert not index._journal_path(reservation.reservation_id).exists()
    assert index.activate_reservation(activation_request(reservation)).run_id == "run-1"


def test_activation_rejects_preexisting_mismatched_state(tmp_path: Path) -> None:
    RunStateStore(tmp_path, "run-1").compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-2", max_crew_iterations=3),
    )
    index = preparation_index(tmp_path)
    reservation = index.reserve("repo-1")

    with pytest.raises(ActivationStateMismatch):
        index.activate_reservation(activation_request(reservation))

    assert index.lookup("repo-1") is None


def test_activation_rejects_reused_run_id_even_when_existing_state_matches(tmp_path: Path) -> None:
    initial = RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3)
    RunStateStore(tmp_path, "run-1").compare_and_swap(0, EMPTY_STATE_HASH, initial)
    index = preparation_index(tmp_path)
    reservation = index.reserve("repo-1")

    with pytest.raises(RunIdAlreadyUsed):
        index.activate_reservation(activation_request(reservation))

    assert index.lookup("repo-1") is None


def test_activation_rejects_reused_run_id_with_an_empty_run_directory(tmp_path: Path) -> None:
    RunStateStore(tmp_path, "run-1")
    index = preparation_index(tmp_path)
    reservation = index.reserve("repo-1")

    with pytest.raises(RunIdAlreadyUsed):
        index.activate_reservation(activation_request(reservation))

    assert index.lookup("repo-1") is None


@pytest.mark.parametrize(
    "disposition",
    [
        RunDisposition.ACTIVE,
        RunDisposition.WAITING_MCP,
        RunDisposition.HUMAN_REVIEW,
        RunDisposition.REPAIR_REQUIRED,
    ],
)
def test_active_run_release_rejects_nonterminal_generation(tmp_path: Path, disposition: RunDisposition) -> None:
    index, active = activated_index(tmp_path)
    generation = persist_generation(active, disposition)

    with pytest.raises(NonTerminalRunRelease):
        index.release("repo-1", "run-1", active.index_revision, active.index_hash, generation.state_hash)


def test_abandoned_run_requires_consumed_human_authorization(tmp_path: Path) -> None:
    verifier = TrustedAuthorizations("authorization-1")
    index, active = activated_index(tmp_path, verifier)
    generation = abandoned_state(active, verifier)

    index.release("repo-1", "run-1", active.index_revision, active.index_hash, generation.state_hash)

    assert index.lookup("repo-1") is None


def test_abandoned_run_without_consumed_authorization_remains_active_in_index(tmp_path: Path) -> None:
    index, active = activated_index(tmp_path)
    assert active.run_id is not None
    store = RunStateStore(tmp_path, active.run_id)
    current = store.load()
    human_review = store.compare_and_swap(
        current.revision,
        current.state_hash,
        current.state.model_copy(update={"disposition": RunDisposition.HUMAN_REVIEW}),
    )

    with pytest.raises(InvalidStateTransition, match="abandon"):
        store.compare_and_swap(
            human_review.revision,
            human_review.state_hash,
            human_review.state.model_copy(update={"disposition": RunDisposition.ABANDONED}),
        )

    assert index.lookup("repo-1") == active


def test_active_index_release_rejects_signature_shaped_abandon_without_its_verifier(tmp_path: Path) -> None:
    verifier = TrustedAuthorizations("abandon-1")
    index = preparation_index(tmp_path, authorization_verifier=verifier)
    reservation = index.reserve("repo-1")
    active = index.activate_reservation(activation_request(reservation, run_id="run-1"))
    assert active.run_id is not None
    store = RunStateStore(tmp_path, active.run_id, authorization_verifier=verifier)
    current = store.load()
    human_review = store.compare_and_swap(
        current.revision,
        current.state_hash,
        current.state.model_copy(update={"disposition": RunDisposition.HUMAN_REVIEW}),
    )
    abandoned = store.compare_and_swap(
        human_review.revision,
        human_review.state_hash,
        human_review.state.model_copy(
            update={
                "disposition": RunDisposition.ABANDONED,
                "human_authorizations": (
                    consumed_authorization(active.run_id, HumanAuthorizationAction.ABANDON, "abandon-1"),
                ),
            }
        ),
    )

    with pytest.raises(NonTerminalRunRelease):
        preparation_index(tmp_path).release(
            "repo-1",
            active.run_id,
            active.index_revision,
            active.index_hash,
            abandoned.state_hash,
        )


def test_release_keeps_terminal_state_locked_until_index_removal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    index, active = activated_index(tmp_path)
    done = persist_terminal_generation(active, RunDisposition.DONE)
    removal_entered = Event()
    allow_removal = Event()
    original_remove = index._remove_entry_locked
    release_errors: list[Exception] = []

    def paused_remove(repository_id: str) -> None:
        removal_entered.set()
        assert allow_removal.wait(10)
        original_remove(repository_id)

    monkeypatch.setattr(index, "_remove_entry_locked", paused_remove)

    def release() -> None:
        try:
            index.release("repo-1", "run-1", active.index_revision, active.index_hash, done.state_hash)
        except Exception as error:
            release_errors.append(error)

    context = get_context("spawn")
    ready = context.Event()
    proceed = context.Event()
    attempted = context.Event()
    results = context.Queue()
    writer = context.Process(
        target=transition_away_in_process,
        args=(str(tmp_path), "run-1", done.revision, done.state_hash, ready, proceed, attempted, results),
    )
    writer.start()
    assert ready.wait(10)
    releaser = Thread(target=release)
    releaser.start()
    assert removal_entered.wait(10)
    proceed.set()
    assert attempted.wait(10)

    with pytest.raises(Empty):
        results.get(timeout=1)

    allow_removal.set()
    releaser.join(timeout=10)
    writer.join(timeout=10)

    assert not releaser.is_alive()
    assert writer.exitcode == 0
    assert release_errors == []
    assert results.get(timeout=1) == ("error", "InvalidStateTransition")
    assert index.lookup("repo-1") is None
    assert RunStateStore(tmp_path, "run-1").load().state.disposition is RunDisposition.DONE


def test_activation_replay_is_idempotent_and_mismatch_is_refused(tmp_path: Path) -> None:
    index = preparation_index(tmp_path)
    reservation = index.reserve("repo-1")
    request = activation_request(reservation, run_id="run-1")

    first = index.activate_reservation(request)
    assert index.activate_reservation(request) == first

    with pytest.raises(ActivationReplayMismatch):
        index.activate_reservation(
            request.model_copy(
                update={
                    "preparation_input_ref": request.preparation_input_ref.model_copy(
                        update={"input_hash": OTHER_PREPARATION_INPUT_HASH}
                    )
                }
            )
        )


def test_activation_replay_revalidates_malformed_generation_after_interruption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    index = preparation_index(tmp_path)
    reservation = index.reserve("repo-1")
    request = activation_request(reservation)
    assert request.initial_state is not None
    malformed_initial = request.initial_state.model_copy(update={"branch": "ENG-1-malformed"})
    request = request.model_copy(
        update={
            "initial_state": malformed_initial,
            "initial_state_hash": hash_json(malformed_initial.model_dump(mode="json", round_trip=True)),
        }
    )

    def interrupt_after_state_persistence(run_id: str, repository_id: str, initial_generation_hash: str) -> None:
        raise OSError("interrupted after state persistence")

    def bypass_initial_state_validation(*args: object, **kwargs: object) -> None:
        return None

    with monkeypatch.context() as patched:
        patched.setattr(RunStateStore, "_validate_initial_state", bypass_initial_state_validation)
        patched.setattr(index, "_write_run_binding", interrupt_after_state_persistence)
        with pytest.raises(OSError, match="interrupted after state persistence"):
            index.activate_reservation(request)

    assert RunStateStore(tmp_path, "run-1").load().state == request.initial_state

    with pytest.raises(InvalidStateTransition, match="initial"):
        index.activate_reservation(request)

    assert index.lookup("repo-1") is None


def test_no_candidate_activation_is_durable_without_an_active_run(tmp_path: Path) -> None:
    index = preparation_index(tmp_path)
    reservation = index.reserve("repo-1")
    request = activation_request(reservation, run_id=None, preparation_input_hash=PREPARATION_INPUT_HASH)

    first = index.activate_reservation(request)

    assert first.outcome == "no_candidate"
    assert first.run_id is None
    assert index.lookup("repo-1") is None
    assert index.activate_reservation(request) == first
    assert index.reserve("repo-1").repository_id == "repo-1"


def test_no_candidate_replay_survives_interruption_before_journal_completion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    index = preparation_index(tmp_path)
    reservation = index.reserve("repo-1")
    request = activation_request(reservation, run_id=None)
    original_replace = run_index_module._atomic_replace_json

    def interrupt_completed_journal(path: Path, value: object) -> None:
        if (
            path.parent == index.journal_dir
            and isinstance(value, dict)
            and isinstance(value.get("journal"), dict)
            and value["journal"].get("phase") == "completed"
        ):
            raise OSError("interrupted before journal completion")
        original_replace(path, value)

    monkeypatch.setattr(run_index_module, "_atomic_replace_json", interrupt_completed_journal)
    with pytest.raises(OSError, match="interrupted before journal completion"):
        index.activate_reservation(request)
    monkeypatch.setattr(run_index_module, "_atomic_replace_json", original_replace)

    index.reserve("repo-1")

    replayed = index.activate_reservation(request)

    assert replayed.outcome == "no_candidate"
    assert replayed.run_id is None


def test_active_run_binding_rejects_other_repository_state(tmp_path: Path) -> None:
    index = preparation_index(tmp_path)
    reservation = index.reserve("repo-1")
    active = index.activate_reservation(activation_request(reservation, run_id="run-1"))
    store = RunStateStore(tmp_path, "run-1")
    current = store.load()

    with pytest.raises(ValidationError, match="Preparation input repository"):
        current.state.model_copy(update={"repository_id": "repo-2"})
