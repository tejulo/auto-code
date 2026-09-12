from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
from pathlib import Path
from typing import Callable, TypeVar

from auto_code.contracts import (
    ActivationRequest,
    AuthorizationVerifier,
    EvidenceRef,
    EffectIntention,
    EffectIntentionPayload,
    FinalizationEvidence,
    HumanAuthorization,
    HumanAuthorizationAction,
    IdentityResolution,
    PreparationBridgeAttestation,
    PreparationInput,
    PreparationPhase,
    RunnerIdentity,
    RunDisposition,
    RunState,
    TrustedPreparationInputRef,
)
from auto_code.hashing import hash_json
from auto_code.run_index import ActivationResult, ActiveRunIndex, PreparationReservation
from auto_code.state import EMPTY_STATE_HASH, CompareAndSwapConflict, RunStateStore, StateGeneration


T = TypeVar("T")
NOW = datetime(2026, 1, 1, tzinfo=UTC)
CONTRACT_HASH = hashlib.sha256(b"state-contract-v1").hexdigest()
INPUT_HASH = hashlib.sha256(b"state-input-v1").hexdigest()
OUTPUT_HASH = hashlib.sha256(b"state-output-v1").hexdigest()
RECEIPT_HASH = hashlib.sha256(b"state-receipt-v1").hexdigest()
PREPARATION_INPUT_HASH = hashlib.sha256(b"preparation-input-v1").hexdigest()
OTHER_PREPARATION_INPUT_HASH = hashlib.sha256(b"other-preparation-input-v1").hexdigest()
EFFECT_REQUEST_HASH = hashlib.sha256(b"effect-request-v1").hexdigest()


@dataclass(frozen=True)
class ConcurrentResult:
    succeeded: bool


class DeterministicPreparationInputVerifier:
    """Test-only launcher capability for generic index/state fixtures."""

    def verify_and_load_preparation_input(
        self,
        reference: TrustedPreparationInputRef,
    ) -> tuple[TrustedPreparationInputRef, PreparationInput]:
        if (
            reference.bridge_signature is None
            or Path(reference.relative_path).name != f"{reference.input_id}.json"
        ):
            raise ValueError("fixture preparation input is invalid")
        page = {"tickets": []}
        return reference, PreparationInput(
            repository_id=reference.repository_id,
            max_crew_iterations=reference.max_crew_iterations,
            assignee_resolution=IdentityResolution.resolved("fixture-user"),
            milestone_resolution=IdentityResolution.resolved("fixture-milestone"),
            pages=(page,),
            page_hashes={"page-1": hash_json(page)},
            workflow_states={"started": "fixture-started"},
            bridge_attestation=PreparationBridgeAttestation(
                bridge_identity=reference.bridge_identity,
                mcp_server_identity=reference.mcp_server_identity,
                tool_call_id=reference.tool_call_id,
                captured_at=reference.captured_at,
            ),
        )


def preparation_index(
    root: Path,
    *,
    authorization_verifier: AuthorizationVerifier | None = None,
) -> ActiveRunIndex:
    return ActiveRunIndex(
        root,
        authorization_verifier=authorization_verifier,
        preparation_input_verifier=DeterministicPreparationInputVerifier(),
    )


class StateStoreFixture:
    def __init__(self, store: RunStateStore) -> None:
        self.store = store

    def __getattr__(self, name: str) -> object:
        return getattr(self.store, name)

    def corrupt_current_generation(self) -> None:
        generation = self.store.load()
        self.store.generation_path(generation.revision, generation.state_hash).write_text("{corrupt", encoding="utf-8")


def run_concurrently(count: int, operation: Callable[[], T]) -> list[ConcurrentResult]:
    def attempt() -> ConcurrentResult:
        try:
            operation()
        except CompareAndSwapConflict:
            return ConcurrentResult(succeeded=False)
        return ConcurrentResult(succeeded=True)

    with ThreadPoolExecutor(max_workers=count) as executor:
        return list(executor.map(lambda _: attempt(), range(count)))


def transition_away_in_process(
    root: str,
    run_id: str,
    expected_revision: int,
    expected_hash: str,
    ready: object,
    proceed: object,
    attempted: object,
    results: object,
) -> None:
    ready.set()
    proceed.wait()
    try:
        store = RunStateStore(Path(root), run_id)
        attempted.set()
        current = store.load()
        store.compare_and_swap(
            expected_revision,
            expected_hash,
            current.state.model_copy(update={"disposition": RunDisposition.ACTIVE}),
        )
    except Exception as error:
        results.put(("error", type(error).__name__))
    else:
        results.put(("ok", ""))


def competing_cas_in_process(root: str, run_id: str, ready: object, proceed: object, results: object) -> None:
    store = RunStateStore(Path(root), run_id)
    generation = store.load()
    ready.set()
    proceed.wait()
    try:
        store.compare_and_swap(
            generation.revision,
            generation.state_hash,
            generation.state.begin_iteration(),
        )
    except Exception as error:
        results.put(("error", type(error).__name__))
    else:
        results.put(("ok", ""))


def reserve_and_activate_in_process(
    root: str,
    repository_id: str,
    run_id: str,
    ready: object,
    proceed: object,
    results: object,
) -> None:
    ready.set()
    proceed.wait()
    try:
        index = preparation_index(Path(root))
        reservation = index.reserve(repository_id)
        active = index.activate_reservation(activation_request(reservation, run_id=run_id))
    except Exception as error:
        results.put(("error", type(error).__name__))
    else:
        results.put(("active", active.run_id))


def state_with_effect(effect_id: str) -> RunState:
    return RunState(
        run_id="run-1",
        ticket_id="ENG-1",
        repository_id="repo-1",
        max_crew_iterations=3,
        effect_ledger=(
            EffectIntention(
                effect_id=effect_id,
                sequence=1,
                timestamp=NOW,
                payload=EffectIntentionPayload(
                    operation="record_effect",
                    target="linear/tickets/ENG-1",
                    request_hash=EFFECT_REQUEST_HASH,
                ),
            ),
        ),
    )


def activation_request(
    reservation: PreparationReservation,
    *,
    run_id: str | None = "run-1",
    preparation_input_hash: str = PREPARATION_INPUT_HASH,
    initial_state: RunState | None = None,
) -> ActivationRequest:
    reference = TrustedPreparationInputRef(
        input_id="33333333-3333-4333-8333-333333333333",
        relative_path="trusted-mcp/preparation/33333333-3333-4333-8333-333333333333.json",
        repository_id=reservation.repository_id,
        reservation_id=reservation.reservation_id,
        challenge_hash=reservation.challenge_hash,
        input_hash=preparation_input_hash,
        query_hash="a" * 64,
        payload_hash="b" * 64,
        result_hash="c" * 64,
        source_page_hashes={"page-1": "d" * 64},
        pagination_complete=True,
        max_crew_iterations=3,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        tool_call_id="tool-call-1",
        captured_at=NOW,
        observations=("Trusted preparation input captured.",),
        bridge_signature="e" * 64,
    )
    values: dict[str, object] = {
        "reservation_id": reservation.reservation_id,
        "repository_id": reservation.repository_id,
        "expected_index_revision": reservation.index_revision,
        "expected_index_hash": reservation.index_hash,
        "preparation_input_ref": reference,
        "run_id": run_id,
    }
    if run_id is not None:
        state = initial_state or RunState(
            run_id=run_id,
            ticket_id="ENG-1",
            repository_id=reservation.repository_id,
            max_crew_iterations=3,
            preparation_phase=PreparationPhase.SELECTED,
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
            runner_identity=RunnerIdentity(
                content_hash="4" * 64,
                source_sha="5" * 64,
                dependency_lock_hash="6" * 64,
                contract_bundle_hash="7" * 64,
                built_at=NOW,
            ),
        )
        values["initial_state"] = state
        values["initial_state_hash"] = hash_json(state.model_dump(mode="json", round_trip=True))
    return ActivationRequest(**values)


def persist_generation(active: ActivationResult, disposition: RunDisposition) -> StateGeneration:
    assert active.run_id is not None
    store = RunStateStore(active.state_root, active.run_id)
    current = store.load()
    if current.state.disposition is disposition:
        return current
    return store.compare_and_swap(
        current.revision,
        current.state_hash,
        current.state.model_copy(update={"disposition": disposition}),
    )


def persist_terminal_generation(active: ActivationResult, disposition: RunDisposition) -> StateGeneration:
    if disposition is not RunDisposition.DONE:
        return persist_generation(active, disposition)
    assert active.run_id is not None
    store = RunStateStore(active.state_root, active.run_id)
    current = store.load()
    if current.state.disposition is RunDisposition.DONE:
        return current
    evidence = FinalizationEvidence(
        prefinalization_ticket_projection="ticket-projection-1",
        commit_sha="a" * 40,
        pushed_sha="a" * 40,
        linear_done_receipt="linear-receipt-1",
    )
    ready = store.compare_and_swap(
        current.revision,
        current.state_hash,
        current.state.model_copy(
            update={
                "review_manifest": "review-manifest-1",
                "review_result": "approved-review-result-1",
                "finalization_eligible": True,
                "prefinalization_ticket_projection": evidence.prefinalization_ticket_projection,
                "commit_sha": evidence.commit_sha,
                "pushed_sha": evidence.pushed_sha,
                "linear_done_receipt": evidence.linear_done_receipt,
            }
        ),
    )
    return store.compare_and_swap(
        ready.revision,
        ready.state_hash,
        ready.state.model_copy(
            update={"disposition": RunDisposition.DONE, "finalization_evidence": evidence}
        ),
    )


def activated_index(
    tmp_path: Path,
    authorization_verifier: AuthorizationVerifier | None = None,
) -> tuple[ActiveRunIndex, ActivationResult]:
    index = preparation_index(tmp_path, authorization_verifier=authorization_verifier)
    reservation = index.reserve("repo-1")
    return index, index.activate_reservation(activation_request(reservation))


def abandoned_state(
    active: ActivationResult,
    authorization_verifier: AuthorizationVerifier | None = None,
) -> StateGeneration:
    assert active.run_id is not None
    authorization = HumanAuthorization(
        authorization_id="authorization-1",
        action=HumanAuthorizationAction.ABANDON,
        run_id=active.run_id,
        challenge="operator-challenge",
        actor="operator",
        reason="operator abandoned the run",
        issued_at=NOW,
        expires_at=datetime(2027, 1, 1, tzinfo=UTC),
        key_id="operator-key",
        signature="operator-signature",
        consumed_at=NOW,
    )
    store = RunStateStore(active.state_root, active.run_id, authorization_verifier=authorization_verifier)
    current = store.load()
    human_review = store.compare_and_swap(
        current.revision,
        current.state_hash,
        current.state.model_copy(update={"disposition": RunDisposition.HUMAN_REVIEW}),
    )
    return store.compare_and_swap(
        human_review.revision,
        human_review.state_hash,
        human_review.state.model_copy(
            update={
                "disposition": RunDisposition.ABANDONED,
                "human_authorizations": (authorization,),
            }
        ),
    )
