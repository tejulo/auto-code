from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import BaseModel

from auto_code.contracts import (
    ActivationRequest,
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
    IdentityResolution,
    McpActionRequest,
    PendingExternalRequest,
    PreparationPhase,
    RunnerIdentity,
    RunState,
    RunDisposition,
    TicketSnapshot,
    TrustedMcpReceipt,
    TrustedPreparationInputRef,
    preparation_input_envelope_hash,
    sanitize_untrusted_text,
    sanitize_untrusted_value,
    sanitize_url,
)
from auto_code.linear import (
    ConflictingReceiptReplay,
    IdentityResolutionError,
    LinearDataError,
    LinearGateway,
    TicketProjectionTooLarge,
    UntrustedReceiptError,
    select_ticket,
)
from auto_code.hashing import canonical_json_bytes, hash_json
from auto_code.mcp_bridge import McpBridgeError, McpToolResult, TrustedLinearBridge, UnpersistedMcpRequestError, _sign
from auto_code.run_index import ActivationStateMismatch, ActiveRunIndex
from auto_code.state import (
    BridgeReceiptAuthority,
    EMPTY_STATE_HASH,
    InvalidStateTransition,
    RunStateStore,
    StateGeneration,
)


NOW = datetime(2026, 1, 1, tzinfo=UTC)


class FakeLinearMcp:
    def __init__(self, result: object, *, external_revision: str = "revision-2") -> None:
        self.result = result
        self.external_revision = external_revision
        self.calls: list[tuple[str, str, object]] = []

    def call(self, server_identity: str, tool_name: str, arguments: object) -> McpToolResult:
        self.calls.append((server_identity, tool_name, arguments))
        return McpToolResult(
            tool_call_id=f"tool-call-{len(self.calls)}",
            result=self.result,
            external_revision=self.external_revision,
            observations=("The trusted Linear MCP call completed.",),
        )


class MutatingArgumentsLinearMcp(FakeLinearMcp):
    def __init__(self, result: object, raw_arguments: dict[str, object]) -> None:
        super().__init__(result)
        self.raw_arguments = raw_arguments

    def call(self, server_identity: str, tool_name: str, arguments: object) -> McpToolResult:
        self.raw_arguments["ticket_id"] = "ENG-2"
        self.raw_arguments["state_id"] = "changed-state"
        workflow = self.raw_arguments["workflow"]
        assert isinstance(workflow, dict)
        states = workflow["states"]
        assert isinstance(states, list)
        first_state = states[0]
        assert isinstance(first_state, dict)
        first_state["id"] = "changed-state"
        states.append({"id": "unexpected-state"})
        return super().call(server_identity, tool_name, arguments)


def trusted_bridge(tmp_path: Path, client: FakeLinearMcp) -> TrustedLinearBridge:
    return TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=client,
    )


def receipt_evidence(receipt: TrustedMcpReceipt) -> EvidenceRef:
    return EvidenceRef(
        relative_path=receipt.relative_path,
        sha256=receipt.content_hash,
        media_type="application/json",
        creator="trusted-mcp-bridge",
    )


def preparation_response(pages: list[object]) -> dict[str, object]:
    return {
        "pages": pages,
        "pagination_complete": True,
        "max_crew_iterations": 2,
        "assignee_resolution": {"status": "resolved", "resolved_id": "user-1"},
        "milestone_resolution": {"status": "resolved", "resolved_id": "milestone-1"},
        "workflow_states": {"started": "state-1", "completed": "state-2"},
    }


def initial_generation(
    state_root: Path,
    *,
    receipt_authority: BridgeReceiptAuthority | None = None,
) -> tuple[RunStateStore, object]:
    store = RunStateStore(state_root, "run-1", receipt_authority=receipt_authority)
    generation = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3),
    )
    return store, generation


def persisted_ticket_request(
    tmp_path: Path,
    ticket_id: str,
) -> tuple[RunStateStore, TrustedLinearBridge, LinearGateway, StateGeneration, McpActionRequest]:
    bridge = trusted_bridge(tmp_path, FakeLinearMcp({"state": "started"}))
    store = RunStateStore(tmp_path, "run-1", receipt_authority=bridge.receipt_authority)
    initial = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3),
    )
    gateway = LinearGateway(store, bridge.receipt_authority)
    request = gateway.request_state(initial, ticket_id)
    return store, bridge, gateway, gateway.persist_pending(initial, request), request


def alternate_root_reconciliation_candidate(
    tmp_path: Path,
) -> tuple[RunStateStore, StateGeneration, RunState, BridgeReceiptAuthority]:
    store, _, _, pending, request = persisted_ticket_request(tmp_path, "ENG-1")
    alternate = trusted_bridge(tmp_path / "alternate-root", FakeLinearMcp({"state": "started"}))
    alternate_receipt = alternate._write_signed_receipt(
        request,
        McpToolResult(
            tool_call_id="alternate-tool-call",
            result={"state": "started"},
            external_revision="alternate-revision",
        ),
        target=request.target,
    )
    pending_request = pending.state.pending_external_request
    assert pending_request is not None
    evidence = receipt_evidence(alternate_receipt)
    candidate = pending.state.model_copy(
        update={
            "disposition": RunDisposition.ACTIVE,
            "pending_external_request": None,
            "effect_ledger": (
                *pending.state.effect_ledger,
                EffectInvocation(
                    effect_id=pending_request.effect_id,
                    sequence=pending.state.effect_ledger[-1].sequence + 1,
                    timestamp=alternate_receipt.observed_at,
                    payload=EffectInvocationPayload(),
                ),
                EffectObservation(
                    effect_id=pending_request.effect_id,
                    sequence=pending.state.effect_ledger[-1].sequence + 2,
                    timestamp=alternate_receipt.observed_at,
                    payload=EffectObservationPayload(
                        outcome=alternate_receipt.outcome,
                        external_revision=alternate_receipt.external_revision,
                        evidence_refs=(evidence,),
                    ),
                ),
                EffectReconciliation(
                    effect_id=pending_request.effect_id,
                    sequence=pending.state.effect_ledger[-1].sequence + 3,
                    timestamp=alternate_receipt.observed_at,
                    payload=EffectReconciliationPayload(
                        outcome=alternate_receipt.outcome,
                        evidence_refs=(evidence,),
                        receipt_hash=alternate_receipt.content_hash,
                    ),
                ),
            ),
        }
    )
    return store, pending, candidate, alternate.receipt_authority


def preparation_generation(
    state_root: Path,
    *,
    receipt_authority: BridgeReceiptAuthority | None = None,
) -> tuple[RunStateStore, object]:
    reference = TrustedPreparationInputRef(
        input_id="22222222-2222-4222-8222-222222222222",
        relative_path="trusted-mcp/preparation/22222222-2222-4222-8222-222222222222.json",
        repository_id="repo-1",
        reservation_id="reservation-1",
        challenge_hash="a" * 64,
        input_hash="b" * 64,
        query_hash="c" * 64,
        payload_hash="d" * 64,
        result_hash="e" * 64,
        source_page_hashes={"page-1": "f" * 64},
        pagination_complete=True,
        max_crew_iterations=3,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        tool_call_id="tool-call-1",
        captured_at=NOW,
        observations=("Trusted preparation input captured.",),
        bridge_signature="0" * 64,
    )
    state = RunState(
        run_id="run-1",
        ticket_id="ENG-1",
        repository_id="repo-1",
        max_crew_iterations=3,
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
    store = RunStateStore(state_root, "run-1", receipt_authority=receipt_authority)
    initial = store.compare_and_swap(0, EMPTY_STATE_HASH, state)
    return store, store.compare_and_swap(
        initial.revision,
        initial.state_hash,
        initial.state.model_copy(update={"preparation_phase": PreparationPhase.IN_PROGRESS_REQUESTED}),
    )


def test_selects_highest_priority_then_oldest_and_excludes_active_blockers() -> None:
    raw = [
        {
            "id": "ENG-3",
            "state_type": "unstarted",
            "assignee_id": "u",
            "milestone_id": "m",
            "priority": 1,
            "created_at": "2026-01-01T00:00:00Z",
            "blockers": [{"state_type": "started"}],
        },
        {
            "id": "ENG-2",
            "state_type": "unstarted",
            "assignee_id": "u",
            "milestone_id": "m",
            "priority": 1,
            "created_at": "2026-01-03T00:00:00Z",
            "blockers": [],
        },
        {
            "id": "ENG-1",
            "state_type": "unstarted",
            "assignee_id": "u",
            "milestone_id": "m",
            "priority": 1,
            "created_at": "2026-01-02T00:00:00Z",
            "blockers": [],
            "title": "API_KEY=never-expose-this",
        },
    ]

    selected = select_ticket(raw, "u", "m")
    assert selected is not None
    assert selected.id == "ENG-1"
    assert "never-expose-this" not in selected.title


def test_completed_or_canceled_blockers_are_inactive() -> None:
    raw = [
        {
            "id": "ENG-1",
            "state_type": "unstarted",
            "assignee_id": "u",
            "milestone_id": "m",
            "priority": 2,
            "created_at": "2026-01-01T00:00:00Z",
            "blockers": [{"state_type": "completed"}, {"state_type": "canceled"}],
        }
    ]

    assert select_ticket(raw, "u", "m").id == "ENG-1"


def test_selection_rejects_duplicate_ids_and_malformed_timestamps_and_sorts_nonpositive_last() -> None:
    duplicate = [
        {
            "id": "ENG-1",
            "state_type": "unstarted",
            "assignee_id": "u",
            "milestone_id": "m",
            "priority": 1,
            "created_at": "2026-01-01T00:00:00Z",
            "blockers": [],
        },
        {
            "id": "eng-1",
            "state_type": "unstarted",
            "assignee_id": "u",
            "milestone_id": "m",
            "priority": 2,
            "created_at": "2026-01-02T00:00:00Z",
            "blockers": [],
        },
    ]
    malformed = [
        {
            "id": "ENG-2",
            "state_type": "unstarted",
            "assignee_id": "u",
            "milestone_id": "m",
            "priority": 1,
            "created_at": "not-a-timestamp",
            "blockers": [],
        }
    ]
    priorities = [
        {
            "id": "ENG-3",
            "state_type": "unstarted",
            "assignee_id": "u",
            "milestone_id": "m",
            "priority": 0,
            "created_at": "2026-01-01T00:00:00Z",
            "blockers": [],
        },
        {
            "id": "ENG-2",
            "state_type": "unstarted",
            "assignee_id": "u",
            "milestone_id": "m",
            "priority": 2,
            "created_at": "2026-01-03T00:00:00Z",
            "blockers": [],
        },
        {
            "id": "ENG-1",
            "state_type": "unstarted",
            "assignee_id": "u",
            "milestone_id": "m",
            "priority": 2,
            "created_at": "2026-01-03T00:00:00Z",
            "blockers": [],
        },
    ]

    with pytest.raises(LinearDataError):
        select_ticket(duplicate, "u", "m")
    with pytest.raises(LinearDataError):
        select_ticket(malformed, "u", "m")
    assert select_ticket(priorities, "u", "m").id == "ENG-1"


def test_identity_resolution_requires_an_exact_resolved_identifier() -> None:
    assert IdentityResolution.resolved("user-1").require_resolved("assignee") == "user-1"

    for resolution in (IdentityResolution.not_found(), IdentityResolution.ambiguous(("user-1", "user-2"))):
        with pytest.raises(IdentityResolutionError):
            resolution.require_resolved("assignee")


def snapshot_data() -> dict[str, object]:
    return {
        "id": "ENG-7",
        "title": "Preserve customer settings",
        "description": (
            "Read https://user:password@example.test/requirements?token=abc#section "
            "and API_KEY=very-secret-value before implementation."
        ),
        "criteria": ["The setting persists."],
        "comments": [{"id": "comment-1", "body": "Confirm the expected behavior."}],
        "labels": [{"name": "customer-impact"}],
        "relations": [{"type": "blocks", "title": "Update the migration."}],
        "subtickets": [{"id": "ENG-8", "title": "Document the change", "description": "Update the docs."}],
        "attachments": [
            {
                "name": "notes.txt",
                "url": "https://user:password@example.test/notes?access_token=abc#fragment",
                "text": "The migration remains backwards compatible.",
            },
            {
                "name": "archive.txt",
                "url": "ftp://user:password@example.test/archive?access_token=abc#fragment",
            }
        ],
        "workspace_id": "workspace-1",
        "team_id": "team-1",
    }


def test_ticket_snapshot_redacts_untrusted_data_and_constraint_projection_excludes_transport_metadata() -> None:
    first = TicketSnapshot.from_untrusted(
        snapshot_data(),
        captured_at=NOW,
        pagination_complete=True,
        source_page_hashes={"issues-page-1": "a" * 64},
    )
    second = TicketSnapshot.from_untrusted(
        snapshot_data(),
        captured_at=NOW + timedelta(minutes=1),
        pagination_complete=True,
        source_page_hashes={"issues-page-2": "b" * 64},
    )
    stored = str(first.model_dump(mode="json"))
    analyst = first.analyst_projection(max_chars=32_768)

    assert "password" not in stored
    assert "token=abc" not in stored
    assert "very-secret-value" not in stored
    assert "https://example.test/requirements" in first.description
    assert first.attachments[0].url == "https://example.test/notes"
    assert first.attachments[1].url == "ftp://example.test/archive"
    assert first.constraint_projection().content_hash == second.constraint_projection().content_hash
    assert "Preserve customer settings" in analyst.to_prompt_text()


def test_structured_secret_key_values_are_redacted_before_snapshot_and_preparation_persistence(tmp_path: Path) -> None:
    assert sanitize_untrusted_value({"nested": {"api_key": "value-with-no-marker"}}) == {
        "nested": {"api_key": "[REDACTED]"}
    }

    raw = snapshot_data()
    raw["relations"] = [{"nested": {"api_key": "ticket-value-with-no-marker"}}]
    snapshot = TicketSnapshot.from_untrusted(
        raw,
        captured_at=NOW,
        pagination_complete=True,
        source_page_hashes={"issues-page-1": "a" * 64},
    )
    assert "ticket-value-with-no-marker" not in snapshot.analyst_projection().to_prompt_text()

    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=FakeLinearMcp(preparation_response([{"nested": {"api_key": "preparation-value-with-no-marker"}}])),
    )
    reference = bridge.query_preparation(
        "challenge-value",
        {"assignee": "user-1"},
        repository_id="repo-1",
        reservation_id="reservation-1",
    )
    persisted = (tmp_path / reference.relative_path).read_text(encoding="ascii")

    assert "preparation-value-with-no-marker" not in persisted


def test_plural_secret_key_values_are_redacted_after_camel_case_normalization(tmp_path: Path) -> None:
    assert sanitize_untrusted_value({"nested": {"clientCredentials": "value-with-no-marker"}}) == {
        "nested": {"clientCredentials": "[REDACTED]"}
    }

    raw = snapshot_data()
    raw["relations"] = [{"nested": {"credentials": "ticket-value-with-no-marker"}}]
    snapshot = TicketSnapshot.from_untrusted(
        raw,
        captured_at=NOW,
        pagination_complete=True,
        source_page_hashes={"issues-page-1": "a" * 64},
    )
    assert "ticket-value-with-no-marker" not in snapshot.analyst_projection().to_prompt_text()

    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=FakeLinearMcp(preparation_response([{"nested": {"credentials": "preparation-value-with-no-marker"}}])),
    )
    reference = bridge.query_preparation(
        "challenge-value",
        {"assignee": "user-1"},
        repository_id="repo-1",
        reservation_id="reservation-1",
    )
    persisted = (tmp_path / reference.relative_path).read_text(encoding="ascii")

    assert "preparation-value-with-no-marker" not in persisted


def test_protocol_relative_urls_are_sanitized_directly_and_in_ticket_text() -> None:
    source = "//user:password@example.test/path?token=value#fragment"
    expected = "//example.test/path"

    assert sanitize_url(source) == expected
    assert sanitize_untrusted_text(f"Read {source} before implementation.") == f"Read {expected} before implementation."

    raw = snapshot_data()
    raw["description"] = f"Read {source} before implementation."
    snapshot = TicketSnapshot.from_untrusted(
        raw,
        captured_at=NOW,
        pagination_complete=True,
        source_page_hashes={"issues-page-1": "a" * 64},
    )

    assert snapshot.description == f"Read {expected} before implementation."


def test_ticket_projection_refuses_to_silently_drop_oversized_requirement_text() -> None:
    raw = snapshot_data()
    raw["description"] = "x" * 33_000
    snapshot = TicketSnapshot.from_untrusted(
        raw,
        captured_at=NOW,
        pagination_complete=True,
        source_page_hashes={"issues-page-1": "a" * 64},
    )

    assert len(snapshot.description) == 33_000
    with pytest.raises(TicketProjectionTooLarge):
        snapshot.analyst_projection(max_chars=32_768)


def test_bridge_rejects_a_model_copied_split_ticket_request_before_mcp_call(tmp_path: Path) -> None:
    client = FakeLinearMcp({"state": "started"})
    bridge = trusted_bridge(tmp_path, client)
    store = RunStateStore(tmp_path, "run-1", receipt_authority=bridge.receipt_authority)
    initial = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3),
    )
    gateway = LinearGateway(store, bridge.receipt_authority)
    request = gateway.request_state(initial, "ENG-1")
    pending = gateway.persist_pending(initial, request)
    split_request = BaseModel.model_copy(request, update={"target": "ENG-2"})

    with pytest.raises(McpBridgeError, match=r"^MCP ticket target is invalid$"):
        bridge.execute(split_request)

    assert client.calls == []
    assert store.load() == pending


def test_store_rejects_an_authority_bound_to_another_root(tmp_path: Path) -> None:
    authority = BridgeReceiptAuthority(tmp_path / "other", "launcher-bridge", "linear-mcp", b"test-only-launcher-key")

    with pytest.raises(ValueError, match="state root"):
        RunStateStore(tmp_path, "run-1", receipt_authority=authority)


def test_gateway_requires_the_store_authority_object(tmp_path: Path) -> None:
    bridge = trusted_bridge(tmp_path, FakeLinearMcp({"state": "started"}))
    store = RunStateStore(tmp_path, "run-1", receipt_authority=bridge.receipt_authority)
    different_authority = BridgeReceiptAuthority(
        tmp_path,
        "launcher-bridge",
        "linear-mcp",
        b"test-only-launcher-key",
    )

    with pytest.raises(ValueError, match="store-bound receipt authority"):
        LinearGateway(store, different_authority)


@pytest.mark.parametrize(
    ("attribute", "replacement"),
    (
        ("state_root", Path("/other-root")),
        ("bridge_identity", "other-bridge"),
        ("mcp_server_identity", "other-mcp"),
        ("_signing_key", b"other-test-only-key"),
    ),
)
def test_receipt_authority_rejects_post_construction_field_reassignment(
    tmp_path: Path,
    attribute: str,
    replacement: Path | str | bytes,
) -> None:
    bridge = trusted_bridge(tmp_path, FakeLinearMcp({"state": "started"}))
    store, initial = initial_generation(tmp_path, receipt_authority=bridge.receipt_authority)
    authority = bridge.receipt_authority
    original = getattr(authority, attribute)

    with pytest.raises(AttributeError):
        setattr(authority, attribute, replacement)

    assert getattr(authority, attribute) == original
    assert store.load() == initial


def test_receipt_authority_repr_does_not_expose_its_signing_key(tmp_path: Path) -> None:
    authority = BridgeReceiptAuthority(tmp_path, "launcher-bridge", "linear-mcp", b"test-only-launcher-key")

    assert "test-only-launcher-key" not in repr(authority)


def test_store_and_bridge_authority_bindings_reject_post_construction_replacement(tmp_path: Path) -> None:
    bridge = trusted_bridge(tmp_path, FakeLinearMcp({"state": "started"}))
    store, initial = initial_generation(tmp_path, receipt_authority=bridge.receipt_authority)
    replacement = BridgeReceiptAuthority(tmp_path, "other-bridge", "other-mcp", b"other-test-only-key")

    with pytest.raises(AttributeError):
        store.receipt_authority = replacement
    with pytest.raises(AttributeError):
        bridge.receipt_authority = replacement

    assert store.receipt_authority is bridge.receipt_authority
    assert store.load() == initial


def test_gateway_constructed_after_double_legacy_authority_rebinding_uses_the_sealed_binding(tmp_path: Path) -> None:
    bridge = trusted_bridge(tmp_path, FakeLinearMcp({"state": "started"}))
    store, initial = initial_generation(tmp_path, receipt_authority=bridge.receipt_authority)
    alternate = BridgeReceiptAuthority(
        tmp_path / "alternate-root",
        "other-bridge",
        "other-mcp",
        b"other-test-only-key",
    )
    object.__setattr__(store, "_receipt_authority", alternate)
    object.__setattr__(store, "_construction_receipt_authority", alternate)

    assert store.receipt_authority is bridge.receipt_authority
    with pytest.raises(ValueError, match="store-bound receipt authority"):
        LinearGateway(store, alternate)

    gateway = LinearGateway(store, bridge.receipt_authority)
    request = gateway.request_state(initial, "ENG-1")
    pending = gateway.persist_pending(initial, request)
    assert store.load() == pending


def test_direct_cas_rejects_alternate_root_receipt_after_double_legacy_authority_rebinding(tmp_path: Path) -> None:
    store, pending, candidate, alternate = alternate_root_reconciliation_candidate(tmp_path)
    before_generations = tuple(store.generations_dir.iterdir())
    before_pointer = store.current_path.read_bytes()
    object.__setattr__(store, "_receipt_authority", alternate)
    object.__setattr__(store, "_construction_receipt_authority", alternate)

    with pytest.raises(InvalidStateTransition, match=r"^pending request requires a trusted receipt reconciliation$"):
        store.compare_and_swap(pending.revision, pending.state_hash, candidate)

    assert tuple(store.generations_dir.iterdir()) == before_generations
    assert store.current_path.read_bytes() == before_pointer
    assert store.load() == pending


def test_locked_cas_rejects_alternate_root_receipt_after_double_legacy_authority_rebinding(tmp_path: Path) -> None:
    store, pending, candidate, alternate = alternate_root_reconciliation_candidate(tmp_path)
    before_generations = tuple(store.generations_dir.iterdir())
    before_pointer = store.current_path.read_bytes()
    object.__setattr__(store, "_receipt_authority", alternate)
    object.__setattr__(store, "_construction_receipt_authority", alternate)

    with store.interprocess_lock():
        with pytest.raises(InvalidStateTransition, match=r"^pending request requires a trusted receipt reconciliation$"):
            store.compare_and_swap_locked(pending.revision, pending.state_hash, candidate)

    assert tuple(store.generations_dir.iterdir()) == before_generations
    assert store.current_path.read_bytes() == before_pointer
    assert store.load() == pending


def test_gateway_and_bridge_snapshot_mutable_model_copied_request_before_dispatch(tmp_path: Path) -> None:
    raw_arguments: dict[str, object] = {
        "ticket_id": "ENG-1",
        "state_id": "state-1",
        "workflow": {"states": [{"id": "state-1"}]},
    }
    client = MutatingArgumentsLinearMcp({"state": "started"}, raw_arguments)
    bridge = trusted_bridge(tmp_path, client)
    store, initial = initial_generation(tmp_path, receipt_authority=bridge.receipt_authority)
    gateway = LinearGateway(store, bridge.receipt_authority)
    request = gateway.request_action(
        initial,
        operation="compare_and_start_ticket",
        entity="ticket",
        target="ENG-1",
        expected_external_revision=None,
        arguments={
            "ticket_id": "ENG-1",
            "state_id": "state-1",
            "workflow": {"states": [{"id": "state-1"}]},
        },
    )
    mutable_request = BaseModel.model_copy(request, update={"arguments": raw_arguments})

    pending = gateway.persist_pending(initial, mutable_request)
    receipt = bridge.execute(mutable_request)

    assert raw_arguments == {
        "ticket_id": "ENG-2",
        "state_id": "changed-state",
        "workflow": {"states": [{"id": "changed-state"}, {"id": "unexpected-state"}]},
    }
    assert len(client.calls) == 1
    _, operation, client_arguments = client.calls[0]
    assert operation == "compare_and_start_ticket"
    assert isinstance(client_arguments, Mapping)
    assert client_arguments["ticket_id"] == "ENG-1"
    assert client_arguments["state_id"] == "state-1"
    assert client_arguments["workflow"]["states"] == ({"id": "state-1"},)
    assert pending.state.effect_ledger[-1].payload.target == "ENG-1"
    assert pending.state.pending_external_request is not None
    assert pending.state.pending_external_request.payload_hash == request.payload_hash
    assert receipt.target == "ENG-1"
    assert receipt.payload_hash == request.payload_hash
    assert gateway.consume_receipt(pending, receipt).state.pending_external_request is None


def test_gateway_persist_pending_hides_model_copied_secret_arguments(tmp_path: Path) -> None:
    bridge = trusted_bridge(tmp_path, FakeLinearMcp({"state": "started"}))
    store, initial = initial_generation(tmp_path, receipt_authority=bridge.receipt_authority)
    gateway = LinearGateway(store, bridge.receipt_authority)
    request = gateway.request_state(initial, "ENG-1")
    sentinel = "API_KEY=fix-2-secret-sentinel"
    raw_arguments = {"ticket_id": "ENG-1", "nested": [{"value": sentinel}]}
    copied = BaseModel.model_copy(request, update={"arguments": raw_arguments})

    with pytest.raises(ValueError) as rejected:
        gateway.persist_pending(initial, copied)

    assert str(rejected.value) == "MCP action request is invalid"
    assert sentinel not in str(rejected.value)
    assert str(raw_arguments) not in str(rejected.value)
    assert store.load() == initial


def test_gateway_consumes_the_authority_loaded_receipt_after_caller_copy_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, bridge, gateway, pending, request = persisted_ticket_request(tmp_path, "ENG-1")
    receipt = bridge.execute(request)
    caller_copy = BaseModel.model_copy(receipt)
    original_validate_generation = gateway._validate_generation

    # Simulate a caller mutating its copied receipt after authority verification.
    def mutate_caller_copy_after_authority_verification(generation: StateGeneration) -> None:
        object.__setattr__(caller_copy, "outcome", EffectOutcome.FAILURE)
        original_validate_generation(generation)

    monkeypatch.setattr(gateway, "_validate_generation", mutate_caller_copy_after_authority_verification)

    consumed = gateway.consume_receipt(pending, caller_copy)

    assert consumed.state.pending_external_request is None
    assert consumed.state.effect_ledger[-2].payload.outcome is EffectOutcome.SUCCESS
    assert store.load() == consumed


def test_pending_request_cannot_be_detached_without_its_authenticated_reconciliation(tmp_path: Path) -> None:
    store, _, _, pending, _ = persisted_ticket_request(tmp_path, "ENG-1")

    with pytest.raises(InvalidStateTransition, match="pending request"):
        store.compare_and_swap(
            pending.revision,
            pending.state_hash,
            pending.state.model_copy(update={"pending_external_request": None}),
        )

    assert store.load() == pending


def test_pending_request_cannot_be_replaced_or_reattached_after_its_source_generation(tmp_path: Path) -> None:
    store, _, gateway, pending, _ = persisted_ticket_request(tmp_path, "ENG-1")
    replacement = gateway.request_state(pending, "ENG-2")
    replacement_pending = PendingExternalRequest(
        request_id=replacement.request_id,
        effect_id=replacement.effect_id,
        request_hash=replacement.request_hash,
        operation=replacement.operation,
        effect_hash=replacement.effect_hash,
        expected_revision=replacement.expected_revision,
        expected_state_hash=replacement.expected_state_hash,
        expected_external_revision=replacement.expected_external_revision,
        payload_hash=replacement.payload_hash,
    )
    replacement_intention = EffectIntention(
        effect_id=replacement.effect_id,
        sequence=pending.state.effect_ledger[-1].sequence + 1,
        timestamp=NOW,
        payload=EffectIntentionPayload(
            operation=replacement.operation,
            target=replacement.target,
            request_hash=replacement.request_hash,
        ),
    )
    replacement_state = pending.state.model_copy(
        update={
            "pending_external_request": replacement_pending,
            "effect_ledger": (*pending.state.effect_ledger, replacement_intention),
        }
    )

    with pytest.raises(InvalidStateTransition, match="pending request"):
        store.compare_and_swap(pending.revision, pending.state_hash, replacement_state)

    assert store.load() == pending


def test_new_pending_request_must_bind_to_the_predecessor_generation(tmp_path: Path) -> None:
    bridge = trusted_bridge(tmp_path, FakeLinearMcp({"state": "started"}))
    store = RunStateStore(tmp_path, "run-1", receipt_authority=bridge.receipt_authority)
    initial = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3),
    )
    gateway = LinearGateway(store, bridge.receipt_authority)
    request = gateway.request_state(initial, "ENG-1")
    misbound_pending = PendingExternalRequest(
        request_id=request.request_id,
        effect_id=request.effect_id,
        request_hash=request.request_hash,
        operation=request.operation,
        effect_hash=request.effect_hash,
        expected_revision=initial.revision + 1,
        expected_state_hash="f" * 64,
        expected_external_revision=request.expected_external_revision,
        payload_hash=request.payload_hash,
    )
    candidate = initial.state.model_copy(
        update={
            "disposition": RunDisposition.WAITING_MCP,
            "pending_external_request": misbound_pending,
            "effect_ledger": (
                EffectIntention(
                    effect_id=request.effect_id,
                    sequence=1,
                    timestamp=NOW,
                    payload=EffectIntentionPayload(
                        operation=request.operation,
                        target=request.target,
                        request_hash=request.request_hash,
                    ),
                ),
            ),
        }
    )

    with pytest.raises(InvalidStateTransition, match="predecessor generation"):
        store.compare_and_swap(initial.revision, initial.state_hash, candidate)

    assert store.load() == initial


def test_old_receipt_cannot_be_consumed_after_pending_lifecycle_tampering(tmp_path: Path) -> None:
    store, bridge, gateway, pending, request = persisted_ticket_request(tmp_path, "ENG-1")
    old_receipt = bridge.execute(request)

    tampered = pending.state.model_copy(update={"pending_external_request": None})
    with pytest.raises(InvalidStateTransition):
        store.compare_and_swap(pending.revision, pending.state_hash, tampered)

    assert gateway.consume_receipt(pending, old_receipt).state.pending_external_request is None


def test_pending_request_rejects_synthetic_events_for_its_effect_while_it_remains_pending(tmp_path: Path) -> None:
    store, _, _, pending, _ = persisted_ticket_request(tmp_path, "ENG-1")
    synthetic = pending.state.model_copy(
        update={
            "effect_ledger": (
                *pending.state.effect_ledger,
                EffectInvocation(
                    effect_id=pending.state.pending_external_request.effect_id,
                    sequence=pending.state.effect_ledger[-1].sequence + 1,
                    timestamp=NOW,
                    payload=EffectInvocationPayload(),
                ),
            ),
        }
    )

    with pytest.raises(InvalidStateTransition, match="pending request"):
        store.compare_and_swap(pending.revision, pending.state_hash, synthetic)

    assert store.load() == pending


def test_pending_request_allows_unrelated_generic_events_while_it_remains_pending(tmp_path: Path) -> None:
    store, _, _, pending, _ = persisted_ticket_request(tmp_path, "ENG-1")
    candidate = pending.state.model_copy(
        update={
            "effect_ledger": (
                *pending.state.effect_ledger,
                EffectIntention(
                    effect_id="generic-effect",
                    sequence=pending.state.effect_ledger[-1].sequence + 1,
                    timestamp=NOW,
                    payload=EffectIntentionPayload(
                        operation="record_effect",
                        target="generic-target",
                        request_hash="a" * 64,
                    ),
                ),
            ),
        }
    )

    assert store.compare_and_swap(pending.revision, pending.state_hash, candidate).state == candidate


def test_foreign_run_receipt_is_not_treated_as_an_exact_replay(tmp_path: Path) -> None:
    _, bridge, _, _, request = persisted_ticket_request(tmp_path, "ENG-1")
    receipt = bridge.execute(request)
    target_store = RunStateStore(tmp_path, "run-2", receipt_authority=bridge.receipt_authority)
    target_initial = target_store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-2", ticket_id="ENG-2", repository_id="repo-2", max_crew_iterations=3),
    )
    generic_reconciliation = target_initial.state.model_copy(
        update={
            "effect_ledger": (
                EffectIntention(
                    effect_id=receipt.effect_id,
                    sequence=1,
                    timestamp=NOW,
                    payload=EffectIntentionPayload(
                        operation="record_effect",
                        target="generic-target",
                        request_hash=receipt.request_hash,
                    ),
                ),
                EffectInvocation(
                    effect_id=receipt.effect_id,
                    sequence=2,
                    timestamp=NOW,
                    payload=EffectInvocationPayload(),
                ),
                EffectObservation(
                    effect_id=receipt.effect_id,
                    sequence=3,
                    timestamp=NOW,
                    payload=EffectObservationPayload(
                        outcome=receipt.outcome,
                        external_revision=receipt.external_revision,
                    ),
                ),
                EffectReconciliation(
                    effect_id=receipt.effect_id,
                    sequence=4,
                    timestamp=NOW,
                    payload=EffectReconciliationPayload(
                        outcome=receipt.outcome,
                        receipt_hash=receipt.content_hash,
                    ),
                ),
            ),
        }
    )
    target = target_store.compare_and_swap(
        target_initial.revision,
        target_initial.state_hash,
        generic_reconciliation,
    )
    target_gateway = LinearGateway(target_store, bridge.receipt_authority)

    with pytest.raises(ConflictingReceiptReplay):
        target_gateway.consume_receipt(target, receipt)

    assert target_store.load() == target


def test_consumed_pending_request_cannot_be_reattached_by_direct_cas(tmp_path: Path) -> None:
    store, bridge, gateway, pending, request = persisted_ticket_request(tmp_path, "ENG-1")
    former_pending = pending.state.pending_external_request
    assert former_pending is not None
    consumed = gateway.consume_receipt(pending, bridge.execute(request))
    reattached = BaseModel.model_copy(
        consumed.state,
        update={
            "disposition": RunDisposition.WAITING_MCP,
            "pending_external_request": former_pending,
        },
    )

    with pytest.raises(InvalidStateTransition):
        store.compare_and_swap(consumed.revision, consumed.state_hash, reattached)

    assert store.load() == consumed


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
def test_gateway_rejects_a_coherent_ticket_retarget_before_pending_persistence(
    tmp_path: Path,
    operation: str,
) -> None:
    client = FakeLinearMcp({"state": "started"})
    bridge = trusted_bridge(tmp_path, client)
    store, initial = initial_generation(tmp_path, receipt_authority=bridge.receipt_authority)
    gateway = LinearGateway(store, bridge.receipt_authority)
    request = gateway.request_action(
        initial,
        operation=operation,
        entity="ticket",
        target="ENG-1",
        expected_external_revision=None,
        arguments={"ticket_id": "ENG-1"},
    )
    retargeted = BaseModel.model_copy(
        request,
        update={"target": "ENG-2", "arguments": {"ticket_id": "ENG-2"}},
    )

    with pytest.raises(ValueError):
        gateway.persist_pending(initial, retargeted)

    assert store.load() == initial
    assert client.calls == []


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
def test_bridge_rejects_a_coherent_ticket_retarget_before_persisted_request_lookup(
    tmp_path: Path,
    operation: str,
) -> None:
    client = FakeLinearMcp({"state": "started"})
    bridge = trusted_bridge(tmp_path, client)
    store, initial = initial_generation(tmp_path, receipt_authority=bridge.receipt_authority)
    gateway = LinearGateway(store, bridge.receipt_authority)
    request = gateway.request_action(
        initial,
        operation=operation,
        entity="ticket",
        target="ENG-1",
        expected_external_revision=None,
        arguments={"ticket_id": "ENG-1"},
    )
    retargeted = BaseModel.model_copy(
        request,
        update={"target": "ENG-2", "arguments": {"ticket_id": "ENG-2"}},
    )

    with pytest.raises(McpBridgeError) as rejected:
        bridge.execute(retargeted)

    assert not isinstance(rejected.value, UnpersistedMcpRequestError)
    assert store.load() == initial
    assert client.calls == []


def test_bridge_rejects_unpersisted_requests_and_gateway_accepts_only_authenticated_matching_receipts(
    tmp_path: Path,
) -> None:
    client = FakeLinearMcp({"state": "started"})
    bridge = trusted_bridge(tmp_path, client)
    store, initial = initial_generation(tmp_path, receipt_authority=bridge.receipt_authority)
    gateway = LinearGateway(store, bridge.receipt_authority)
    request = gateway.request_state(initial, "ENG-1", expected_external_revision="revision-1")

    with pytest.raises(UnpersistedMcpRequestError):
        bridge.execute(request)

    pending = gateway.persist_pending(initial, request)
    other_server_bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="other-linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=FakeLinearMcp({"state": "started"}),
    )
    foreign_server_receipt = other_server_bridge.execute(request)
    with pytest.raises(UntrustedReceiptError):
        gateway.consume_receipt(pending, foreign_server_receipt)

    receipt = bridge.execute(request)
    assert receipt.target == request.target
    with pytest.raises(ValueError):
        bridge.receipt_authority.load_verified_receipt(receipt_evidence(receipt.model_copy(update={"target": "ENG-2"})))
    forged = receipt.model_copy(update={"bridge_signature": None})

    with pytest.raises(UntrustedReceiptError):
        gateway.consume_receipt(pending, forged)

    first = gateway.consume_receipt(pending, receipt)
    assert first.state.pending_external_request is None
    assert tuple(event.kind for event in first.state.effect_ledger) == (
        "intention",
        "invocation",
        "observation",
        "reconciliation",
    )
    assert gateway.consume_receipt(first, receipt) == first
    assert client.calls == [("linear-mcp", "query_ticket_state", request.arguments)]


def test_reconciles_normalized_receipt_with_a_legacy_uppercase_pending_request_hash(tmp_path: Path) -> None:
    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=FakeLinearMcp({"state": "started"}),
    )
    store, initial = initial_generation(tmp_path, receipt_authority=bridge.receipt_authority)
    gateway = LinearGateway(store, bridge.receipt_authority)
    request = gateway.request_state(initial, "ENG-1", expected_external_revision="revision-1")
    legacy_request_hash = request.request_hash.upper()
    legacy_waiting_state = initial.state.model_copy(
        update={
            "disposition": RunDisposition.WAITING_MCP,
            "effect_ledger": (
                EffectIntention(
                    effect_id=request.effect_id,
                    sequence=1,
                    timestamp=NOW,
                    payload=EffectIntentionPayload(
                        operation=request.operation,
                        target=request.target,
                        request_hash=legacy_request_hash,
                    ),
                ),
            ),
            "pending_external_request": PendingExternalRequest(
                request_id=request.request_id,
                effect_id=request.effect_id,
                request_hash=legacy_request_hash,
                operation=request.operation,
                effect_hash=request.effect_hash,
                expected_revision=request.expected_revision,
                expected_state_hash=request.expected_state_hash,
                expected_external_revision=request.expected_external_revision,
                payload_hash=request.payload_hash,
            ),
        }
    )
    legacy_generation = store.compare_and_swap(initial.revision, initial.state_hash, legacy_waiting_state)

    receipt = bridge.execute(request)
    reconciled = gateway.consume_receipt(legacy_generation, receipt)

    assert receipt.request_hash == request.request_hash
    assert reconciled.state.pending_external_request is None
    assert reconciled.state.effect_ledger[0].payload.request_hash == legacy_request_hash


def test_receipt_hook_updates_preparation_phase_in_the_same_cas_as_receipt_reconciliation(tmp_path: Path) -> None:
    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=FakeLinearMcp({"state": "started"}),
    )
    store, requested = preparation_generation(tmp_path, receipt_authority=bridge.receipt_authority)
    gateway = LinearGateway(store, bridge.receipt_authority)
    request = gateway.request_action(
        requested,
        operation="compare_and_start_ticket",
        entity="ticket",
        target="ENG-1",
        expected_external_revision=None,
        arguments={"ticket_id": "ENG-1", "state_id": "state-1"},
    )
    pending = gateway.persist_pending(requested, request)
    receipt = bridge.execute(request)

    reconciled = gateway.consume_receipt(
        pending,
        receipt,
        state_update=lambda state, _: state.model_copy(
            update={"preparation_phase": PreparationPhase.IN_PROGRESS_CONFIRMED}
        ),
    )

    assert reconciled.revision == pending.revision + 1
    assert reconciled.state.preparation_phase is PreparationPhase.IN_PROGRESS_CONFIRMED
    assert reconciled.state.effect_ledger[-2].payload.external_revision == "revision-2"
    assert reconciled.state.effect_ledger[-2].payload.evidence_refs[0].relative_path == receipt.relative_path


def test_preparation_receipt_hook_rejects_query_ticket_state_confirmation(tmp_path: Path) -> None:
    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=FakeLinearMcp({"state": "started"}),
    )
    store, requested = preparation_generation(tmp_path, receipt_authority=bridge.receipt_authority)
    gateway = LinearGateway(store, bridge.receipt_authority)
    request = gateway.request_state(requested, "ENG-1")
    pending = gateway.persist_pending(requested, request)
    receipt = bridge.execute(request)

    with pytest.raises(InvalidStateTransition, match="compare_and_start_ticket"):
        gateway.consume_receipt(
            pending,
            receipt,
            state_update=lambda state, _: state.model_copy(
                update={"preparation_phase": PreparationPhase.IN_PROGRESS_CONFIRMED}
            ),
        )

    assert store.load() == pending


def test_preparation_confirmation_rejects_synthetic_direct_cas_receipt_events(tmp_path: Path) -> None:
    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=FakeLinearMcp({"state": "started"}),
    )
    _, requested = preparation_generation(tmp_path)
    store = RunStateStore(tmp_path, "run-1", receipt_authority=bridge.receipt_authority)
    gateway = LinearGateway(store, bridge.receipt_authority)
    request = gateway.request_action(
        requested,
        operation="compare_and_start_ticket",
        entity="ticket",
        target="ENG-1",
        expected_external_revision=None,
        arguments={"ticket_id": "ENG-1", "state_id": "state-1"},
    )
    pending = gateway.persist_pending(requested, request)
    synthetic = pending.state.model_copy(
        update={
            "disposition": RunDisposition.ACTIVE,
            "preparation_phase": PreparationPhase.IN_PROGRESS_CONFIRMED,
            "pending_external_request": None,
            "effect_ledger": (
                *pending.state.effect_ledger,
                EffectInvocation(
                    effect_id=request.effect_id,
                    sequence=2,
                    timestamp=NOW,
                    payload=EffectInvocationPayload(),
                ),
                EffectObservation(
                    effect_id=request.effect_id,
                    sequence=3,
                    timestamp=NOW,
                    payload=EffectObservationPayload(outcome=EffectOutcome.SUCCESS),
                ),
                EffectReconciliation(
                    effect_id=request.effect_id,
                    sequence=4,
                    timestamp=NOW,
                    payload=EffectReconciliationPayload(outcome=EffectOutcome.SUCCESS),
                ),
            ),
        }
    )

    with pytest.raises(InvalidStateTransition, match="trusted receipt"):
        store.compare_and_swap(pending.revision, pending.state_hash, synthetic)

    assert store.load() == pending


def test_preparation_confirmation_rejects_persisted_receipt_with_mismatched_evidence_hash(tmp_path: Path) -> None:
    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=FakeLinearMcp({"state": "started"}),
    )
    store, requested = preparation_generation(tmp_path, receipt_authority=bridge.receipt_authority)
    gateway = LinearGateway(store, bridge.receipt_authority)
    request = gateway.request_action(
        requested,
        operation="compare_and_start_ticket",
        entity="ticket",
        target="ENG-1",
        expected_external_revision=None,
        arguments={"ticket_id": "ENG-1", "state_id": "state-1"},
    )
    pending = gateway.persist_pending(requested, request)
    receipt = bridge.execute(request)
    mismatched_hash = "f" * 64 if receipt.content_hash != "f" * 64 else "e" * 64
    evidence = EvidenceRef(
        relative_path=receipt.relative_path,
        sha256=mismatched_hash,
        media_type="application/json",
        creator="trusted-mcp-bridge",
    )
    synthetic = pending.state.model_copy(
        update={
            "disposition": RunDisposition.ACTIVE,
            "preparation_phase": PreparationPhase.IN_PROGRESS_CONFIRMED,
            "pending_external_request": None,
            "effect_ledger": (
                *pending.state.effect_ledger,
                EffectInvocation(
                    effect_id=request.effect_id,
                    sequence=2,
                    timestamp=receipt.observed_at,
                    payload=EffectInvocationPayload(),
                ),
                EffectObservation(
                    effect_id=request.effect_id,
                    sequence=3,
                    timestamp=receipt.observed_at,
                    payload=EffectObservationPayload(
                        outcome=receipt.outcome,
                        external_revision=receipt.external_revision,
                        evidence_refs=(evidence,),
                    ),
                ),
                EffectReconciliation(
                    effect_id=request.effect_id,
                    sequence=4,
                    timestamp=receipt.observed_at,
                    payload=EffectReconciliationPayload(
                        outcome=receipt.outcome,
                        evidence_refs=(evidence,),
                        receipt_hash=mismatched_hash,
                    ),
                ),
            ),
        }
    )

    assert bridge.receipt_authority.load_verified_receipt(receipt_evidence(receipt)) == receipt
    with pytest.raises(InvalidStateTransition, match="trusted receipt"):
        store.compare_and_swap(pending.revision, pending.state_hash, synthetic)

    assert store.load() == pending


def test_preparation_confirmation_rejects_signed_receipt_for_a_different_ticket(tmp_path: Path) -> None:
    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=FakeLinearMcp({"state": "started"}),
    )
    store, requested = preparation_generation(tmp_path, receipt_authority=bridge.receipt_authority)
    gateway = LinearGateway(store, bridge.receipt_authority)
    request = gateway.request_action(
        requested,
        operation="compare_and_start_ticket",
        entity="ticket",
        target="ENG-2",
        expected_external_revision=None,
        arguments={"ticket_id": "ENG-2", "state_id": "state-1"},
    )
    pending = gateway.persist_pending(requested, request)
    receipt = bridge.execute(request)

    assert receipt.target == "ENG-2"
    assert bridge.receipt_authority.load_verified_receipt(receipt_evidence(receipt)) == receipt
    with pytest.raises(InvalidStateTransition, match="trusted receipt"):
        gateway.consume_receipt(
            pending,
            receipt,
            state_update=lambda state, _: state.model_copy(
                update={"preparation_phase": PreparationPhase.IN_PROGRESS_CONFIRMED}
            ),
        )

    assert store.load() == pending


def test_preparation_restore_rejects_signed_receipt_for_a_different_ticket(tmp_path: Path) -> None:
    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=FakeLinearMcp({"state": "started"}),
    )
    store, requested = preparation_generation(tmp_path, receipt_authority=bridge.receipt_authority)
    gateway = LinearGateway(store, bridge.receipt_authority)
    start_request = gateway.request_action(
        requested,
        operation="compare_and_start_ticket",
        entity="ticket",
        target="ENG-1",
        expected_external_revision=None,
        arguments={"ticket_id": "ENG-1", "state_id": "state-1"},
    )
    start_pending = gateway.persist_pending(requested, start_request)
    confirmed = gateway.consume_receipt(
        start_pending,
        bridge.execute(start_request),
        state_update=lambda state, _: state.model_copy(
            update={"preparation_phase": PreparationPhase.IN_PROGRESS_CONFIRMED}
        ),
    )
    branch_sequence = confirmed.state.effect_ledger[-1].sequence + 1
    compensation_required = store.compare_and_swap(
        confirmed.revision,
        confirmed.state_hash,
        confirmed.state.model_copy(
            update={
                "preparation_phase": PreparationPhase.COMPENSATION_REQUIRED,
                "effect_ledger": (
                    *confirmed.state.effect_ledger,
                    EffectIntention(
                        effect_id="branch-effect",
                        sequence=branch_sequence,
                        timestamp=NOW,
                        payload=EffectIntentionPayload(
                            operation="create_ticket_branch",
                            target="ENG-1",
                            request_hash="a" * 64,
                        ),
                    ),
                    EffectInvocation(
                        effect_id="branch-effect",
                        sequence=branch_sequence + 1,
                        timestamp=NOW,
                        payload=EffectInvocationPayload(),
                    ),
                    EffectObservation(
                        effect_id="branch-effect",
                        sequence=branch_sequence + 2,
                        timestamp=NOW,
                        payload=EffectObservationPayload(outcome=EffectOutcome.FAILURE),
                    ),
                    EffectReconciliation(
                        effect_id="branch-effect",
                        sequence=branch_sequence + 3,
                        timestamp=NOW,
                        payload=EffectReconciliationPayload(outcome=EffectOutcome.FAILURE),
                    ),
                ),
            }
        ),
    )
    restore_request = gateway.request_action(
        compensation_required,
        operation="restore_ticket_state",
        entity="ticket",
        target="ENG-2",
        expected_external_revision=None,
        arguments={"ticket_id": "ENG-2", "state_id": "state-1"},
    )
    pending = gateway.persist_pending(compensation_required, restore_request)
    receipt = bridge.execute(restore_request)

    assert receipt.target == "ENG-2"
    assert bridge.receipt_authority.load_verified_receipt(receipt_evidence(receipt)) == receipt
    with pytest.raises(InvalidStateTransition, match="restore reconciliation"):
        gateway.consume_receipt(
            pending,
            receipt,
            state_update=lambda state, _: state.model_copy(
                update={"compensated": True, "disposition": RunDisposition.HUMAN_REVIEW}
            ),
        )

    assert store.load() == pending


def test_receipt_consumption_retains_a_trusted_external_revision_without_restricting_its_provider_format(
    tmp_path: Path,
) -> None:
    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=FakeLinearMcp({"state": "started"}, external_revision="revision:2"),
    )
    store, initial = initial_generation(tmp_path, receipt_authority=bridge.receipt_authority)
    gateway = LinearGateway(store, bridge.receipt_authority)
    request = gateway.request_state(initial, "ENG-1")
    pending = gateway.persist_pending(initial, request)

    reconciled = gateway.consume_receipt(pending, bridge.execute(request))

    assert reconciled.state.effect_ledger[-2].payload.external_revision == "revision:2"


def test_conflicting_authenticated_receipt_replay_fails(tmp_path: Path) -> None:
    client = FakeLinearMcp({"state": "started"})
    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=client,
    )
    store, initial = initial_generation(tmp_path, receipt_authority=bridge.receipt_authority)
    gateway = LinearGateway(store, bridge.receipt_authority)
    request = gateway.request_ticket_projection(initial, "ENG-1")
    pending = gateway.persist_pending(initial, request)
    first_receipt = bridge.execute(request)
    client.result = {"title": "Changed after the first observation"}
    conflicting = bridge.execute(request)
    consumed = gateway.consume_receipt(pending, first_receipt)

    with pytest.raises(ConflictingReceiptReplay):
        gateway.consume_receipt(consumed, conflicting)


def test_action_requests_reject_secret_like_arguments_before_persistence(tmp_path: Path) -> None:
    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=FakeLinearMcp({"state": "started"}),
    )
    store, initial = initial_generation(tmp_path, receipt_authority=bridge.receipt_authority)
    gateway = LinearGateway(store, bridge.receipt_authority)

    with pytest.raises(ValueError):
        gateway.request_action(
            initial,
            operation="query_ticket_state",
            entity="ticket",
            target="ENG-1",
            expected_external_revision=None,
            arguments={"ticket_id": "ENG-1", "authorization": "Bearer super-secret-value"},
        )

    assert store.load() == initial


def test_preparation_query_writes_sanitized_challenge_free_trusted_input(tmp_path: Path) -> None:
    client = FakeLinearMcp(
        preparation_response(
            [
                {
                    "echoed_challenge": "challenge-value",
                    "issues": [{"id": "ENG-1", "description": "API_KEY=never-persist-this"}],
                }
            ]
        )
    )
    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=client,
    )

    reference = bridge.query_preparation(
        "challenge-value",
        {"assignee": "user-1", "milestone": "milestone-1"},
        repository_id="repo-1",
        reservation_id="reservation-1",
    )
    persisted = (tmp_path / reference.relative_path).read_text(encoding="ascii")

    assert "challenge-value" not in persisted
    assert "never-persist-this" not in persisted
    assert reference.pagination_complete is True
    assert reference.max_crew_iterations == 2
    assert reference.source_page_hashes
    assert reference.observations == ("The trusted Linear MCP call completed.",)
    assert bridge.verify_preparation_input(reference)
    assert not bridge.verify_preparation_input(reference.model_copy(update={"bridge_signature": None}))


def test_preparation_verification_rejects_a_signed_reference_from_another_mcp_server(tmp_path: Path) -> None:
    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=FakeLinearMcp(preparation_response([])),
    )
    other_server_bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="other-linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=FakeLinearMcp(preparation_response([])),
    )

    foreign_reference = other_server_bridge.query_preparation(
        "challenge-value",
        {"assignee": "user-1"},
        repository_id="repo-1",
        reservation_id="reservation-1",
    )

    assert not bridge.verify_preparation_input(foreign_reference)


def test_preparation_loader_rejects_a_swapped_bridge_envelope_path_and_hash(tmp_path: Path) -> None:
    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=FakeLinearMcp(
            {
                "pages": [{"tickets": []}],
                "pagination_complete": True,
                "max_crew_iterations": 2,
                "assignee_resolution": {"status": "resolved", "resolved_id": "user-1"},
                "milestone_resolution": {"status": "resolved", "resolved_id": "milestone-1"},
                "workflow_states": {"started": "state-1", "completed": "state-2"},
            }
        ),
    )

    first = bridge.query_preparation(
        "challenge-one",
        {"assignee": "user-1", "milestone": "milestone-1"},
        repository_id="repo-1",
        reservation_id="reservation-1",
    )
    second = bridge.query_preparation(
        "challenge-two",
        {"assignee": "user-1", "milestone": "milestone-1"},
        repository_id="repo-1",
        reservation_id="reservation-2",
    )

    loaded_reference, loaded_input = bridge.load_verified_preparation_input(
        tmp_path / first.relative_path,
        first.input_hash,
    )

    assert loaded_reference == first
    assert loaded_input.repository_id == "repo-1"
    with pytest.raises(McpBridgeError):
        bridge.load_verified_preparation_input(tmp_path / second.relative_path, first.input_hash)


def test_preparation_loader_rejects_a_signed_envelope_whose_path_does_not_match_its_input_id(tmp_path: Path) -> None:
    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=FakeLinearMcp(preparation_response([{"tickets": []}])),
    )
    reference = bridge.query_preparation(
        "challenge-value",
        {"assignee": "user-1", "milestone": "milestone-1"},
        repository_id="repo-1",
        reservation_id="reservation-1",
    )
    _, preparation_input = bridge.load_verified_preparation_input(
        tmp_path / reference.relative_path,
        reference.input_hash,
    )
    input_id = "55555555-5555-4555-8555-555555555555"
    forged = reference.model_copy(
        update={
            "input_id": input_id,
            "relative_path": f"trusted-mcp/preparation/not-{input_id}.json",
            "input_hash": "0" * 64,
            "bridge_signature": None,
        }
    )
    forged = forged.model_copy(update={"input_hash": preparation_input_envelope_hash(forged, preparation_input)})
    forged = forged.model_copy(update={"bridge_signature": _sign(bridge._signing_key, forged.signed_payload())})
    path = tmp_path / forged.relative_path
    path.write_bytes(
        canonical_json_bytes(
            {
                "reference": forged.model_dump(mode="json", round_trip=True),
                "input": preparation_input.model_dump(mode="json", round_trip=True),
            }
        )
    )

    with pytest.raises(McpBridgeError):
        bridge.load_verified_preparation_input(path, forged.input_hash)


def test_preparation_loader_rejects_incomplete_pagination_before_it_can_be_selected(tmp_path: Path) -> None:
    response = preparation_response([{"tickets": []}])
    response["pagination_complete"] = False
    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=FakeLinearMcp(response),
    )
    reference = bridge.query_preparation(
        "challenge-value",
        {"assignee": "user-1", "milestone": "milestone-1"},
        repository_id="repo-1",
        reservation_id="reservation-1",
    )

    with pytest.raises(McpBridgeError):
        bridge.load_verified_preparation_input(tmp_path / reference.relative_path, reference.input_hash)


def test_preparation_bridge_rejects_a_nonpositive_budget_before_persisting_an_envelope(tmp_path: Path) -> None:
    response = preparation_response([{"tickets": []}])
    response["max_crew_iterations"] = 0
    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=FakeLinearMcp(response),
    )

    with pytest.raises(McpBridgeError):
        bridge.query_preparation(
            "challenge-value",
            {"assignee": "user-1", "milestone": "milestone-1"},
            repository_id="repo-1",
            reservation_id="reservation-1",
        )

    assert list(bridge.preparation_dir.iterdir()) == []


def test_preparation_loader_rejects_caller_authored_paths_without_exposing_the_challenge(tmp_path: Path) -> None:
    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=FakeLinearMcp(preparation_response([{"tickets": []}])),
    )
    caller_authored = tmp_path / "caller-authored.json"
    caller_authored.write_text('{"challenge":"challenge-value"}', encoding="ascii")

    with pytest.raises(McpBridgeError) as error:
        bridge.load_verified_preparation_input(caller_authored, "a" * 64)

    assert "challenge-value" not in str(error.value)


@pytest.mark.parametrize(
    "reference_update",
    (
        {"bridge_signature": "0" * 64},
        {"relative_path": "trusted-mcp/preparation/55555555-5555-4555-8555-555555555555.json"},
    ),
)
def test_activation_rejects_a_forged_bridge_reference_before_journal_or_state_publication(
    tmp_path: Path,
    reference_update: dict[str, str],
) -> None:
    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=FakeLinearMcp(preparation_response([{"tickets": []}])),
    )
    index = ActiveRunIndex(tmp_path, preparation_input_verifier=bridge)
    reservation = index.reserve("repo-1")
    reference = bridge.query_preparation(
        reservation.challenge or "",
        {"assignee": "user-1", "milestone": "milestone-1"},
        repository_id=reservation.repository_id,
        reservation_id=reservation.reservation_id,
    )
    forged = reference.model_copy(update=reference_update)
    initial = RunState(
        run_id="run-1",
        ticket_id="ENG-1",
        repository_id=reservation.repository_id,
        max_crew_iterations=forged.max_crew_iterations,
        project_policy_hash="1" * 64,
        preparation_input_ref=forged,
        preparation_input_hash=forged.input_hash,
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
    request = ActivationRequest(
        reservation_id=reservation.reservation_id,
        repository_id=reservation.repository_id,
        expected_index_revision=reservation.index_revision,
        expected_index_hash=reservation.index_hash,
        preparation_input_ref=forged,
        run_id=initial.run_id,
        initial_state=initial,
        initial_state_hash=hash_json(initial.model_dump(mode="json", round_trip=True)),
    )

    with pytest.raises(ActivationStateMismatch, match="bridge"):
        index.activate_reservation(request)

    assert not index._journal_path(reservation.reservation_id).exists()
    assert not RunStateStore(tmp_path, initial.run_id).current_path.exists()
    assert index.lookup(reservation.repository_id) is None
