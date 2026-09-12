from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
import hmac
import re
from typing import Any, Protocol

from pydantic import ValidationError

from .contracts import (
    CandidateTicket,
    EvidenceRef,
    EffectIntention,
    EffectIntentionPayload,
    EffectInvocation,
    EffectInvocationPayload,
    EffectObservation,
    EffectObservationPayload,
    EffectReconciliation,
    EffectReconciliationPayload,
    IdentityResolution,
    IdentityResolutionError,
    McpActionRequest,
    PendingExternalRequest,
    RunDisposition,
    RunState,
    TicketProjectionTooLargeError,
    TicketSnapshot,
    TrustedMcpReceipt,
)
from .state import BridgeReceiptAuthority, CompareAndSwapConflict, RunStateStore, StateGeneration


class LinearDataError(ValueError):
    pass


class UntrustedReceiptError(ValueError):
    pass


class ConflictingReceiptReplay(ValueError):
    pass


class PendingRequestConflict(ValueError):
    pass


TicketProjectionTooLarge = TicketProjectionTooLargeError

_CANONICAL_TICKET_ID = re.compile(r"^[A-Z0-9][A-Z0-9._-]{0,255}$")


class ReceiptStateUpdate(Protocol):
    def __call__(self, state: RunState, receipt: TrustedMcpReceipt) -> RunState: ...


class PendingStateUpdate(Protocol):
    def __call__(self, state: RunState, request: McpActionRequest) -> RunState: ...


def select_ticket(raw: object, assignee_id: str, milestone_id: str) -> CandidateTicket | None:
    """Select a deterministic unstarted ticket without making an external call."""

    if not _is_identifier(assignee_id) or not _is_identifier(milestone_id):
        raise LinearDataError("Resolved Linear identities are invalid")
    normalized = tuple(_normalize_ticket(item) for item in _ticket_items(raw))
    identifiers = [identifier for identifier, _, _ in normalized]
    if len(set(identifiers)) != len(identifiers):
        raise LinearDataError("Linear ticket data contains duplicate canonical IDs")

    candidates = [
        ticket
        for _, ticket, active_blocker in normalized
        if ticket is not None
        and ticket.assignee_id == assignee_id
        and ticket.milestone_id == milestone_id
        and not active_blocker
    ]
    if not candidates:
        return None
    return min(candidates, key=_candidate_order)


def _ticket_items(raw: object) -> tuple[object, ...]:
    if isinstance(raw, Mapping):
        raw = raw.get("tickets")
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        raise LinearDataError("Linear ticket response is malformed")
    return tuple(raw)


def _normalize_ticket(raw: object) -> tuple[str, CandidateTicket | None, bool]:
    if not isinstance(raw, Mapping):
        raise LinearDataError("Linear ticket response is malformed")
    try:
        identifier = _canonical_ticket_id(raw.get("id"))
        state_type = _state_type(raw.get("state_type"))
        assignee_id = _required_identifier(raw.get("assignee_id"))
        milestone_id = _required_identifier(raw.get("milestone_id"))
        priority = _priority(raw.get("priority"))
        created_at = _timestamp(raw.get("created_at"))
        blockers = raw.get("blockers", ())
        if not isinstance(blockers, Sequence) or isinstance(blockers, (str, bytes)):
            raise ValueError("Blockers must be a collection")
        active_blocker = any(_blocker_is_active(blocker) for blocker in blockers)
        title = raw.get("title", "")
        if not isinstance(title, str):
            raise ValueError("Ticket title is invalid")
        ticket = (
            CandidateTicket(
                id=identifier,
                state_type="unstarted",
                assignee_id=assignee_id,
                milestone_id=milestone_id,
                priority=priority,
                created_at=created_at,
                title=title,
            )
            if state_type == "unstarted"
            else None
        )
        return (identifier, ticket, active_blocker)
    except (TypeError, ValueError, ValidationError) as error:
        raise LinearDataError("Linear ticket response is malformed") from error


def _candidate_order(ticket: CandidateTicket) -> tuple[int, int, datetime, str]:
    if ticket.priority is None:
        return (1, 0, ticket.created_at, ticket.id)
    return (0, ticket.priority, ticket.created_at, ticket.id)


def _canonical_ticket_id(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("Ticket ID is invalid")
    identifier = value.strip().upper()
    if _CANONICAL_TICKET_ID.fullmatch(identifier) is None:
        raise ValueError("Ticket ID is invalid")
    return identifier


def _required_identifier(value: object) -> str:
    if not _is_identifier(value):
        raise ValueError("Linear identifier is invalid")
    assert isinstance(value, str)
    return value


def _is_identifier(value: object) -> bool:
    return isinstance(value, str) and bool(value) and len(value) <= 256 and not any(character.isspace() for character in value)


def _state_type(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise ValueError("Linear state type is invalid")
    return value.strip().lower()


def _priority(value: object) -> int | None:
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError("Linear priority is invalid")
    return value if value > 0 else None


def _timestamp(value: object) -> datetime:
    if not isinstance(value, str) or not value:
        raise ValueError("Linear timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(f"{value[:-1]}+00:00" if value.endswith("Z") else value)
    except ValueError as error:
        raise ValueError("Linear timestamp is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("Linear timestamp is invalid")
    return parsed.astimezone(UTC)


def _blocker_is_active(value: object) -> bool:
    if not isinstance(value, Mapping):
        raise ValueError("Linear blocker is invalid")
    return _state_type(value.get("state_type")) not in {"completed", "canceled"}


class LinearGateway:
    """Own request construction and state CAS; it cannot call Linear itself."""

    def __init__(self, store: RunStateStore, receipt_authority: BridgeReceiptAuthority) -> None:
        if (
            not isinstance(store, RunStateStore)
            or not isinstance(receipt_authority, BridgeReceiptAuthority)
            or store.receipt_authority is not receipt_authority
        ):
            raise ValueError("Linear gateway requires a store-bound receipt authority")
        self._store = store
        self._receipt_authority = receipt_authority

    @property
    def store(self) -> RunStateStore:
        return self._store

    def request_ticket_projection(
        self,
        generation: StateGeneration,
        ticket_id: str,
        *,
        expected_external_revision: str | None = None,
    ) -> McpActionRequest:
        return self.request_action(
            generation,
            operation="query_ticket_projection",
            entity="ticket",
            target=ticket_id,
            expected_external_revision=expected_external_revision,
            arguments={"ticket_id": ticket_id},
        )

    def request_state(
        self,
        generation: StateGeneration,
        ticket_id: str,
        *,
        expected_external_revision: str | None = None,
    ) -> McpActionRequest:
        return self.request_action(
            generation,
            operation="query_ticket_state",
            entity="ticket",
            target=ticket_id,
            expected_external_revision=expected_external_revision,
            arguments={"ticket_id": ticket_id},
        )

    def request_action(
        self,
        generation: StateGeneration,
        *,
        operation: str,
        entity: str,
        target: str,
        expected_external_revision: str | None,
        arguments: Mapping[str, Any],
    ) -> McpActionRequest:
        self._validate_generation(generation)
        return McpActionRequest.create(
            operation=operation,
            entity=entity,
            target=target,
            expected_external_revision=expected_external_revision,
            run_id=generation.state.run_id,
            expected_revision=generation.revision,
            expected_state_hash=generation.state_hash,
            arguments=arguments,
        )

    def persist_pending(
        self,
        generation: StateGeneration,
        request: McpActionRequest,
        *,
        state_update: PendingStateUpdate | None = None,
    ) -> StateGeneration:
        snapshot = McpActionRequest.snapshot(request)
        self._validate_request_binding(generation, snapshot)
        if generation.state.pending_external_request is not None:
            if _pending_matches_request(generation.state.pending_external_request, snapshot):
                return generation
            raise PendingRequestConflict("A different MCP request is already pending")
        if generation.state.disposition is not RunDisposition.ACTIVE:
            raise PendingRequestConflict("MCP requests require an active run")

        sequence = generation.state.effect_ledger[-1].sequence + 1 if generation.state.effect_ledger else 1
        pending = PendingExternalRequest(
            request_id=snapshot.request_id,
            effect_id=snapshot.effect_id,
            request_hash=snapshot.request_hash,
            operation=snapshot.operation,
            entity=snapshot.entity,
            target=snapshot.target,
            arguments=snapshot.arguments,
            effect_hash=snapshot.effect_hash,
            expected_revision=snapshot.expected_revision,
            expected_state_hash=snapshot.expected_state_hash,
            expected_external_revision=snapshot.expected_external_revision,
            payload_hash=snapshot.payload_hash,
        )
        intended = EffectIntention(
            effect_id=snapshot.effect_id,
            sequence=sequence,
            timestamp=datetime.now(UTC),
            payload=EffectIntentionPayload(
                operation=snapshot.operation,
                target=snapshot.target,
                request_hash=snapshot.request_hash,
            ),
        )
        state = generation.state.model_copy(
            update={
                "disposition": RunDisposition.WAITING_MCP,
                "effect_ledger": (*generation.state.effect_ledger, intended),
                "pending_external_request": pending,
            }
        )
        if state_update is not None:
            if not callable(state_update):
                raise ValueError("pending state update must be callable")
            updated = state_update(state, request)
            if not isinstance(updated, RunState):
                raise ValueError("pending state update must return a RunState")
            if updated.effect_ledger != state.effect_ledger or updated.pending_external_request != state.pending_external_request:
                raise ValueError("pending state update must preserve the pending intention")
            state = updated
        try:
            return self._store.compare_and_swap(generation.revision, generation.state_hash, state)
        except CompareAndSwapConflict:
            current = self._store.load()
            if current.state.pending_external_request is not None and _pending_matches_request(
                current.state.pending_external_request, snapshot
            ):
                return current
            raise

    def replay_pending(self, generation: StateGeneration) -> McpActionRequest | None:
        """Reconstruct the exact persisted request without creating another effect."""

        self._validate_generation(generation)
        current = self._store.load()
        if current != generation:
            raise CompareAndSwapConflict("authoritative state no longer matches the expected generation")
        pending = current.state.pending_external_request
        if pending is None:
            return None
        try:
            request = pending.reconstruct_request(current.state.run_id)
        except ValueError:
            raise PendingRequestConflict("persisted MCP request cannot be replayed") from None
        self._validate_persisted_request(current, request)
        return request

    def consume_receipt(
        self,
        generation: StateGeneration,
        receipt: TrustedMcpReceipt,
        *,
        state_update: ReceiptStateUpdate | None = None,
    ) -> StateGeneration:
        if not isinstance(receipt, TrustedMcpReceipt):
            raise UntrustedReceiptError("MCP receipt is not bridge authenticated")
        authenticated_receipt = self._load_trusted_receipt(receipt)
        if authenticated_receipt is None:
            raise UntrustedReceiptError("MCP receipt is not bridge authenticated")
        receipt = authenticated_receipt
        self._validate_generation(generation)
        current = self._store.load()
        if current.state.pending_external_request is None:
            if _receipt_was_consumed(current, receipt):
                return current
            raise ConflictingReceiptReplay("MCP receipt conflicts with the recorded effect")
        if current != generation:
            raise CompareAndSwapConflict("authoritative state no longer matches the expected generation")
        pending = current.state.pending_external_request
        if not _receipt_matches_pending(receipt, pending, current.state.run_id):
            raise UntrustedReceiptError("MCP receipt does not match the pending request")

        invoked = EffectInvocation(
            effect_id=pending.effect_id,
            sequence=current.state.effect_ledger[-1].sequence + 1,
            timestamp=receipt.observed_at,
            payload=EffectInvocationPayload(),
        )
        observed = EffectObservation(
            effect_id=pending.effect_id,
            sequence=invoked.sequence + 1,
            timestamp=receipt.observed_at,
            payload=EffectObservationPayload(
                outcome=receipt.outcome,
                external_revision=receipt.external_revision,
                evidence_refs=(self._receipt_evidence(receipt),),
            ),
        )
        reconciled = EffectReconciliation(
            effect_id=pending.effect_id,
            sequence=observed.sequence + 1,
            timestamp=receipt.observed_at,
            payload=EffectReconciliationPayload(
                outcome=receipt.outcome,
                evidence_refs=(self._receipt_evidence(receipt),),
                receipt_hash=receipt.content_hash,
            ),
        )
        state = current.state.model_copy(
            update={
                "disposition": RunDisposition.ACTIVE,
                "effect_ledger": (*current.state.effect_ledger, invoked, observed, reconciled),
                "pending_external_request": None,
            }
        )
        if state_update is not None:
            if not callable(state_update):
                raise ValueError("receipt state update must be callable")
            updated = state_update(state, receipt)
            if not isinstance(updated, RunState):
                raise ValueError("receipt state update must return a RunState")
            if updated.effect_ledger != state.effect_ledger or updated.pending_external_request is not None:
                raise ValueError("receipt state update must preserve reconciled receipt events")
            state = updated
        try:
            return self._store.compare_and_swap(current.revision, current.state_hash, state)
        except CompareAndSwapConflict:
            latest = self._store.load()
            if _receipt_was_consumed(latest, receipt):
                return latest
            raise

    def _load_trusted_receipt(self, receipt: TrustedMcpReceipt) -> TrustedMcpReceipt | None:
        self._require_authority_binding()
        try:
            authenticated_receipt = self._receipt_authority.load_verified_receipt(self._receipt_evidence(receipt))
        except Exception:
            return None
        return authenticated_receipt if authenticated_receipt == receipt else None

    def _validate_generation(self, generation: StateGeneration) -> None:
        self._require_authority_binding()
        if not isinstance(generation, StateGeneration) or generation.state.run_id != self._store.run_id:
            raise ValueError("MCP action requires this run's authoritative generation")

    def _require_authority_binding(self) -> None:
        if self._store.receipt_authority is not self._receipt_authority:
            raise ValueError("Linear gateway receipt authority binding has changed")

    def _validate_request_binding(self, generation: StateGeneration, request: McpActionRequest) -> None:
        self._validate_generation(generation)
        if not isinstance(request, McpActionRequest):
            raise ValueError("MCP action request is invalid")
        request.validate_request_hashes()
        if (
            request.run_id != generation.state.run_id
            or request.expected_revision != generation.revision
            or request.expected_state_hash != generation.state_hash
        ):
            raise ValueError("MCP action request does not match its run CAS binding")

    @staticmethod
    def _validate_persisted_request(generation: StateGeneration, request: McpActionRequest) -> None:
        pending = generation.state.pending_external_request
        if pending is None or not _pending_matches_request(pending, request):
            raise PendingRequestConflict("persisted MCP request does not match its pending binding")
        intentions, _ = generation.state.validate_effect_ledger()
        intention = intentions.get(pending.effect_id)
        if (
            intention is None
            or intention.payload.operation != request.operation
            or intention.payload.target != request.target
            or not _request_hashes_match(intention.payload.request_hash, request.request_hash)
        ):
            raise PendingRequestConflict("persisted MCP request does not match its effect intention")

    @staticmethod
    def _receipt_evidence(receipt: TrustedMcpReceipt) -> EvidenceRef:
        return EvidenceRef(
            relative_path=receipt.relative_path,
            sha256=receipt.content_hash,
            media_type="application/json",
            creator="trusted-mcp-bridge",
        )


def _pending_matches_request(pending: PendingExternalRequest, request: McpActionRequest) -> bool:
    return (
        pending.request_id == request.request_id
        and pending.effect_id == request.effect_id
        and _request_hashes_match(pending.request_hash, request.request_hash)
        and pending.operation == request.operation
        and pending.entity == request.entity
        and pending.target == request.target
        and pending.arguments == request.arguments
        and pending.effect_hash == request.effect_hash
        and pending.expected_revision == request.expected_revision
        and pending.expected_state_hash == request.expected_state_hash
        and pending.expected_external_revision == request.expected_external_revision
        and pending.payload_hash == request.payload_hash
    )


def _receipt_matches_pending(receipt: TrustedMcpReceipt, pending: PendingExternalRequest, run_id: str) -> bool:
    return (
        receipt.run_id == run_id
        and receipt.request_id == pending.request_id
        and receipt.effect_id == pending.effect_id
        and _request_hashes_match(receipt.request_hash, pending.request_hash)
        and receipt.operation == pending.operation
        and receipt.effect_hash == pending.effect_hash
        and receipt.expected_revision == pending.expected_revision
        and receipt.expected_state_hash == pending.expected_state_hash
        and receipt.expected_external_revision == pending.expected_external_revision
        and receipt.payload_hash == pending.payload_hash
    )


def _request_hashes_match(first: str, second: str) -> bool:
    return hmac.compare_digest(first.lower(), second.lower())


def _receipt_was_consumed(generation: StateGeneration, receipt: TrustedMcpReceipt) -> bool:
    return generation.state.run_id == receipt.run_id and any(
        isinstance(event, EffectReconciliation)
        and event.effect_id == receipt.effect_id
        and event.payload.receipt_hash == receipt.content_hash
        for event in generation.state.effect_ledger
    )
