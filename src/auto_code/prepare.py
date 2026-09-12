from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
import hmac
from pathlib import Path
from typing import Literal, Protocol

from pydantic import ValidationError

from .contracts import (
    ActivationRequest,
    CompatibilityClaimBinding,
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
    IdentityResolutionError,
    McpActionRequest,
    PreparationInput,
    PreparationPhase,
    PersistedBranchBinding,
    RunDisposition,
    RunState,
    RunnerIdentity,
    SelectedActivationClaimRequest,
    TicketSnapshot,
    TrustedMcpReceipt,
    TrustedPreparationInputRef,
    _looks_sensitive,
    reject_unsafe_persisted_value,
)
from .git import BranchBinding, BranchReuseError
from .compatibility import CompatibilityPreflightError, load_descriptor_bound_policy
from .hashing import hash_json
from .linear import LinearGateway, select_ticket
from .run_index import ActivationResult, IndexProbeResult, PreparationReservation, ReservationOwner, SelectedActivationClaim
from .state import (
    AuthoritativeStateCorrupt,
    StateGeneration,
    RunStateStore,
    _ensure_directory,
    _normalize_state_root,
    _read_canonical_json,
    _require_identifier,
    _validate_persisted_value,
    _write_new_json,
)


class PreparationContextError(RuntimeError):
    pass


class PrepareError(RuntimeError):
    pass


class _PreparationIndex(Protocol):
    def probe_or_reserve(self, repository_id: str, owner: ReservationOwner) -> IndexProbeResult: ...

    def activate_reservation(self, request: ActivationRequest) -> ActivationResult: ...

    def activation_result(self, reference: TrustedPreparationInputRef, challenge: str) -> ActivationResult | None: ...

    def activation_reservation(
        self,
        reference: TrustedPreparationInputRef,
        challenge: str,
    ) -> PreparationReservation: ...

    def claim_selected_activation(self, request: SelectedActivationClaimRequest) -> SelectedActivationClaim: ...

    def record_claim_compatibility(
        self,
        reference: TrustedPreparationInputRef,
        challenge: str,
        binding: CompatibilityClaimBinding,
    ) -> SelectedActivationClaim: ...

    def complete_selected_activation(
        self,
        reference: TrustedPreparationInputRef,
        challenge: str,
    ) -> ActivationResult | None: ...

    def complete_selected_activation_human_review(
        self,
        reference: TrustedPreparationInputRef,
        challenge: str,
    ) -> ActivationResult | None: ...


class _PreparationBridge(Protocol):
    def load_verified_preparation_input(
        self,
        input_path: Path,
        input_hash: str,
    ) -> tuple[TrustedPreparationInputRef, PreparationInput]: ...

    def verify_and_load_preparation_input(
        self,
        reference: TrustedPreparationInputRef,
    ) -> tuple[TrustedPreparationInputRef, PreparationInput]: ...


class _RepositoryGuard(Protocol):
    repository: Path

    def repository_identity(self) -> str: ...

    def prepare_ticket_branch(self, ticket_id: str, title: str, *, checkpoint_lineage: str) -> BranchBinding: ...

    def create_bound_ticket_branch(self, binding: BranchBinding) -> str: ...

    def reconcile_branch(self, binding: BranchBinding, *, checkpoint_lineage: str) -> str: ...


class _CompatibilityVerifier(Protocol):
    def verify(self, runtime_config: object, role_config: object) -> object: ...


@dataclass(frozen=True)
class PrepareProbeResult:
    kind: Literal["RESUME", "BLOCKED", "INPUT_REQUIRED"]
    repository_id: str
    run_id: str | None = None
    reservation_id: str | None = None
    challenge: str | None = None

    @classmethod
    def resume(cls, repository_id: str, active_run: ActivationResult) -> PrepareProbeResult:
        return cls(kind="RESUME", repository_id=repository_id, run_id=active_run.run_id)

    @classmethod
    def blocked(cls, repository_id: str, reservation: PreparationReservation) -> PrepareProbeResult:
        return cls(kind="BLOCKED", repository_id=repository_id, reservation_id=reservation.reservation_id)

    @classmethod
    def input_required(cls, repository_id: str, reservation: PreparationReservation) -> PrepareProbeResult:
        return cls(
            kind="INPUT_REQUIRED",
            repository_id=repository_id,
            reservation_id=reservation.reservation_id,
            challenge=reservation.challenge,
        )


@dataclass(frozen=True)
class PrepareResult:
    kind: Literal["NO_CANDIDATE", "WAIT", "ACTIVATED"]
    generation: StateGeneration | None
    action_request: McpActionRequest | None
    run_id: str | None

    @classmethod
    def waiting(cls, generation: StateGeneration, request: McpActionRequest) -> PrepareResult:
        return cls(kind="WAIT", generation=generation, action_request=request, run_id=generation.state.run_id)

    @classmethod
    def current(cls, generation: StateGeneration) -> PrepareResult:
        return cls(kind="ACTIVATED", generation=generation, action_request=None, run_id=generation.state.run_id)


class PrepareCoordinator:
    def __init__(
        self,
        *,
        index: _PreparationIndex,
        bridge: _PreparationBridge,
        git: _RepositoryGuard,
        compatibility: _CompatibilityVerifier,
        runtime_config: object,
        role_config: object,
        reservation_owner: Callable[[], ReservationOwner],
        now: Callable[[], datetime],
        linear: LinearGateway | None = None,
        context: PreparationContextAuthority | None = None,
    ) -> None:
        self.index = index
        self.bridge = bridge
        self.git = git
        self.compatibility = compatibility
        self.runtime_config = runtime_config
        self.role_config = role_config
        self.reservation_owner = reservation_owner
        self.now = now
        self.linear = linear
        self.context = context

    def probe(self, repository_path: Path) -> PrepareProbeResult:
        self._require_repository_path(repository_path)
        repository_id = self.git.repository_identity()
        probe = self.index.probe_or_reserve(repository_id, self.reservation_owner())
        if probe.outcome == "active":
            assert probe.active_run is not None
            return PrepareProbeResult.resume(repository_id, probe.active_run)
        assert probe.reservation is not None
        if probe.outcome == "blocked":
            return PrepareProbeResult.blocked(repository_id, probe.reservation)
        if probe.reservation.challenge is None:
            raise PrepareError("preparation reservation challenge is unavailable")
        return PrepareProbeResult.input_required(repository_id, probe.reservation)

    def activate_reservation(self, input_path: Path, input_hash: str, challenge: str) -> PrepareResult:
        if not isinstance(challenge, str) or not challenge:
            raise PrepareError("preparation reservation is unavailable")
        reference, preparation_input = self.bridge.load_verified_preparation_input(input_path, input_hash)
        replay = self.index.activation_result(reference, challenge)
        if replay is not None:
            return self._result_from_activation(replay)
        reservation = self.index.activation_reservation(reference, challenge)
        self._require_matching_reservation(reference, preparation_input, reservation, challenge)
        try:
            assignee_id = preparation_input.assignee_resolution.require_resolved("assignee")
            milestone_id = preparation_input.milestone_resolution.require_resolved("milestone")
        except IdentityResolutionError:
            raise PrepareError("trusted preparation input does not resolve selection identities") from None
        candidate = select_ticket(preparation_input.pages, assignee_id, milestone_id)
        if candidate is None:
            return self._activate_no_candidate(reservation, reference)
        raw_ticket = self._selected_raw_ticket(preparation_input.pages, candidate.id)
        original_state_id = self._required_ticket_field(raw_ticket, "state_id")
        original_external_revision = self._required_ticket_field(raw_ticket, "external_revision")
        snapshot = TicketSnapshot.from_untrusted(
            raw_ticket,
            captured_at=self.now(),
            pagination_complete=True,
            source_page_hashes=reference.source_page_hashes,
        )
        claim = self.index.claim_selected_activation(
            SelectedActivationClaimRequest(
                reservation_id=reservation.reservation_id,
                repository_id=reservation.repository_id,
                expected_index_revision=reservation.index_revision,
                expected_index_hash=reservation.index_hash,
                preparation_input_ref=reference,
                ticket_snapshot=snapshot,
                original_state_id=original_state_id,
                original_external_revision=original_external_revision,
            )
        )
        if claim.outcome == "wait":
            return PrepareResult(kind="WAIT", generation=None, action_request=None, run_id=claim.run_id)
        if claim.outcome == "preflight_failed":
            activation = self.index.complete_selected_activation_human_review(reference, challenge)
            if activation is None:
                return PrepareResult(kind="WAIT", generation=None, action_request=None, run_id=claim.run_id)
            return self._result_from_activation(activation)
        if claim.outcome == "preflight_required":
            try:
                compatibility = self.compatibility.verify(self.runtime_config, self.role_config)
            except CompatibilityPreflightError:
                activation = self.index.complete_selected_activation_human_review(reference, challenge)
                if activation is None:
                    return PrepareResult(kind="WAIT", generation=None, action_request=None, run_id=claim.run_id)
                return self._result_from_activation(activation)
            self.index.record_claim_compatibility(
                reference,
                challenge,
                self._compatibility_claim_binding(compatibility),
            )
        activation = self.index.complete_selected_activation(reference, challenge)
        if activation is None:
            return PrepareResult(kind="WAIT", generation=None, action_request=None, run_id=claim.run_id)
        return self._result_from_activation(activation)

    def advance(self, run_id: str, expected_revision: int, expected_hash: str) -> PrepareResult:
        generation = self._load_expected(run_id, expected_revision, expected_hash)
        try:
            load_descriptor_bound_policy(self.runtime_config)
        except Exception:
            return PrepareResult.current(
                self.linear.store.compare_and_swap(
                    generation.revision,
                    generation.state_hash,
                    generation.state.model_copy(update={"disposition": RunDisposition.HUMAN_REVIEW}),
                )
            )
        state = generation.state
        if state.preparation_phase is PreparationPhase.SELECTED:
            context = self._load_context(run_id)
            request = self.linear.request_action(
                generation,
                operation="compare_and_start_ticket",
                entity="ticket",
                target=state.ticket_id,
                expected_external_revision=context.original_external_revision,
                arguments=self._start_arguments(context),
            )
            requested = self.linear.persist_pending(
                generation,
                request,
                state_update=self._start_request_phase_update,
            )
            return PrepareResult.waiting(requested, request)
        if state.preparation_phase is PreparationPhase.IN_PROGRESS_REQUESTED:
            request = self.linear.replay_pending(generation)
            if request is None:
                raise PrepareError("persisted start request is unavailable")
            return PrepareResult.waiting(generation, request)
        if state.preparation_phase is PreparationPhase.IN_PROGRESS_CONFIRMED:
            return PrepareResult.current(self._reconcile_branch(generation))
        if state.preparation_phase is PreparationPhase.COMPENSATION_REQUIRED:
            if state.compensated or state.disposition is not RunDisposition.ACTIVE:
                return PrepareResult.current(generation)
            return self._request_restore(generation)
        return PrepareResult.current(generation)

    def consume_receipt(
        self,
        run_id: str,
        expected_revision: int,
        expected_hash: str,
        receipt_ref: EvidenceRef,
    ) -> PrepareResult:
        generation = self._load_expected(run_id, expected_revision, expected_hash)
        if not isinstance(receipt_ref, EvidenceRef):
            raise PrepareError("trusted receipt reference is invalid")
        authority = self.linear.store.receipt_authority
        if authority is None:
            raise PrepareError("trusted receipt reference is invalid")
        try:
            receipt = authority.load_verified_receipt(receipt_ref)
        except Exception:
            raise PrepareError("trusted receipt reference is invalid") from None
        return PrepareResult.current(
            self.linear.consume_receipt(
                generation,
                receipt,
                state_update=self._receipt_phase_update,
            )
        )

    def _load_expected(self, run_id: str, expected_revision: int, expected_hash: str) -> StateGeneration:
        if self.linear is None or self.context is None:
            raise PrepareError("preparation reconciliation is unavailable")
        if not isinstance(run_id, str) or run_id != self.linear.store.run_id:
            raise PrepareError("preparation run binding is invalid")
        if (
            not isinstance(expected_revision, int)
            or isinstance(expected_revision, bool)
            or expected_revision < 1
            or not isinstance(expected_hash, str)
        ):
            raise PrepareError("preparation generation binding is invalid")
        try:
            generation = self.linear.store.load()
        except Exception:
            raise PrepareError("preparation generation is unavailable") from None
        if generation.revision != expected_revision or generation.state_hash != expected_hash.lower():
            raise PrepareError("preparation generation binding is invalid")
        return generation

    def _load_context(self, run_id: str) -> PreparationContext:
        assert self.context is not None
        try:
            return self.context.load_verified(run_id)
        except Exception:
            raise PrepareError("preparation context is unavailable") from None

    def _start_arguments(self, context: PreparationContext) -> dict[str, str]:
        try:
            reference, preparation_input = self.bridge.verify_and_load_preparation_input(context.preparation_input_ref)
            started_state_id = preparation_input.workflow_states["started"]
            if reference != context.preparation_input_ref or not isinstance(started_state_id, str):
                raise ValueError("trusted workflow state is unavailable")
            return {"ticket_id": context.ticket_snapshot.ticket_id, "state_id": started_state_id}
        except Exception:
            raise PrepareError("trusted workflow state is unavailable") from None

    def _request_restore(self, generation: StateGeneration) -> PrepareResult:
        context = self._load_context(generation.state.run_id)
        request = self.linear.request_action(
            generation,
            operation="restore_ticket_state",
            entity="ticket",
            target=generation.state.ticket_id,
            expected_external_revision=context.original_external_revision,
            arguments={"ticket_id": generation.state.ticket_id, "state_id": context.original_state_id},
        )
        return PrepareResult.waiting(self.linear.persist_pending(generation, request), request)

    def _reconcile_branch(self, generation: StateGeneration) -> StateGeneration:
        context = self._load_context(generation.state.run_id)
        state = generation.state
        intention = self._branch_intention(state)
        if intention is None:
            return self._record_branch_intention(generation, context.ticket_snapshot.title)
        _, phases = state.validate_effect_ledger()
        phase = phases[intention.effect_id]
        binding = state.branch_binding
        if binding is None:
            if phase == "awaiting_observation":
                return self._enter_human_review(generation)
            invoked = self._append_branch_invocation(generation, intention.effect_id)
            try:
                binding = self.git.prepare_ticket_branch(
                    state.ticket_id,
                    context.ticket_snapshot.title,
                    checkpoint_lineage="preparation",
                )
            except BranchReuseError:
                return self._enter_human_review(invoked)
            except Exception:
                return self._record_branch_result(invoked, intention.effect_id, EffectOutcome.FAILURE, branch=None)
            if not isinstance(binding, BranchBinding):
                return self._enter_human_review(invoked)
            return self._record_prepared_binding(invoked, intention.effect_id, binding)
        if phase == "awaiting_observation":
            try:
                branch = self.git.reconcile_branch(self._git_branch_binding(binding), checkpoint_lineage="preparation")
            except BranchReuseError:
                return self._enter_human_review(generation)
            except Exception:
                return self._record_branch_result(generation, intention.effect_id, EffectOutcome.FAILURE, branch=None)
            if not isinstance(branch, str) or branch != binding.branch:
                return self._enter_human_review(generation)
            return self._record_branch_result(generation, intention.effect_id, EffectOutcome.SUCCESS, branch=branch)
        invoked = self._append_branch_invocation(generation, intention.effect_id)
        try:
            branch = self.git.create_bound_ticket_branch(self._git_branch_binding(binding))
        except BranchReuseError:
            return self._enter_human_review(invoked)
        except Exception:
            return self._record_branch_result(invoked, intention.effect_id, EffectOutcome.FAILURE, branch=None)
        if not isinstance(branch, str) or branch != binding.branch:
            return self._enter_human_review(invoked)
        return self._record_branch_result(invoked, intention.effect_id, EffectOutcome.SUCCESS, branch=branch)

    def _record_branch_intention(self, generation: StateGeneration, title: str) -> StateGeneration:
        state = generation.state
        sequence = state.effect_ledger[-1].sequence + 1 if state.effect_ledger else 1
        request_hash = hash_json({"operation": "create_ticket_branch", "ticket_id": state.ticket_id, "title": title})
        effect_id = f"git-create-ticket-branch-{hash_json((state.run_id, state.ticket_id, request_hash))[:24]}"
        intention = EffectIntention(
            effect_id=effect_id,
            sequence=sequence,
            timestamp=self.now(),
            payload=EffectIntentionPayload(operation="create_ticket_branch", target=state.ticket_id, request_hash=request_hash),
        )
        return self.linear.store.compare_and_swap(
            generation.revision,
            generation.state_hash,
            state.model_copy(update={"effect_ledger": (*state.effect_ledger, intention)}),
        )

    def _append_branch_invocation(self, generation: StateGeneration, effect_id: str) -> StateGeneration:
        state = generation.state
        invocation = EffectInvocation(
            effect_id=effect_id,
            sequence=state.effect_ledger[-1].sequence + 1,
            timestamp=self.now(),
            payload=EffectInvocationPayload(),
        )
        return self.linear.store.compare_and_swap(
            generation.revision,
            generation.state_hash,
            state.model_copy(update={"effect_ledger": (*state.effect_ledger, invocation)}),
        )

    def _record_prepared_binding(self, generation: StateGeneration, effect_id: str, binding: BranchBinding) -> StateGeneration:
        state = generation.state
        observation = EffectObservation(
            effect_id=effect_id,
            sequence=state.effect_ledger[-1].sequence + 1,
            timestamp=self.now(),
            payload=EffectObservationPayload(outcome=EffectOutcome.SUCCESS),
        )
        return self.linear.store.compare_and_swap(
            generation.revision,
            generation.state_hash,
            state.model_copy(
                update={
                    "effect_ledger": (*state.effect_ledger, observation),
                    "branch_binding": PersistedBranchBinding(
                        ticket_id=binding.ticket_id,
                        branch=binding.branch,
                        base_sha=binding.base_sha,
                        repository_identity=binding.repository_identity,
                        remote_fingerprint=binding.remote_fingerprint,
                        default_branch=binding.default_branch,
                        checkpoint_lineage=binding.checkpoint_lineage,
                    ),
                }
            ),
        )

    def _record_branch_result(
        self,
        generation: StateGeneration,
        effect_id: str,
        outcome: EffectOutcome,
        *,
        branch: str | None,
    ) -> StateGeneration:
        state = generation.state
        sequence = state.effect_ledger[-1].sequence + 1
        events = (
            EffectObservation(
                effect_id=effect_id,
                sequence=sequence,
                timestamp=self.now(),
                payload=EffectObservationPayload(outcome=outcome),
            ),
            EffectReconciliation(
                effect_id=effect_id,
                sequence=sequence + 1,
                timestamp=self.now(),
                payload=EffectReconciliationPayload(outcome=outcome),
            ),
        )
        updates: dict[str, object] = {
            "effect_ledger": (*state.effect_ledger, *events),
            "preparation_phase": (
                PreparationPhase.BRANCH_CREATED if outcome is EffectOutcome.SUCCESS else PreparationPhase.COMPENSATION_REQUIRED
            ),
        }
        if branch is not None:
            updates["branch"] = branch
        return self.linear.store.compare_and_swap(
            generation.revision,
            generation.state_hash,
            state.model_copy(update=updates),
        )

    @staticmethod
    def _branch_intention(state: RunState) -> EffectIntention | None:
        return next(
            (
                event
                for event in reversed(state.effect_ledger)
                if isinstance(event, EffectIntention)
                and event.payload.operation == "create_ticket_branch"
                and event.payload.target == state.ticket_id
            ),
            None,
        )

    @staticmethod
    def _git_branch_binding(binding: PersistedBranchBinding) -> BranchBinding:
        return BranchBinding(
            ticket_id=binding.ticket_id,
            branch=binding.branch,
            base_sha=binding.base_sha,
            repository_identity=binding.repository_identity,
            remote_fingerprint=binding.remote_fingerprint,
            default_branch=binding.default_branch,
            checkpoint_lineage=binding.checkpoint_lineage,
        )

    def _enter_human_review(self, generation: StateGeneration) -> StateGeneration:
        return self.linear.store.compare_and_swap(
            generation.revision,
            generation.state_hash,
            generation.state.model_copy(update={"disposition": RunDisposition.HUMAN_REVIEW}),
        )

    @staticmethod
    def _start_request_phase_update(state: RunState, request: McpActionRequest) -> RunState:
        if request.operation != "compare_and_start_ticket":
            raise ValueError("start request phase update received an unexpected operation")
        return state.model_copy(update={"preparation_phase": PreparationPhase.IN_PROGRESS_REQUESTED})

    @staticmethod
    def _receipt_phase_update(state: RunState, receipt: TrustedMcpReceipt) -> RunState:
        if (
            state.preparation_phase is PreparationPhase.IN_PROGRESS_REQUESTED
            and receipt.operation == "compare_and_start_ticket"
            and receipt.outcome is EffectOutcome.SUCCESS
            and receipt.target == state.ticket_id
        ):
            return state.model_copy(update={"preparation_phase": PreparationPhase.IN_PROGRESS_CONFIRMED})
        if (
            state.preparation_phase is PreparationPhase.COMPENSATION_REQUIRED
            and receipt.operation == "restore_ticket_state"
            and receipt.outcome is EffectOutcome.SUCCESS
            and receipt.target == state.ticket_id
        ):
            return state.model_copy(update={"compensated": True, "disposition": RunDisposition.HUMAN_REVIEW})
        return state.model_copy(update={"disposition": RunDisposition.HUMAN_REVIEW})

    def _require_repository_path(self, repository_path: Path) -> None:
        if not isinstance(repository_path, Path) or repository_path != self.git.repository:
            raise PrepareError("repository path does not match the bound repository")

    def _require_matching_reservation(
        self,
        reference: TrustedPreparationInputRef,
        preparation_input: PreparationInput,
        reservation: PreparationReservation,
        challenge: str,
    ) -> PreparationReservation:
        if (
            not reference.pagination_complete
            or reference.repository_id != reservation.repository_id
            or reference.reservation_id != reservation.reservation_id
            or preparation_input.repository_id != reference.repository_id
            or reference.max_crew_iterations != preparation_input.max_crew_iterations
            or preparation_input.max_crew_iterations <= 0
            or dict(reference.source_page_hashes) != dict(preparation_input.page_hashes)
            or not hmac.compare_digest(reference.challenge_hash, reservation.challenge_hash)
            or not hmac.compare_digest(reference.challenge_hash, hash_json(challenge))
        ):
            raise PrepareError("trusted preparation input does not match its reservation")
        return reservation

    @staticmethod
    def _selected_raw_ticket(pages: tuple[Mapping[str, object], ...], ticket_id: str) -> Mapping[str, object]:
        selected = [
            page
            for page in pages
            if isinstance(page.get("id"), str) and page["id"].strip().upper() == ticket_id
        ]
        if len(selected) != 1:
            raise PrepareError("selected ticket source is unavailable")
        return selected[0]

    def _activate_no_candidate(
        self,
        reservation: PreparationReservation,
        reference: TrustedPreparationInputRef,
    ) -> PrepareResult:
        activation = self.index.activate_reservation(
            ActivationRequest(
                reservation_id=reservation.reservation_id,
                repository_id=reservation.repository_id,
                expected_index_revision=reservation.index_revision,
                expected_index_hash=reservation.index_hash,
                preparation_input_ref=reference,
            )
        )
        if activation.outcome != "no_candidate" or activation.run_id is not None:
            raise PrepareError("no-candidate activation did not complete")
        return PrepareResult(kind="NO_CANDIDATE", generation=None, action_request=None, run_id=None)

    @staticmethod
    def _compatibility_claim_binding(compatibility: object) -> CompatibilityClaimBinding:
        receipt = getattr(compatibility, "receipt", None)
        receipt_ref = getattr(compatibility, "receipt_ref", None)
        runner_identity = getattr(receipt, "runner_identity", None)
        if (
            not isinstance(receipt_ref, EvidenceRef)
            or not isinstance(runner_identity, RunnerIdentity)
            or not isinstance(getattr(receipt, "content_hash", None), str)
            or not isinstance(getattr(receipt, "project_policy_hash", None), str)
        ):
            raise PrepareError("compatibility preflight result is invalid")
        try:
            return CompatibilityClaimBinding(
                compatibility_receipt_hash=receipt.content_hash,
                compatibility_receipt_ref=receipt_ref,
                project_policy_hash=receipt.project_policy_hash,
                runner_identity=runner_identity,
            )
        except ValidationError:
            raise PrepareError("compatibility preflight result is invalid") from None

    @staticmethod
    def _result_from_activation(activation: ActivationResult) -> PrepareResult:
        if activation.outcome == "no_candidate":
            return PrepareResult(kind="NO_CANDIDATE", generation=None, action_request=None, run_id=None)
        if activation.run_id is None:
            raise PrepareError("selected activation did not complete")
        generation = RunStateStore.load_read_only(activation.state_root, activation.run_id)
        if generation.state_hash != activation.initial_generation_hash:
            raise PrepareError("selected activation state does not match its index binding")
        return PrepareResult(kind="ACTIVATED", generation=generation, action_request=None, run_id=activation.run_id)

    @staticmethod
    def _required_ticket_field(raw_ticket: Mapping[str, object], field: str) -> str:
        value = raw_ticket.get(field)
        if (
            not isinstance(value, str)
            or not value
            or (field == "external_revision" and (len(value) > 256 or _looks_sensitive(value) or value == "[REDACTED]"))
        ):
            raise PrepareError(f"selected ticket {field} is unavailable")
        try:
            return reject_unsafe_persisted_value(value)
        except ValueError:
            raise PrepareError(f"selected ticket {field} is unavailable") from None


@dataclass(frozen=True)
class PreparationContext:
    run_id: str
    repository_id: str
    ticket_snapshot: TicketSnapshot
    ticket_snapshot_hash: str
    original_state_id: str
    original_external_revision: str
    preparation_input_ref: TrustedPreparationInputRef
    preparation_input_hash: str
    compatibility_receipt_hash: str
    compatibility_receipt_ref: EvidenceRef
    runner_identity: RunnerIdentity

    def __post_init__(self) -> None:
        _require_identifier(self.run_id, "run ID")
        _require_identifier(self.repository_id, "repository ID")
        _require_identifier(self.original_state_id, "original state ID")
        if not isinstance(self.original_external_revision, str):
            raise ValueError("original external revision must be text")
        reject_unsafe_persisted_value(self.original_external_revision)
        if not isinstance(self.ticket_snapshot, TicketSnapshot):
            raise ValueError("preparation context snapshot is invalid")
        if not isinstance(self.preparation_input_ref, TrustedPreparationInputRef):
            raise ValueError("preparation context input is invalid")
        if not isinstance(self.compatibility_receipt_ref, EvidenceRef):
            raise ValueError("preparation context receipt is invalid")
        if not isinstance(self.runner_identity, RunnerIdentity):
            raise ValueError("preparation context runner is invalid")
        if self.ticket_snapshot.content_hash != self.ticket_snapshot_hash:
            raise ValueError("preparation context snapshot is invalid")
        if self.preparation_input_ref.input_hash != self.preparation_input_hash:
            raise ValueError("preparation context input is invalid")
        if self.preparation_input_ref.repository_id != self.repository_id:
            raise ValueError("preparation context repository is invalid")
        if self.compatibility_receipt_ref.sha256 != self.compatibility_receipt_hash:
            raise ValueError("preparation context receipt is invalid")
        if (
            self.compatibility_receipt_ref.creator != "trusted-launcher"
            or self.compatibility_receipt_ref.media_type != "application/json"
        ):
            raise ValueError("preparation context receipt is invalid")

    def to_canonical_payload(self) -> dict[str, object]:
        ticket_snapshot = TicketSnapshot.model_validate(self.ticket_snapshot.model_dump(mode="json", round_trip=True))
        preparation_input_ref = TrustedPreparationInputRef.model_validate(
            self.preparation_input_ref.model_dump(mode="json", round_trip=True)
        )
        compatibility_receipt_ref = EvidenceRef.model_validate(
            self.compatibility_receipt_ref.model_dump(mode="json", round_trip=True)
        )
        runner_identity = RunnerIdentity.model_validate(self.runner_identity.model_dump(mode="json", round_trip=True))
        if (
            ticket_snapshot.content_hash != self.ticket_snapshot_hash
            or preparation_input_ref.input_hash != self.preparation_input_hash
            or preparation_input_ref.repository_id != self.repository_id
            or compatibility_receipt_ref.sha256 != self.compatibility_receipt_hash
        ):
            raise ValueError("preparation context bindings are invalid")
        payload = {
            "run_id": self.run_id,
            "repository_id": self.repository_id,
            "ticket_snapshot": ticket_snapshot.model_dump(mode="json", round_trip=True),
            "ticket_snapshot_hash": self.ticket_snapshot_hash,
            "original_state_id": self.original_state_id,
            "original_external_revision": self.original_external_revision,
            "preparation_input_ref": preparation_input_ref.model_dump(mode="json", round_trip=True),
            "preparation_input_hash": self.preparation_input_hash,
            "compatibility_receipt_hash": self.compatibility_receipt_hash,
            "compatibility_receipt_ref": compatibility_receipt_ref.model_dump(mode="json", round_trip=True),
            "runner_identity": runner_identity.model_dump(mode="json", round_trip=True),
        }
        _validate_persisted_value(payload)
        return payload

    @classmethod
    def from_canonical_payload(cls, payload: object) -> PreparationContext:
        if not isinstance(payload, dict) or set(payload) != {
            "run_id",
            "repository_id",
            "ticket_snapshot",
            "ticket_snapshot_hash",
            "original_state_id",
            "original_external_revision",
            "preparation_input_ref",
            "preparation_input_hash",
            "compatibility_receipt_hash",
            "compatibility_receipt_ref",
            "runner_identity",
        }:
            raise ValueError("preparation context has an invalid shape")
        context = cls(
            run_id=payload["run_id"],
            repository_id=payload["repository_id"],
            ticket_snapshot=TicketSnapshot.model_validate(payload["ticket_snapshot"]),
            ticket_snapshot_hash=payload["ticket_snapshot_hash"],
            original_state_id=payload["original_state_id"],
            original_external_revision=payload["original_external_revision"],
            preparation_input_ref=TrustedPreparationInputRef.model_validate(payload["preparation_input_ref"]),
            preparation_input_hash=payload["preparation_input_hash"],
            compatibility_receipt_hash=payload["compatibility_receipt_hash"],
            compatibility_receipt_ref=EvidenceRef.model_validate(payload["compatibility_receipt_ref"]),
            runner_identity=RunnerIdentity.model_validate(payload["runner_identity"]),
        )
        if context.to_canonical_payload() != payload:
            raise ValueError("preparation context is not canonical")
        return context


class PreparationContextAuthority:
    def __init__(self, root: Path) -> None:
        self.root = _normalize_state_root(root)

    def write_new(self, context: PreparationContext) -> Path:
        if not isinstance(context, PreparationContext):
            raise PreparationContextError("preparation context cannot be written")
        try:
            path = self._path(context.run_id, create=True)
            payload = context.to_canonical_payload()
            if not _write_new_json(path, payload) and _read_canonical_json(path, "preparation context") != payload:
                raise PreparationContextError("preparation context cannot be written")
            return path
        except (AuthoritativeStateCorrupt, ValueError, ValidationError):
            raise PreparationContextError("preparation context cannot be written") from None

    def load_verified(self, run_id: str) -> PreparationContext:
        try:
            path = self._path(run_id, create=False)
            context = PreparationContext.from_canonical_payload(_read_canonical_json(path, "preparation context"))
            if context.run_id != run_id:
                raise ValueError("preparation context path does not match run")
            return context
        except (AuthoritativeStateCorrupt, ValueError, ValidationError):
            raise PreparationContextError("preparation context is invalid") from None

    def _path(self, run_id: str, *, create: bool) -> Path:
        safe_run_id = _require_identifier(run_id, "run ID")
        runs_dir = _ensure_directory(self.root, self.root / "runs", create=create)
        run_dir = _ensure_directory(self.root, runs_dir / safe_run_id, create=create)
        return run_dir / "preparation-context.json"
