from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
import os
from pathlib import Path
import secrets
import socket
from typing import Literal, Protocol
import uuid

from .contracts import (
    ActivationRequest,
    AuthorizationVerifier,
    CompatibilityClaimBinding,
    HumanAuthorization,
    HumanAuthorizationAction,
    PreparationContextPayload,
    PreparationInput,
    PreparationPhase,
    RunDisposition,
    RunState,
    SelectedActivationClaimRequest,
    TicketSnapshot,
    TrustedPreparationInputRef,
)
from .hashing import hash_json
from .state import (
    EMPTY_STATE_HASH,
    AuthoritativeStateCorrupt,
    RunStateStore,
    StateGeneration,
    _atomic_replace_json,
    _ensure_directory,
    _interprocess_lock,
    _is_sha256,
    _normalize_state_root,
    _path_lstat,
    _read_canonical_json,
    _require_identifier,
    _require_sha256,
    _run_binding_path,
    _unlink_regular_file,
    _write_new_json,
)


class ActiveRunIndexError(RuntimeError):
    pass


class ActiveRunExists(ActiveRunIndexError):
    pass


class PreparationReservationExists(ActiveRunIndexError):
    pass


class ActivationReplayMismatch(ActiveRunIndexError):
    pass


class ActivationReservationMismatch(ActiveRunIndexError):
    pass


class ActivationStateMismatch(ActiveRunIndexError):
    pass


class RunIdAlreadyUsed(ActiveRunIndexError):
    pass


class AuthoritativeIndexCorrupt(ActiveRunIndexError):
    pass


class IndexCompareAndSwapConflict(ActiveRunIndexError):
    pass


class NonTerminalRunRelease(ActiveRunIndexError):
    pass


class TerminalGenerationMismatch(ActiveRunIndexError):
    pass


class PreparationInputVerifier(Protocol):
    def verify_and_load_preparation_input(
        self,
        reference: TrustedPreparationInputRef,
    ) -> tuple[TrustedPreparationInputRef, PreparationInput]: ...


@dataclass(frozen=True)
class ReservationOwner:
    host: str
    pid: int

    def __post_init__(self) -> None:
        _require_identifier(self.host, "reservation owner host")
        if not isinstance(self.pid, int) or isinstance(self.pid, bool) or self.pid < 1:
            raise ValueError("reservation owner PID must be positive")


@dataclass(frozen=True)
class PreparationReservation:
    repository_id: str
    reservation_id: str
    challenge_hash: str
    index_revision: int
    index_hash: str
    issued_at: datetime
    expires_at: datetime
    owner_host: str
    owner_pid: int
    challenge: str | None = field(default=None, repr=False, compare=False)


@dataclass(frozen=True)
class ActivationResult:
    outcome: Literal["active", "no_candidate"]
    repository_id: str
    run_id: str | None
    index_revision: int | None
    index_hash: str | None
    state_root: Path = field(repr=False)
    initial_generation_hash: str = EMPTY_STATE_HASH


ActiveRunRecord = ActivationResult


@dataclass(frozen=True)
class SelectedActivationClaim:
    outcome: Literal["preflight_required", "wait", "preflight_complete", "preflight_failed"]
    repository_id: str
    run_id: str


@dataclass(frozen=True)
class IndexProbeResult:
    outcome: Literal["active", "blocked", "reserved"]
    active_run: ActiveRunRecord | None = None
    reservation: PreparationReservation | None = None

    def __post_init__(self) -> None:
        if self.outcome == "active" and self.active_run is not None and self.reservation is None:
            return
        if self.outcome in {"blocked", "reserved"} and self.reservation is not None and self.active_run is None:
            return
        raise ValueError("index probe result does not match its outcome")


@dataclass(frozen=True)
class _IndexEntry:
    revision: int
    index_hash: str
    record: dict[str, object]


class ActiveRunIndex:
    """One locked Active Run record per repository identity.

    Composite transactions acquire locks in this order: repository index, run ID,
    then run state. No code acquires an index lock while holding a run-state lock.
    """

    def __init__(
        self,
        root: Path,
        *,
        authorization_verifier: AuthorizationVerifier | None = None,
        preparation_input_verifier: PreparationInputVerifier | None = None,
    ) -> None:
        self.root = _normalize_state_root(root)
        self.authorization_verifier = authorization_verifier
        self.preparation_input_verifier = preparation_input_verifier
        self.index_dir = _ensure_directory(self.root, self.root / "active-run-index")
        self.journal_dir = _ensure_directory(self.root, self.root / "preparation-journal")
        _ensure_directory(self.root, self.root / "active-run-bindings")
        self.locks_dir = _ensure_directory(self.root, self.root / "locks")

    def lookup(self, repository_id: str) -> ActivationResult | None:
        repository_id = _require_identifier(repository_id, "repository ID")
        with self._repository_lock(repository_id):
            entry = self._load_entry_locked(repository_id)
            if entry is None or entry.record["kind"] in {"reservation", "no_candidate"}:
                return None
            return self._active_result(entry)

    def reserve(self, repository_id: str) -> PreparationReservation:
        result = self.probe_or_reserve(
            repository_id,
            ReservationOwner(host=self._local_host(), pid=os.getpid()),
        )
        if result.outcome == "active":
            raise ActiveRunExists(f"repository {repository_id} already has an Active Run")
        if result.outcome == "blocked":
            raise PreparationReservationExists(f"repository {repository_id} already has a preparation reservation")
        assert result.reservation is not None
        return result.reservation

    def probe_or_reserve(self, repository_id: str, owner: ReservationOwner) -> IndexProbeResult:
        """Atomically return an Active Run, live reservation, or a new reservation."""

        repository_id = _require_identifier(repository_id, "repository ID")
        if not isinstance(owner, ReservationOwner):
            raise ValueError("reservation owner is invalid")
        with self._repository_lock(repository_id):
            entry = self._load_entry_locked(repository_id)
            if entry is None:
                return IndexProbeResult(outcome="reserved", reservation=self._create_reservation_locked(repository_id, owner))
            if entry.record["kind"] == "active":
                return IndexProbeResult(outcome="active", active_run=self._active_result(entry))
            if entry.record["kind"] == "reservation":
                reservation = self._reservation_from_entry(entry)
                if self._can_clear_stale_reservation_locked(entry, reservation):
                    self._remove_entry_locked(repository_id)
                    return IndexProbeResult(
                        outcome="reserved",
                        reservation=self._create_reservation_locked(repository_id, owner),
                    )
                return IndexProbeResult(outcome="blocked", reservation=reservation)
            self._complete_no_candidate_journal_locked(entry)
            self._remove_entry_locked(repository_id)
            return IndexProbeResult(outcome="reserved", reservation=self._create_reservation_locked(repository_id, owner))

    def activate_reservation(self, request: ActivationRequest) -> ActivationResult:
        repository_id = _require_identifier(request.repository_id, "repository ID")
        reservation_id = _require_identifier(request.reservation_id, "reservation ID")
        _require_sha256(request.challenge_hash, "challenge hash")
        _require_sha256(request.preparation_input_hash, "preparation input hash")
        if (
            not isinstance(request.expected_index_revision, int)
            or isinstance(request.expected_index_revision, bool)
            or request.expected_index_revision < 1
        ):
            raise ValueError("expected index revision must be positive")
        _require_sha256(request.expected_index_hash, "expected index hash")
        if request.run_id is not None:
            _require_identifier(request.run_id, "run ID")
        self._verify_preparation_input(request.preparation_input_ref)
        intent = self._activation_intent(request)
        with self._repository_lock(repository_id):
            if request.run_id is None:
                return self._activate_locked(request, intent)
            with self._run_id_lock(request.run_id):
                return self._activate_locked(request, intent)

    def activation_result(
        self,
        reference: TrustedPreparationInputRef,
        challenge: str,
    ) -> ActivationResult | None:
        """Return only a completed matching activation for durable coordinator replay."""

        if not isinstance(reference, TrustedPreparationInputRef) or not isinstance(challenge, str):
            raise ActivationReservationMismatch("activation replay is invalid")
        with self._repository_lock(reference.repository_id):
            journal = self._load_journal_locked(reference.reservation_id)
            if journal is None:
                return None
            if (
                journal["repository_id"] != reference.repository_id
                or journal["challenge_hash"] != hash_json(challenge)
                or journal["preparation_input_hash"] != reference.input_hash
                or journal["preparation_input_ref"] != reference.model_dump(mode="json", round_trip=True)
            ):
                raise ActivationReplayMismatch("activation replay does not match the durable request")
            if journal.get("selection_claim") is not None and journal["phase"] in {
                "claimed",
                "preflight_complete",
                "preflight_failed",
            }:
                return None
            if journal["phase"] != "completed":
                request = self._request_from_journal(journal)
                run_id = request.run_id
                if run_id is None:
                    return self._complete_prepared_activation_locked(request, journal)
                with self._run_id_lock(run_id):
                    return self._complete_prepared_activation_locked(request, journal)
            result = self._journal_result(journal)
            if result.outcome == "active":
                self._verify_persisted_context_locked(journal)
            return result

    def activation_reservation(
        self,
        reference: TrustedPreparationInputRef,
        challenge: str,
    ) -> PreparationReservation:
        """Load the durable reservation and its current CAS binding for activation."""

        if not isinstance(reference, TrustedPreparationInputRef) or not isinstance(challenge, str):
            raise ActivationReservationMismatch("activation reservation is invalid")
        with self._repository_lock(reference.repository_id):
            entry = self._load_entry_locked(reference.repository_id)
            if entry is None or entry.record["kind"] != "reservation":
                raise ActivationReservationMismatch("activation does not own an active preparation reservation")
            if (
                entry.record["reservation_id"] != reference.reservation_id
                or entry.record["challenge_hash"] != hash_json(challenge)
            ):
                raise ActivationReservationMismatch("activation does not match the preparation reservation")
            return self._reservation_from_entry(entry, challenge=challenge)

    def claim_selected_activation(self, request: SelectedActivationClaimRequest) -> SelectedActivationClaim:
        """Durably claim a verified selection before compatibility preflight starts."""

        if not isinstance(request, SelectedActivationClaimRequest):
            raise ActivationReservationMismatch("selected activation claim is invalid")
        preparation_input = self._verify_preparation_input(request.preparation_input_ref)
        self._validate_selected_claim(request, preparation_input)
        with self._repository_lock(request.repository_id):
            journal = self._load_journal_locked(request.reservation_id)
            if journal is not None:
                try:
                    persisted_claim = SelectedActivationClaimRequest.model_validate(journal["selection_claim"])
                    self._validate_selected_claim(persisted_claim, preparation_input)
                except Exception as error:
                    raise AuthoritativeIndexCorrupt("selected activation claim is corrupt") from error
                if not self._journal_claim_matches(journal, request, persisted_claim):
                    raise ActivationReplayMismatch("selected activation claim does not match the durable request")
                run_id = self._selected_run_id(persisted_claim)
                with self._run_id_lock(run_id):
                    if journal["phase"] == "claimed":
                        if self._claimed_preflight_has_expired_locked(journal):
                            journal = {**journal, "phase": "preflight_failed"}
                            self._save_journal_locked(request.reservation_id, journal)
                            return SelectedActivationClaim("preflight_failed", request.repository_id, run_id)
                        return SelectedActivationClaim("wait", request.repository_id, run_id)
                    if journal["phase"] == "preflight_failed":
                        return SelectedActivationClaim("preflight_failed", request.repository_id, run_id)
                    if journal["phase"] == "preflight_complete":
                        return SelectedActivationClaim("preflight_complete", request.repository_id, run_id)
                    if journal["phase"] in {"prepared", "completed"}:
                        return SelectedActivationClaim("preflight_complete", request.repository_id, run_id)
                    raise AuthoritativeIndexCorrupt("selected activation claim has an invalid phase")
            run_id = self._selected_run_id(request)
            with self._run_id_lock(run_id):
                entry = self._load_entry_locked(request.repository_id)
                if entry is None or entry.record["kind"] != "reservation":
                    raise ActivationReservationMismatch("selected activation claim does not own a preparation reservation")
                if (
                    entry.record["reservation_id"] != request.reservation_id
                    or entry.record["challenge_hash"] != request.preparation_input_ref.challenge_hash
                    or entry.revision != request.expected_index_revision
                    or entry.index_hash != request.expected_index_hash
                ):
                    raise ActivationReservationMismatch("selected activation claim does not match the preparation reservation")
                self._assert_run_id_unused(run_id, request.repository_id)
                journal = {
                    "reservation_id": request.reservation_id,
                    "repository_id": request.repository_id,
                    "expected_index_revision": request.expected_index_revision,
                    "expected_index_hash": request.expected_index_hash,
                    "challenge_hash": request.preparation_input_ref.challenge_hash,
                    "preparation_input_hash": request.preparation_input_ref.input_hash,
                    "preparation_input_ref": request.preparation_input_ref.model_dump(mode="json", round_trip=True),
                    "run_id": run_id,
                    "initial_generation_hash": EMPTY_STATE_HASH,
                    "initial_state": None,
                    "preparation_context_payload": None,
                    "preparation_context_hash": None,
                    "selection_claim": request.model_dump(mode="json", round_trip=True),
                    "compatibility_binding": None,
                    "outcome": "active",
                    "phase": "claimed",
                    "index_revision": None,
                    "index_hash": None,
                }
                self._save_journal_locked(request.reservation_id, journal)
                return SelectedActivationClaim("preflight_required", request.repository_id, run_id)

    def record_claim_compatibility(
        self,
        reference: TrustedPreparationInputRef,
        challenge: str,
        binding: CompatibilityClaimBinding,
    ) -> SelectedActivationClaim:
        """Attach the verified receipt to an existing claim before any run files exist."""

        if not isinstance(reference, TrustedPreparationInputRef) or not isinstance(challenge, str):
            raise ActivationReservationMismatch("selected activation claim is invalid")
        if not isinstance(binding, CompatibilityClaimBinding):
            raise ActivationStateMismatch("selected activation compatibility binding is invalid")
        with self._repository_lock(reference.repository_id):
            journal = self._load_journal_locked(reference.reservation_id)
            if journal is None or journal.get("selection_claim") is None:
                raise ActivationReservationMismatch("selected activation claim is unavailable")
            self._require_claim_reference(journal, reference, challenge)
            run_id = journal["run_id"]
            assert isinstance(run_id, str)
            if journal["phase"] == "claimed":
                updated = {**journal, "compatibility_binding": binding.model_dump(mode="json", round_trip=True), "phase": "preflight_complete"}
                self._save_journal_locked(reference.reservation_id, updated)
                return SelectedActivationClaim("preflight_complete", reference.repository_id, run_id)
            if journal["phase"] in {"preflight_complete", "prepared", "completed"}:
                if journal.get("compatibility_binding") != binding.model_dump(mode="json", round_trip=True):
                    raise ActivationReplayMismatch("selected activation compatibility does not match the durable claim")
                return SelectedActivationClaim("preflight_complete", reference.repository_id, run_id)
            raise AuthoritativeIndexCorrupt("selected activation claim has an invalid phase")

    def complete_selected_activation(
        self,
        reference: TrustedPreparationInputRef,
        challenge: str,
    ) -> ActivationResult | None:
        """Publish context and initial state only from a preflight-complete durable claim."""

        if not isinstance(reference, TrustedPreparationInputRef) or not isinstance(challenge, str):
            raise ActivationReservationMismatch("selected activation claim is invalid")
        with self._repository_lock(reference.repository_id):
            journal = self._load_journal_locked(reference.reservation_id)
            if journal is None or journal.get("selection_claim") is None:
                raise ActivationReservationMismatch("selected activation claim is unavailable")
            self._require_claim_reference(journal, reference, challenge)
            if journal["phase"] == "claimed":
                return None
            if journal["phase"] == "completed":
                self._verify_persisted_context_locked(journal)
                return self._journal_result(journal)
            if journal["phase"] != "preflight_complete":
                raise AuthoritativeIndexCorrupt("selected activation claim has an invalid phase")
            request = self._request_from_selected_claim(journal)
            with self._run_id_lock(request.run_id or "invalid"):
                prepared = {
                    **journal,
                    "initial_generation_hash": request.initial_state_hash,
                    "initial_state": request.initial_state.model_dump(mode="json", round_trip=True) if request.initial_state else None,
                    "preparation_context_payload": request.preparation_context_payload.model_dump(mode="json", round_trip=True) if request.preparation_context_payload else None,
                    "preparation_context_hash": request.preparation_context_hash,
                    "phase": "prepared",
                }
                self._save_journal_locked(reference.reservation_id, prepared)
                return self._complete_prepared_activation_locked(request, prepared)

    def complete_selected_activation_human_review(
        self,
        reference: TrustedPreparationInputRef,
        challenge: str,
    ) -> ActivationResult | None:
        """Persist the selected run in Human Review when compatibility preflight cannot complete."""

        if not isinstance(reference, TrustedPreparationInputRef) or not isinstance(challenge, str):
            raise ActivationReservationMismatch("selected activation claim is invalid")
        with self._repository_lock(reference.repository_id):
            journal = self._load_journal_locked(reference.reservation_id)
            if journal is None or journal.get("selection_claim") is None:
                raise ActivationReservationMismatch("selected activation claim is unavailable")
            self._require_claim_reference(journal, reference, challenge)
            if journal["phase"] == "completed":
                self._verify_persisted_context_locked(journal)
                return self._journal_result(journal)
            if journal["phase"] == "claimed":
                journal = {**journal, "phase": "preflight_failed"}
                self._save_journal_locked(reference.reservation_id, journal)
            if journal["phase"] != "preflight_failed":
                raise AuthoritativeIndexCorrupt("selected activation claim has an invalid phase")
            request = self._human_review_request_from_selected_claim(journal)
            prepared = {
                **journal,
                "initial_generation_hash": request.initial_state_hash,
                "initial_state": request.initial_state.model_dump(mode="json", round_trip=True) if request.initial_state else None,
                "preparation_context_payload": None,
                "preparation_context_hash": None,
                "phase": "prepared",
            }
            self._save_journal_locked(reference.reservation_id, prepared)
            return self._complete_prepared_activation_locked(request, prepared)

    def release(
        self,
        repository_id: str,
        run_id: str,
        expected_index_revision: int,
        expected_index_hash: str,
        terminal_generation_hash: str,
    ) -> None:
        repository_id = _require_identifier(repository_id, "repository ID")
        run_id = _require_identifier(run_id, "run ID")
        if not isinstance(expected_index_revision, int) or isinstance(expected_index_revision, bool) or expected_index_revision < 1:
            raise ValueError("expected index revision must be positive")
        expected_index_hash = _require_sha256(expected_index_hash, "expected index hash")
        terminal_generation_hash = _require_sha256(terminal_generation_hash, "terminal generation hash")
        with self._repository_lock(repository_id):
            entry = self._load_entry_locked(repository_id)
            if entry is None or entry.record["kind"] != "active":
                raise IndexCompareAndSwapConflict("repository has no matching Active Run")
            if (
                entry.record["run_id"] != run_id
                or entry.revision != expected_index_revision
                or entry.index_hash != expected_index_hash
            ):
                raise IndexCompareAndSwapConflict("Active Run index no longer matches the expected binding")
            store = RunStateStore(self.root, run_id, authorization_verifier=self.authorization_verifier)
            # Keep the index lock while acquiring state so no writer can unbind a terminal run.
            with store.interprocess_lock():
                generation = store.load_locked()
                if generation.state_hash != terminal_generation_hash:
                    raise TerminalGenerationMismatch("terminal generation is not the current bound generation")
                state = generation.state
                if state.repository_id != repository_id:
                    raise AuthoritativeIndexCorrupt("terminal state repository does not match the Active Run index")
                if state.disposition is RunDisposition.DONE:
                    pass
                elif state.disposition is RunDisposition.ABANDONED and self._has_consumed_abandon_authorization(state):
                    pass
                else:
                    raise NonTerminalRunRelease("only terminal authorized generations may release an Active Run")
                self._remove_entry_locked(repository_id)

    @contextmanager
    def _repository_lock(self, repository_id: str) -> Iterator[None]:
        with _interprocess_lock(self.locks_dir / f"index-{hash_json(repository_id)}.lock"):
            yield

    @contextmanager
    def _run_id_lock(self, run_id: str) -> Iterator[None]:
        with _interprocess_lock(self.locks_dir / f"run-id-{hash_json(run_id)}.lock"):
            yield

    def _activate_locked(self, request: ActivationRequest, intent: dict[str, object]) -> ActivationResult:
        reservation_id = request.reservation_id
        journal = self._load_journal_locked(reservation_id)
        if journal is not None:
            if self._journal_intent(journal) != intent:
                raise ActivationReplayMismatch("activation replay does not match the durable request")
            if journal["phase"] == "completed":
                if journal["outcome"] == "active":
                    self._verify_persisted_context_locked(journal)
                return self._journal_result(journal)
            return self._complete_prepared_activation_locked(request, journal)
        entry = self._load_entry_locked(request.repository_id)
        if entry is None or entry.record["kind"] != "reservation":
            raise ActivationReservationMismatch("activation does not own an active preparation reservation")
        if (
            entry.record["reservation_id"] != request.reservation_id
            or entry.record["challenge_hash"] != intent["challenge_hash"]
        ):
            raise ActivationReservationMismatch("activation does not match the preparation reservation")
        if entry.revision != request.expected_index_revision or entry.index_hash != request.expected_index_hash:
            raise ActivationReservationMismatch("activation reservation CAS no longer matches")
        if request.run_id is not None:
            self._assert_run_id_unused(request.run_id, request.repository_id)
            self._validate_preparation_initial_state(request)
        journal = {
            **intent,
            "selection_claim": None,
            "compatibility_binding": None,
            "phase": "prepared",
            "index_revision": None,
            "index_hash": None,
        }
        self._save_journal_locked(reservation_id, journal)
        return self._complete_prepared_activation_locked(request, journal)

    def _complete_prepared_activation_locked(
        self,
        request: ActivationRequest,
        journal: dict[str, object],
    ) -> ActivationResult:
        repository_id = journal["repository_id"]
        reservation_id = journal["reservation_id"]
        assert isinstance(repository_id, str)
        assert isinstance(reservation_id, str)
        entry = self._load_entry_locked(repository_id)
        if entry is not None and entry.record["kind"] == "reservation":
            if (
                entry.revision != journal["expected_index_revision"]
                or entry.index_hash != journal["expected_index_hash"]
            ):
                raise ActivationReservationMismatch("activation reservation CAS no longer matches")
        if journal["outcome"] == "no_candidate":
            if entry is None:
                raise AuthoritativeIndexCorrupt("no-candidate journal lost its preparation reservation")
            if entry.record["kind"] == "reservation":
                if entry.record["reservation_id"] != reservation_id:
                    raise AuthoritativeIndexCorrupt("no-candidate journal conflicts with another reservation")
                entry = self._new_entry(
                    entry.revision + 1,
                    {
                        "kind": "no_candidate",
                        "repository_id": repository_id,
                        "reservation_id": reservation_id,
                        "challenge_hash": journal["challenge_hash"],
                        "preparation_input_hash": journal["preparation_input_hash"],
                        "initial_generation_hash": EMPTY_STATE_HASH,
                    },
                )
                self._save_entry_locked(repository_id, entry)
            elif entry.record["kind"] != "no_candidate" or entry.record["reservation_id"] != reservation_id:
                raise AuthoritativeIndexCorrupt("no-candidate journal conflicts with the Active Run index")
            return self._complete_journal_locked(reservation_id, journal, entry)
        run_id = journal["run_id"]
        assert isinstance(run_id, str)
        self._persist_preparation_context(request, journal)
        generation = self._persist_initial_state(request, journal)
        self._write_run_binding(run_id, repository_id, generation.state_hash)
        if entry is None:
            raise AuthoritativeIndexCorrupt("activation journal lost its preparation reservation")
        if entry.record["kind"] == "reservation":
            if entry.record["reservation_id"] != reservation_id:
                raise AuthoritativeIndexCorrupt("activation journal conflicts with another reservation")
            entry = self._new_entry(
                entry.revision + 1,
                {
                    "kind": "active",
                    "repository_id": repository_id,
                    "reservation_id": reservation_id,
                    "challenge_hash": journal["challenge_hash"],
                    "preparation_input_hash": journal["preparation_input_hash"],
                    "run_id": run_id,
                    "initial_generation_hash": generation.state_hash,
                },
            )
            self._save_entry_locked(repository_id, entry)
        elif (
            entry.record["kind"] != "active"
            or entry.record["run_id"] != run_id
            or entry.record["reservation_id"] != reservation_id
            or entry.record["initial_generation_hash"] != generation.state_hash
        ):
            raise AuthoritativeIndexCorrupt("activation journal conflicts with another Active Run")
        return self._complete_journal_locked(reservation_id, journal, entry)

    def _persist_initial_state(self, request: ActivationRequest, journal: dict[str, object]) -> StateGeneration:
        assert request.run_id is not None
        self._validate_preparation_initial_state(request)
        assert request.initial_state is not None
        expected_hash = journal["initial_generation_hash"]
        assert isinstance(expected_hash, str)
        store = RunStateStore(self.root, request.run_id, authorization_verifier=self.authorization_verifier)
        with store.interprocess_lock():
            current = store.load_optional_locked(allow_orphaned_recovery=True)
            if current is None:
                generation = store.compare_and_swap_locked(0, EMPTY_STATE_HASH, request.initial_state)
            else:
                self._validate_preparation_initial_state(
                    request.model_copy(update={"initial_state": current.state})
                )
                generation = current
            if (
                generation.state_hash != expected_hash
                or generation.state != request.initial_state
                or generation.state.run_id != request.run_id
                or generation.state.repository_id != request.repository_id
            ):
                raise ActivationStateMismatch("persisted initial state does not match activation")
            return generation

    def _persist_preparation_context(self, request: ActivationRequest, journal: dict[str, object]) -> None:
        assert request.run_id is not None
        context = request.preparation_context_payload
        context_hash = request.preparation_context_hash
        if context is None or context_hash is None:
            return
        payload = context.model_dump(mode="json", round_trip=True)
        if hash_json(payload) != context_hash:
            raise ActivationStateMismatch("preparation context does not match activation")
        expected = journal.get("preparation_context_payload")
        if expected != payload or journal.get("preparation_context_hash") != context_hash:
            raise ActivationStateMismatch("preparation context does not match activation")
        runs_dir = _ensure_directory(self.root, self.root / "runs")
        run_dir = _ensure_directory(self.root, runs_dir / request.run_id)
        path = run_dir / "preparation-context.json"
        if _write_new_json(path, payload):
            return
        if _read_canonical_json(path, "preparation context") != payload:
            raise ActivationStateMismatch("preparation context conflicts with activation")

    def _verify_persisted_context_locked(self, journal: dict[str, object]) -> None:
        payload = journal.get("preparation_context_payload")
        context_hash = journal.get("preparation_context_hash")
        run_id = journal.get("run_id")
        if payload is None and context_hash is None:
            return
        if not isinstance(payload, dict) or not isinstance(context_hash, str) or not isinstance(run_id, str):
            raise AuthoritativeIndexCorrupt("activation journal lacks its preparation context")
        try:
            context = PreparationContextPayload.model_validate(payload)
            if hash_json(payload) != context_hash or context.run_id != run_id:
                raise ValueError("preparation context does not match journal")
            stored = _read_canonical_json(self.root / "runs" / run_id / "preparation-context.json", "preparation context")
            if stored != payload:
                raise ValueError("preparation context does not match journal")
        except Exception as error:
            raise AuthoritativeIndexCorrupt("activation preparation context is corrupt") from error

    @staticmethod
    def _validate_preparation_initial_state(request: ActivationRequest) -> None:
        assert request.initial_state is not None
        state = request.initial_state
        if not state.has_preparation_binding:
            if state.disposition is not RunDisposition.HUMAN_REVIEW:
                RunStateStore._validate_initial_state(state, require_preparation_binding=True)
            if state.preparation_phase is not PreparationPhase.SELECTED or request.preparation_context_payload is not None:
                raise ActivationStateMismatch("Human Review activation state is invalid")
            expected = RunState(
                run_id=state.run_id,
                ticket_id=state.ticket_id,
                repository_id=state.repository_id,
                max_crew_iterations=state.max_crew_iterations,
                preparation_phase=PreparationPhase.SELECTED,
                disposition=RunDisposition.HUMAN_REVIEW,
            )
            if state != expected:
                raise ActivationStateMismatch("Human Review activation state is invalid")
            return
        RunStateStore._validate_initial_state(state, require_preparation_binding=True)
        if (
            state.preparation_input_ref != request.preparation_input_ref
            or state.preparation_input_hash != request.preparation_input_hash
        ):
            raise ActivationStateMismatch("initial state does not bind the trusted preparation input")
        context = request.preparation_context_payload
        if context is not None and (
            context.run_id != state.run_id
            or context.repository_id != state.repository_id
            or context.ticket_snapshot_hash != state.ticket_snapshot_hash
            or context.preparation_input_hash != state.preparation_input_hash
            or context.compatibility_receipt_hash != state.compatibility_receipt_hash
        ):
            raise ActivationStateMismatch("initial state does not bind the preparation context")

    @staticmethod
    def _selected_run_id(request: SelectedActivationClaimRequest) -> str:
        identity = {
            "repository_id": request.repository_id,
            "reservation_id": request.reservation_id,
            "preparation_input_hash": request.preparation_input_ref.input_hash,
            "ticket_snapshot_hash": request.ticket_snapshot.content_hash,
        }
        return f"run-{hash_json(identity)[:32]}"

    def _claimed_preflight_has_expired_locked(self, journal: dict[str, object]) -> bool:
        repository_id = journal["repository_id"]
        reservation_id = journal["reservation_id"]
        assert isinstance(repository_id, str)
        assert isinstance(reservation_id, str)
        entry = self._load_entry_locked(repository_id)
        if (
            entry is None
            or entry.record["kind"] != "reservation"
            or entry.record["reservation_id"] != reservation_id
            or entry.revision != journal["expected_index_revision"]
            or entry.index_hash != journal["expected_index_hash"]
        ):
            raise AuthoritativeIndexCorrupt("claimed preflight no longer owns its preparation reservation")
        return self._now() >= self._reservation_from_entry(entry).expires_at

    @staticmethod
    def _require_claim_reference(
        journal: dict[str, object],
        reference: TrustedPreparationInputRef,
        challenge: str,
    ) -> None:
        if (
            journal["repository_id"] != reference.repository_id
            or journal["challenge_hash"] != hash_json(challenge)
            or journal["preparation_input_hash"] != reference.input_hash
            or journal["preparation_input_ref"] != reference.model_dump(mode="json", round_trip=True)
        ):
            raise ActivationReplayMismatch("selected activation claim does not match the durable request")

    @staticmethod
    def _journal_claim_matches(
        journal: dict[str, object],
        request: SelectedActivationClaimRequest,
        persisted_claim: SelectedActivationClaimRequest,
    ) -> bool:
        requested = request.model_dump(mode="json", round_trip=True)
        persisted = persisted_claim.model_dump(mode="json", round_trip=True)
        requested.pop("ticket_snapshot")
        persisted.pop("ticket_snapshot")
        return requested == persisted and journal.get("run_id") == ActiveRunIndex._selected_run_id(persisted_claim)

    @staticmethod
    def _validate_selected_claim(request: SelectedActivationClaimRequest, preparation_input: PreparationInput) -> None:
        from .linear import select_ticket

        try:
            candidate = select_ticket(
                preparation_input.pages,
                preparation_input.assignee_resolution.require_resolved("assignee"),
                preparation_input.milestone_resolution.require_resolved("milestone"),
            )
            if candidate is None or candidate.id != request.ticket_snapshot.ticket_id:
                raise ValueError("selected ticket does not match trusted input")
            raw = next(
                page
                for page in preparation_input.pages
                if isinstance(page.get("id"), str) and page["id"].strip().upper() == candidate.id
            )
            snapshot = TicketSnapshot.from_untrusted(
                raw,
                captured_at=request.ticket_snapshot.captured_at,
                pagination_complete=True,
                source_page_hashes=request.preparation_input_ref.source_page_hashes,
            )
            if (
                snapshot != request.ticket_snapshot
                or raw.get("state_id") != request.original_state_id
                or raw.get("external_revision") != request.original_external_revision
            ):
                raise ValueError("selected ticket does not match trusted input")
        except Exception as error:
            raise ActivationStateMismatch("selected activation claim does not match trusted preparation input") from error

    def _request_from_selected_claim(self, journal: dict[str, object]) -> ActivationRequest:
        try:
            claim = SelectedActivationClaimRequest.model_validate(journal["selection_claim"])
            binding = CompatibilityClaimBinding.model_validate(journal["compatibility_binding"])
            run_id = journal["run_id"]
            if not isinstance(run_id, str) or run_id != self._selected_run_id(claim):
                raise ValueError("selected run ID is invalid")
            context = PreparationContextPayload(
                run_id=run_id,
                repository_id=claim.repository_id,
                ticket_snapshot=claim.ticket_snapshot,
                ticket_snapshot_hash=claim.ticket_snapshot.content_hash,
                original_state_id=claim.original_state_id,
                original_external_revision=claim.original_external_revision,
                preparation_input_ref=claim.preparation_input_ref,
                preparation_input_hash=claim.preparation_input_ref.input_hash,
                compatibility_receipt_hash=binding.compatibility_receipt_hash,
                compatibility_receipt_ref=binding.compatibility_receipt_ref,
                runner_identity=binding.runner_identity,
            )
            state = RunState(
                run_id=run_id,
                ticket_id=claim.ticket_snapshot.ticket_id,
                repository_id=claim.repository_id,
                max_crew_iterations=claim.preparation_input_ref.max_crew_iterations,
                preparation_phase="selected",
                project_policy_hash=binding.project_policy_hash,
                preparation_input_ref=claim.preparation_input_ref,
                preparation_input_hash=claim.preparation_input_ref.input_hash,
                ticket_snapshot_hash=claim.ticket_snapshot.content_hash,
                compatibility_receipt_hash=binding.compatibility_receipt_hash,
                compatibility_receipt_ref=binding.compatibility_receipt_ref,
                disposition=RunDisposition.ACTIVE,
                runner_identity=binding.runner_identity,
            )
            context_hash = hash_json(context.model_dump(mode="json", round_trip=True))
            return ActivationRequest(
                reservation_id=claim.reservation_id,
                repository_id=claim.repository_id,
                expected_index_revision=claim.expected_index_revision,
                expected_index_hash=claim.expected_index_hash,
                preparation_input_ref=claim.preparation_input_ref,
                run_id=run_id,
                initial_state=state,
                initial_state_hash=hash_json(state.model_dump(mode="json", round_trip=True)),
                preparation_context_payload=context,
                preparation_context_hash=context_hash,
            )
        except Exception as error:
            raise AuthoritativeIndexCorrupt("selected activation claim is corrupt") from error

    def _human_review_request_from_selected_claim(self, journal: dict[str, object]) -> ActivationRequest:
        try:
            claim = SelectedActivationClaimRequest.model_validate(journal["selection_claim"])
            run_id = journal["run_id"]
            if not isinstance(run_id, str) or run_id != self._selected_run_id(claim):
                raise ValueError("selected run ID is invalid")
            state = RunState(
                run_id=run_id,
                ticket_id=claim.ticket_snapshot.ticket_id,
                repository_id=claim.repository_id,
                max_crew_iterations=claim.preparation_input_ref.max_crew_iterations,
                preparation_phase=PreparationPhase.SELECTED,
                disposition=RunDisposition.HUMAN_REVIEW,
            )
            return ActivationRequest(
                reservation_id=claim.reservation_id,
                repository_id=claim.repository_id,
                expected_index_revision=claim.expected_index_revision,
                expected_index_hash=claim.expected_index_hash,
                preparation_input_ref=claim.preparation_input_ref,
                run_id=run_id,
                initial_state=state,
                initial_state_hash=hash_json(state.model_dump(mode="json", round_trip=True)),
            )
        except Exception as error:
            raise AuthoritativeIndexCorrupt("selected activation claim is corrupt") from error

    def _verify_preparation_input(self, reference: TrustedPreparationInputRef) -> PreparationInput:
        verifier = self.preparation_input_verifier
        if verifier is None:
            raise ActivationStateMismatch("activation requires a bridge preparation input verifier")
        try:
            loaded_reference, preparation_input = verifier.verify_and_load_preparation_input(reference)
        except Exception:
            raise ActivationStateMismatch("activation preparation input is not bridge verified") from None
        if loaded_reference != reference or not isinstance(preparation_input, PreparationInput):
            raise ActivationStateMismatch("activation preparation input is not bridge verified")
        return preparation_input

    def _assert_run_id_unused(self, run_id: str, repository_id: str) -> None:
        try:
            binding = _path_lstat(_run_binding_path(self.root, run_id), "active run binding")
            exists = RunStateStore.run_directory_exists(self.root, run_id)
        except AuthoritativeStateCorrupt as error:
            raise AuthoritativeIndexCorrupt("existing run identity cannot be inspected safely") from error
        if binding is not None:
            raise RunIdAlreadyUsed("run ID already has an immutable Active Run binding")
        if not exists:
            return
        store = RunStateStore(self.root, run_id, authorization_verifier=self.authorization_verifier)
        with store.interprocess_lock():
            current = store.load_optional_locked()
        if current is not None and (
            current.state.run_id != run_id or current.state.repository_id != repository_id
        ):
            raise ActivationStateMismatch("pre-existing state identity does not match activation")
        raise RunIdAlreadyUsed("run ID already has authoritative state")

    def _complete_journal_locked(
        self,
        reservation_id: str,
        journal: dict[str, object],
        entry: _IndexEntry,
    ) -> ActivationResult:
        completed = {
            **journal,
            "phase": "completed",
            "index_revision": entry.revision,
            "index_hash": entry.index_hash,
        }
        self._save_journal_locked(reservation_id, completed)
        return self._journal_result(completed)

    def _index_path(self, repository_id: str) -> Path:
        return self.index_dir / f"{hash_json(repository_id)}.json"

    def _journal_path(self, reservation_id: str) -> Path:
        return self.journal_dir / f"{reservation_id}.json"

    def _load_entry_locked(self, repository_id: str) -> _IndexEntry | None:
        path = self._index_path(repository_id)
        try:
            if _path_lstat(path, "Active Run index") is None:
                return None
            envelope = _read_canonical_json(path, "Active Run index")
            if not isinstance(envelope, dict) or set(envelope) != {"revision", "index_hash", "record"}:
                raise ValueError("invalid index shape")
            revision = envelope["revision"]
            index_hash = envelope["index_hash"]
            record = envelope["record"]
            if (
                not isinstance(revision, int)
                or isinstance(revision, bool)
                or revision < 1
                or not _is_sha256(index_hash)
                or index_hash != index_hash.lower()
                or not isinstance(record, dict)
                or hash_json(record) != index_hash
            ):
                raise ValueError("invalid index values")
            self._validate_record(record, repository_id)
        except (AuthoritativeStateCorrupt, ValueError, TypeError) as error:
            raise AuthoritativeIndexCorrupt("Active Run index is corrupt") from error
        return _IndexEntry(revision=revision, index_hash=index_hash, record=record)

    def _save_entry_locked(self, repository_id: str, entry: _IndexEntry) -> None:
        _atomic_replace_json(
            self._index_path(repository_id),
            {"revision": entry.revision, "index_hash": entry.index_hash, "record": entry.record},
        )

    def _remove_entry_locked(self, repository_id: str) -> None:
        try:
            _unlink_regular_file(self._index_path(repository_id), "Active Run index")
        except FileNotFoundError as error:
            raise IndexCompareAndSwapConflict("Active Run index disappeared during release") from error

    def _new_entry(self, revision: int, record: dict[str, object]) -> _IndexEntry:
        return _IndexEntry(revision=revision, index_hash=hash_json(record), record=record)

    def _create_reservation_locked(self, repository_id: str, owner: ReservationOwner) -> PreparationReservation:
        issued_at = self._now()
        if issued_at.tzinfo is None or issued_at.utcoffset() is None:
            raise AuthoritativeIndexCorrupt("reservation clock returned a naive timestamp")
        expires_at = issued_at + timedelta(minutes=5)
        reservation_id = uuid.uuid4().hex
        challenge = secrets.token_urlsafe(32)
        record = {
            "kind": "reservation",
            "repository_id": repository_id,
            "reservation_id": reservation_id,
            "challenge_hash": hash_json(challenge),
            "issued_at": issued_at.isoformat(),
            "expires_at": expires_at.isoformat(),
            "owner_host": owner.host,
            "owner_pid": owner.pid,
        }
        entry = self._new_entry(1, record)
        self._save_entry_locked(repository_id, entry)
        return self._reservation_from_entry(entry, challenge=challenge)

    def _reservation_from_entry(self, entry: _IndexEntry, *, challenge: str | None = None) -> PreparationReservation:
        record = entry.record
        return PreparationReservation(
            repository_id=record["repository_id"],  # type: ignore[arg-type]
            reservation_id=record["reservation_id"],  # type: ignore[arg-type]
            challenge_hash=record["challenge_hash"],  # type: ignore[arg-type]
            index_revision=entry.revision,
            index_hash=entry.index_hash,
            issued_at=self._reservation_timestamp(record["issued_at"], "reservation issued time"),
            expires_at=self._reservation_timestamp(record["expires_at"], "reservation expiry time"),
            owner_host=record["owner_host"],  # type: ignore[arg-type]
            owner_pid=record["owner_pid"],  # type: ignore[arg-type]
            challenge=challenge,
        )

    def _can_clear_stale_reservation_locked(
        self,
        entry: _IndexEntry,
        reservation: PreparationReservation,
    ) -> bool:
        if self._now() < reservation.expires_at:
            return False
        if self._load_journal_locked(reservation.reservation_id) is not None:
            return False
        # The repository lock and a reservation entry prove that no Active Run is published.
        return self._same_host_owner_is_dead(reservation.owner_host, reservation.owner_pid)

    @staticmethod
    def _reservation_timestamp(value: object, field: str) -> datetime:
        if not isinstance(value, str):
            raise ValueError(f"{field} is invalid")
        try:
            timestamp = datetime.fromisoformat(value)
        except ValueError as error:
            raise ValueError(f"{field} is invalid") from error
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError(f"{field} is invalid")
        return timestamp.astimezone(UTC)

    @staticmethod
    def _now() -> datetime:
        return datetime.now(UTC)

    @staticmethod
    def _local_host() -> str:
        return _require_identifier(socket.gethostname(), "reservation owner host")

    def _same_host_owner_is_dead(self, owner_host: str, owner_pid: int) -> bool:
        if owner_host != self._local_host() or owner_pid == os.getpid():
            return False
        try:
            os.kill(owner_pid, 0)
        except ProcessLookupError:
            return True
        except (PermissionError, OSError):
            return False
        return False

    def _validate_record(self, record: dict[str, object], repository_id: str) -> None:
        kind = record.get("kind")
        if kind == "reservation":
            expected = {
                "kind",
                "repository_id",
                "reservation_id",
                "challenge_hash",
                "issued_at",
                "expires_at",
                "owner_host",
                "owner_pid",
            }
            identifiers = ("repository_id", "reservation_id", "owner_host")
            hashes = ("challenge_hash",)
        elif kind == "no_candidate":
            expected = {
                "kind",
                "repository_id",
                "reservation_id",
                "challenge_hash",
                "preparation_input_hash",
                "initial_generation_hash",
            }
            identifiers = ("repository_id", "reservation_id")
            hashes = ("challenge_hash", "preparation_input_hash", "initial_generation_hash")
        elif kind == "active":
            expected = {
                "kind",
                "repository_id",
                "reservation_id",
                "challenge_hash",
                "preparation_input_hash",
                "run_id",
                "initial_generation_hash",
            }
            identifiers = ("repository_id", "reservation_id", "run_id")
            hashes = ("challenge_hash", "preparation_input_hash", "initial_generation_hash")
        else:
            raise ValueError("unknown index record kind")
        if set(record) != expected or record["repository_id"] != repository_id:
            raise ValueError("index record does not match its repository")
        for field in identifiers:
            _require_identifier(record[field], field)
        for field in hashes:
            _require_sha256(record[field], field)
        if kind == "reservation":
            issued_at = self._reservation_timestamp(record["issued_at"], "reservation issued time")
            expires_at = self._reservation_timestamp(record["expires_at"], "reservation expiry time")
            if expires_at <= issued_at:
                raise ValueError("reservation expiry must follow issue time")
            if (
                not isinstance(record["owner_pid"], int)
                or isinstance(record["owner_pid"], bool)
                or record["owner_pid"] < 1
            ):
                raise ValueError("reservation owner PID is invalid")

    def _activation_intent(self, request: ActivationRequest) -> dict[str, object]:
        return {
            "reservation_id": request.reservation_id,
            "repository_id": request.repository_id,
            "expected_index_revision": request.expected_index_revision,
            "expected_index_hash": _require_sha256(request.expected_index_hash, "expected index hash"),
            "challenge_hash": _require_sha256(request.challenge_hash, "challenge hash"),
            "preparation_input_hash": _require_sha256(
                request.preparation_input_hash,
                "preparation input hash",
            ),
            "preparation_input_ref": request.preparation_input_ref.model_dump(mode="json", round_trip=True),
            "run_id": request.run_id,
            "initial_generation_hash": (
                _require_sha256(request.initial_state_hash, "initial state hash")
                if request.initial_state_hash is not None
                else EMPTY_STATE_HASH
            ),
            "initial_state": (
                request.initial_state.model_dump(mode="json", round_trip=True)
                if request.initial_state is not None
                else None
            ),
            "preparation_context_payload": (
                request.preparation_context_payload.model_dump(mode="json", round_trip=True)
                if request.preparation_context_payload is not None
                else None
            ),
            "preparation_context_hash": request.preparation_context_hash,
            "outcome": "active" if request.run_id is not None else "no_candidate",
        }

    def _load_journal_locked(self, reservation_id: str) -> dict[str, object] | None:
        path = self._journal_path(reservation_id)
        try:
            if _path_lstat(path, "activation journal") is None:
                return None
            envelope = _read_canonical_json(path, "activation journal")
            if not isinstance(envelope, dict) or set(envelope) != {"journal_hash", "journal"}:
                raise ValueError("invalid journal shape")
            journal_hash = envelope["journal_hash"]
            journal = envelope["journal"]
            if not _is_sha256(journal_hash) or not isinstance(journal, dict) or hash_json(journal) != journal_hash:
                raise ValueError("invalid journal checksum")
            self._validate_journal(journal, reservation_id)
        except (AuthoritativeStateCorrupt, ValueError, TypeError) as error:
            raise AuthoritativeIndexCorrupt("activation journal is corrupt") from error
        return journal

    def _save_journal_locked(self, reservation_id: str, journal: dict[str, object]) -> None:
        _atomic_replace_json(
            self._journal_path(reservation_id),
            {"journal_hash": hash_json(journal), "journal": journal},
        )

    def _validate_journal(self, journal: dict[str, object], reservation_id: str) -> None:
        expected = {
            "reservation_id",
            "repository_id",
            "expected_index_revision",
            "expected_index_hash",
            "challenge_hash",
            "preparation_input_hash",
            "preparation_input_ref",
            "run_id",
            "initial_generation_hash",
            "initial_state",
            "preparation_context_payload",
            "preparation_context_hash",
            "selection_claim",
            "compatibility_binding",
            "outcome",
            "phase",
            "index_revision",
            "index_hash",
        }
        if set(journal) != expected or journal["reservation_id"] != reservation_id:
            raise ValueError("journal shape does not match reservation")
        _require_identifier(journal["reservation_id"], "reservation ID")
        _require_identifier(journal["repository_id"], "repository ID")
        if (
            not isinstance(journal["expected_index_revision"], int)
            or isinstance(journal["expected_index_revision"], bool)
            or journal["expected_index_revision"] < 1
        ):
            raise ValueError("journal expected index revision is invalid")
        _require_sha256(journal["expected_index_hash"], "expected index hash")
        _require_sha256(journal["challenge_hash"], "challenge hash")
        _require_sha256(journal["preparation_input_hash"], "preparation input hash")
        reference = TrustedPreparationInputRef.model_validate(journal["preparation_input_ref"])
        if (
            reference.repository_id != journal["repository_id"]
            or reference.reservation_id != journal["reservation_id"]
            or reference.challenge_hash != journal["challenge_hash"]
            or reference.input_hash != journal["preparation_input_hash"]
        ):
            raise ValueError("journal preparation input provenance does not match activation")
        _require_sha256(journal["initial_generation_hash"], "initial generation hash")
        if journal["outcome"] not in {"active", "no_candidate"} or journal["phase"] not in {
            "claimed",
            "preflight_failed",
            "preflight_complete",
            "prepared",
            "completed",
        }:
            raise ValueError("journal has an invalid outcome or phase")
        if journal["phase"] in {"claimed", "preflight_failed", "preflight_complete", "prepared"}:
            if journal["index_revision"] is not None or journal["index_hash"] is not None:
                raise ValueError("prepared journal cannot have an index binding")
        elif not isinstance(journal["index_revision"], int) or journal["index_revision"] < 1:
            raise ValueError("completed journal lacks an index revision")
        elif _require_sha256(journal["index_hash"], "index hash") != journal["index_hash"]:
            raise ValueError("completed journal has a noncanonical index hash")
        selection_claim = journal["selection_claim"]
        compatibility_binding = journal["compatibility_binding"]
        if selection_claim is not None:
            claim = SelectedActivationClaimRequest.model_validate(selection_claim)
            if (
                journal["outcome"] != "active"
                or claim.repository_id != journal["repository_id"]
                or claim.reservation_id != journal["reservation_id"]
                or claim.preparation_input_ref != reference
                or journal["run_id"] != self._selected_run_id(claim)
            ):
                raise ValueError("selected activation claim does not match journal")
            if journal["phase"] in {"claimed", "preflight_failed"}:
                if (
                    compatibility_binding is not None
                    or journal["initial_state"] is not None
                    or journal["preparation_context_payload"] is not None
                    or journal["preparation_context_hash"] is not None
                    or journal["initial_generation_hash"] != EMPTY_STATE_HASH
                ):
                    raise ValueError("claimed activation cannot contain completed work")
                return
            if journal["phase"] == "preflight_complete":
                CompatibilityClaimBinding.model_validate(compatibility_binding)
                if journal["initial_state"] is not None or journal["preparation_context_payload"] is not None:
                    raise ValueError("preflight-complete claim cannot publish run state")
                return
            if compatibility_binding is not None:
                CompatibilityClaimBinding.model_validate(compatibility_binding)
        elif compatibility_binding is not None:
            raise ValueError("unclaimed activation cannot contain compatibility binding")
        if journal["outcome"] == "active":
            _require_identifier(journal["run_id"], "run ID")
            initial_state = RunState.model_validate(journal["initial_state"])
            if (
                initial_state.run_id != journal["run_id"]
                or initial_state.repository_id != journal["repository_id"]
                or hash_json(initial_state.model_dump(mode="json", round_trip=True)) != journal["initial_generation_hash"]
            ):
                raise ValueError("journal initial state does not match activation")
            if (journal["preparation_context_payload"] is None) != (journal["preparation_context_hash"] is None):
                raise ValueError("journal preparation context does not match activation")
            if journal["preparation_context_payload"] is not None:
                context = PreparationContextPayload.model_validate(journal["preparation_context_payload"])
                if (
                    journal["preparation_context_hash"] != hash_json(context.model_dump(mode="json", round_trip=True))
                    or context.run_id != journal["run_id"]
                    or context.repository_id != journal["repository_id"]
                    or context.preparation_input_ref != reference
                ):
                    raise ValueError("journal preparation context does not match activation")
        elif (
            journal["run_id"] is not None
            or journal["initial_generation_hash"] != EMPTY_STATE_HASH
            or journal["initial_state"] is not None
            or journal["preparation_context_payload"] is not None
            or journal["preparation_context_hash"] is not None
        ):
            raise ValueError("no-candidate journal cannot bind a run")

    def _journal_intent(self, journal: dict[str, object]) -> dict[str, object]:
        return {
            "reservation_id": journal["reservation_id"],
            "repository_id": journal["repository_id"],
            "expected_index_revision": journal["expected_index_revision"],
            "expected_index_hash": journal["expected_index_hash"],
            "challenge_hash": journal["challenge_hash"],
            "preparation_input_hash": journal["preparation_input_hash"],
            "preparation_input_ref": journal["preparation_input_ref"],
            "run_id": journal["run_id"],
            "initial_generation_hash": journal["initial_generation_hash"],
            "initial_state": journal["initial_state"],
            "preparation_context_payload": journal["preparation_context_payload"],
            "preparation_context_hash": journal["preparation_context_hash"],
            "outcome": journal["outcome"],
        }

    @staticmethod
    def _request_from_journal(journal: dict[str, object]) -> ActivationRequest:
        values: dict[str, object] = {
            "reservation_id": journal["reservation_id"],
            "repository_id": journal["repository_id"],
            "expected_index_revision": journal["expected_index_revision"],
            "expected_index_hash": journal["expected_index_hash"],
            "preparation_input_ref": journal["preparation_input_ref"],
            "run_id": journal["run_id"],
            "initial_state": journal["initial_state"],
            "initial_state_hash": journal["initial_generation_hash"] if journal["run_id"] is not None else None,
            "preparation_context_payload": journal["preparation_context_payload"],
            "preparation_context_hash": journal["preparation_context_hash"],
        }
        return ActivationRequest.model_validate(values)

    def _complete_no_candidate_journal_locked(self, entry: _IndexEntry) -> None:
        record = entry.record
        reservation_id = record["reservation_id"]
        assert isinstance(reservation_id, str)
        journal = self._load_journal_locked(reservation_id)
        if journal is None or journal["outcome"] != "no_candidate":
            raise AuthoritativeIndexCorrupt("no-candidate index marker has no matching journal")
        if self._journal_intent(journal) != {
            "reservation_id": record["reservation_id"],
            "repository_id": record["repository_id"],
            "expected_index_revision": journal["expected_index_revision"],
            "expected_index_hash": journal["expected_index_hash"],
            "challenge_hash": record["challenge_hash"],
            "preparation_input_hash": record["preparation_input_hash"],
            "preparation_input_ref": journal["preparation_input_ref"],
            "run_id": None,
            "initial_generation_hash": EMPTY_STATE_HASH,
            "initial_state": None,
            "preparation_context_payload": None,
            "preparation_context_hash": None,
            "outcome": "no_candidate",
        }:
            raise AuthoritativeIndexCorrupt("no-candidate index marker conflicts with its journal")
        if journal["phase"] == "prepared":
            self._complete_journal_locked(reservation_id, journal, entry)

    def _write_run_binding(self, run_id: str, repository_id: str, initial_generation_hash: str) -> None:
        path = _run_binding_path(self.root, run_id)
        binding = {
            "run_id": run_id,
            "repository_id": repository_id,
            "initial_generation_hash": initial_generation_hash,
        }
        if _write_new_json(path, binding):
            return
        try:
            existing = _read_canonical_json(path, "active run binding")
        except AuthoritativeStateCorrupt as error:
            raise AuthoritativeIndexCorrupt("active run binding is corrupt") from error
        if existing != binding:
            raise AuthoritativeIndexCorrupt("run ID is already bound to another repository or generation")

    def _active_result(self, entry: _IndexEntry) -> ActivationResult:
        record = entry.record
        return ActivationResult(
            outcome="active",
            repository_id=record["repository_id"],  # type: ignore[arg-type]
            run_id=record["run_id"],  # type: ignore[arg-type]
            index_revision=entry.revision,
            index_hash=entry.index_hash,
            state_root=self.root,
            initial_generation_hash=record["initial_generation_hash"],  # type: ignore[arg-type]
        )

    def _journal_result(self, journal: dict[str, object]) -> ActivationResult:
        return ActivationResult(
            outcome=journal["outcome"],  # type: ignore[arg-type]
            repository_id=journal["repository_id"],  # type: ignore[arg-type]
            run_id=journal["run_id"],  # type: ignore[arg-type]
            index_revision=journal["index_revision"],  # type: ignore[arg-type]
            index_hash=journal["index_hash"],  # type: ignore[arg-type]
            state_root=self.root,
            initial_generation_hash=journal["initial_generation_hash"],  # type: ignore[arg-type]
        )

    def _has_consumed_abandon_authorization(self, state: RunState) -> bool:
        return any(
            authorization.action is HumanAuthorizationAction.ABANDON
            and authorization.consumed_at is not None
            and authorization.issued_at <= authorization.consumed_at <= authorization.expires_at
            and self._verifies(authorization, HumanAuthorizationAction.ABANDON)
            for authorization in state.human_authorizations
        )

    def _verifies(self, authorization: HumanAuthorization, action: HumanAuthorizationAction) -> bool:
        if self.authorization_verifier is None:
            return False
        try:
            return bool(self.authorization_verifier.verify(authorization, action))
        except Exception:
            return False
