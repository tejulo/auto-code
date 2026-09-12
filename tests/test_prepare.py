from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
import json
from pathlib import Path
from threading import Event, Thread

import pytest

from auto_code.contracts import (
    BrowserPreflightStatus,
    CatalogObservation,
    CompatibilityClaimBinding,
    CompatibilityComponentObservation,
    CompatibilityReceipt,
    EvidenceRef,
    EffectOutcome,
    HumanAuthorization,
    HumanAuthorizationAction,
    IdentityResolution,
    PreparationInput,
    PreparationPhase,
    RunDisposition,
    RunnerIdentity,
    TicketSnapshot,
    TrustedMcpReceipt,
    TrustedPreparationInputRef,
    SelectedActivationClaimRequest,
)
from auto_code.hashing import canonical_json_bytes, hash_json
from auto_code.compatibility import CompatibilityPreflightError, CompatibilityPreflightResult, CompatibilityReceiptAuthority
from auto_code.linear import LinearGateway
from auto_code.mcp_bridge import McpToolResult, TrustedLinearBridge, _sign
from auto_code.git import BranchBinding, BranchReuseError
from auto_code.model_catalog import ModelCatalog, ModelRef
from auto_code.model_compatibility import ModelCompatibilityProfile, ModelCompatibilityRegistry
from auto_code.model_config import RoleName
from auto_code.prepare import (
    PrepareError,
    PreparationContext,
    PreparationContextAuthority,
    PreparationContextError,
    PrepareCoordinator,
)
from auto_code.run_index import (
    ActivationReservationMismatch,
    ActiveRunIndex,
    ReservationOwner,
)
from auto_code.state import InvalidStateTransition, RunStateStore


NOW = datetime(2026, 9, 11, tzinfo=UTC)


@pytest.fixture
def verified_context() -> PreparationContext:
    ticket_snapshot = TicketSnapshot.from_untrusted(
        {"id": "ENG-1", "title": "Persist a preparation context"},
        captured_at=NOW,
        pagination_complete=True,
        source_page_hashes={"page-1": "1" * 64},
    )
    preparation_input_ref = TrustedPreparationInputRef(
        input_id="11111111-1111-4111-8111-111111111111",
        relative_path="trusted-mcp/preparation/11111111-1111-4111-8111-111111111111.json",
        repository_id="repo-1",
        reservation_id="reservation-1",
        challenge_hash="2" * 64,
        input_hash="3" * 64,
        query_hash="4" * 64,
        payload_hash="5" * 64,
        result_hash="6" * 64,
        source_page_hashes={"page-1": "7" * 64},
        pagination_complete=True,
        max_crew_iterations=3,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        tool_call_id="tool-call-1",
        captured_at=NOW,
        observations=("Trusted preparation input captured.",),
        bridge_signature="8" * 64,
    )
    compatibility_receipt_ref = EvidenceRef(
        relative_path="trusted-launcher/compatibility/11111111-1111-4111-8111-111111111111.json",
        sha256="9" * 64,
        media_type="application/json",
        creator="trusted-launcher",
    )
    return PreparationContext(
        run_id="run-1",
        repository_id="repo-1",
        ticket_snapshot=ticket_snapshot,
        ticket_snapshot_hash=ticket_snapshot.content_hash,
        original_state_id="state-1",
        original_external_revision="revision-1",
        preparation_input_ref=preparation_input_ref,
        preparation_input_hash=preparation_input_ref.input_hash,
        compatibility_receipt_hash=compatibility_receipt_ref.sha256,
        compatibility_receipt_ref=compatibility_receipt_ref,
        runner_identity=RunnerIdentity(
            content_hash="a" * 64,
            source_sha="b" * 64,
            dependency_lock_hash="c" * 64,
            contract_bundle_hash="d" * 64,
            built_at=NOW,
        ),
    )


def tamper_context_file(root: Path, run_id: str, tamper: str) -> None:
    path = root / "runs" / run_id / "preparation-context.json"
    if tamper == "noncanonical":
        path.write_bytes(path.read_bytes() + b"\n")
        return
    payload = json.loads(path.read_text(encoding="ascii"))
    if tamper == "snapshot_hash":
        payload["ticket_snapshot_hash"] = "0" * 64
    elif tamper == "input_ref":
        payload["preparation_input_ref"]["repository_id"] = "repo-2"
    elif tamper == "receipt_ref":
        payload["compatibility_receipt_ref"]["sha256"] = "0" * 64
    elif tamper == "runner":
        payload["runner_identity"]["source_sha"] = "not-a-hash"
    else:
        payload["run_id"] = "run-2"
    path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")), encoding="ascii")


def test_context_write_once_loads_a_complete_preparation_binding(tmp_path: Path, verified_context: PreparationContext) -> None:
    authority = PreparationContextAuthority(tmp_path)

    path = authority.write_new(verified_context)

    assert path == tmp_path / "runs" / verified_context.run_id / "preparation-context.json"
    assert authority.load_verified(verified_context.run_id) == verified_context
    assert authority.write_new(verified_context) == path


def test_context_refuses_a_conflicting_write_without_replacing_the_original(
    tmp_path: Path,
    verified_context: PreparationContext,
) -> None:
    authority = PreparationContextAuthority(tmp_path)
    path = authority.write_new(verified_context)
    original_bytes = path.read_bytes()

    with pytest.raises(PreparationContextError):
        authority.write_new(replace(verified_context, original_external_revision="revision-2"))

    assert path.read_bytes() == original_bytes


@pytest.mark.parametrize("nested", ("ticket_snapshot", "preparation_input_ref", "compatibility_receipt_ref", "runner_identity"))
def test_context_revalidates_each_nested_contract_before_writing(
    tmp_path: Path,
    verified_context: PreparationContext,
    nested: str,
) -> None:
    if nested == "ticket_snapshot":
        forged = TicketSnapshot.model_construct(
            **{
                **verified_context.ticket_snapshot.model_dump(round_trip=True),
                "content_hash": "not-a-hash",
            },
        )
    elif nested == "preparation_input_ref":
        forged = TrustedPreparationInputRef.model_construct(
            **{
                **verified_context.preparation_input_ref.model_dump(round_trip=True),
                "input_hash": "not-a-hash",
            },
        )
    elif nested == "compatibility_receipt_ref":
        forged = EvidenceRef.model_construct(
            **{
                **verified_context.compatibility_receipt_ref.model_dump(round_trip=True),
                "sha256": "not-a-hash",
            },
        )
    else:
        forged = RunnerIdentity.model_construct(
            **{
                **verified_context.runner_identity.model_dump(round_trip=True),
                "source_sha": "not-a-hash",
            },
        )
    authority = PreparationContextAuthority(tmp_path)
    object.__setattr__(verified_context, nested, forged)

    with pytest.raises(PreparationContextError):
        authority.write_new(verified_context)


def test_context_normalizes_malformed_external_revision_to_the_context_error(
    tmp_path: Path,
    verified_context: PreparationContext,
) -> None:
    authority = PreparationContextAuthority(tmp_path)
    path = authority.write_new(verified_context)
    payload = json.loads(path.read_text(encoding="ascii"))
    payload["original_external_revision"] = 1
    path.write_bytes(canonical_json_bytes(payload))

    with pytest.raises(PreparationContextError):
        authority.load_verified(verified_context.run_id)


@pytest.mark.parametrize("tamper", ("snapshot_hash", "input_ref", "receipt_ref", "runner", "path", "noncanonical"))
def test_context_rejects_tampered_or_noncanonical_persisted_bindings(
    tmp_path: Path,
    verified_context: PreparationContext,
    tamper: str,
) -> None:
    authority = PreparationContextAuthority(tmp_path)
    authority.write_new(verified_context)
    tamper_context_file(tmp_path, verified_context.run_id, tamper)

    with pytest.raises(PreparationContextError):
        authority.load_verified(verified_context.run_id)


@pytest.mark.parametrize("replacement", ("directory", "symlink"))
def test_context_rejects_nonregular_persisted_storage(
    tmp_path: Path,
    verified_context: PreparationContext,
    replacement: str,
) -> None:
    authority = PreparationContextAuthority(tmp_path)
    path = authority.write_new(verified_context)
    if replacement == "directory":
        path.unlink()
        path.mkdir()
    else:
        preserved = path.with_name("preserved-context.json")
        path.rename(preserved)
        path.symlink_to(preserved)

    with pytest.raises(PreparationContextError):
        authority.load_verified(verified_context.run_id)


@dataclass(frozen=True)
class FakeCompatibilityReceipt:
    content_hash: str
    project_policy_hash: str
    runner_identity: RunnerIdentity


@dataclass(frozen=True)
class FakeCompatibilityResult:
    receipt: FakeCompatibilityReceipt
    receipt_ref: EvidenceRef


class FakeGitGuard:
    def __init__(self, repository: Path) -> None:
        self.repository = repository
        self.identity_calls = 0
        self.calls: list[str] = []
        self.branch_calls: list[tuple[str, str]] = []
        self.prepare_calls: list[tuple[str, str, str]] = []
        self.bound_create_calls: list[BranchBinding] = []
        self.reconcile_calls: list[BranchBinding] = []
        self.fail_branch = False
        self.interrupt_after_bound_create = False
        self.binding = BranchBinding(
            ticket_id="ENG-1",
            branch="ENG-1-safe-title",
            base_sha="a" * 40,
            repository_identity="b" * 64,
            remote_fingerprint="c" * 64,
            default_branch="main",
            checkpoint_lineage="preparation",
        )

    def repository_identity(self) -> str:
        self.identity_calls += 1
        return "repo-1"

    def create_ticket_branch(self, ticket_id: str, title: str) -> str:
        self.branch_calls.append((ticket_id, title))
        if self.fail_branch:
            raise RuntimeError("guarded branch creation failed")
        return "ENG-1-safe-title"

    def prepare_ticket_branch(self, ticket_id: str, title: str, *, checkpoint_lineage: str) -> BranchBinding:
        self.prepare_calls.append((ticket_id, title, checkpoint_lineage))
        return self.binding

    def create_bound_ticket_branch(self, binding: BranchBinding) -> str:
        self.bound_create_calls.append(binding)
        if self.fail_branch:
            raise RuntimeError("branch creation failed")
        if self.interrupt_after_bound_create:
            raise KeyboardInterrupt("simulated interruption after branch creation")
        return binding.branch

    def reconcile_branch(self, binding: BranchBinding, *, checkpoint_lineage: str) -> str:
        assert checkpoint_lineage == "preparation"
        self.reconcile_calls.append(binding)
        return binding.branch


class FakeCompatibilityVerifier:
    def __init__(self, result: FakeCompatibilityResult) -> None:
        self.result = result
        self.calls: list[tuple[object, object]] = []

    def verify(self, runtime_config: object, role_config: object) -> FakeCompatibilityResult:
        self.calls.append((runtime_config, role_config))
        return self.result


class FailingCompatibilityVerifier:
    def __init__(self) -> None:
        self.calls: list[tuple[object, object]] = []

    def verify(self, runtime_config: object, role_config: object) -> object:
        self.calls.append((runtime_config, role_config))
        raise CompatibilityPreflightError("credential-like details must not be persisted")


class CrashingCompatibilityVerifier:
    def __init__(self) -> None:
        self.calls: list[tuple[object, object]] = []

    def verify(self, runtime_config: object, role_config: object) -> object:
        self.calls.append((runtime_config, role_config))
        raise KeyboardInterrupt("simulated process death during compatibility preflight")


class PreparationAuthorizations:
    def __init__(self, *authorization_ids: str) -> None:
        self.authorization_ids = frozenset(authorization_ids)

    def verify(self, authorization: HumanAuthorization, action: HumanAuthorizationAction) -> bool:
        return authorization.action is action and authorization.authorization_id in self.authorization_ids


def consumed_resume_authorization(run_id: str, authorization_id: str) -> HumanAuthorization:
    return HumanAuthorization(
        authorization_id=authorization_id,
        action=HumanAuthorizationAction.RESUME,
        run_id=run_id,
        challenge="operator-challenge",
        actor="operator",
        reason="operator authorized this transition",
        issued_at=NOW,
        expires_at=datetime(2027, 1, 1, tzinfo=UTC),
        key_id="operator-key",
        signature="signature-shaped-data",
        additional_iterations=1,
        consumed_at=NOW,
    )


class PreparationInputClient:
    def __init__(self, result: object) -> None:
        self.result = result
        self.calls: list[tuple[str, str, object]] = []

    def call(self, server_identity: str, operation: str, arguments: object) -> McpToolResult:
        self.calls.append((server_identity, operation, arguments))
        assert operation == "query_preparation"
        return McpToolResult(tool_call_id="tool-call-1", result=self.result)


def test_selected_activation_with_real_index_publishes_context_with_its_initial_state(tmp_path: Path) -> None:
    """A selected activation publishes only the index-owned deterministic run identity."""
    repository = tmp_path / "repository"
    repository.mkdir()
    client = PreparationInputClient(
        {
            "pages": [
                {
                    "id": "ENG-1",
                    "title": "Activate trusted preparation",
                    "state_type": "unstarted",
                    "state_id": "state-1",
                    "external_revision": "revision-1",
                    "assignee_id": "user-1",
                    "milestone_id": "milestone-1",
                    "priority": 1,
                    "created_at": "2026-09-10T00:00:00Z",
                    "blockers": [],
                }
            ],
            "pagination_complete": True,
            "max_crew_iterations": 3,
            "assignee_resolution": {"status": "resolved", "resolved_id": "user-1"},
            "milestone_resolution": {"status": "resolved", "resolved_id": "milestone-1"},
            "workflow_states": {"started": "state-started"},
        }
    )
    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-signing-key-123",
        client=client,
    )
    index = ActiveRunIndex(tmp_path, preparation_input_verifier=bridge)
    runner_identity = RunnerIdentity(
        content_hash="1" * 64,
        source_sha="2" * 64,
        dependency_lock_hash="3" * 64,
        contract_bundle_hash="4" * 64,
        built_at=NOW,
    )
    receipt = FakeCompatibilityReceipt(
        content_hash="5" * 64,
        project_policy_hash="6" * 64,
        runner_identity=runner_identity,
    )
    compatibility = FakeCompatibilityVerifier(
        FakeCompatibilityResult(
            receipt=receipt,
            receipt_ref=EvidenceRef(
                relative_path="trusted-launcher/compatibility/11111111-1111-4111-8111-111111111111.json",
                sha256=receipt.content_hash,
                media_type="application/json",
                creator="trusted-launcher",
            ),
        )
    )
    coordinator = PrepareCoordinator(
        index=index,
        bridge=bridge,
        git=FakeGitGuard(repository),
        compatibility=compatibility,
        runtime_config="runtime-config",
        role_config="role-config",
        reservation_owner=lambda: ReservationOwner(host="test-host", pid=1),
        now=lambda: NOW,
    )

    probe = coordinator.probe(repository)
    assert probe.challenge is not None
    reference = bridge.query_preparation(
        probe.challenge,
        {"operation": "prepare"},
        repository_id="repo-1",
        reservation_id=probe.reservation_id or "",
    )

    result = coordinator.activate_reservation(tmp_path / reference.relative_path, reference.input_hash, probe.challenge)

    assert result.run_id is not None
    state = RunStateStore.load_read_only(tmp_path, result.run_id).state
    assert state.preparation_phase is PreparationPhase.SELECTED
    assert PreparationContextAuthority(tmp_path).load_verified(result.run_id).ticket_snapshot_hash == state.ticket_snapshot_hash

    restarted = PrepareCoordinator(
        index=index,
        bridge=bridge,
        git=FakeGitGuard(repository),
        compatibility=compatibility,
        runtime_config="runtime-config",
        role_config="role-config",
        reservation_owner=lambda: ReservationOwner(host="test-host", pid=1),
        now=lambda: NOW,
    )

    assert restarted.activate_reservation(tmp_path / reference.relative_path, reference.input_hash, probe.challenge) == result
    assert len(compatibility.calls) == 1


@pytest.mark.parametrize("revision", ("x" * 257, "api_key=secret-value"))
def test_selected_ticket_rejects_unbounded_or_sensitive_external_revision(revision: str) -> None:
    """Removing the MCP external-revision boundary would admit unsafe context data before preflight."""

    with pytest.raises(PrepareError):
        PrepareCoordinator._required_ticket_field({"external_revision": revision}, "external_revision")


@pytest.mark.parametrize("revision", ("x" * 257, "api_key=secret-value"))
def test_malformed_external_revision_rejects_before_compatibility_preflight(tmp_path: Path, revision: str) -> None:
    """Moving revision validation after claim preflight would persist or verify unsafe ticket state."""
    repository = tmp_path / "repository"
    repository.mkdir()
    client = PreparationInputClient(
        {
            "pages": [{"id": "ENG-1", "title": "Unsafe revision", "state_type": "unstarted", "state_id": "state-1", "external_revision": revision, "assignee_id": "user-1", "milestone_id": "milestone-1", "priority": 1, "created_at": "2026-09-10T00:00:00Z", "blockers": []}],
            "pagination_complete": True,
            "max_crew_iterations": 3,
            "assignee_resolution": {"status": "resolved", "resolved_id": "user-1"},
            "milestone_resolution": {"status": "resolved", "resolved_id": "milestone-1"},
            "workflow_states": {"started": "state-started"},
        }
    )
    bridge = TrustedLinearBridge(state_root=tmp_path, bridge_identity="launcher-bridge", mcp_server_identity="linear-mcp", receipt_signing_key=b"test-signing-key-123", client=client)
    index = ActiveRunIndex(tmp_path, preparation_input_verifier=bridge)
    runner = RunnerIdentity(content_hash="1" * 64, source_sha="2" * 64, dependency_lock_hash="3" * 64, contract_bundle_hash="4" * 64, built_at=NOW)
    compatibility = FakeCompatibilityVerifier(FakeCompatibilityResult(FakeCompatibilityReceipt("5" * 64, "6" * 64, runner), EvidenceRef(relative_path="trusted-launcher/compatibility/11111111-1111-4111-8111-111111111111.json", sha256="5" * 64, media_type="application/json", creator="trusted-launcher")))
    coordinator = PrepareCoordinator(index=index, bridge=bridge, git=FakeGitGuard(repository), compatibility=compatibility, runtime_config="runtime-config", role_config="role-config", reservation_owner=lambda: ReservationOwner(host="test-host", pid=1), now=lambda: NOW)
    probe = coordinator.probe(repository)
    assert probe.challenge is not None
    reference = bridge.query_preparation(probe.challenge, {"operation": "prepare"}, repository_id="repo-1", reservation_id=probe.reservation_id or "")

    with pytest.raises(PrepareError, match="external_revision"):
        coordinator.activate_reservation(tmp_path / reference.relative_path, reference.input_hash, probe.challenge)

    assert compatibility.calls == []
    assert not list((tmp_path / "preparation-journal").glob("*.json"))
    assert not (tmp_path / "runs").exists()


def test_probe_reports_a_real_index_reservation_as_blocked_without_loading_input(tmp_path: Path) -> None:
    """Ignoring an index-owned live reservation would let another coordinator request preparation input."""
    repository = tmp_path / "repository"
    repository.mkdir()
    index = ActiveRunIndex(tmp_path)
    reservation = index.probe_or_reserve("repo-1", ReservationOwner(host="other-host", pid=2)).reservation
    assert reservation is not None

    class NeverLoadBridge:
        def load_verified_preparation_input(self, input_path: Path, input_hash: str) -> object:
            raise AssertionError("blocked probes must not load preparation input")

    coordinator = PrepareCoordinator(
        index=index,
        bridge=NeverLoadBridge(),  # type: ignore[arg-type]
        git=FakeGitGuard(repository),
        compatibility=object(),
        runtime_config="runtime-config",
        role_config="role-config",
        reservation_owner=lambda: ReservationOwner(host="this-host", pid=1),
        now=lambda: NOW,
    )

    result = coordinator.probe(repository)

    assert result.kind == "BLOCKED"
    assert result.reservation_id == reservation.reservation_id


@pytest.mark.parametrize(
    ("malformation", "error_type", "message"),
    (
        ("reservation", ActivationReservationMismatch, "activation does not match"),
        ("reference", ActivationReservationMismatch, "activation does not own"),
        ("page_hashes", PrepareError, "trusted preparation input does not match"),
        ("resolution", PrepareError, "trusted preparation input does not resolve"),
        ("budget", PrepareError, "trusted preparation input does not match"),
    ),
)
def test_public_activation_rejects_malformed_bridge_backed_selection_inputs_before_preflight(
    tmp_path: Path,
    malformation: str,
    error_type: type[PrepareError] | type[ActivationReservationMismatch],
    message: str,
) -> None:
    """Removing a public selection guard would let a malformed input reach preflight or publication."""
    repository = tmp_path / "repository"
    repository.mkdir()
    client = PreparationInputClient(
        {
            "pages": [{"id": "ENG-1", "title": "Selection boundary", "state_type": "unstarted", "state_id": "state-1", "external_revision": "revision-1", "assignee_id": "user-1", "milestone_id": "milestone-1", "priority": 1, "created_at": "2026-09-10T00:00:00Z", "blockers": []}],
            "pagination_complete": True,
            "max_crew_iterations": 3,
            "assignee_resolution": {"status": "resolved", "resolved_id": "user-1"},
            "milestone_resolution": {"status": "resolved", "resolved_id": "milestone-1"},
            "workflow_states": {"started": "state-started"},
        }
    )
    bridge = TrustedLinearBridge(state_root=tmp_path, bridge_identity="launcher-bridge", mcp_server_identity="linear-mcp", receipt_signing_key=b"test-signing-key-123", client=client)
    index = ActiveRunIndex(tmp_path, preparation_input_verifier=bridge)
    runner = RunnerIdentity(content_hash="1" * 64, source_sha="2" * 64, dependency_lock_hash="3" * 64, contract_bundle_hash="4" * 64, built_at=NOW)
    compatibility = FakeCompatibilityVerifier(FakeCompatibilityResult(FakeCompatibilityReceipt("5" * 64, "6" * 64, runner), EvidenceRef(relative_path="trusted-launcher/compatibility/11111111-1111-4111-8111-111111111111.json", sha256="5" * 64, media_type="application/json", creator="trusted-launcher")))

    class MalformedBridge:
        def load_verified_preparation_input(self, input_path: Path, input_hash: str) -> tuple[TrustedPreparationInputRef, PreparationInput]:
            reference, preparation_input = bridge.load_verified_preparation_input(input_path, input_hash)
            if malformation == "reservation":
                return reference.model_copy(update={"reservation_id": "other-reservation"}), preparation_input
            if malformation == "reference":
                return reference.model_copy(update={"repository_id": "other-repository"}), preparation_input
            if malformation == "page_hashes":
                invalid_input = PreparationInput.model_construct(
                    **{**preparation_input.model_dump(round_trip=True), "page_hashes": {"page-1": "0" * 64}}
                )
                return reference, invalid_input
            if malformation == "resolution":
                return reference, preparation_input.model_copy(update={"assignee_resolution": IdentityResolution.not_found()})
            invalid_reference = TrustedPreparationInputRef.model_construct(**{**reference.model_dump(round_trip=True), "max_crew_iterations": 0})
            invalid_input = PreparationInput.model_construct(**{**preparation_input.model_dump(round_trip=True), "max_crew_iterations": 0})
            return invalid_reference, invalid_input

    coordinator = PrepareCoordinator(index=index, bridge=MalformedBridge(), git=FakeGitGuard(repository), compatibility=compatibility, runtime_config="runtime-config", role_config="role-config", reservation_owner=lambda: ReservationOwner(host="test-host", pid=1), now=lambda: NOW)
    probe = coordinator.probe(repository)
    assert probe.challenge is not None
    reference = bridge.query_preparation(probe.challenge, {"operation": "prepare"}, repository_id="repo-1", reservation_id=probe.reservation_id or "")
    journal_before = list((tmp_path / "preparation-journal").glob("*.json"))

    with pytest.raises(error_type, match=message):
        coordinator.activate_reservation(tmp_path / reference.relative_path, reference.input_hash, probe.challenge)

    assert compatibility.calls == []
    assert list((tmp_path / "preparation-journal").glob("*.json")) == journal_before
    assert not list((tmp_path / "runs").glob("*/preparation-context.json")) if (tmp_path / "runs").exists() else True


def test_index_owned_preflight_complete_claim_allows_a_fresh_coordinator_to_publish_once(tmp_path: Path) -> None:
    """Dropping the durable preflight binding would rerun compatibility after a restart."""
    repository = tmp_path / "repository"
    repository.mkdir()
    client = PreparationInputClient(
        {
            "pages": [
                {
                    "id": "ENG-1",
                    "title": "Claim trusted preparation",
                    "state_type": "unstarted",
                    "state_id": "state-1",
                    "external_revision": "revision-1",
                    "assignee_id": "user-1",
                    "milestone_id": "milestone-1",
                    "priority": 1,
                    "created_at": "2026-09-10T00:00:00Z",
                    "blockers": [],
                }
            ],
            "pagination_complete": True,
            "max_crew_iterations": 3,
            "assignee_resolution": {"status": "resolved", "resolved_id": "user-1"},
            "milestone_resolution": {"status": "resolved", "resolved_id": "milestone-1"},
            "workflow_states": {"started": "state-started"},
        }
    )
    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-signing-key-123",
        client=client,
    )
    index = ActiveRunIndex(tmp_path, preparation_input_verifier=bridge)
    runner = RunnerIdentity(
        content_hash="1" * 64,
        source_sha="2" * 64,
        dependency_lock_hash="3" * 64,
        contract_bundle_hash="4" * 64,
        built_at=NOW,
    )
    receipt_ref = EvidenceRef(
        relative_path="trusted-launcher/compatibility/11111111-1111-4111-8111-111111111111.json",
        sha256="5" * 64,
        media_type="application/json",
        creator="trusted-launcher",
    )
    compatibility = FakeCompatibilityVerifier(
        FakeCompatibilityResult(
            receipt=FakeCompatibilityReceipt("5" * 64, "6" * 64, runner),
            receipt_ref=receipt_ref,
        )
    )
    first = PrepareCoordinator(
        index=index,
        bridge=bridge,
        git=FakeGitGuard(repository),
        compatibility=compatibility,
        runtime_config="runtime-config",
        role_config="role-config",
        reservation_owner=lambda: ReservationOwner(host="test-host", pid=1),
        now=lambda: NOW,
    )
    probe = first.probe(repository)
    assert probe.challenge is not None
    reference = bridge.query_preparation(
        probe.challenge,
        {"operation": "prepare"},
        repository_id="repo-1",
        reservation_id=probe.reservation_id or "",
    )
    loaded_reference, preparation_input = bridge.load_verified_preparation_input(
        tmp_path / reference.relative_path,
        reference.input_hash,
    )
    raw = preparation_input.pages[0]
    snapshot = TicketSnapshot.from_untrusted(
        raw,
        captured_at=NOW,
        pagination_complete=True,
        source_page_hashes=loaded_reference.source_page_hashes,
    )
    claim_request = SelectedActivationClaimRequest(
        reservation_id=probe.reservation_id or "",
        repository_id="repo-1",
        expected_index_revision=1,
        expected_index_hash=index.activation_reservation(loaded_reference, probe.challenge).index_hash,
        preparation_input_ref=loaded_reference,
        ticket_snapshot=snapshot,
        original_state_id="state-1",
        original_external_revision="revision-1",
    )

    claim = index.claim_selected_activation(claim_request)
    assert claim.outcome == "preflight_required"
    assert not list((tmp_path / "runs").glob("*/preparation-context.json")) if (tmp_path / "runs").exists() else True
    index.record_claim_compatibility(
        loaded_reference,
        probe.challenge,
        CompatibilityClaimBinding(
            compatibility_receipt_hash="5" * 64,
            compatibility_receipt_ref=receipt_ref,
            project_policy_hash="6" * 64,
            runner_identity=runner,
        ),
    )

    restarted = PrepareCoordinator(
        index=index,
        bridge=bridge,
        git=FakeGitGuard(repository),
        compatibility=compatibility,
        runtime_config="runtime-config",
        role_config="role-config",
        reservation_owner=lambda: ReservationOwner(host="other-host", pid=2),
        now=lambda: NOW.replace(day=12),
    )
    result = restarted.activate_reservation(tmp_path / reference.relative_path, reference.input_hash, probe.challenge)

    assert result.kind == "ACTIVATED"
    assert result.run_id == claim.run_id
    assert len(compatibility.calls) == 0
    generation = RunStateStore.load_read_only(tmp_path, claim.run_id)
    assert generation.state.ticket_snapshot_hash == snapshot.content_hash
    assert PreparationContextAuthority(tmp_path).load_verified(claim.run_id).ticket_snapshot_hash == snapshot.content_hash


def test_concurrent_selected_activation_waits_without_a_second_compatibility_preflight(tmp_path: Path) -> None:
    """Moving the selection claim after preflight permits two compatibility receipts and contexts."""
    repository = tmp_path / "repository"
    repository.mkdir()
    started = Event()
    release = Event()

    runner = RunnerIdentity(content_hash="1" * 64, source_sha="2" * 64, dependency_lock_hash="3" * 64, contract_bundle_hash="4" * 64, built_at=NOW)
    profiles = ModelCompatibilityRegistry(
        (ModelCompatibilityProfile("opencode-go", "model-1", "chat", frozenset({"structured_output", "text", "tool_calling"})),)
    )
    authority = CompatibilityReceiptAuthority(tmp_path, "trusted-launcher", runner)
    catalog = ModelCatalog(("model-1",))
    resolved_models = {
        role: profiles.resolve(ModelRef("opencode-go", "model-1"), catalog, frozenset({"structured_output", "text", "tool_calling"}))
        for role in RoleName
    }

    class BlockingCompatibility:
        def __init__(self) -> None:
            self.calls: list[tuple[object, object]] = []
            self.result: CompatibilityPreflightResult | None = None

        def verify(self, runtime_config: object, role_config: object) -> CompatibilityPreflightResult:
            self.calls.append((runtime_config, role_config))
            started.set()
            assert release.wait(timeout=5)
            observation = CatalogObservation(
                provider="opencode-go",
                endpoint_identity="catalog-one",
                credential_scope_hash="7" * 64,
                fetched_at=NOW,
                expires_at=NOW.replace(day=12),
                model_set_hash=hash_json(sorted(catalog.model_ids)),
                profile_bundle_hash=profiles.profile_bundle_hash,
                response_evidence_hash="8" * 64,
            )
            components = tuple(
                CompatibilityComponentObservation(
                    component=component,
                    expected_constraint=constraint,
                    observed_version=version,
                    verified_identity_hash="9" * 64,
                    evidence_hashes=("a" * 64,),
                )
                for component, constraint, version in (
                    ("crewai", "1.15.20", "1.15.20"),
                    ("node", ">=20.19.0", "20.19.0"),
                    ("openspec", "1.12.0", "1.12.0"),
                    ("python", "3.12.x", "3.12.13"),
                    ("ralph", "1.0.10", "1.0.10"),
                )
            )
            receipt = CompatibilityReceipt(
                receipt_id="123e4567-e89b-12d3-a456-426614174000",
                issued_at=NOW,
                launcher_identity="trusted-launcher",
                runner_identity=runner,
                runner_content_hash=runner.content_hash,
                project_policy_hash="6" * 64,
                selected_role_models_hash=hash_json({role.value: "opencode-go/model-1" for role in RoleName}),
                profile_bundle_hash=profiles.profile_bundle_hash,
                catalog_receipt_hashes={"opencode-go": observation.content_hash},
                catalog_observations=(observation,),
                browser_preflight_status=BrowserPreflightStatus.NOT_CONFIGURED,
                component_observations=components,
                relative_path="trusted-launcher/compatibility/123e4567-e89b-12d3-a456-426614174000.json",
            )
            receipt_ref = authority.publish(receipt)
            assert authority.load_verified_receipt(receipt_ref) == receipt
            self.result = CompatibilityPreflightResult(
                receipt=receipt,
                receipt_ref=receipt_ref,
                catalogs={"opencode-go": catalog},
                resolved_models=resolved_models,
                profiles=profiles,
            )
            return self.result

    client = PreparationInputClient(
        {
            "pages": [{"id": "ENG-1", "title": "Concurrent claim", "state_type": "unstarted", "state_id": "state-1", "external_revision": "revision-1", "assignee_id": "user-1", "milestone_id": "milestone-1", "priority": 1, "created_at": "2026-09-10T00:00:00Z", "blockers": []}],
            "pagination_complete": True,
            "max_crew_iterations": 3,
            "assignee_resolution": {"status": "resolved", "resolved_id": "user-1"},
            "milestone_resolution": {"status": "resolved", "resolved_id": "milestone-1"},
            "workflow_states": {"started": "state-started"},
        }
    )
    bridge = TrustedLinearBridge(state_root=tmp_path, bridge_identity="launcher-bridge", mcp_server_identity="linear-mcp", receipt_signing_key=b"test-signing-key-123", client=client)
    index = ActiveRunIndex(tmp_path, preparation_input_verifier=bridge)
    compatibility = BlockingCompatibility()
    def coordinator(owner: ReservationOwner) -> PrepareCoordinator:
        return PrepareCoordinator(index=index, bridge=bridge, git=FakeGitGuard(repository), compatibility=compatibility, runtime_config="runtime-config", role_config="role-config", reservation_owner=lambda: owner, now=lambda: NOW)

    first = coordinator(ReservationOwner(host="first-host", pid=1))
    probe = first.probe(repository)
    assert probe.challenge is not None
    reference = bridge.query_preparation(probe.challenge, {"operation": "prepare"}, repository_id="repo-1", reservation_id=probe.reservation_id or "")
    outcomes: list[object] = []
    worker = Thread(target=lambda: outcomes.append(first.activate_reservation(tmp_path / reference.relative_path, reference.input_hash, probe.challenge)))
    worker.start()
    assert started.wait(timeout=5)

    waiting = coordinator(ReservationOwner(host="second-host", pid=2)).activate_reservation(tmp_path / reference.relative_path, reference.input_hash, probe.challenge)
    assert waiting.kind == "WAIT"
    assert len(compatibility.calls) == 1
    assert not (tmp_path / "runs").exists()
    assert not (tmp_path / "trusted-launcher" / "compatibility").exists()

    release.set()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert len(outcomes) == 1
    assert getattr(outcomes[0], "kind") == "ACTIVATED"
    assert len(compatibility.calls) == 1
    assert len(list((tmp_path / "runs").glob("*/preparation-context.json"))) == 1
    assert compatibility.result is not None
    state = RunStateStore.load_read_only(tmp_path, outcomes[0].run_id).state
    assert state.compatibility_receipt_ref == compatibility.result.receipt_ref
    assert authority.load_verified_receipt(state.compatibility_receipt_ref) == compatibility.result.receipt
    replayed = coordinator(ReservationOwner(host="third-host", pid=3)).activate_reservation(tmp_path / reference.relative_path, reference.input_hash, probe.challenge)
    assert replayed == outcomes[0]
    assert len(compatibility.calls) == 1


class PreparationReconciliationHarness:
    """Real state/index/gateway composition with only local deterministic boundary fakes."""

    def __init__(
        self,
        tmp_path: Path,
        *,
        compatibility: object | None = None,
        authorization_verifier: object | None = None,
        activate: bool = True,
    ) -> None:
        self.root = tmp_path
        self.repository = tmp_path / "repository"
        self.repository.mkdir()
        self.client = PreparationInputClient(
            {
                "pages": [
                    {
                        "id": "ENG-1",
                        "title": "Safe title",
                        "state_type": "unstarted",
                        "state_id": "state-original",
                        "external_revision": "revision-original",
                        "assignee_id": "user-1",
                        "milestone_id": "milestone-1",
                        "priority": 1,
                        "created_at": "2026-09-10T00:00:00Z",
                        "blockers": [],
                    }
                ],
                "pagination_complete": True,
                "max_crew_iterations": 3,
                "assignee_resolution": {"status": "resolved", "resolved_id": "user-1"},
                "milestone_resolution": {"status": "resolved", "resolved_id": "milestone-1"},
                "workflow_states": {"started": "state-started"},
            }
        )
        self.bridge = TrustedLinearBridge(
            state_root=tmp_path,
            bridge_identity="launcher-bridge",
            mcp_server_identity="linear-mcp",
            receipt_signing_key=b"test-signing-key-123",
            client=self.client,
        )
        self.index = ActiveRunIndex(
            tmp_path,
            preparation_input_verifier=self.bridge,
            authorization_verifier=authorization_verifier,
        )
        runner = RunnerIdentity(
            content_hash="1" * 64,
            source_sha="2" * 64,
            dependency_lock_hash="3" * 64,
            contract_bundle_hash="4" * 64,
            built_at=NOW,
        )
        self.compatibility = compatibility or FakeCompatibilityVerifier(
            FakeCompatibilityResult(
                receipt=FakeCompatibilityReceipt("5" * 64, "6" * 64, runner),
                receipt_ref=EvidenceRef(
                    relative_path="trusted-launcher/compatibility/11111111-1111-4111-8111-111111111111.json",
                    sha256="5" * 64,
                    media_type="application/json",
                    creator="trusted-launcher",
                ),
            )
        )
        self.git = FakeGitGuard(self.repository)
        self.coordinator = self._coordinator()
        probe = self.coordinator.probe(self.repository)
        assert probe.challenge is not None
        reference = self.bridge.query_preparation(
            probe.challenge,
            {"operation": "prepare"},
            repository_id="repo-1",
            reservation_id=probe.reservation_id or "",
        )
        self.reference = reference
        self.challenge = probe.challenge
        if activate:
            self.activate()

    def activate(self) -> None:
        activated = self.coordinator.activate_reservation(
            self.root / self.reference.relative_path,
            self.reference.input_hash,
            self.challenge,
        )
        assert activated.run_id is not None
        self.run_id = activated.run_id
        self.store = RunStateStore(
            self.root,
            self.run_id,
            receipt_authority=self.bridge.receipt_authority,
            authorization_verifier=self.index.authorization_verifier,
        )
        self.gateway = LinearGateway(self.store, self.bridge.receipt_authority)
        self.coordinator = self._coordinator(linear=self.gateway, context=PreparationContextAuthority(self.root))

    def _coordinator(
        self,
        *,
        linear: LinearGateway | None = None,
        context: PreparationContextAuthority | None = None,
    ) -> PrepareCoordinator:
        return PrepareCoordinator(
            index=self.index,
            bridge=self.bridge,
            git=self.git,
            compatibility=self.compatibility,
            runtime_config="runtime-config",
            role_config="role-config",
            reservation_owner=lambda: ReservationOwner(host="test-host", pid=1),
            now=lambda: NOW,
            linear=linear,
            context=context,
        )

    def load(self):
        return self.store.load()

    def publish_receipt(
        self,
        request: object,
        receipt_id: str,
        *,
        outcome: EffectOutcome = EffectOutcome.SUCCESS,
        external_revision: str = "revision-after-action",
    ) -> EvidenceRef:
        assert hasattr(request, "request_id")
        provisional = TrustedMcpReceipt(
            receipt_id=receipt_id,
            request_id=request.request_id,
            effect_id=request.effect_id,
            effect_hash=request.effect_hash,
            request_hash=request.request_hash,
            operation=request.operation,
            target=request.target,
            run_id=request.run_id,
            expected_revision=request.expected_revision,
            expected_state_hash=request.expected_state_hash,
            expected_external_revision=request.expected_external_revision,
            payload_hash=request.payload_hash,
            result_hash=hash_json({"result": "synthetic"}),
            outcome=outcome,
            external_revision=external_revision,
            bridge_identity="launcher-bridge",
            mcp_server_identity="linear-mcp",
            tool_call_id="synthetic-tool-call",
            observed_at=NOW,
            observations=("Synthetic trusted receipt.",),
            relative_path=f"trusted-mcp/receipts/{receipt_id}.json",
        )
        receipt = provisional.model_copy(
            update={"bridge_signature": _sign(b"test-signing-key-123", provisional.signed_payload())}
        )
        path = self.root / receipt.relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(canonical_json_bytes(receipt.model_dump(mode="json", round_trip=True)))
        return EvidenceRef(
            relative_path=receipt.relative_path,
            sha256=receipt.content_hash,
            media_type="application/json",
            creator="trusted-mcp-bridge",
        )


@pytest.fixture
def descriptor_policy(monkeypatch: pytest.MonkeyPatch) -> list[object]:
    """The recheck boundary is isolated; it never loads host configuration in these tests."""

    calls: list[object] = []

    def load(runtime_config: object) -> object:
        calls.append(runtime_config)
        return object()

    monkeypatch.setattr("auto_code.prepare.load_descriptor_bound_policy", load, raising=False)
    return calls


def test_advance_persists_start_request_before_bridge_execution(
    tmp_path: Path,
    descriptor_policy: list[object],
) -> None:
    """Removing pending persistence would allow a start request to reach transport without a CAS binding."""
    harness = PreparationReconciliationHarness(tmp_path)
    selected = harness.load()

    result = harness.coordinator.advance(harness.run_id, selected.revision, selected.state_hash)

    assert result.action_request is not None
    assert result.action_request.operation == "compare_and_start_ticket"
    assert result.action_request.expected_external_revision == "revision-original"
    assert result.action_request.arguments == {"ticket_id": "ENG-1", "state_id": "state-started"}
    assert harness.load().state.preparation_phase is PreparationPhase.IN_PROGRESS_REQUESTED
    assert harness.load().state.pending_external_request is not None
    assert [operation for _, operation, _ in harness.client.calls] == ["query_preparation"]
    assert descriptor_policy == ["runtime-config"]


def test_root_bound_start_receipt_confirms_then_allows_guarded_branch_creation(
    tmp_path: Path,
    descriptor_policy: list[object],
) -> None:
    """Skipping receipt-backed confirmation would allow branch creation before Linear's durable start result."""
    harness = PreparationReconciliationHarness(tmp_path)
    selected = harness.load()
    pending = harness.coordinator.advance(harness.run_id, selected.revision, selected.state_hash)
    assert pending.action_request is not None
    receipt_ref = harness.publish_receipt(pending.action_request, "11111111-1111-4111-8111-111111111112")
    waiting = harness.load()

    confirmed = harness.coordinator.consume_receipt(harness.run_id, waiting.revision, waiting.state_hash, receipt_ref)
    assert confirmed.generation is not None
    assert confirmed.generation.state.preparation_phase is PreparationPhase.IN_PROGRESS_CONFIRMED

    intended = harness.coordinator.advance(
        harness.run_id,
        confirmed.generation.revision,
        confirmed.generation.state_hash,
    )
    assert intended.generation is not None
    prepared = harness.coordinator.advance(
        harness.run_id,
        intended.generation.revision,
        intended.generation.state_hash,
    )
    assert prepared.generation is not None
    branched = harness.coordinator.advance(
        harness.run_id,
        prepared.generation.revision,
        prepared.generation.state_hash,
    )

    assert branched.generation is not None
    assert branched.generation.state.preparation_phase is PreparationPhase.BRANCH_CREATED
    assert branched.generation.state.branch == "ENG-1-safe-title"
    assert harness.git.prepare_calls == [("ENG-1", "Safe title", "preparation")]
    assert harness.git.bound_create_calls == [harness.git.binding]
    assert tuple(event.kind for event in branched.generation.state.effect_ledger[-6:]) == (
        "intention",
        "invocation",
        "observation",
        "invocation",
        "observation",
        "reconciliation",
    )
    assert descriptor_policy == ["runtime-config"] * 4


def test_consume_receipt_rejects_a_receipt_payload_instead_of_a_root_bound_reference(
    tmp_path: Path,
    descriptor_policy: list[object],
) -> None:
    """Accepting caller-owned receipt data would bypass the bridge-root authentication boundary."""
    harness = PreparationReconciliationHarness(tmp_path)
    selected = harness.load()
    pending = harness.coordinator.advance(harness.run_id, selected.revision, selected.state_hash)
    assert pending.action_request is not None
    receipt_ref = harness.publish_receipt(pending.action_request, "11111111-1111-4111-8111-111111111113")
    receipt = harness.bridge.receipt_authority.load_verified_receipt(receipt_ref)
    waiting = harness.load()

    with pytest.raises(PrepareError, match="receipt reference"):
        harness.coordinator.consume_receipt(harness.run_id, waiting.revision, waiting.state_hash, receipt)  # type: ignore[arg-type]

    assert harness.load() == waiting


def test_branch_failure_records_reconciliation_then_restores_only_the_original_revision(
    tmp_path: Path,
    descriptor_policy: list[object],
) -> None:
    """Replacing a branch failure with a synthetic bridge receipt would skip the required local effect ledger."""
    harness = PreparationReconciliationHarness(tmp_path)
    selected = harness.load()
    pending = harness.coordinator.advance(harness.run_id, selected.revision, selected.state_hash)
    assert pending.action_request is not None
    start_ref = harness.publish_receipt(pending.action_request, "11111111-1111-4111-8111-111111111114")
    waiting = harness.load()
    confirmed = harness.coordinator.consume_receipt(harness.run_id, waiting.revision, waiting.state_hash, start_ref)
    assert confirmed.generation is not None
    harness.git.fail_branch = True

    intended = harness.coordinator.advance(
        harness.run_id,
        confirmed.generation.revision,
        confirmed.generation.state_hash,
    )
    assert intended.generation is not None
    prepared = harness.coordinator.advance(
        harness.run_id,
        intended.generation.revision,
        intended.generation.state_hash,
    )
    assert prepared.generation is not None
    compensation = harness.coordinator.advance(
        harness.run_id,
        prepared.generation.revision,
        prepared.generation.state_hash,
    )
    assert compensation.generation is not None
    assert compensation.generation.state.preparation_phase is PreparationPhase.COMPENSATION_REQUIRED
    assert compensation.generation.state.effect_ledger[-1].payload.outcome is EffectOutcome.FAILURE

    restore = harness.coordinator.advance(
        harness.run_id,
        compensation.generation.revision,
        compensation.generation.state_hash,
    )
    assert restore.action_request is not None
    assert restore.action_request.operation == "restore_ticket_state"
    assert restore.action_request.expected_external_revision == "revision-original"
    assert restore.action_request.arguments == {"ticket_id": "ENG-1", "state_id": "state-original"}
    restore_ref = harness.publish_receipt(restore.action_request, "11111111-1111-4111-8111-111111111115")
    waiting_restore = harness.load()

    restored = harness.coordinator.consume_receipt(
        harness.run_id,
        waiting_restore.revision,
        waiting_restore.state_hash,
        restore_ref,
    )

    assert restored.generation is not None
    assert restored.generation.state.disposition is RunDisposition.HUMAN_REVIEW
    assert restored.generation.state.compensated is True
    assert restored.generation.state.preparation_phase is PreparationPhase.COMPENSATION_REQUIRED
    current = harness.coordinator.advance(
        harness.run_id,
        restored.generation.revision,
        restored.generation.state_hash,
    )
    assert current.action_request is None
    assert current.generation == restored.generation


def test_preparation_resume_rejects_invalid_authorization_and_preserves_history_after_authenticated_restore(
    tmp_path: Path,
    descriptor_policy: list[object],
) -> None:
    """Replacing an authenticated resume with an arbitrary authorization could reset compensated preparation without preserving its evidence."""
    harness = PreparationReconciliationHarness(
        tmp_path,
        authorization_verifier=PreparationAuthorizations("resume-valid"),
    )
    selected = harness.load()
    start = harness.coordinator.advance(harness.run_id, selected.revision, selected.state_hash)
    assert start.action_request is not None
    start_ref = harness.publish_receipt(start.action_request, "11111111-1111-4111-8111-111111111121")
    requested = harness.load()
    confirmed = harness.coordinator.consume_receipt(harness.run_id, requested.revision, requested.state_hash, start_ref)
    assert confirmed.generation is not None
    harness.git.fail_branch = True
    intended = harness.coordinator.advance(harness.run_id, confirmed.generation.revision, confirmed.generation.state_hash)
    assert intended.generation is not None
    prepared = harness.coordinator.advance(harness.run_id, intended.generation.revision, intended.generation.state_hash)
    assert prepared.generation is not None
    compensation = harness.coordinator.advance(harness.run_id, prepared.generation.revision, prepared.generation.state_hash)
    assert compensation.generation is not None
    restore = harness.coordinator.advance(harness.run_id, compensation.generation.revision, compensation.generation.state_hash)
    assert restore.action_request is not None
    restore_ref = harness.publish_receipt(restore.action_request, "11111111-1111-4111-8111-111111111122")
    waiting_restore = harness.load()
    restored = harness.coordinator.consume_receipt(
        harness.run_id,
        waiting_restore.revision,
        waiting_restore.state_hash,
        restore_ref,
    )
    assert restored.generation is not None
    assert restored.generation.state.disposition is RunDisposition.HUMAN_REVIEW
    ledger = restored.generation.state.effect_ledger
    history = restored.generation.state.failure_history

    with pytest.raises(InvalidStateTransition, match="resume authorization is not trusted"):
        harness.store.compare_and_swap(
            restored.generation.revision,
            restored.generation.state_hash,
            restored.generation.state.model_copy(
                update={
                    "preparation_phase": PreparationPhase.SELECTED,
                    "disposition": RunDisposition.ACTIVE,
                    "human_authorizations": (consumed_resume_authorization(harness.run_id, "resume-invalid"),),
                }
            ),
        )

    resumed = harness.store.compare_and_swap(
        restored.generation.revision,
        restored.generation.state_hash,
        restored.generation.state.model_copy(
            update={
                "preparation_phase": PreparationPhase.SELECTED,
                "disposition": RunDisposition.ACTIVE,
                "human_authorizations": (consumed_resume_authorization(harness.run_id, "resume-valid"),),
            }
        ),
    )

    assert resumed.state.preparation_phase is PreparationPhase.SELECTED
    assert resumed.state.disposition is RunDisposition.ACTIVE
    assert resumed.state.effect_ledger == ledger
    assert resumed.state.failure_history == history


def test_start_request_phase_is_persisted_with_its_pending_intention_in_one_cas(
    tmp_path: Path,
    descriptor_policy: list[object],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A second coordinator CAS can leave a selected run with an unreplayable pending start request."""
    harness = PreparationReconciliationHarness(tmp_path)
    selected = harness.load()
    original = harness.store.compare_and_swap
    calls = 0

    def reject_second_cas(*args: object, **kwargs: object):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("simulated interruption between start persistence and phase update")
        return original(*args, **kwargs)

    monkeypatch.setattr(harness.store, "compare_and_swap", reject_second_cas)

    result = harness.coordinator.advance(harness.run_id, selected.revision, selected.state_hash)

    assert result.action_request is not None
    assert calls == 1
    assert harness.load().state.preparation_phase is PreparationPhase.IN_PROGRESS_REQUESTED
    assert harness.load().state.pending_external_request is not None


def test_restart_replays_the_exact_persisted_start_request_without_another_effect(
    tmp_path: Path,
    descriptor_policy: list[object],
) -> None:
    """Dropping pending request payload fields prevents a restarted coordinator from invoking the intended request."""
    harness = PreparationReconciliationHarness(tmp_path)
    selected = harness.load()

    first = harness.coordinator.advance(harness.run_id, selected.revision, selected.state_hash)
    assert first.action_request is not None
    persisted = harness.load()
    effect_ledger = persisted.state.effect_ledger

    replayed = harness.coordinator.advance(harness.run_id, persisted.revision, persisted.state_hash)

    assert replayed.kind == "WAIT"
    assert replayed.action_request == first.action_request
    assert replayed.generation == persisted
    assert harness.load().state.effect_ledger == effect_ledger


def test_pending_request_rejects_arguments_that_do_not_match_its_persisted_request_hash(
    tmp_path: Path,
    descriptor_policy: list[object],
) -> None:
    """Accepting altered persisted arguments would make a receipt hash appear to authorize a different bridge action."""
    harness = PreparationReconciliationHarness(tmp_path)
    selected = harness.load()
    pending = harness.coordinator.advance(harness.run_id, selected.revision, selected.state_hash)
    assert pending.generation is not None
    persisted_request = pending.generation.state.pending_external_request
    assert persisted_request is not None

    tampered = persisted_request.model_copy(
        update={"arguments": {"ticket_id": "ENG-1", "state_id": "different-start-state"}}
    )

    with pytest.raises(ValueError, match="Pending request cannot be reconstructed"):
        pending.generation.state.model_copy(update={"pending_external_request": tampered})


def test_compatibility_preflight_failure_persists_secret_free_human_review_without_external_effects(
    tmp_path: Path,
) -> None:
    """Escaping compatibility preflight errors strands a selected activation without a resumable Human Review outcome."""
    compatibility = FailingCompatibilityVerifier()

    harness = PreparationReconciliationHarness(tmp_path, compatibility=compatibility)
    state = harness.load().state

    assert state.disposition is RunDisposition.HUMAN_REVIEW
    assert state.preparation_phase is PreparationPhase.SELECTED
    assert state.effect_ledger == ()
    assert state.pending_external_request is None
    assert state.failure_history == ()
    assert harness.git.prepare_calls == []
    assert harness.git.bound_create_calls == []
    assert compatibility.calls == [("runtime-config", "role-config")]


def test_policy_failure_enters_human_review_without_persisting_a_linear_request_or_git_effect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Letting descriptor-policy errors escape leaves a selected Active Run unsafe to resume."""
    harness = PreparationReconciliationHarness(tmp_path)
    selected = harness.load()
    monkeypatch.setattr(
        "auto_code.prepare.load_descriptor_bound_policy",
        lambda _: (_ for _ in ()).throw(RuntimeError("descriptor policy unavailable")),
    )

    result = harness.coordinator.advance(harness.run_id, selected.revision, selected.state_hash)

    assert result.generation is not None
    assert result.generation.state.disposition is RunDisposition.HUMAN_REVIEW
    assert result.generation.state.pending_external_request is None
    assert result.generation.state.effect_ledger == ()
    assert harness.git.prepare_calls == []
    assert harness.git.bound_create_calls == []


def test_branch_interruption_retries_with_the_durable_binding_and_never_recreates_or_deletes(
    tmp_path: Path,
    descriptor_policy: list[object],
) -> None:
    """Creating a branch before its intention and binding are durable makes an interrupted result unrecoverable."""
    harness = PreparationReconciliationHarness(tmp_path)
    selected = harness.load()
    pending = harness.coordinator.advance(harness.run_id, selected.revision, selected.state_hash)
    assert pending.action_request is not None
    start_ref = harness.publish_receipt(pending.action_request, "11111111-1111-4111-8111-111111111116")
    waiting = harness.load()
    confirmed = harness.coordinator.consume_receipt(harness.run_id, waiting.revision, waiting.state_hash, start_ref)
    assert confirmed.generation is not None

    intended = harness.coordinator.advance(harness.run_id, confirmed.generation.revision, confirmed.generation.state_hash)
    assert intended.generation is not None
    assert intended.generation.state.preparation_phase is PreparationPhase.IN_PROGRESS_CONFIRMED
    assert intended.generation.state.effect_ledger[-1].kind == "intention"
    assert harness.git.prepare_calls == []
    assert harness.git.bound_create_calls == []

    prepared = harness.coordinator.advance(harness.run_id, intended.generation.revision, intended.generation.state_hash)
    assert prepared.generation is not None
    assert prepared.generation.state.branch_binding is not None
    assert prepared.generation.state.branch_binding.branch == "ENG-1-safe-title"
    assert harness.git.prepare_calls == [("ENG-1", "Safe title", "preparation")]
    assert harness.git.bound_create_calls == []

    harness.git.interrupt_after_bound_create = True
    with pytest.raises(KeyboardInterrupt):
        harness.coordinator.advance(harness.run_id, prepared.generation.revision, prepared.generation.state_hash)
    uncertain = harness.load()
    assert uncertain.state.branch_binding == prepared.generation.state.branch_binding
    assert uncertain.state.validate_effect_ledger()[1][uncertain.state.effect_ledger[-1].effect_id] == "awaiting_observation"
    harness.git.interrupt_after_bound_create = False

    reconciled = harness.coordinator.advance(harness.run_id, uncertain.revision, uncertain.state_hash)

    assert reconciled.generation is not None
    assert reconciled.generation.state.preparation_phase is PreparationPhase.BRANCH_CREATED
    assert reconciled.generation.state.branch == "ENG-1-safe-title"
    assert len(harness.git.bound_create_calls) == 1
    assert harness.git.reconcile_calls == [harness.git.binding]


def test_expired_preflight_claim_after_a_crash_enters_human_review_without_rerunning_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dead preflight claim must resolve durably instead of blocking activation or starting another preflight."""
    compatibility = CrashingCompatibilityVerifier()
    harness = PreparationReconciliationHarness(tmp_path, compatibility=compatibility, activate=False)

    with pytest.raises(KeyboardInterrupt, match="simulated process death"):
        harness.activate()

    monkeypatch.setattr(harness.index, "_now", lambda: datetime.max.replace(tzinfo=UTC))
    recovered = harness.coordinator.activate_reservation(
        harness.root / harness.reference.relative_path,
        harness.reference.input_hash,
        harness.challenge,
    )

    assert recovered.run_id is not None
    assert recovered.kind == "ACTIVATED"
    assert RunStateStore.load_read_only(tmp_path, recovered.run_id).state.disposition is RunDisposition.HUMAN_REVIEW
    assert compatibility.calls == [("runtime-config", "role-config")]


def test_preflight_failed_journal_replay_completes_human_review_after_a_crash_between_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A persisted preflight failure is a recoverable journal phase, not corruption."""
    compatibility = FailingCompatibilityVerifier()
    harness = PreparationReconciliationHarness(tmp_path, compatibility=compatibility, activate=False)
    original_save = harness.index._save_journal_locked

    def crash_after_preflight_failure(reservation_id: str, journal: dict[str, object]) -> None:
        original_save(reservation_id, journal)
        if journal["phase"] == "preflight_failed":
            raise KeyboardInterrupt("simulated crash after durable preflight failure")

    monkeypatch.setattr(harness.index, "_save_journal_locked", crash_after_preflight_failure)
    with pytest.raises(KeyboardInterrupt, match="simulated crash"):
        harness.activate()
    monkeypatch.setattr(harness.index, "_save_journal_locked", original_save)

    recovered = harness.coordinator.activate_reservation(
        harness.root / harness.reference.relative_path,
        harness.reference.input_hash,
        harness.challenge,
    )

    assert recovered.run_id is not None
    assert RunStateStore.load_read_only(tmp_path, recovered.run_id).state.disposition is RunDisposition.HUMAN_REVIEW
    assert compatibility.calls == [("runtime-config", "role-config")]


def _advance_to_bound_branch_creation(harness: PreparationReconciliationHarness) -> object:
    selected = harness.load()
    start = harness.coordinator.advance(harness.run_id, selected.revision, selected.state_hash)
    assert start.action_request is not None
    receipt_ref = harness.publish_receipt(start.action_request, "11111111-1111-4111-8111-111111111123")
    requested = harness.load()
    confirmed = harness.coordinator.consume_receipt(harness.run_id, requested.revision, requested.state_hash, receipt_ref)
    assert confirmed.generation is not None
    intended = harness.coordinator.advance(
        harness.run_id,
        confirmed.generation.revision,
        confirmed.generation.state_hash,
    )
    assert intended.generation is not None
    prepared = harness.coordinator.advance(
        harness.run_id,
        intended.generation.revision,
        intended.generation.state_hash,
    )
    assert prepared.generation is not None
    return prepared.generation


@pytest.mark.parametrize("failure", ("ordinary", "reuse", "unexpected_result"))
def test_branch_failure_classification_preserves_ambiguous_branches_for_human_review(
    tmp_path: Path,
    descriptor_policy: list[object],
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    """Only an ordinary guarded creation failure can trigger Linear compensation."""
    harness = PreparationReconciliationHarness(tmp_path)
    prepared = _advance_to_bound_branch_creation(harness)
    if failure == "ordinary":
        harness.git.fail_branch = True
    elif failure == "reuse":
        def raise_reuse_error(binding: BranchBinding) -> str:
            raise BranchReuseError("simulated branch reuse ambiguity")

        monkeypatch.setattr(harness.git, "create_bound_ticket_branch", raise_reuse_error)
    else:
        monkeypatch.setattr(harness.git, "create_bound_ticket_branch", lambda binding: "other-ticket-branch")

    result = harness.coordinator.advance(harness.run_id, prepared.revision, prepared.state_hash)

    assert result.generation is not None
    if failure == "ordinary":
        assert result.generation.state.preparation_phase is PreparationPhase.COMPENSATION_REQUIRED
        assert result.generation.state.disposition is RunDisposition.ACTIVE
    else:
        assert result.generation.state.preparation_phase is PreparationPhase.IN_PROGRESS_CONFIRMED
        assert result.generation.state.disposition is RunDisposition.HUMAN_REVIEW
        assert result.generation.state.compensated is False
    assert descriptor_policy == ["runtime-config"] * 4
