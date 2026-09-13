from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
import socket

import pytest

from auto_code.contracts import EvidenceRef, RunState, RunnerIdentity, TicketSnapshot, TrustedPreparationInputRef
from auto_code.finalization_launcher import (
    FinalizationArtifactAuthority,
    FinalizationArtifactError,
    FinalizationLauncher,
    FinalizationLauncherRuntime,
)
from auto_code.finalization_service import FinalizationKeyAuthority
from auto_code.prepare import PreparationContext, PreparationContextAuthority
from auto_code.state import EMPTY_STATE_HASH, RunStateStore


def _runner_identity() -> RunnerIdentity:
    return RunnerIdentity(
        content_hash="a" * 64,
        source_sha="b" * 64,
        dependency_lock_hash="c" * 64,
        contract_bundle_hash="d" * 64,
        runner_archive_hash="e" * 64,
        built_at=datetime(2026, 9, 13, tzinfo=UTC),
    )


def _snapshot(ticket_id: str) -> TicketSnapshot:
    return TicketSnapshot.from_untrusted(
        {"id": ticket_id, "title": "Finalize safely"},
        captured_at=datetime(2026, 9, 13, tzinfo=UTC),
        pagination_complete=True,
        source_page_hashes={"page-1": "f" * 64},
    )


def _preparation_ref() -> TrustedPreparationInputRef:
    return TrustedPreparationInputRef(
        input_id="11111111-1111-4111-8111-111111111111",
        relative_path="trusted-mcp/preparation/11111111-1111-4111-8111-111111111111.json",
        repository_id="repo-1",
        reservation_id="reservation-1",
        challenge_hash="b" * 64,
        input_hash="c" * 64,
        query_hash="d" * 64,
        payload_hash="e" * 64,
        result_hash="f" * 64,
        source_page_hashes={"page-1": "a" * 64},
        pagination_complete=True,
        max_crew_iterations=1,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        tool_call_id="tool-call-1",
        captured_at=datetime(2026, 9, 13, tzinfo=UTC),
        observations=("Trusted preparation input captured.",),
        bridge_signature="0" * 64,
    )


def _persisted_run(state_root: Path) -> tuple[RunStateStore, object]:
    binding = FinalizationKeyAuthority(state_root).provision("reservation-1")
    store = RunStateStore(state_root, "run-1")
    generation = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(
            run_id="run-1",
            ticket_id="ENG-1",
            repository_id="repo-1",
            max_crew_iterations=1,
            finalization_public_key=binding.public_key,
            finalization_public_key_hash=binding.public_key_hash,
        ),
    )
    return store, generation


def test_launcher_issues_a_finalize_descriptor_from_the_exact_active_run(tmp_path: Path) -> None:
    """Removing launcher key composition would leave the descriptor unsigned or unbound."""

    store, generation = _persisted_run(tmp_path)
    socket_path = tmp_path / "finalization.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    try:
        launcher = FinalizationLauncher.from_runtime(
            FinalizationLauncherRuntime(state_root=tmp_path)
        )

        descriptor = launcher.serve_descriptor(
            "run-1",
            generation.revision,
            generation.state_hash,
            socket_path=socket_path,
        )
    finally:
        listener.close()

    assert descriptor.operation == "finalize"
    assert descriptor.run_id == "run-1"
    assert descriptor.expected_revision == generation.revision
    assert descriptor.expected_state_hash == generation.state_hash


def test_artifact_authority_rejects_a_preparation_baseline_for_another_ticket(tmp_path: Path) -> None:
    """Trusting state or artifact input over Preparation Context would permit ticket substitution."""

    _, generation = _persisted_run(tmp_path)
    snapshot = _snapshot("ENG-2")
    preparation_ref = _preparation_ref()
    context = PreparationContext(
        run_id="run-1",
        repository_id="repo-1",
        ticket_snapshot=snapshot,
        ticket_snapshot_hash=snapshot.content_hash,
        original_state_id="started",
        original_external_revision="revision-1",
        preparation_input_ref=preparation_ref,
        preparation_input_hash=preparation_ref.input_hash,
        compatibility_receipt_hash="e" * 64,
        compatibility_receipt_ref=EvidenceRef(
            relative_path="trusted-launcher/compatibility/11111111-1111-4111-8111-111111111111.json",
            sha256="e" * 64,
            media_type="application/json",
            creator="trusted-launcher",
        ),
        runner_identity=_runner_identity(),
    )
    PreparationContextAuthority(tmp_path).write_new(context)

    with pytest.raises(FinalizationArtifactError, match="ticket baseline"):
        FinalizationArtifactAuthority(tmp_path).load_for(generation.state)
