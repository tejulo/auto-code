from __future__ import annotations

import array
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auto_code.contracts import (
    EvidenceRef,
    ReviewManifest,
    RunState,
    RunnerIdentity,
    Stage,
    StageOutput,
    TicketSnapshot,
    TrustedPreparationInputRef,
    RunDisposition,
)
from auto_code.hashing import canonical_json_bytes
from auto_code.run_index import ActiveRunIndex
from launcher_finalization import (
    FinalizationArtifactAuthority,
    FinalizationArtifactError,
    FinalizationLauncher,
    FinalizationLauncherError,
    _LauncherRuntime as FinalizationLauncherRuntime,
)
from auto_code.finalization_service import (
    FinalizationCapabilityError,
    FinalizationParentCapability,
    _LauncherFinalizationServiceInternal,
)
from auto_code.prepare import PreparationContext, PreparationContextAuthority
from auto_code.process import LauncherSocketSandbox, SandboxChildEvidence, SandboxCompleted
from auto_code.state import EMPTY_STATE_HASH, RunStateStore


_BOOTSTRAP_TEST_KEY = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("11" * 32))


@dataclass
class _ForgedSandboxRecord:
    operations: list[str] = field(default_factory=list)
    received_descriptors: list[int] = field(default_factory=list)
    errors: list[BaseException] = field(default_factory=list)
    thread: threading.Thread | None = None


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


_SIGNING_KEYS: dict[Path, Ed25519PrivateKey] = {}


def _persisted_run(state_root: Path) -> tuple[RunStateStore, object]:
    signing_key = Ed25519PrivateKey.generate()
    public_key = signing_key.public_key().public_bytes_raw().hex()
    _SIGNING_KEYS[state_root] = signing_key
    store = RunStateStore(state_root, "run-1")
    generation = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(
            run_id="run-1",
            ticket_id="ENG-1",
            repository_id="repo-1",
            max_crew_iterations=1,
            finalization_public_key=public_key,
            finalization_public_key_hash=__import__("hashlib").sha256(bytes.fromhex(public_key)).hexdigest(),
        ),
    )
    return store, generation


def _runtime(state_root: Path, index: object) -> FinalizationLauncherRuntime:
    signing_key = _SIGNING_KEYS.get(state_root)
    parent = None
    if signing_key is not None:
        key_hash = __import__("hashlib").sha256(signing_key.public_key().public_bytes_raw()).hexdigest()
        unsigned = {
            "domain": "auto-code-finalization-parent/v1",
            "public_key": _BOOTSTRAP_TEST_KEY.public_key().public_bytes_raw().hex(),
            "finalization_public_key_hash": key_hash,
        }
        parent = FinalizationParentCapability(
            public_key=unsigned["public_key"],
            finalization_public_key_hash=key_hash,
            signature=_BOOTSTRAP_TEST_KEY.sign(canonical_json_bytes(unsigned)).hex(),
        )
    return FinalizationLauncherRuntime(
        state_root=state_root,
        active_run_index=index,
        signing_key=signing_key,
        finalization_parent=parent,
    )


class ActiveIndexHarness:
    def __init__(
        self,
        state_root: Path,
        *,
        active: bool = True,
        run_id: str = "run-1",
        index_revision: int = 1,
        index_hash: str = "a" * 64,
    ) -> None:
        self.state_root = state_root
        self.active = active
        self.run_id = run_id
        self.index_revision = index_revision
        self.index_hash = index_hash

    def lookup(self, repository_id: str) -> object | None:
        if not self.active:
            return None
        return SimpleNamespace(
            repository_id=repository_id,
            run_id=self.run_id,
            index_revision=self.index_revision,
            index_hash=self.index_hash,
            state_root=self.state_root,
        )


def test_launcher_issues_a_finalize_descriptor_from_the_exact_active_run(tmp_path: Path) -> None:
    """Removing launcher key composition would leave the descriptor unsigned or unbound."""

    _, generation = _persisted_run(tmp_path)
    socket_path = tmp_path / "finalization.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    try:
        launcher = FinalizationLauncher(
            _runtime(tmp_path, ActiveIndexHarness(tmp_path))
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


def test_launcher_rejects_descriptor_issuance_after_the_active_run_index_is_released(tmp_path: Path) -> None:
    """Skipping index lookup would issue a capability for a released or replaced Active Run."""

    _, generation = _persisted_run(tmp_path)
    socket_path = tmp_path / "finalization.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    try:
        launcher = FinalizationLauncher(
            _runtime(tmp_path, ActiveIndexHarness(tmp_path, active=False))
        )

        with pytest.raises(FinalizationLauncherError, match="Active Run Index"):
            launcher.serve_descriptor("run-1", generation.revision, generation.state_hash, socket_path=socket_path)
    finally:
        listener.close()


def test_launcher_exposes_no_direct_finalizer_invocation(tmp_path: Path) -> None:
    """All launcher execution enters through an issued descriptor and durable nonce lifecycle."""

    launcher = FinalizationLauncher(
        _runtime(tmp_path, ActiveIndexHarness(tmp_path))
    )

    assert not hasattr(launcher, "serve")


def test_ticket_child_cannot_start_without_a_procfs_isolated_launcher_sandbox(tmp_path: Path) -> None:
    """A direct child can read FD 8 through procfs, so finalization must not spawn one."""

    _, generation = _persisted_run(tmp_path)
    launcher = FinalizationLauncher(_runtime(tmp_path, ActiveIndexHarness(tmp_path)))
    marker = tmp_path / "ticket-ran"
    key = tmp_path / "launcher-key"
    key.write_text("launcher-private-key", encoding="ascii")
    descriptor = os.open(key, os.O_RDONLY)
    saved_fd_eight = os.dup(8)
    ticket = (
        sys.executable,
        "-c",
        (
            "from pathlib import Path; import os; "
            f"Path({str(marker)!r}).write_bytes(open('/proc/%s/fd/8' % os.getppid(), 'rb').read()); "
            "from auto_code.finalization_service import invoke_protected_capability; "
            "invoke_protected_capability('finalize', 'run-1', "
            f"{generation.revision}, '{generation.state_hash}', None)"
        ),
    )
    try:
        os.dup2(descriptor, 8, inheritable=True)
        with pytest.raises(FinalizationLauncherError, match="sandbox"):
            launcher.serve_ticket_process("run-1", generation.revision, generation.state_hash, ticket)
    finally:
        os.dup2(saved_fd_eight, 8, inheritable=True)
        os.close(saved_fd_eight)
        os.close(descriptor)

    assert not marker.exists()


def test_launcher_prepares_verified_child_before_transferring_finalization_capabilities(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, generation = _persisted_run(tmp_path)
    actions: list[str] = []

    class PreparedChild:
        pid = 124

        def transfer_finalization_fds(self, capability_fds: tuple[int, int, int]) -> SandboxChildEvidence:
            assert tuple(os.pread(descriptor, 1, 0) for descriptor in capability_fds) == (b"{", b"{", b"{")
            actions.append("transfer")
            return SandboxChildEvidence("f" * 32, "e" * 64, 124, 456, 789, (0, 1, 2, 4, 5, 6), "0" * 128)

        def poll(self) -> int | None:
            return None

        def wait(self, timeout: float | None = None) -> SandboxCompleted:
            actions.append("wait")
            return SandboxCompleted(0)

        def terminate_group(self) -> None:
            actions.append("terminate")

        def kill_group(self) -> None:
            actions.append("kill")

    class SequencedSandbox(LauncherSocketSandbox):
        def __init__(self) -> None:
            pass

        def prepare_finalization_child(self, argv: tuple[str, ...]) -> PreparedChild:
            assert argv == (sys.executable, "-c", "pass")
            actions.append("prepare")
            return PreparedChild()

    monkeypatch.setattr(
        _LauncherFinalizationServiceInternal,
        "serve_once",
        lambda self, listener: actions.append("serve"),
    )
    runtime = replace(
        _runtime(tmp_path, ActiveIndexHarness(tmp_path)),
        sandbox=SequencedSandbox(),
    )

    result = FinalizationLauncher(runtime).serve_ticket_process(
        "run-1",
        generation.revision,
        generation.state_hash,
        (sys.executable, "-c", "pass"),
    )

    assert result == 0
    assert actions == ["prepare", "transfer", "serve", "wait"]


def test_launcher_kills_child_when_post_transfer_evidence_is_not_only_456(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _, generation = _persisted_run(tmp_path)
    actions: list[str] = []

    class PreparedChild:
        pid = 124

        def transfer_finalization_fds(self, capability_fds: tuple[int, int, int]) -> SandboxChildEvidence:
            actions.append("transfer")
            return SandboxChildEvidence("f" * 32, "e" * 64, 124, 456, 789, (0, 1, 2, 4, 5), "0" * 128)

        def wait(self, timeout: float | None = None) -> SandboxCompleted:
            actions.append("wait")
            return SandboxCompleted(-9)

        def terminate_group(self) -> None:
            actions.append("terminate")

        def kill_group(self) -> None:
            actions.append("kill")

    class SequencedSandbox(LauncherSocketSandbox):
        def __init__(self) -> None:
            pass

        def prepare_finalization_child(self, argv: tuple[str, ...]) -> PreparedChild:
            return PreparedChild()

    monkeypatch.setattr(
        _LauncherFinalizationServiceInternal,
        "serve_once",
        lambda self, listener: actions.append("serve"),
    )
    runtime = replace(
        _runtime(tmp_path, ActiveIndexHarness(tmp_path)),
        sandbox=SequencedSandbox(),
    )

    with pytest.raises(FinalizationLauncherError, match="lifecycle"):
        FinalizationLauncher(runtime).serve_ticket_process(
            "run-1",
            generation.revision,
            generation.state_hash,
            (sys.executable, "-c", "pass"),
        )

    assert actions == ["transfer", "kill", "wait"]


def test_launcher_reaps_child_and_reports_kill_failure_after_invalid_post_transfer_evidence(
    tmp_path: Path,
) -> None:
    _, generation = _persisted_run(tmp_path)
    actions: list[str] = []

    class PreparedChild:
        pid = 124

        def transfer_finalization_fds(self, capability_fds: tuple[int, int, int]) -> SandboxChildEvidence:
            actions.append("transfer")
            return SandboxChildEvidence("f" * 32, "e" * 64, 124, 456, 789, (0, 1, 2, 4, 5), "0" * 128)

        def wait(self, timeout: float | None = None) -> SandboxCompleted:
            actions.append("wait")
            return SandboxCompleted(-9)

        def terminate_group(self) -> None:
            actions.append("terminate")

        def kill_group(self) -> None:
            actions.append("kill")
            raise OSError("sandbox kill failed")

    class SequencedSandbox(LauncherSocketSandbox):
        def __init__(self) -> None:
            pass

        def prepare_finalization_child(self, argv: tuple[str, ...]) -> PreparedChild:
            return PreparedChild()

    runtime = replace(
        _runtime(tmp_path, ActiveIndexHarness(tmp_path)),
        sandbox=SequencedSandbox(),
    )

    with pytest.raises(FinalizationLauncherError, match="cleanup failed") as raised:
        FinalizationLauncher(runtime).serve_ticket_process(
            "run-1",
            generation.revision,
            generation.state_hash,
            (sys.executable, "-c", "pass"),
        )

    assert actions == ["transfer", "kill", "wait"]
    assert isinstance(raised.value.__cause__, OSError)


def test_launcher_reports_both_cleanup_failures_after_invalid_post_transfer_evidence(tmp_path: Path) -> None:
    _, generation = _persisted_run(tmp_path)
    actions: list[str] = []

    class PreparedChild:
        pid = 124

        def transfer_finalization_fds(self, capability_fds: tuple[int, int, int]) -> SandboxChildEvidence:
            actions.append("transfer")
            return SandboxChildEvidence("f" * 32, "e" * 64, 124, 456, 789, (0, 1, 2, 4, 5), "0" * 128)

        def wait(self, timeout: float | None = None) -> SandboxCompleted:
            actions.append("wait")
            raise OSError("sandbox reap failed")

        def terminate_group(self) -> None:
            actions.append("terminate")

        def kill_group(self) -> None:
            actions.append("kill")
            raise OSError("sandbox kill failed")

    class SequencedSandbox(LauncherSocketSandbox):
        def __init__(self) -> None:
            pass

        def prepare_finalization_child(self, argv: tuple[str, ...]) -> PreparedChild:
            return PreparedChild()

    runtime = replace(
        _runtime(tmp_path, ActiveIndexHarness(tmp_path)),
        sandbox=SequencedSandbox(),
    )

    with pytest.raises(FinalizationLauncherError, match="cleanup failed") as raised:
        FinalizationLauncher(runtime).serve_ticket_process(
            "run-1",
            generation.revision,
            generation.state_hash,
            (sys.executable, "-c", "pass"),
        )

    assert actions == ["transfer", "kill", "wait"]
    assert isinstance(raised.value.__cause__, ExceptionGroup)
    assert {str(error) for error in raised.value.__cause__.exceptions} == {
        "sandbox kill failed",
        "sandbox reap failed",
    }


@pytest.mark.parametrize(
    "index",
    (
        lambda root: ActiveIndexHarness(root, run_id="run-2"),
        lambda root: ActiveIndexHarness(root, index_revision=0),
        lambda root: ActiveIndexHarness(root, index_hash="invalid"),
    ),
)
def test_launcher_rejects_nonexact_active_run_index_bindings(
    tmp_path: Path,
    index: object,
) -> None:
    """Accepting a stale index binding would authorize finalization for another Active Run."""

    _, generation = _persisted_run(tmp_path)
    socket_path = tmp_path / "finalization.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    try:
        launcher = FinalizationLauncher(
            _runtime(tmp_path, index(tmp_path))
        )

        with pytest.raises(FinalizationLauncherError, match="Active Run Index"):
            launcher.serve_descriptor("run-1", generation.revision, generation.state_hash, socket_path=socket_path)
    finally:
        listener.close()


def test_artifact_authority_rejects_duplicate_openspec_stage_outputs_before_hash_mapping() -> None:
    """Collapsing duplicate stages in a dict would hide a conflicting approved artifact."""

    state = RunState.model_construct(
        run_id="run-1",
        ticket_id="ENG-1",
        repository_id="repo-1",
        max_crew_iterations=1,
        stage_outputs=(
            StageOutput(stage=Stage.ARCHITECT_PROPOSAL, content_hash="a" * 64),
            StageOutput(stage=Stage.ARCHITECT_PROPOSAL, content_hash="b" * 64),
        ),
    )
    review = ReviewManifest(
        baseline_sha="a" * 40,
        requirements_package_hash="a" * 64,
        change_outline_hash="a" * 64,
        artifact_hashes={"proposal": "a" * 64, "specs": "c" * 64, "design": "d" * 64, "tasks": "e" * 64},
        task_definition_hash="a" * 64,
        task_status_hash="a" * 64,
        product_manifest_hash="a" * 64,
        build_identity_hash="a" * 64,
        project_policy_hash="a" * 64,
        verification_result_hash="a" * 64,
        browser_result_hash="a" * 64,
    )

    with pytest.raises(FinalizationArtifactError, match="duplicate"):
        FinalizationArtifactAuthority._artifact_hashes(state, review)


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


def _write_bootstrap_descriptor(path: Path, payload: object) -> int:
    path.write_bytes(canonical_json_bytes(payload))
    path.chmod(0o600)
    return os.open(path, os.O_RDONLY)


def _installed_launcher_result(
    tmp_path: Path,
    *,
    mutate_bootstrap: bool = False,
    substitute: str | None = None,
    forged_sandbox: _ForgedSandboxRecord | None = None,
) -> subprocess.CompletedProcess[str]:
    state_root = tmp_path / "state"
    state_root.mkdir(mode=0o700)
    repository = tmp_path / "repository"
    repository.mkdir(mode=0o700)
    signing_key = Ed25519PrivateKey.generate()
    state = RunState(
        run_id="run-1",
        ticket_id="ENG-1",
        repository_id="repo-1",
        max_crew_iterations=1,
        disposition=RunDisposition.HUMAN_REVIEW,
        finalization_public_key=signing_key.public_key().public_bytes_raw().hex(),
        finalization_public_key_hash=__import__("hashlib").sha256(signing_key.public_key().public_bytes_raw()).hexdigest(),
    )
    from tests.state_fixtures import DeterministicPreparationInputVerifier

    index = ActiveRunIndex(
        state_root,
        finalization_signing_key=signing_key,
        preparation_input_verifier=DeterministicPreparationInputVerifier(),
    )
    reservation = index.reserve("repo-1")
    from tests.state_fixtures import activation_request

    active = index.activate_reservation(activation_request(reservation, initial_state=state))
    generation = RunStateStore(state_root, active.run_id).load()
    key_hash = __import__("hashlib").sha256(signing_key.public_key().public_bytes_raw()).hexdigest()
    bridge_client, bridge_server = socket.socketpair()
    replacement_client: socket.socket | None = None
    replacement_server: socket.socket | None = None
    sandbox_listener: socket.socket | None = None
    sandbox_thread: threading.Thread | None = None
    descriptor_paths = [tmp_path / f"bootstrap-{number}.json" for number in range(3, 9)]
    key_path = tmp_path / "finalization-key.bin"
    key_path.write_bytes(signing_key.private_bytes_raw())
    key_path.chmod(0o600)
    descriptors: list[int] = []
    try:
        state_descriptor = {"domain": "auto-code-launcher-state/v1", "state_root": str(state_root)}
        index_descriptor = {
            "domain": "auto-code-launcher-index/v1",
            "state_root": str(state_root),
            "finalization_public_key_hash": key_hash,
        }
        bridge_descriptor = {
            "domain": "auto-code-launcher-bridge/v1",
            "state_root": str(state_root),
            "bridge_identity": "launcher-bridge",
            "mcp_server_identity": "linear-mcp",
            "receipt_signing_key": "22" * 16,
            "transport_fd": 9,
        }
        git_descriptor = {
            "domain": "auto-code-launcher-git/v1",
            "repository_root": str(repository),
            "remote": "origin",
            "base_branch": None,
            "protected_paths": [],
            "commit_excluded_paths": [],
        }
        transport_metadata = os.fstat(bridge_client.fileno())
        peer_pid, peer_uid, peer_gid = struct.unpack(
            "3i",
            bridge_client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")),
        )
        parent = {
            "domain": "auto-code-finalization-parent/v1",
            "public_key": _BOOTSTRAP_TEST_KEY.public_key().public_bytes_raw().hex(),
            "finalization_public_key_hash": key_hash,
        }
        parent["signature"] = _BOOTSTRAP_TEST_KEY.sign(canonical_json_bytes(parent)).hex()
        config = {
            "domain": "auto-code-launcher-bootstrap/v1",
            "state_root": str(state_root),
            "repository_root": str(repository),
            "bridge_identity": "launcher-bridge",
            "mcp_server_identity": "linear-mcp",
            "bridge_fd": 6,
            "state_fd": 4,
            "index_fd": 5,
            "git_fd": 7,
            "key_fd": 8,
            "state_sha256": __import__("hashlib").sha256(canonical_json_bytes(state_descriptor)).hexdigest(),
            "index_sha256": __import__("hashlib").sha256(canonical_json_bytes(index_descriptor)).hexdigest(),
            "bridge_sha256": __import__("hashlib").sha256(canonical_json_bytes(bridge_descriptor)).hexdigest(),
            "git_sha256": __import__("hashlib").sha256(canonical_json_bytes(git_descriptor)).hexdigest(),
            "key_sha256": __import__("hashlib").sha256(key_path.read_bytes()).hexdigest(),
            "bridge_transport_device": transport_metadata.st_dev,
            "bridge_transport_inode": transport_metadata.st_ino,
            "bridge_transport_peer_pid": peer_pid,
            "bridge_transport_peer_uid": peer_uid,
            "bridge_transport_peer_gid": peer_gid,
            "finalization_public_key_hash": key_hash,
            "finalization_parent": parent,
        }
        if forged_sandbox is not None:
            sandbox_key = Ed25519PrivateKey.generate()
            forged_key = Ed25519PrivateKey.generate()
            sandbox_path = tmp_path / "sandbox.sock"
            sandbox_listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sandbox_listener.bind(str(sandbox_path))
            sandbox_listener.listen(3)

            def serve_forged_sandbox() -> None:
                try:
                    assert sandbox_listener is not None
                    connection, _ = sandbox_listener.accept()
                    with connection:
                        request = json.loads(connection.makefile("rb").readline())
                        forged_sandbox.operations.append(request["operation"])
                        child_id = "f" * 32
                        evidence = {
                            "domain": "auto-code-sandbox-child-evidence/v1",
                            "sandbox_identity": "launcher",
                            "challenge": request["challenge"],
                            "child_id": child_id,
                            "pid": 124,
                            "pid_namespace_inode": 456,
                            "mount_namespace_inode": 789,
                            "fd_numbers": [],
                        }
                        connection.sendall(
                            canonical_json_bytes(
                                {
                                    "child_id": child_id,
                                    "evidence": {
                                        **{
                                            key: value
                                            for key, value in evidence.items()
                                            if key not in {"domain", "sandbox_identity"}
                                        },
                                        "signature": forged_key.sign(canonical_json_bytes(evidence)).hex(),
                                    },
                                }
                            )
                            + b"\n"
                        )
                        descriptors = array.array("i")
                        try:
                            raw, ancillary, flags, _ = connection.recvmsg(
                                65_536,
                                socket.CMSG_SPACE(64 * descriptors.itemsize),
                            )
                            if flags & socket.MSG_CTRUNC:
                                raise RuntimeError("sandbox ancillary data was truncated")
                            for level, kind, data in ancillary:
                                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                                    descriptors.frombytes(data[: len(data) - (len(data) % descriptors.itemsize)])
                            forged_sandbox.received_descriptors.extend(descriptors)
                            if raw:
                                forged_sandbox.operations.append(json.loads(raw)["operation"])
                        finally:
                            for descriptor in descriptors:
                                try:
                                    os.close(descriptor)
                                except OSError:
                                    pass
                except BaseException as error:
                    forged_sandbox.errors.append(error)

            sandbox_thread = threading.Thread(target=serve_forged_sandbox)
            forged_sandbox.thread = sandbox_thread
            sandbox_thread.start()
            config.update(
                {
                    "sandbox_socket_path": str(sandbox_path),
                    "sandbox_identity": "launcher",
                    "sandbox_public_key": sandbox_key.public_key().public_bytes_raw().hex(),
                }
            )
        config["signature"] = _BOOTSTRAP_TEST_KEY.sign(canonical_json_bytes(config)).hex()
        payloads = (config, state_descriptor, index_descriptor, bridge_descriptor, git_descriptor)
        if mutate_bootstrap:
            payloads = ({"domain": "attacker"}, *payloads[1:])
        if substitute == "state":
            payloads = (
                payloads[0],
                {**state_descriptor, "state_root": str(tmp_path / "attacker-state")},
                payloads[2],
                payloads[3],
                payloads[4],
            )
        if substitute == "index":
            payloads = (
                payloads[0],
                payloads[1],
                {**index_descriptor, "finalization_public_key_hash": "0" * 64},
                payloads[3],
                payloads[4],
            )
        if substitute == "bridge":
            payloads = (
                payloads[0],
                payloads[1],
                payloads[2],
                {**bridge_descriptor, "receipt_signing_key": "33" * 16},
                payloads[4],
            )
        if substitute == "git":
            payloads = (
                payloads[0],
                payloads[1],
                payloads[2],
                payloads[3],
                {**git_descriptor, "remote": "attacker"},
            )
        if substitute == "key":
            replacement_key = Ed25519PrivateKey.generate()
            key_path.write_bytes(replacement_key.private_bytes_raw())
        if substitute == "transport":
            replacement_client, replacement_server = socket.socketpair()
        for path, payload in zip(descriptor_paths[:5], payloads, strict=True):
            descriptors.append(_write_bootstrap_descriptor(path, payload))
        descriptors.append(os.open(key_path, os.O_RDONLY))
        wrapper = (
            "import os, sys; sources=[os.dup(int(source)) for source in sys.argv[1:8]]; "
            "[(os.dup2(source, target, inheritable=True)) for target, source in enumerate(sources[:6], 3)]; "
            "os.dup2(sources[6], 9, inheritable=True); "
            "[(os.set_inheritable(target, True)) for target in (*range(3, 9), 9)]; "
            "os.execv(sys.argv[8], sys.argv[8:])"
        )
        return subprocess.run(
            [
                sys.executable,
                "-c",
                wrapper,
                *(str(descriptor) for descriptor in descriptors),
                str((replacement_client or bridge_client).fileno()),
                str(Path(sys.executable).with_name("auto-code-launcher")),
                "finalize",
                "--run",
                "run-1",
                "--expected-revision",
                str(generation.revision),
                "--expected-hash",
                generation.state_hash,
            ],
            capture_output=True,
            check=False,
            text=True,
            pass_fds=(*descriptors, (replacement_client or bridge_client).fileno()),
        )
    finally:
        for descriptor in descriptors:
            os.close(descriptor)
        bridge_client.close()
        bridge_server.close()
        if replacement_client is not None:
            replacement_client.close()
        if replacement_server is not None:
            replacement_server.close()
        if sandbox_listener is not None:
            sandbox_listener.close()
        if sandbox_thread is not None:
            sandbox_thread.join(timeout=3)


def test_installed_launcher_fails_closed_without_a_procfs_isolation_capability(tmp_path: Path) -> None:
    """A bootstrap without a verified sandbox cannot safely start a ticket child."""

    result = _installed_launcher_result(tmp_path)

    assert result.returncode == 2
    assert result.stderr == "auto-code-launcher: protected runtime unavailable\n"


def test_installed_launcher_refuses_forged_evidence_before_capability(tmp_path: Path) -> None:
    """A forged preparation proof must fail closed before the ticket receives capability FDs."""

    sandbox = _ForgedSandboxRecord()
    result = _installed_launcher_result(tmp_path, forged_sandbox=sandbox)

    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == "auto-code-launcher: protected runtime unavailable\n"
    assert sandbox.operations == ["prepare_finalization_child"]
    assert sandbox.received_descriptors == []
    assert sandbox.errors == []
    assert sandbox.thread is not None
    assert not sandbox.thread.is_alive()


def test_protected_bootstrap_requires_a_procfs_isolation_capability_even_with_a_valid_socketpair(tmp_path: Path) -> None:
    """A bridge transport alone cannot make the ticket process isolated."""

    result = _installed_launcher_result(tmp_path)

    assert result.returncode == 2
    assert result.stderr == "auto-code-launcher: protected runtime unavailable\n"


def test_installed_launcher_rejects_a_replaced_bootstrap_descriptor(tmp_path: Path) -> None:
    """Accepting substituted bootstrap data would let a ticket replace launcher authority."""

    result = _installed_launcher_result(tmp_path, mutate_bootstrap=True)

    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == "auto-code-launcher: protected runtime unavailable\n"


@pytest.mark.parametrize("substitute", ("state", "index", "bridge", "git", "key", "transport"))
def test_installed_launcher_rejects_every_substituted_bootstrap_capability(
    tmp_path: Path,
    substitute: str,
) -> None:
    """Removing an envelope capability binding would authorize an attacker substitution."""

    result = _installed_launcher_result(tmp_path, substitute=substitute)

    assert result.returncode == 2
    assert result.stdout == ""
    assert result.stderr == "auto-code-launcher: protected runtime unavailable\n"
