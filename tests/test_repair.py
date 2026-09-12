from __future__ import annotations

from datetime import UTC, datetime
from dataclasses import replace
import json
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auto_code.checkpoint import CheckpointAuthority
from auto_code.cli import TrustedRuntimeConfig, main as ticket_main
from auto_code.contracts import RunnerIdentity, RunDisposition, RunState, Stage, StageOutput
from auto_code import repair_entrypoint
from auto_code.repair import (
    InjectedCrash,
    MissingRepairPlanError,
    RepairGuard,
    RepairPlan,
    RepairTicketOverlap,
    UnauthorizedRepairError,
)
from auto_code.runner import RepairRunner, RunnerActivationReceipt, RunnerRegistry, TrustedLauncher
from auto_code.state import EMPTY_STATE_HASH, RunStateStore, _atomic_replace_json, _path_lstat, _write_new_json
from auto_code.hashing import canonical_json_bytes


NOW = datetime(2026, 9, 12, tzinfo=UTC)


def identity(character: str, *, contract: str = "d") -> RunnerIdentity:
    return RunnerIdentity(
        content_hash=character * 64,
        source_sha="b" * 64,
        dependency_lock_hash="c" * 64,
        contract_bundle_hash=contract * 64,
        built_at=NOW,
    )


def repair_descriptor_payload(tmp_path: Path, *, expiry: str = "2030-01-01T00:00:00+00:00") -> dict[str, object]:
    return {
        "repair_runner_identity": identity("e").model_dump(mode="json"),
        "registry_root": str(tmp_path / "registry"),
        "state_root": str(tmp_path / "state"),
        "repair_workspace_root": str(tmp_path / "repair-workspaces"),
        "regression_command": ["pytest", "tests/test_repair.py"],
        "expiry": expiry,
        "nonce": "f" * 64,
    }


def signed_repair_descriptor(tmp_path: Path, *, expiry: str = "2030-01-01T00:00:00+00:00") -> bytes:
    payload = repair_descriptor_payload(tmp_path, expiry=expiry)
    signature = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex("a5e8e70e8f786ccf0020ae4dcdbcf1a6b2d687e65c7a179ef23def7bfb6a02ad")
    ).sign(canonical_json_bytes(payload)).hex()
    return json.dumps({"payload": payload, "signature": signature}).encode("ascii")


def protected_activation(registry: RunnerRegistry):
    """Test-only activation harness; production composition is reachable only from the verified runtime."""
    def activate(request, new_runner_identity):
        path = registry.activation_path(request.content_hash)
        if _path_lstat(path, "runner activation receipt") is not None:
            return registry.lookup_activation(request.content_hash)
        receipt = RunnerActivationReceipt(
            request_hash=request.content_hash,
            old_runner_identity=request.old_runner_identity,
            new_runner_identity=new_runner_identity,
            old_contract_bundle_hash=request.old_runner_identity.contract_bundle_hash,
            new_contract_bundle_hash=new_runner_identity.contract_bundle_hash,
            compatible_checkpoint_stages=(),
            contract_hashes=dict(request.contract_hashes),
        )
        _write_new_json(path, receipt.payload())
        _atomic_replace_json(registry.pointer_path, {"request_hash": request.content_hash})
        if registry._crash_marker == "REGISTRY_POINTER_REPLACED":
            registry._crash_marker = None
            raise InjectedCrash("injected crash after registry pointer replacement")
        return receipt

    return activate


class FakeWorktreeFactory:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir()

    def create(self, handle_id: str) -> Path:
        path = self.root / handle_id
        path.mkdir()
        (path / "src" / "auto_code").mkdir(parents=True)
        (path / "src" / "auto_code" / "runner.py").write_text("baseline", encoding="ascii")
        return path


class FakeRepairGit:
    def __init__(self, changed: set[str] | None = None) -> None:
        self.changed = changed or set()

    def baseline_hash(self, workspace: Path) -> str:
        return "1" * 64

    def changed_paths_since(self, workspace: Path, baseline_hash: str) -> set[str]:
        assert baseline_hash == "1" * 64
        return self.changed

    def source_hash(self, workspace: Path) -> str:
        return "2" * 64

    def dependency_lock_hash(self, workspace: Path) -> str:
        return "3" * 64


class FakeProcess:
    def __init__(self) -> None:
        self.commands: list[tuple[tuple[str, ...], Path]] = []

    def run(self, argv: tuple[str, ...], workspace: Path) -> None:
        self.commands.append((argv, workspace))


@pytest.fixture
def repair_launcher(tmp_path: Path) -> RepairRunner:
    registry = RunnerRegistry(tmp_path / "state", repair_runner_identity=identity("e"))
    return RepairRunner(
        worktree_factory=FakeWorktreeFactory(tmp_path / "repair-worktrees"),
        git=FakeRepairGit(),
        process=FakeProcess(),
        registry=registry,
        repair_runner_identity=identity("e"),
        activate=protected_activation(registry),
        now=lambda: NOW,
    )


@pytest.fixture
def valid_repair_plan() -> RepairPlan:
    return RepairPlan(
        root_cause="The supervisor's activation check is incomplete.",
        files=("src/auto_code/runner.py",),
        change="Validate and journal the activation before a restart.",
        regression_command=("pytest", "tests/test_repair.py"),
        evidence=("failure-evidence-hash",),
    )


def repair_request(repair_launcher: RepairRunner, plan: RepairPlan, *, contracts: dict[Stage, str] | None = None):
    workspace = repair_launcher.prepare_workspace("run-1", "f" * 64, identity("a"))
    guard = RepairGuard(workspace.path)
    baseline = guard.capture_baseline(workspace)
    return guard.create_request(
        plan,
        baseline,
        ticket_product_manifest="9" * 64,
        run_id="run-1",
        ticket_repository_id="ticket-repository",
        repair_repository_id="repair-repository",
        old_runner_identity=identity("a"),
        project_policy_hash="8" * 64,
        ticket_owned_paths=(),
        contract_hashes=contracts or {},
    )


def test_repair_requires_a_valid_plan(repair_launcher: RepairRunner) -> None:
    """Removing plan-path validation would let an unreviewed repair enter the gate."""
    workspace = repair_launcher.prepare_workspace("run-1", "f" * 64, identity("a"))

    with pytest.raises(MissingRepairPlanError):
        RepairGuard(workspace.path).validate_path(workspace.path / "missing.json")


def test_repair_rejects_unplanned_product_file(
    tmp_path: Path,
    valid_repair_plan: RepairPlan,
) -> None:
    """Dropping automation-path checks would permit a repair to change product code."""
    git = FakeRepairGit({"product.py"})
    registry = RunnerRegistry(tmp_path / "state", repair_runner_identity=identity("e"))
    launcher = RepairRunner(
        worktree_factory=FakeWorktreeFactory(tmp_path / "repair-worktrees"),
        git=git,
        process=FakeProcess(),
        registry=registry,
        repair_runner_identity=identity("e"),
        activate=protected_activation(registry),
        now=lambda: NOW,
    )
    request = repair_request(launcher, valid_repair_plan)

    with pytest.raises(UnauthorizedRepairError, match="product.py"):
        launcher.validate_build_activate(request)


def test_repair_rejects_path_owned_by_same_repository_ticket(
    tmp_path: Path,
    valid_repair_plan: RepairPlan,
) -> None:
    """Removing same-repository overlap detection would let repair alter ticket-owned files."""
    git = FakeRepairGit({"src/auto_code/runner.py"})
    registry = RunnerRegistry(tmp_path / "state", repair_runner_identity=identity("e"))
    launcher = RepairRunner(
        worktree_factory=FakeWorktreeFactory(tmp_path / "repair-worktrees"),
        git=git,
        process=FakeProcess(),
        registry=registry,
        repair_runner_identity=identity("e"),
        activate=protected_activation(registry),
        now=lambda: NOW,
    )
    workspace = launcher.prepare_workspace("run-1", "f" * 64, identity("a"))
    guard = RepairGuard(workspace.path)
    request = guard.create_request(
        valid_repair_plan,
        guard.capture_baseline(workspace),
        ticket_product_manifest="9" * 64,
        run_id="run-1",
        ticket_repository_id="same-repository",
        repair_repository_id="same-repository",
        old_runner_identity=identity("a"),
        project_policy_hash="8" * 64,
        ticket_owned_paths=("src/auto_code/runner.py",),
        contract_hashes={},
    )

    with pytest.raises(RepairTicketOverlap):
        launcher.validate_build_activate(request)


def test_active_runner_cannot_activate_itself(tmp_path: Path, valid_repair_plan: RepairPlan) -> None:
    """Allowing the ticket runner to activate a repair would remove the independent gate."""
    registry = RunnerRegistry(tmp_path / "state", repair_runner_identity=identity("e"))
    launcher = RepairRunner(
        worktree_factory=FakeWorktreeFactory(tmp_path / "repair-worktrees"),
        git=FakeRepairGit({"src/auto_code/runner.py"}),
        process=FakeProcess(),
        registry=registry,
        repair_runner_identity=identity("e"),
        activate=protected_activation(registry),
        now=lambda: NOW,
    )
    assert launcher.registry is registry
    assert not hasattr(registry, "activate")


def test_activation_revalidates_contracts_before_restart(
    tmp_path: Path,
    valid_repair_plan: RepairPlan,
) -> None:
    """Keeping a descendant checkpoint after its contract changes would reuse invalid work."""
    git = FakeRepairGit({"src/auto_code/runner.py"})
    registry = RunnerRegistry(tmp_path / "registry", repair_runner_identity=identity("e"))
    repair_launcher = RepairRunner(
        worktree_factory=FakeWorktreeFactory(tmp_path / "repair-worktrees"),
        git=git,
        process=FakeProcess(),
        registry=registry,
        repair_runner_identity=identity("e"),
        activate=protected_activation(registry),
        now=lambda: NOW,
    )
    authority = CheckpointAuthority(tmp_path / "state")
    analyst = authority.issue(
        stage=Stage.ANALYST,
        contract_hash="1" * 64,
        input_hashes={"ticket": "2" * 64},
        output_manifest_hash="3" * 64,
        validator="validator",
        validator_version="1",
        validation_receipt_hash="4" * 64,
    )
    programmer = authority.issue(
        stage=Stage.PROGRAMMER,
        contract_hash="5" * 64,
        input_hashes={"task": "6" * 64},
        output_manifest_hash="7" * 64,
        validator="validator",
        validator_version="1",
        validation_receipt_hash="8" * 64,
    )
    store = RunStateStore(tmp_path / "state", "run-1")
    initial = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3),
    )
    repair_state = store.compare_and_swap(
        initial.revision,
        initial.state_hash,
        initial.state.model_copy(
            update={
                "disposition": RunDisposition.REPAIR_REQUIRED,
                "runner_identity": identity("a"),
                "checkpoints": {Stage.ANALYST: analyst, Stage.PROGRAMMER: programmer},
                "stage_outputs": (
                    StageOutput(stage=Stage.ANALYST, content_hash="3" * 64),
                    StageOutput(stage=Stage.PROGRAMMER, content_hash="7" * 64),
                ),
            }
        ),
    )
    request = repair_request(repair_launcher, valid_repair_plan, contracts={Stage.ANALYST: "0" * 64})

    activation = repair_launcher.validate_build_activate(request)
    generation = TrustedLauncher(store, registry).reconcile_activation("run-1", request.content_hash)

    assert generation.state.runner_identity == activation.new_runner_identity
    assert generation.state.checkpoints == {}
    assert tuple(generation.state.checkpoints) == activation.compatible_checkpoint_stages
    assert TrustedLauncher(store, registry).restart_receipt("run-1").runner_identity == activation.new_runner_identity
    assert repair_state.state.runner_identity == identity("a")


def test_crash_after_registry_activation_recovers_receipt(
    tmp_path: Path,
    valid_repair_plan: RepairPlan,
) -> None:
    """Rebuilding after an activation-pointer crash could activate divergent runner bytes."""
    git = FakeRepairGit({"src/auto_code/runner.py"})
    registry = RunnerRegistry(tmp_path / "registry", repair_runner_identity=identity("e"))
    repair_launcher = RepairRunner(
        worktree_factory=FakeWorktreeFactory(tmp_path / "repair-worktrees"),
        git=git,
        process=FakeProcess(),
        registry=registry,
        repair_runner_identity=identity("e"),
        activate=protected_activation(registry),
        now=lambda: NOW,
    )
    store = RunStateStore(tmp_path / "state", "run-1")
    initial = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3),
    )
    store.compare_and_swap(
        initial.revision,
        initial.state_hash,
        initial.state.model_copy(update={"disposition": RunDisposition.REPAIR_REQUIRED, "runner_identity": identity("a")}),
    )
    request = repair_request(repair_launcher, valid_repair_plan)
    repair_launcher.crash_after("REGISTRY_POINTER_REPLACED")

    with pytest.raises(InjectedCrash):
        repair_launcher.validate_build_activate(request)

    activation = registry.lookup_activation(request.content_hash)
    generation = TrustedLauncher(store, registry).reconcile_activation("run-1", request.content_hash)

    assert generation.state.runner_identity == activation.new_runner_identity
    assert registry.lookup_activation(request.content_hash) == activation


def test_ticket_repair_request_binds_the_expected_state_and_prints_only_its_hash(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Skipping the expected-state binding would let a stale ticket runner request a repair."""
    project = tmp_path / "project"
    project.mkdir()
    runtime = TrustedRuntimeConfig(
        state_root=tmp_path / "state",
        project_root=project,
        project_policy_path=project / "auto-code.yaml",
        project_policy_hash="8" * 64,
        runner_identity=identity("a"),
    )
    calls: list[tuple[str, int, str, Path, Path]] = []

    class Coordinator:
        def create_request(self, run_id: str, revision: int, state_hash: str, workspace: Path, plan: Path) -> object:
            calls.append((run_id, revision, state_hash, workspace, plan))
            return type("Request", (), {"content_hash": "f" * 64})()

    assert ticket_main(
        [
            "repair-request",
            "--run",
            "run-1",
            "--expected-revision",
            "2",
            "--expected-hash",
            "a" * 64,
            "--workspace",
            str(tmp_path / "repair-worktree"),
            "--plan",
            str(tmp_path / "repair-plan.json"),
            "--json",
        ],
        runtime=runtime,
        repair_request_coordinator_factory=lambda _: Coordinator(),
    ) == 0

    assert calls == [("run-1", 2, "a" * 64, tmp_path / "repair-worktree", tmp_path / "repair-plan.json")]
    assert capsys.readouterr().out == '{"request_hash": "' + "f" * 64 + '"}\n'


def test_protected_repair_entrypoint_dispatches_only_the_selected_operation() -> None:
    """Dispatching a repair command through the ticket runner would bypass the repair boundary."""
    calls: list[tuple[str, str]] = []

    assert repair_entrypoint.main(
        ["prepare", "--run", "run-1", "--failure", "a" * 64],
        prepare=lambda run_id, failure_hash: calls.append((run_id, failure_hash)),
    ) == 0

    assert calls == [("run-1", "a" * 64)]


def test_registry_has_no_ticket_facing_activation_api(
    tmp_path: Path,
    valid_repair_plan: RepairPlan,
) -> None:
    """Replacing the protected capability with a caller value would let ticket code self-activate."""
    registry = RunnerRegistry(tmp_path / "state", repair_runner_identity=identity("e"))
    launcher = RepairRunner(
        worktree_factory=FakeWorktreeFactory(tmp_path / "repair-worktrees"),
        git=FakeRepairGit({"src/auto_code/runner.py"}),
        process=FakeProcess(),
        registry=registry,
        repair_runner_identity=identity("e"),
        activate=protected_activation(registry),
        now=lambda: NOW,
    )
    assert launcher.registry is registry
    assert not hasattr(registry, "activate")
    assert not hasattr(registry, "activate_once")
    assert not hasattr(registry, "_activate_once")
    assert not hasattr(repair_entrypoint, "_compose_activation")


def test_restarted_repair_runner_rejects_an_unissued_workspace_handle(
    tmp_path: Path,
    valid_repair_plan: RepairPlan,
) -> None:
    """Dropping the durable issued-handle lookup would permit a forged repair workspace."""
    registry = RunnerRegistry(tmp_path / "state", repair_runner_identity=identity("e"))
    launcher = RepairRunner(
        worktree_factory=FakeWorktreeFactory(tmp_path / "repair-worktrees"),
        git=FakeRepairGit({"src/auto_code/runner.py"}),
        process=FakeProcess(),
        registry=registry,
        repair_runner_identity=identity("e"),
        activate=protected_activation(registry),
        now=lambda: NOW,
    )
    request = repair_request(launcher, valid_repair_plan)
    forged = request.baseline.__class__(
        workspace_id="f" * 32,
        path=request.baseline.path,
        baseline_hash=request.baseline.baseline_hash,
        run_id=request.baseline.run_id,
        old_runner_hash=request.baseline.old_runner_hash,
        expires_at=request.baseline.expires_at,
    )

    with pytest.raises(UnauthorizedRepairError, match="issued"):
        launcher.validate_build_activate(replace(request, baseline=forged))


def test_installed_entrypoint_composes_a_protected_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Leaving the installed command callback-only would make protected repair unavailable."""
    calls: list[tuple[str, str]] = []

    class Runtime:
        def prepare(self, run_id: str, failure_hash: str) -> None:
            calls.append((run_id, failure_hash))

        def apply(self, workspace: str, request_hash: str) -> None:
            raise AssertionError("apply was not requested")

    monkeypatch.setattr(repair_entrypoint, "load_protected_runtime", lambda: Runtime())

    assert repair_entrypoint.main(["prepare", "--run", "run-1", "--failure", "a" * 64]) == 0
    assert calls == [("run-1", "a" * 64)]


def test_protected_repair_runtime_requires_a_signed_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Falling back to an environment or unsigned config would expose repair authority."""
    descriptor_path = tmp_path / "repair-runtime.json"
    descriptor_path.write_bytes(json.dumps(repair_descriptor_payload(tmp_path)).encode("ascii"))
    descriptor = os.open(descriptor_path, os.O_RDONLY)
    try:
        monkeypatch.setattr(repair_entrypoint, "_REPAIR_DESCRIPTOR_FD", descriptor)

        with pytest.raises(repair_entrypoint.RepairRuntimeConfigurationError, match="descriptor is invalid"):
            repair_entrypoint.load_protected_runtime()
    finally:
        os.close(descriptor)

    descriptor_path.write_bytes(signed_repair_descriptor(tmp_path, expiry="2020-01-01T00:00:00+00:00"))
    descriptor = os.open(descriptor_path, os.O_RDONLY)
    try:
        monkeypatch.setattr(repair_entrypoint, "_REPAIR_DESCRIPTOR_FD", descriptor)

        with pytest.raises(repair_entrypoint.RepairRuntimeConfigurationError, match="descriptor is invalid"):
            repair_entrypoint.load_protected_runtime()
    finally:
        os.close(descriptor)


def test_protected_repair_runtime_loads_a_valid_signed_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The protected executable receives its complete authority only from its descriptor."""
    descriptor_path = tmp_path / "repair-runtime.json"
    descriptor_path.write_bytes(signed_repair_descriptor(tmp_path))
    descriptor = os.open(descriptor_path, os.O_RDONLY)
    try:
        monkeypatch.setattr(repair_entrypoint, "_REPAIR_DESCRIPTOR_FD", descriptor)

        runtime = repair_entrypoint.load_protected_runtime()
    finally:
        os.close(descriptor)

    assert runtime.descriptor.registry_root == tmp_path / "registry"
    assert runtime.descriptor.regression_command == ("pytest", "tests/test_repair.py")


def test_protected_repair_runtime_rejects_a_forged_or_expired_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A repaired runner must not accept descriptor substitution or replay."""
    descriptor_path = tmp_path / "repair-runtime.json"
    payload = repair_descriptor_payload(tmp_path)
    descriptor_path.write_bytes(
        json.dumps({"payload": payload, "signature": "0" * 128}).encode("ascii")
    )
    descriptor = os.open(descriptor_path, os.O_RDONLY)
    try:
        monkeypatch.setattr(repair_entrypoint, "_REPAIR_DESCRIPTOR_FD", descriptor)

        with pytest.raises(repair_entrypoint.RepairRuntimeConfigurationError, match="descriptor is invalid"):
            repair_entrypoint.load_protected_runtime()
    finally:
        os.close(descriptor)


def test_protected_repair_runtime_consumes_a_nonce_for_one_activation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reusing a valid descriptor must fail before its expiry time."""
    descriptor_path = tmp_path / "repair-runtime.json"
    descriptor_path.write_bytes(signed_repair_descriptor(tmp_path))
    descriptor = os.open(descriptor_path, os.O_RDONLY)
    try:
        monkeypatch.setattr(repair_entrypoint, "_REPAIR_DESCRIPTOR_FD", descriptor)
        runtime = repair_entrypoint.load_protected_runtime()
    finally:
        os.close(descriptor)

    assert runtime.consume_nonce("a" * 64)
    assert not runtime.consume_nonce("a" * 64)


def test_reconciliation_recovers_old_runner_termination_after_state_cas(
    tmp_path: Path,
    valid_repair_plan: RepairPlan,
) -> None:
    """A crash after the state transition must still terminate the old runner on recovery."""
    registry = RunnerRegistry(tmp_path / "registry", repair_runner_identity=identity("e"))
    launcher = RepairRunner(
        worktree_factory=FakeWorktreeFactory(tmp_path / "repair-worktrees"),
        git=FakeRepairGit({"src/auto_code/runner.py"}),
        process=FakeProcess(),
        registry=registry,
        repair_runner_identity=identity("e"),
        activate=protected_activation(registry),
        now=lambda: NOW,
    )
    store = RunStateStore(tmp_path / "state", "run-1")
    initial = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3),
    )
    store.compare_and_swap(
        initial.revision,
        initial.state_hash,
        initial.state.model_copy(update={"disposition": RunDisposition.REPAIR_REQUIRED, "runner_identity": identity("a")}),
    )
    request = repair_request(launcher, valid_repair_plan)
    launcher.validate_build_activate(request)
    interrupted = TrustedLauncher(store, registry)
    interrupted.crash_after("STATE_CAS_REPLACED")

    with pytest.raises(InjectedCrash):
        interrupted.reconcile_activation("run-1", request.content_hash)

    terminated: list[str] = []
    recovered = TrustedLauncher(store, registry, terminate_old_runner=terminated.append)
    recovered.reconcile_activation("run-1", request.content_hash)

    assert terminated == ["run-1"]
