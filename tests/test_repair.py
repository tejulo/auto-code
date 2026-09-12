from __future__ import annotations

from datetime import UTC, datetime
from dataclasses import replace
from pathlib import Path

import pytest

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
from auto_code.runner import RepairActivationAuthority, RepairRunner, RunnerRegistry, TrustedLauncher
from auto_code.state import EMPTY_STATE_HASH, RunStateStore


NOW = datetime(2026, 9, 12, tzinfo=UTC)


def identity(character: str, *, contract: str = "d") -> RunnerIdentity:
    return RunnerIdentity(
        content_hash=character * 64,
        source_sha="b" * 64,
        dependency_lock_hash="c" * 64,
        contract_bundle_hash=contract * 64,
        built_at=NOW,
    )


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
        activation_authority=registry._repair_authority,
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
        activation_authority=registry._repair_authority,
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
        activation_authority=registry._repair_authority,
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
        activation_authority=registry._repair_authority,
        now=lambda: NOW,
    )
    request = repair_request(launcher, valid_repair_plan)

    with pytest.raises(PermissionError):
        registry.activate(request)


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
        activation_authority=registry._repair_authority,
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
        activation_authority=registry._repair_authority,
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


def test_registry_rejects_a_forged_activation_authority(
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
        activation_authority=registry._repair_authority,
        now=lambda: NOW,
    )
    request = repair_request(launcher, valid_repair_plan)

    with pytest.raises(PermissionError):
        registry.activate_once(request, identity("b"), authority=RepairActivationAuthority())


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
        activation_authority=registry._repair_authority,
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
