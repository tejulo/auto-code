from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
import inspect
import json
import os
from pathlib import Path
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auto_code import repair_entrypoint
from auto_code.cli import TrustedRuntimeConfig, main as ticket_main
from auto_code.contracts import (
    EvidenceRef,
    FailureClass,
    FailureRecord,
    FailureSource,
    FindingKind,
    ProductChangeFile,
    ProductChangeManifest,
    RepairRunnerIdentity,
    RunnerIdentity,
    RunDisposition,
    RunState,
    Stage,
    TrustedPreparationInputRef,
)
from auto_code.git import RepairSourceFile, RepairSourceManifest
from auto_code.hashing import canonical_json_bytes, hash_json
from auto_code.process import (
    CommandResult,
    ProcessRunner,
    SandboxCompleted,
    SandboxPolicy,
    VerifiedExecutable,
)
from auto_code.repair import (
    InjectedCrash,
    MissingRepairPlanError,
    RepairGuard,
    RepairPlan,
    RepairRequest,
    RepairRequestCoordinator,
    RepairTicketOverlap,
    RepairWorkspaceIdentity,
    UnauthorizedRepairError,
)
from auto_code.runner import (
    BuiltRunnerRelease,
    PendingRunnerActivation,
    RepairJournal,
    RepairRegression,
    RepairRunner,
    RunnerActivationReceipt,
    RunnerRegistry,
    TrustedLauncher,
)
from auto_code.state import EMPTY_STATE_HASH, RunStateStore


NOW = datetime(2026, 9, 12, tzinfo=UTC)


def identity(character: str, *, contract: str = "d", repair: bool = False) -> RunnerIdentity:
    model = RepairRunnerIdentity if repair else RunnerIdentity
    return model(
        content_hash=character * 64,
        source_sha="b" * 64,
        dependency_lock_hash="c" * 64,
        contract_bundle_hash=contract * 64,
        built_at=NOW,
    )


def descriptor_payload(
    tmp_path: Path,
    *,
    operation: str = "prepare",
    expiry: str = "2030-01-01T00:00:00+00:00",
) -> dict[str, object]:
    payload: dict[str, object] = {
        "operation": operation,
        "run_id": "run-1",
        "expected_revision": 2,
        "expected_state_hash": "1" * 64,
        "repair_runner_identity": identity("e", repair=True).model_dump(mode="json"),
        "registry_root": str(tmp_path / "state"),
        "state_root": str(tmp_path / "state"),
        "repair_repository_root": str(tmp_path / "repair-repository"),
        "repair_workspace_root": str(tmp_path / "repair-workspaces"),
        "git_executable": "/usr/bin/git",
        "git_executable_hash": "2" * 64,
        "regression_command": [sys.executable, "-m", "pytest"],
        "regression_executable_hash": "3" * 64,
        "regression_timeout": 60,
        "environment": {},
        "sandbox_policy_hash": "4" * 64,
        "expiry": expiry,
        "nonce": "5" * 64,
    }
    if operation == "prepare":
        payload["failure_hash"] = "6" * 64
    else:
        payload.update(
            {
                "workspace_id": "workspace-1",
                "workspace_path": str(tmp_path / "repair-workspaces" / "workspace-1"),
                "request_hash": "7" * 64,
            }
        )
    return payload


def signed_descriptor(path: Path, payload: dict[str, object], key: Ed25519PrivateKey) -> int:
    path.write_bytes(
        canonical_json_bytes(
            {
                "payload": payload,
                "signature": key.sign(canonical_json_bytes(payload)).hex(),
            }
        )
    )
    return os.open(path, os.O_RDONLY)


def preparation_state(*, runner: RunnerIdentity) -> RunState:
    preparation = TrustedPreparationInputRef(
        input_id="11111111-1111-4111-8111-111111111111",
        relative_path="trusted-mcp/preparation/11111111-1111-4111-8111-111111111111.json",
        repository_id="repo-1",
        reservation_id="reservation-1",
        challenge_hash="1" * 64,
        input_hash="2" * 64,
        query_hash="3" * 64,
        payload_hash="4" * 64,
        result_hash="5" * 64,
        source_page_hashes={"page-1": "6" * 64},
        pagination_complete=True,
        max_crew_iterations=3,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        tool_call_id="tool-call-1",
        captured_at=NOW,
        observations=("captured",),
        bridge_signature="7" * 64,
    )
    return RunState(
        run_id="run-1",
        ticket_id="ENG-1",
        repository_id="repo-1",
        max_crew_iterations=3,
        project_policy_hash="8" * 64,
        preparation_input_ref=preparation,
        preparation_input_hash=preparation.input_hash,
        ticket_snapshot_hash="9" * 64,
        compatibility_receipt_hash="a" * 64,
        compatibility_receipt_ref=EvidenceRef(
            relative_path="preflight/compatibility.json",
            sha256="a" * 64,
            media_type="application/json",
            creator="trusted-launcher",
        ),
        runner_identity=runner,
    )


def product_manifest() -> ProductChangeManifest:
    return ProductChangeManifest.from_files(
        "a" * 40,
        (
            ProductChangeFile(
                path="src/auto_code/runner.py",
                status="M",
                old_path=None,
                old_mode="100644",
                mode="100644",
                old_object_id="b" * 40,
                object_id="c" * 40,
                binary=False,
                untracked=False,
            ),
        ),
    )


def repair_failure() -> FailureRecord:
    return FailureRecord(
        failure_class=FailureClass.ORCHESTRATION,
        failure_source=FailureSource.SUPERVISOR,
        finding_kind=FindingKind.INVALID_ROUTING,
        evidence_refs=(
            EvidenceRef(
                relative_path="failures/failure.json",
                sha256="d" * 64,
                media_type="application/json",
                creator="supervisor",
            ),
        ),
    )


class FakeWorktreeFactory:
    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True)

    def create(self, handle_id: str) -> Path:
        path = self.root / handle_id
        (path / "src" / "auto_code").mkdir(parents=True)
        (path / "src" / "auto_code" / "runner.py").write_text("baseline\n", encoding="ascii")
        return path


class FakeGit:
    def __init__(self) -> None:
        self.calls = 0

    def baseline_hash(self, workspace: Path) -> str:
        return "a" * 40

    def collect_repair_source_manifest(
        self,
        baseline_hash: str,
        *,
        planned_paths: tuple[str, ...],
        control_paths: tuple[str, ...] = (),
    ) -> RepairSourceManifest:
        self.calls += 1
        assert baseline_hash == "a" * 40
        return RepairSourceManifest(
            baseline_sha=baseline_hash,
            files=(
                RepairSourceFile(
                    path=planned_paths[0],
                    status="M",
                    old_path=None,
                    old_object_id="b" * 40,
                    object_id="c" * 40,
                    mode="100644",
                    binary=False,
                    untracked=False,
                    content_sha256="1" * 64,
                ),
            ),
        )

    def dependency_lock_hash(self) -> str:
        return "2" * 64


class FakeRegression:
    def __init__(self) -> None:
        self.calls = 0

    def run(self, workspace: Path) -> str:
        self.calls += 1
        return "3" * 64


class FakeBuilder:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.calls = 0

    def build(
        self,
        workspace: Path,
        source_manifest: RepairSourceManifest,
        dependency_lock_hash: str,
        contract_manifest_hash: str,
    ) -> BuiltRunnerRelease:
        self.calls += 1
        release = self.root / f"release-{self.calls}"
        release.mkdir(parents=True)
        artifact = release / "runner.py"
        artifact.write_bytes(b"immutable runner\n")
        artifact.chmod(0o444)
        release.chmod(0o555)
        manifest_hash = hash_json(
            [
                {
                    "path": "runner.py",
                    "kind": "file",
                    "mode": 0o444,
                    "content_sha256": sha256(b"immutable runner\n").hexdigest(),
                }
            ]
        )
        return BuiltRunnerRelease(
            root=release,
            release_manifest_hash=manifest_hash,
            repair_source_manifest_hash=source_manifest.content_hash,
            dependency_lock_hash=dependency_lock_hash,
            contract_manifest_hash=contract_manifest_hash,
            build_evidence_hash="4" * 64,
            built_at=NOW,
        )


class RepairHarness:
    def __init__(self, tmp_path: Path, *, same_repository: bool = False) -> None:
        self.state_root = tmp_path / "state"
        self.registry = RunnerRegistry(self.state_root, repair_runner_identity=identity("e", repair=True))
        self.store = RunStateStore(self.state_root, "run-1", repair_activation_verifier=self.registry)
        initial = self.store.compare_and_swap(0, EMPTY_STATE_HASH, preparation_state(runner=identity("a")))
        self.failure = repair_failure()
        self.generation = self.store.compare_and_swap(
            initial.revision,
            initial.state_hash,
            initial.state.model_copy(
                update={
                    "disposition": RunDisposition.REPAIR_REQUIRED,
                    "product_change_manifest": "manifests/product.json",
                    "failure_history": (self.failure,),
                }
            ),
        )
        self.workspace_root = tmp_path / "repair-workspaces"
        self.git = FakeGit()
        self.regression = FakeRegression()
        self.builder = FakeBuilder(tmp_path / "releases")
        self.runner = RepairRunner(
            worktree_factory=FakeWorktreeFactory(self.workspace_root),
            git=self.git,
            regression=self.regression,  # type: ignore[arg-type]
            builder=self.builder,
            registry=self.registry,
            repair_runner_identity=identity("e", repair=True),
            state_root=self.state_root,
            repair_workspace_root=self.workspace_root,
            now=lambda: NOW,
        )
        self.failure_hash = hash_json(self.failure.model_dump(mode="json", round_trip=True))
        self.handle = self.runner.prepare_workspace(self.generation, self.failure_hash)
        control = self.handle.path / ".repair-control"
        control.mkdir()
        self.plan_path = control / "plan.json"
        self.plan = RepairPlan(
            root_cause="The protected repair transaction did not derive authoritative facts.",
            files=("src/auto_code/runner.py",),
            change="Derive and journal every repair phase.",
            evidence=("d" * 64,),
        )
        self.plan_path.write_bytes(canonical_json_bytes(self.plan.payload()))
        self.coordinator = RepairRequestCoordinator(
            self.store,
            load_workspace_handle=self.registry.load_workspace_handle,
            load_product_manifest=lambda _: product_manifest(),
            repair_repository_id="repo-1" if same_repository else "repair-repo",
        )

    def request(self) -> RepairRequest:
        return self.coordinator.create_request(
            "run-1",
            self.generation.revision,
            self.generation.state_hash,
            self.handle.path,
            self.plan_path,
        )


def activation_receipt(request_hash: str, old: RunnerIdentity, new: RunnerIdentity) -> RunnerActivationReceipt:
    return RunnerActivationReceipt(
        request_hash=request_hash,
        run_id="run-1",
        expected_revision=2,
        expected_state_hash="1" * 64,
        failure_hash="2" * 64,
        repair_source_manifest_hash="3" * 64,
        project_policy_hash="4" * 64,
        regression_evidence_hash="5" * 64,
        build_evidence_hash="6" * 64,
        release_manifest_hash=new.content_hash,
        termination_evidence_hash="7" * 64,
        restart_evidence_hash="8" * 64,
        attestation_evidence_hash="9" * 64,
        old_runner_identity=old,
        new_runner_identity=new,
        compatible_checkpoint_stages=(),
        contract_hashes={},
    )


def test_generated_test_key_cannot_sign_a_production_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    descriptor = signed_descriptor(tmp_path / "descriptor.json", descriptor_payload(tmp_path), private_key)
    try:
        monkeypatch.setattr(repair_entrypoint, "_REPAIR_DESCRIPTOR_FD", descriptor)
        with pytest.raises(repair_entrypoint.RepairRuntimeConfigurationError):
            repair_entrypoint.load_protected_runtime()
    finally:
        os.close(descriptor)


def test_injected_test_key_validates_only_when_explicitly_supplied(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    descriptor = signed_descriptor(tmp_path / "descriptor.json", descriptor_payload(tmp_path), private_key)
    try:
        monkeypatch.setattr(repair_entrypoint, "_REPAIR_DESCRIPTOR_FD", descriptor)
        runtime = repair_entrypoint.load_protected_runtime(verification_key=public_key)
    finally:
        os.close(descriptor)

    assert runtime.descriptor.operation == "prepare"


def test_descriptor_authorizes_exactly_one_operation_and_binding_set(tmp_path: Path) -> None:
    prepare = repair_entrypoint.RepairRuntimeDescriptor.from_payload(descriptor_payload(tmp_path), now=NOW)
    assert prepare.authorizes(
        "prepare",
        run_id="run-1",
        expected_revision=2,
        expected_state_hash="1" * 64,
        failure_hash="6" * 64,
    )
    assert not prepare.authorizes(
        "prepare",
        run_id="run-1",
        expected_revision=3,
        expected_state_hash="1" * 64,
        failure_hash="6" * 64,
    )
    assert not prepare.authorizes("apply", request_hash="7" * 64)

    apply = repair_entrypoint.RepairRuntimeDescriptor.from_payload(
        descriptor_payload(tmp_path, operation="apply"), now=NOW
    )
    assert apply.authorizes(
        "apply",
        run_id="run-1",
        expected_revision=2,
        expected_state_hash="1" * 64,
        workspace_id="workspace-1",
        workspace_path=tmp_path / "repair-workspaces" / "workspace-1",
        request_hash="7" * 64,
    )
    assert not apply.authorizes(
        "apply",
        run_id="run-1",
        expected_revision=2,
        expected_state_hash="1" * 64,
        workspace_id="workspace-1",
        workspace_path=tmp_path / "repair-workspaces" / "workspace-1",
        request_hash="8" * 64,
    )


def test_descriptor_contract_rejects_extra_fields_and_expiry(tmp_path: Path) -> None:
    extra = descriptor_payload(tmp_path)
    extra["request_hash"] = "7" * 64
    with pytest.raises(ValueError, match="shape"):
        repair_entrypoint.RepairRuntimeDescriptor.from_payload(extra, now=NOW)
    with pytest.raises(ValueError, match="expired"):
        repair_entrypoint.RepairRuntimeDescriptor.from_payload(
            descriptor_payload(tmp_path, expiry="2020-01-01T00:00:00+00:00"), now=NOW
        )


def test_repair_plan_contract_rejects_commands_unbounded_text_and_unsorted_paths() -> None:
    with pytest.raises(MissingRepairPlanError):
        RepairPlan.from_payload(
            {
                "root_cause": "cause",
                "files": ["src/auto_code/runner.py"],
                "change": "change",
                "evidence": ["a" * 64],
                "regression_command": ["/tmp/attacker"],
            }
        )
    with pytest.raises(ValueError):
        RepairPlan("x" * 4097, ("src/auto_code/runner.py",), "change", ("a" * 64,))
    with pytest.raises(ValueError, match="sorted"):
        RepairPlan(
            "cause",
            ("tests/z.py", "src/auto_code/a.py"),
            "change",
            ("a" * 64,),
        )


def test_request_api_cannot_accept_security_bindings_from_the_caller() -> None:
    assert tuple(inspect.signature(RepairRequestCoordinator.create_request).parameters) == (
        "self",
        "run_id",
        "expected_revision",
        "expected_state_hash",
        "workspace",
        "plan_path",
    )
    assert "contract_hashes" not in inspect.signature(RepairRequestCoordinator).parameters


def test_request_derives_generation_policy_failure_repository_manifest_and_contracts(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    request = harness.request()

    assert request.expected_revision == harness.generation.revision
    assert request.expected_state_hash == harness.generation.state_hash
    assert request.failure_hash == harness.failure_hash
    assert request.repository_id == harness.generation.state.repository_id
    assert request.product_manifest_hash == product_manifest().content_hash
    assert request.project_policy_hash == harness.generation.state.project_policy_hash
    assert request.old_runner_identity == harness.generation.state.runner_identity
    assert request.ticket_owned_paths == ("src/auto_code/runner.py",)
    assert request.contract_hashes == {}


def test_request_rejects_a_stale_generation_before_writing_request(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    with pytest.raises(UnauthorizedRepairError, match="stale"):
        harness.coordinator.create_request(
            "run-1",
            harness.generation.revision + 1,
            harness.generation.state_hash,
            harness.handle.path,
            harness.plan_path,
        )
    assert not (harness.handle.path / ".repair-control" / "requests").exists()


def test_request_rejects_plan_without_authoritative_failure_evidence(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    plan = replace(harness.plan, evidence=("e" * 64,))
    harness.plan_path.write_bytes(canonical_json_bytes(plan.payload()))

    with pytest.raises(UnauthorizedRepairError, match="failure evidence"):
        harness.request()


def test_repair_workspace_replacement_is_rejected_before_capabilities_run(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    identity_value = RepairWorkspaceIdentity.capture(workspace)
    workspace.rename(tmp_path / "original")
    workspace.mkdir()

    with pytest.raises(UnauthorizedRepairError, match="workspace"):
        identity_value.verify()


def test_repair_workspace_root_replacement_is_rejected_before_capabilities_run(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    request = harness.request()
    harness.workspace_root.rename(tmp_path / "original-repair-workspaces")
    harness.workspace_root.mkdir()

    with pytest.raises(UnauthorizedRepairError, match="workspace"):
        harness.runner.validate_regress_build(request)

    assert harness.git.calls == 0
    assert harness.regression.calls == 0


def test_workspace_preparation_derives_the_current_orchestration_failure(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)

    with pytest.raises(UnauthorizedRepairError, match="protected repair state"):
        harness.runner.prepare_workspace(harness.generation, "e" * 64)


def test_repair_guard_rejects_plan_symlink(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    outside = tmp_path / "outside.json"
    outside.write_bytes(
        canonical_json_bytes(RepairPlan("cause", ("src/auto_code/a.py",), "change", ("a" * 64,)).payload())
    )
    (workspace / "plan.json").symlink_to(outside)

    with pytest.raises(MissingRepairPlanError):
        RepairGuard(workspace).validate_path(workspace / "plan.json")


def test_phase_journal_returns_durable_completion_without_repeating_effect(tmp_path: Path) -> None:
    journal = RepairJournal(tmp_path / "state", "a" * 64)
    calls: list[str] = []
    assert journal.run_once("regression", lambda: calls.append("first") or "b" * 64) == "b" * 64
    assert RepairJournal(tmp_path / "state", "a" * 64).run_once(
        "regression", lambda: calls.append("repeat") or "c" * 64
    ) == "b" * 64
    assert calls == ["first"]


def test_regression_uses_hash_verified_process_boundary_minimal_env_and_immutable_evidence(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    home = tmp_path / "home"
    state = tmp_path / "state"
    secrets = tmp_path / "secrets"
    for path in (workspace, home, state, secrets):
        path.mkdir()

    class Verifier:
        def __init__(self) -> None:
            self.paths: list[str] = []

        def require_absolute_verified(self, executable: str) -> VerifiedExecutable:
            self.paths.append(executable)
            return VerifiedExecutable(executable, os.open(os.devnull, os.O_RDONLY))

    class Sandbox:
        def __init__(self) -> None:
            self.calls: list[tuple[tuple[str, ...], float, dict[str, str], object]] = []

        def run(self, argv: tuple[str, ...], **kwargs: object) -> SandboxCompleted:
            self.calls.append((argv, kwargs["timeout"], dict(kwargs["env"]), kwargs["policy"]))
            return SandboxCompleted(0, "passed", "")

    class Sink:
        def write(self, result: CommandResult) -> CommandResult:
            return replace(
                result,
                stdout_path=EvidenceRef(
                    relative_path="repair/stdout.txt",
                    sha256="a" * 64,
                    media_type="text/plain",
                    creator="process",
                ),
                stderr_path=EvidenceRef(
                    relative_path="repair/stderr.txt",
                    sha256="b" * 64,
                    media_type="text/plain",
                    creator="process",
                ),
            )

    verifier = Verifier()
    sandbox = Sandbox()
    policy = SandboxPolicy(
        project_root=workspace,
        readable_roots=(workspace,),
        writable_roots=(workspace,),
        authoritative_state_root=state,
        secret_paths=(secrets,),
        controlled_home=home,
        environment_allowlist=frozenset(),
    )
    evidence_hash = RepairRegression(
        ProcessRunner(verifier, sandbox),  # type: ignore[arg-type]
        (sys.executable, "-m", "pytest"),
        30,
        Sink(),  # type: ignore[arg-type]
        {},
        policy,
    ).run(workspace)

    assert len(evidence_hash) == 64
    assert verifier.paths == [sys.executable]
    assert sandbox.calls[0][1] == 30
    assert sandbox.calls[0][2] == {
        "HOME": str(home),
        "PIP_NO_INDEX": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "npm_config_offline": "true",
    }
    assert all(directory.path != state for directory in sandbox.calls[0][3].readable_roots)


def test_build_identity_requires_an_actual_immutable_release_and_all_bindings(tmp_path: Path) -> None:
    mutable = tmp_path / "mutable-release"
    mutable.mkdir()
    (mutable / "runner.py").write_text("runner\n", encoding="ascii")
    release = BuiltRunnerRelease(
        root=mutable,
        release_manifest_hash="1" * 64,
        repair_source_manifest_hash="2" * 64,
        dependency_lock_hash="3" * 64,
        contract_manifest_hash="4" * 64,
        build_evidence_hash="5" * 64,
        built_at=NOW,
    )
    with pytest.raises(UnauthorizedRepairError, match="mutable"):
        release.verify()

    builder = FakeBuilder(tmp_path / "releases")
    source = FakeGit().collect_repair_source_manifest(
        "a" * 40, planned_paths=("src/auto_code/runner.py",)
    )
    built = builder.build(tmp_path, source, "6" * 64, "7" * 64)
    assert built.identity.content_hash == built.release_manifest_hash
    assert built.identity.source_sha == source.content_hash
    assert built.identity.dependency_lock_hash == "6" * 64
    assert built.identity.contract_bundle_hash == "7" * 64


def test_runner_rejects_same_repository_ticket_overlap_before_regression(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path, same_repository=True)
    request = harness.request()
    with pytest.raises(RepairTicketOverlap):
        harness.runner.validate_regress_build(request)
    assert harness.regression.calls == 0
    assert harness.builder.calls == 0


def test_regression_and_build_are_not_repeated_after_durable_completion(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    request = harness.request()
    first = harness.runner.validate_regress_build(request)
    second = harness.runner.validate_regress_build(request)

    assert first == second
    assert harness.git.calls == 1
    assert harness.regression.calls == 1
    assert harness.builder.calls == 1


def test_pending_build_record_recovers_a_missing_build_journal_completion(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    request = harness.request()
    pending = harness.runner.validate_regress_build(request)
    journal = RepairJournal(harness.state_root, request.content_hash)
    payload = {
        "request_hash": request.content_hash,
        "completed": {
            "source_manifest": pending.repair_source_manifest_hash,
            "regression": pending.regression_evidence_hash,
        },
    }
    from auto_code.state import _atomic_replace_json
    _atomic_replace_json(journal.path, payload)

    recovered = harness.runner.validate_regress_build(request)

    assert recovered == pending
    assert harness.builder.calls == 1
    assert RepairJournal(harness.state_root, request.content_hash).completed("build") == pending.build_evidence_hash


def test_registry_pointer_publish_is_serialized_expected_old_cas(tmp_path: Path) -> None:
    registry = RunnerRegistry(tmp_path / "registry", repair_runner_identity=identity("e", repair=True))
    first = activation_receipt("1" * 64, identity("a"), identity("b"))
    registry.publish_activation(first, expected_old=identity("a"))

    stale = activation_receipt("2" * 64, identity("a"), identity("c"))
    with pytest.raises(UnauthorizedRepairError, match="expected old"):
        registry.publish_activation(stale, expected_old=identity("a"))
    assert registry.lookup_activation("1" * 64) == first


def test_state_transition_verification_accepts_only_the_current_activation_pointer(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    request = harness.request()
    harness.runner.validate_regress_build(request)
    previous = harness.store.load()
    launcher = TrustedLauncher(
        harness.store,
        harness.registry,
        terminate_old_runner=lambda *_: "5" * 64,
        start_new_runner=lambda *_: "6" * 64,
        attest_new_runner=lambda *_: "7" * 64,
        ticket_invoker=lambda argv: argv,
    )
    activated = launcher.reconcile_activation("run-1", request.content_hash)
    assert harness.registry.verify_transition(previous, activated.state)

    from auto_code.state import _atomic_replace_json

    pointer = harness.registry.pointer_path
    payload = json.loads(pointer.read_text(encoding="utf-8"))
    payload["receipt_hash"] = "f" * 64
    _atomic_replace_json(pointer, payload)
    assert not harness.registry.verify_transition(previous, activated.state)
    with pytest.raises(UnauthorizedRepairError, match="pointer"):
        launcher.invoke("run-1", ("status",))


def test_activation_receipt_rejects_missing_transaction_evidence() -> None:
    payload = activation_receipt("1" * 64, identity("a"), identity("b")).payload()
    del payload["termination_evidence_hash"]
    with pytest.raises(ValueError, match="invalid"):
        RunnerActivationReceipt.from_payload(payload)


def test_launcher_keeps_state_non_active_until_termination_start_and_attestation_are_durable(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    request = harness.request()
    harness.runner.validate_regress_build(request)
    calls: list[str] = []
    launcher = TrustedLauncher(
        harness.store,
        harness.registry,
        terminate_old_runner=lambda *_: calls.append("terminate") or "5" * 64,
        start_new_runner=lambda *_: calls.append("start") or "6" * 64,
        attest_new_runner=lambda *_: calls.append("attest") or "7" * 64,
        ticket_invoker=lambda argv: argv,
    )
    launcher.crash_after("new_runner_started")

    with pytest.raises(InjectedCrash):
        launcher.reconcile_activation("run-1", request.content_hash)

    assert harness.store.load().state.disposition is RunDisposition.REPAIR_REQUIRED
    assert calls == ["terminate", "start"]
    with pytest.raises(PermissionError):
        launcher.invoke("run-1", ("status",))

    recovered = TrustedLauncher(
        harness.store,
        harness.registry,
        terminate_old_runner=lambda *_: calls.append("repeat-terminate") or "8" * 64,
        start_new_runner=lambda *_: calls.append("repeat-start") or "9" * 64,
        attest_new_runner=lambda *_: calls.append("attest") or "7" * 64,
        ticket_invoker=lambda argv: argv,
    )
    generation = recovered.reconcile_activation("run-1", request.content_hash)

    assert generation.state.disposition is RunDisposition.ACTIVE
    assert calls == ["terminate", "start", "attest"]
    assert recovered.invoke("run-1", ("status",)) == ("status",)


def test_recovery_after_state_cas_records_final_phase_without_repeating_lifecycle(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    request = harness.request()
    harness.runner.validate_regress_build(request)
    calls: list[str] = []
    launcher = TrustedLauncher(
        harness.store,
        harness.registry,
        terminate_old_runner=lambda *_: calls.append("terminate") or "5" * 64,
        start_new_runner=lambda *_: calls.append("start") or "6" * 64,
        attest_new_runner=lambda *_: calls.append("attest") or "7" * 64,
        ticket_invoker=lambda argv: argv,
    )
    launcher.crash_after("state_cas")

    with pytest.raises(InjectedCrash):
        launcher.reconcile_activation("run-1", request.content_hash)

    recovered = TrustedLauncher(
        harness.store,
        harness.registry,
        terminate_old_runner=lambda *_: calls.append("repeat-terminate") or "8" * 64,
        start_new_runner=lambda *_: calls.append("repeat-start") or "9" * 64,
        attest_new_runner=lambda *_: calls.append("repeat-attest") or "a" * 64,
        ticket_invoker=lambda argv: argv,
    )
    generation = recovered.reconcile_activation("run-1", request.content_hash)

    assert generation.state.disposition is RunDisposition.ACTIVE
    assert calls == ["terminate", "start", "attest"]
    assert RepairJournal(harness.state_root, request.content_hash).completed("state_activated") == generation.state_hash
    assert recovered.invoke("run-1", ("status",)) == ("status",)


def test_protected_runtime_rejects_unbound_regression_capability(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    descriptor = repair_entrypoint.RepairRuntimeDescriptor.from_payload(descriptor_payload(tmp_path), now=NOW)

    with pytest.raises(PermissionError, match="regression"):
        repair_entrypoint.ProtectedRepairRuntime(descriptor).with_capabilities(runner=harness.runner)


def test_state_store_rejects_repair_activation_without_registry_verification(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")
    initial = store.compare_and_swap(0, EMPTY_STATE_HASH, RunState(
        run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3
    ))
    repair = store.compare_and_swap(
        initial.revision,
        initial.state_hash,
        initial.state.model_copy(update={"disposition": RunDisposition.REPAIR_REQUIRED, "runner_identity": identity("a")}),
    )
    forged = repair.state.model_copy(
        update={
            "disposition": RunDisposition.ACTIVE,
            "runner_identity": identity("b"),
            "restart_receipt_hash": "1" * 64,
        }
    )
    with pytest.raises(Exception, match="repair activation"):
        store.compare_and_swap(repair.revision, repair.state_hash, forged)


def test_ticket_cli_passes_only_expected_state_workspace_and_plan_to_request_coordinator(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    project = tmp_path / "project"
    project.mkdir()
    runtime = TrustedRuntimeConfig(
        state_root=tmp_path / "state",
        project_root=project,
        project_policy_path=project / "auto-code.yaml",
        project_policy_hash="8" * 64,
        runner_identity=identity("a"),
    )
    calls: list[tuple[object, ...]] = []

    class Coordinator:
        def create_request(self, *args: object) -> object:
            calls.append(args)
            return type("Request", (), {"content_hash": "f" * 64})()

    result = ticket_main(
        [
            "repair-request", "--run", "run-1", "--expected-revision", "2",
            "--expected-hash", "a" * 64, "--workspace", str(tmp_path / "workspace"),
            "--plan", str(tmp_path / "plan.json"), "--json",
        ],
        runtime=runtime,
        repair_request_coordinator_factory=lambda _: Coordinator(),
    )

    assert result == 0
    assert calls == [("run-1", 2, "a" * 64, tmp_path / "workspace", tmp_path / "plan.json")]
    assert capsys.readouterr().out == '{"request_hash": "' + "f" * 64 + '"}\n'


def test_protected_cli_prepare_requires_generation_binding() -> None:
    calls: list[tuple[object, ...]] = []
    result = repair_entrypoint.main(
        [
            "prepare", "--run", "run-1", "--expected-revision", "2",
            "--expected-hash", "a" * 64, "--failure", "b" * 64,
        ],
        prepare=lambda *args: calls.append(args),
    )
    assert result == 0
    assert calls == [("run-1", 2, "a" * 64, "b" * 64)]


def test_protected_runtime_has_no_ambient_process_or_git_adapter() -> None:
    assert not hasattr(repair_entrypoint, "subprocess")
    assert not hasattr(repair_entrypoint, "_LauncherRepairGit")
    assert not hasattr(repair_entrypoint, "_LauncherRepairProcess")


def test_request_payload_rejects_extra_security_fields(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    payload = harness.request().payload()
    payload["caller_policy_hash"] = "0" * 64
    with pytest.raises(UnauthorizedRepairError, match="invalid"):
        RepairRequest.from_payload(payload)
