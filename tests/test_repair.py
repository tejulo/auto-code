from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
import array
import inspect
import json
import os
from pathlib import Path
import socket
import shutil
import subprocess
import sys
import threading
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auto_code import repair_entrypoint
import auto_code.runner as runner_module
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
    ObservedLauncherEffect,
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
    ReleaseManifestEntry,
    RepairJournal,
    RepairRegression,
    RepairRunner,
    RunnerActivationReceipt,
    RunnerRegistry,
    TrustedLauncher,
    capture_built_release_manifest,
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
    expiry: str | None = None,
    issued_at: datetime | None = None,
) -> dict[str, object]:
    descriptor_time = datetime.now(UTC) if issued_at is None else issued_at
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
        "process_runner_version": "auto-code-process-v1",
        "sandbox_socket": str(tmp_path / "launcher-sandbox.sock"),
        "sandbox_identity": "launcher-sandbox",
        "controlled_home": str(tmp_path / "controlled-home"),
        "secret_paths": [str(tmp_path / "secrets")],
        "evidence_root": str(tmp_path / "state" / "repair-evidence"),
        "release_root": str(tmp_path / "runner-releases"),
        "build_command": [sys.executable, "-m", "auto_code.build_runner"],
        "build_executable_hash": "3" * 64,
        "runner_executable": "runner.py",
        "contract_manifest": "contracts.json",
        "terminate_command": [sys.executable, "terminate"],
        "terminate_executable_hash": "3" * 64,
        "start_command": [sys.executable, "start"],
        "start_executable_hash": "3" * 64,
        "attest_command": [sys.executable, "attest"],
        "attest_executable_hash": "3" * 64,
        "expiry": (descriptor_time + timedelta(minutes=4)).isoformat() if expiry is None else expiry,
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
    payload["sandbox_policy_hash"] = hash_json(
        {
            "repair_repository_root": payload["repair_repository_root"],
            "repair_workspace_root": payload["repair_workspace_root"],
            "controlled_home": payload["controlled_home"],
            "secret_paths": payload["secret_paths"],
            "environment_allowlist": [],
            "dynamic_downloads_disabled": True,
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


class FakeSandboxServer:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.requests: list[dict[str, object]] = []
        self.effects: dict[tuple[str, str], dict[str, object]] = {}
        self.before_build: Callable[[dict[str, object]], None] | None = None
        self.before_worktree: Callable[[], None] | None = None
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._socket.bind(str(path))
        self._socket.listen()
        self._stopped = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stopped = True
        try:
            socket.socket(socket.AF_UNIX, socket.SOCK_STREAM).connect(str(self.path))
        except OSError:
            pass
        self._thread.join(timeout=2)
        self._socket.close()

    def _serve(self) -> None:
        while not self._stopped:
            connection, _ = self._socket.accept()
            with connection:
                descriptors = array.array("i")
                raw, ancillary, _, _ = connection.recvmsg(65_536, socket.CMSG_SPACE(descriptors.itemsize))
                for level, kind, data in ancillary:
                    if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                        descriptors.frombytes(data[: len(data) - (len(data) % descriptors.itemsize)])
                while not raw.endswith(b"\n"):
                    chunk = connection.recv(65_536)
                    if not chunk:
                        break
                    raw += chunk
                if self._stopped:
                    continue
                request = json.loads(raw)
                self.requests.append(request)
                if request.get("operation") == "observe_effect":
                    key = (request["effect_id"], request["binding_hash"])
                    completed = self.effects.get(key)
                    connection.sendall(
                        canonical_json_bytes(
                            {
                                "effect_id": key[0],
                                "binding_hash": key[1],
                                "receipt_hash": None if completed is None else completed["receipt_hash"],
                                "returncode": None if completed is None else completed["returncode"],
                            }
                        )
                        + b"\n"
                    )
                    continue
                effect_key = None
                if request.get("operation") == "invoke_effect":
                    effect_key = (request["effect_id"], request["binding_hash"])
                    completed = self.effects.get(effect_key)
                    if completed is not None:
                        connection.sendall(canonical_json_bytes(completed) + b"\n")
                        continue
                argv = request["argv"]
                stdout = ""
                stderr = ""
                returncode = 0
                executable_name = ""
                if descriptors:
                    executable_name = Path(os.readlink(f"/proc/self/fd/{descriptors[0]}")).name
                if executable_name == "git":
                    completed = subprocess.run(
                        (f"/proc/self/fd/{descriptors[0]}", *argv),
                        cwd=request["policy"]["cwd"],
                        env=request["environment"],
                        pass_fds=(descriptors[0],),
                        capture_output=True,
                        check=False,
                    )
                    returncode = completed.returncode
                    stdout = completed.stdout.decode("utf-8", errors="replace")
                    stderr = completed.stderr.decode("utf-8", errors="replace")
                elif "worktree" in argv and "add" in argv:
                    if self.before_worktree is not None:
                        self.before_worktree()
                    workspace = Path(argv[-1])
                    (workspace / "src" / "auto_code").mkdir(parents=True)
                    (workspace / "src" / "auto_code" / "runner.py").write_text("baseline\n", encoding="ascii")
                elif "rev-parse" in argv:
                    stdout = "a" * 40 + "\n"
                elif argv and argv[0] == "build":
                    if self.before_build is not None:
                        self.before_build(request)
                    release = Path(argv[argv.index("--release-root") + 1])
                    release.mkdir(parents=True)
                    (release / "runner.py").write_text("#!/bin/sh\nexit 0\n", encoding="ascii")
                    (release / "runner.py").chmod(0o555)
                    (release / "contracts.json").write_bytes(canonical_json_bytes({}))
                    (release / "contracts.json").chmod(0o444)
                    release.chmod(0o555)
                response: dict[str, object] = {"returncode": returncode, "stdout": stdout, "stderr": stderr}
                if effect_key is not None:
                    response.update(
                        {
                            "effect_id": effect_key[0],
                            "binding_hash": effect_key[1],
                            "receipt_hash": hash_json(
                                {
                                    "effect_id": effect_key[0],
                                    "binding_hash": effect_key[1],
                                    "returncode": returncode,
                                    "stdout_sha256": sha256(stdout.encode("utf-8")).hexdigest(),
                                    "stderr_sha256": sha256(stderr.encode("utf-8")).hexdigest(),
                                }
                            ),
                        }
                    )
                    self.effects[effect_key] = response
                connection.sendall(canonical_json_bytes(response) + b"\n")
                for descriptor in descriptors:
                    os.close(descriptor)


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
        self.source_contents: list[str] = []

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
        content_hash = self.source_contents.pop(0) if self.source_contents else "1" * 64
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
                    content_sha256=content_hash,
                ),
            ),
        )

    def dependency_lock_hash(self, workspace: Path) -> str:
        return "2" * 64


class FakeRegression:
    def __init__(self) -> None:
        self.calls = 0
        self.results: dict[str, str] = {}

    def observe(self, effect_id: str) -> str | None:
        return self.results.get(effect_id)

    def run(self, effect_id: str, workspace: Path) -> str:
        self.calls += 1
        self.results[effect_id] = "3" * 64
        return self.results[effect_id]


class FakeBuilder:
    def __init__(self, root: Path) -> None:
        self.root = root
        self.calls = 0
        self.sources: list[RepairSourceManifest] = []
        self.contract_hashes: dict[Stage, str] | None = None
        self.results: dict[str, BuiltRunnerRelease] = {}

    def observe(self, effect_id: str) -> BuiltRunnerRelease | None:
        return self.results.get(effect_id)

    def build(
        self,
        effect_id: str,
        workspace: Path,
        source_manifest: RepairSourceManifest,
        dependency_lock_hash: str,
        contract_manifest_hash: str,
    ) -> BuiltRunnerRelease:
        self.calls += 1
        self.sources.append(source_manifest)
        release = self.root / f"release-{self.calls}"
        release.mkdir(parents=True)
        artifact = release / "runner.py"
        artifact.write_bytes(b"#!/bin/sh\nprintf immutable-runner")
        artifact.chmod(0o555)
        release.chmod(0o555)
        manifest = capture_built_release_manifest(release)
        manifest_hash = hash_json(
            [entry.payload() for entry in manifest]
        )
        built = BuiltRunnerRelease(
            root=release,
            release_manifest=manifest,
            release_manifest_hash=manifest_hash,
            runner_executable="runner.py",
            repair_source_manifest_hash=source_manifest.content_hash,
            dependency_lock_hash=dependency_lock_hash,
            contract_hashes={} if self.contract_hashes is None else self.contract_hashes,
            contract_manifest_hash=hash_json(
                {
                    stage.value: digest
                    for stage, digest in ({} if self.contract_hashes is None else self.contract_hashes).items()
                }
            ),
            build_evidence_hash="4" * 64,
            built_at=NOW,
        )
        self.results[effect_id] = built
        return built


class FakeLifecycleEffect:
    def __init__(self, label: str, calls: list[str]) -> None:
        self.label = label
        self.calls = calls
        self.results: dict[str, str] = {}

    def observe(self, effect_id: str, run_id: str, runner: RunnerIdentity) -> str | None:
        return self.results.get(effect_id)

    def invoke(self, effect_id: str, run_id: str, runner: RunnerIdentity) -> str:
        self.calls.append(self.label)
        result = sha256(f"{self.label}:{effect_id}".encode("ascii")).hexdigest()
        self.results[effect_id] = result
        return result


class FakeTicketInvoker:
    def __init__(self, commands: list[tuple[str, ...]] | None = None) -> None:
        self.commands = [] if commands is None else commands

    def invoke(self, executable: VerifiedExecutable, argv: tuple[str, ...]) -> tuple[str, ...]:
        os.fstat(executable.descriptor)
        self.commands.append(argv)
        return argv


class FakeProtectedRepairService:
    def __init__(self) -> None:
        self.request_hash: str | None = None

    def require_prepare(self, generation: object, failure_hash: str) -> None:
        return None

    def require_apply(self, request_hash: str) -> None:
        if self.request_hash is not None and request_hash != self.request_hash:
            raise PermissionError("wrong repair transaction")

    def prepare_handle_id(self, generation: object, failure_hash: str) -> str:
        return uuid.uuid4().hex

    def load_prepared_handle(self, registry: RunnerRegistry, handle_id: str) -> None:
        return None

    def issue_workspace_handle(self, registry: RunnerRegistry, handle: object) -> object:
        path = registry.handles / f"{getattr(handle, 'id')}.json"
        path.write_bytes(canonical_json_bytes(getattr(handle, "payload")()))
        return handle

    def record_pending(
        self, registry: RunnerRegistry, pending: PendingRunnerActivation
    ) -> PendingRunnerActivation:
        path = registry.pending_path(pending.request_hash)
        if not path.exists():
            path.write_bytes(canonical_json_bytes(pending.payload()))
        return registry.lookup_pending(pending.request_hash)

    def publish_activation(
        self,
        registry: RunnerRegistry,
        pending: PendingRunnerActivation,
        receipt: RunnerActivationReceipt,
        journal: RepairJournal,
    ) -> RunnerActivationReceipt:
        from auto_code.state import _atomic_replace_json, _write_new_json

        path = registry.activation_path(receipt.request_hash)
        if not _write_new_json(path, receipt.payload()):
            receipt = registry.lookup_activation(receipt.request_hash)
        _atomic_replace_json(
            registry.pointer_path,
            {
                "request_hash": receipt.request_hash,
                "receipt_hash": receipt.content_hash,
                "runner_identity": receipt.new_runner_identity.model_dump(mode="json", round_trip=True),
            },
        )
        return receipt


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
                    "product_change_manifest_hash": product_manifest().content_hash,
                    "failure_history": (self.failure,),
                }
            ),
        )
        self.workspace_root = tmp_path / "repair-workspaces"
        self.git = FakeGit()
        self.regression = FakeRegression()
        self.builder = FakeBuilder(tmp_path / "releases")
        self.repair_service = FakeProtectedRepairService()
        self.runner = RepairRunner(
            worktree_factory=FakeWorktreeFactory(self.workspace_root),
            git=self.git,
            regression=self.regression,  # type: ignore[arg-type]
            builder=self.builder,
            registry=self.registry,
            repair_runner_identity=identity("e", repair=True),
            state_root=self.state_root,
            repair_workspace_root=self.workspace_root,
            repair_service=self.repair_service,
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
        request = self.coordinator.create_request(
            "run-1",
            self.generation.revision,
            self.generation.state_hash,
            self.handle.path,
            self.plan_path,
        )
        self.repair_service.request_hash = request.content_hash
        return request


def activation_receipt(request_hash: str, old: RunnerIdentity, new: RunnerIdentity) -> RunnerActivationReceipt:
    release_manifest = (
        ReleaseManifestEntry("runner.py", "file", 0o555, "0" * 64),
    )
    release_manifest_hash = hash_json([entry.payload() for entry in release_manifest])
    new = new.model_copy(
        update={
            "content_hash": release_manifest_hash,
            "source_sha": "3" * 64,
            "contract_bundle_hash": hash_json({}),
        }
    )
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
        release_root=Path("/immutable-release"),
        release_manifest=release_manifest,
        release_manifest_hash=release_manifest_hash,
        runner_executable="runner.py",
        termination_evidence_hash="7" * 64,
        restart_evidence_hash="8" * 64,
        attestation_evidence_hash="9" * 64,
        old_runner_identity=old,
        new_runner_identity=new,
        compatible_checkpoint_stages=(),
        previous_contract_hashes={},
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
    prepare = repair_entrypoint.RepairRuntimeDescriptor.from_payload(
        descriptor_payload(tmp_path, issued_at=NOW), now=NOW
    )
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
        descriptor_payload(tmp_path, operation="apply", issued_at=NOW), now=NOW
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
    extra = descriptor_payload(tmp_path, issued_at=NOW)
    extra["request_hash"] = "7" * 64
    with pytest.raises(ValueError, match="shape"):
        repair_entrypoint.RepairRuntimeDescriptor.from_payload(extra, now=NOW)
    with pytest.raises(ValueError, match="expired"):
        repair_entrypoint.RepairRuntimeDescriptor.from_payload(
            descriptor_payload(tmp_path, expiry="2020-01-01T00:00:00+00:00"), now=NOW
        )
    with pytest.raises(ValueError, match="expired"):
        repair_entrypoint.RepairRuntimeDescriptor.from_payload(
            descriptor_payload(tmp_path, expiry=(NOW + timedelta(minutes=6)).isoformat()), now=NOW
        )


def test_descriptor_nonce_is_bound_recoverable_and_terminal_after_completion(tmp_path: Path) -> None:
    descriptor = repair_entrypoint.RepairRuntimeDescriptor.from_payload(
        descriptor_payload(tmp_path, issued_at=NOW), now=NOW
    )
    nonces = repair_entrypoint.DescriptorNonceStore(tmp_path / "state", now=lambda: NOW)

    first = nonces.begin(descriptor)
    recovered = repair_entrypoint.DescriptorNonceStore(tmp_path / "state", now=lambda: NOW).begin(descriptor)
    assert recovered == first

    nonces.complete(descriptor, "a" * 64)
    with pytest.raises(PermissionError, match="consumed"):
        nonces.begin(descriptor)
    with pytest.raises(PermissionError, match="expired"):
        repair_entrypoint.DescriptorNonceStore(
            tmp_path / "state", now=lambda: datetime(2031, 1, 1, tzinfo=UTC)
        ).require_active(descriptor)


def test_descriptor_nonce_transaction_serializes_concurrent_use(tmp_path: Path) -> None:
    descriptor = repair_entrypoint.RepairRuntimeDescriptor.from_payload(
        descriptor_payload(tmp_path, issued_at=NOW), now=NOW
    )
    entered = threading.Event()
    release = threading.Event()
    second_finished = threading.Event()
    outcomes: list[str] = []

    def first() -> None:
        store = repair_entrypoint.DescriptorNonceStore(tmp_path / "state", now=lambda: NOW)
        with store.transaction(descriptor) as transaction:
            entered.set()
            release.wait(timeout=2)
            transaction.complete("a" * 64)

    def second() -> None:
        entered.wait(timeout=2)
        store = repair_entrypoint.DescriptorNonceStore(tmp_path / "state", now=lambda: NOW)
        try:
            with store.transaction(descriptor):
                outcomes.append("entered")
        except PermissionError:
            outcomes.append("consumed")
        finally:
            second_finished.set()

    first_thread = threading.Thread(target=first)
    second_thread = threading.Thread(target=second)
    first_thread.start()
    second_thread.start()
    assert entered.wait(timeout=2)
    assert not second_finished.wait(timeout=0.1)
    release.set()
    first_thread.join(timeout=2)
    second_thread.join(timeout=2)

    assert outcomes == ["consumed"]


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


def test_request_rejects_a_self_consistent_manifest_that_does_not_match_state(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    substitute = ProductChangeManifest.from_files(
        "f" * 40,
        (
            ProductChangeFile(
                path="src/auto_code/substitute.py",
                status="A",
                old_path=None,
                old_mode="000000",
                mode="100644",
                old_object_id=None,
                object_id="e" * 40,
                binary=False,
                untracked=True,
            ),
        ),
    )
    harness.coordinator.load_product_manifest = lambda _: substitute

    with pytest.raises(UnauthorizedRepairError, match="manifest"):
        harness.request()


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


@pytest.mark.parametrize(
    ("crash_point", "calls_before_recovery"),
    (
        ("before_invocation", 0),
        ("after_invocation", 1),
        ("after_observation", 1),
    ),
)
def test_phase_journal_observes_external_state_before_reinvocation(
    tmp_path: Path,
    crash_point: str,
    calls_before_recovery: int,
) -> None:
    external: dict[str, str] = {}
    calls = 0

    def observe() -> str | None:
        return external.get("evidence")

    def invoke() -> str:
        nonlocal calls
        calls += 1
        external["evidence"] = "b" * 64
        return external["evidence"]

    journal = RepairJournal(tmp_path / "state", "a" * 64)
    journal.crash_at("regression", crash_point)
    with pytest.raises(InjectedCrash):
        journal.reconcile_effect("regression", "c" * 64, observe=observe, invoke=invoke)
    assert calls == calls_before_recovery

    result = RepairJournal(tmp_path / "state", "a" * 64).reconcile_effect(
        "regression", "c" * 64, observe=observe, invoke=invoke
    )
    assert result == "b" * 64
    assert calls == 1


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
            self.effects: dict[tuple[str, str], ObservedLauncherEffect] = {}

        def run(self, argv: tuple[str, ...], **kwargs: object) -> SandboxCompleted:
            self.calls.append((argv, kwargs["timeout"], dict(kwargs["env"]), kwargs["policy"]))
            return SandboxCompleted(0, "passed", "")

        def observe_effect(
            self, effect_id: str, binding_hash: str, **kwargs: object
        ) -> ObservedLauncherEffect | None:
            return self.effects.get((effect_id, binding_hash))

        def run_effect(self, argv: tuple[str, ...], **kwargs: object) -> tuple[SandboxCompleted, str]:
            effect_id = kwargs.pop("effect_id")
            binding_hash = kwargs.pop("binding_hash")
            completed = self.run(argv, **kwargs)
            receipt = hash_json({"effect_id": effect_id, "binding_hash": binding_hash})
            self.effects[(effect_id, binding_hash)] = ObservedLauncherEffect(receipt, completed.returncode)
            return completed, receipt

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
    ).run("f" * 64, workspace)

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
        release_manifest=(),
        release_manifest_hash="1" * 64,
        runner_executable="runner.py",
        repair_source_manifest_hash="2" * 64,
        dependency_lock_hash="3" * 64,
        contract_hashes={},
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
    built = builder.build("e" * 64, tmp_path, source, "6" * 64, "7" * 64)
    assert built.identity.content_hash == built.release_manifest_hash
    assert built.identity.source_sha == source.content_hash
    assert built.identity.dependency_lock_hash == "6" * 64
    assert built.identity.contract_bundle_hash == hash_json({})


@pytest.mark.parametrize(
    ("limit_name", "limit"),
    (
        ("MAX_RELEASE_FILES", 1),
        ("MAX_RELEASE_FILE_BYTES", 1),
        ("MAX_RELEASE_TOTAL_BYTES", 1),
    ),
)
def test_release_manifest_rejects_file_count_per_file_and_aggregate_oversize(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    limit_name: str,
    limit: int,
) -> None:
    release = tmp_path / "release"
    release.mkdir()
    for name in ("runner", "contracts.json"):
        path = release / name
        path.write_bytes(b"content")
        path.chmod(0o555)
    release.chmod(0o555)
    monkeypatch.setattr(runner_module, limit_name, limit, raising=False)

    with pytest.raises(UnauthorizedRepairError, match="limit"):
        capture_built_release_manifest(release)


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
    assert harness.git.calls == 3
    assert harness.regression.calls == 1
    assert harness.builder.calls == 1


def test_source_mutation_after_regression_recaptures_and_reruns_before_build(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    request = harness.request()
    harness.git.source_contents = ["1" * 64, *("9" * 64 for _ in range(4))]

    pending = harness.runner.validate_regress_build(request)

    assert harness.regression.calls == 2
    assert harness.builder.calls == 1
    expected_source = RepairSourceManifest(
        baseline_sha="a" * 40,
        files=(
            RepairSourceFile(
                path="src/auto_code/runner.py",
                status="M",
                old_path=None,
                old_object_id="b" * 40,
                object_id="c" * 40,
                mode="100644",
                binary=False,
                untracked=False,
                content_sha256="9" * 64,
            ),
        ),
    )
    assert harness.builder.sources == [expected_source]
    assert pending.repair_source_manifest_hash == expected_source.content_hash


@pytest.mark.parametrize("phase", ("regression", "build"))
@pytest.mark.parametrize("point", ("before_invocation", "after_invocation", "after_observation"))
def test_repair_effect_recovery_observes_before_reinvoking(
    tmp_path: Path,
    phase: str,
    point: str,
) -> None:
    harness = RepairHarness(tmp_path)
    request = harness.request()
    harness.runner.crash_at(phase, point)

    with pytest.raises(InjectedCrash):
        harness.runner.validate_regress_build(request)
    harness.runner.validate_regress_build(request)

    if phase == "regression":
        assert harness.regression.calls == 1
        assert harness.builder.calls == 1
    else:
        assert harness.regression.calls == 1
        assert harness.builder.calls == 1


def test_built_contract_manifest_drives_per_stage_compatibility(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    request = replace(
        harness.request(),
        contract_hashes={Stage.ANALYST: "a" * 64, Stage.ARCHITECT_OUTLINE: "b" * 64},
    )
    harness.repair_service.request_hash = request.content_hash
    harness.builder.contract_hashes = {
        Stage.ANALYST: "a" * 64,
        Stage.ARCHITECT_OUTLINE: "c" * 64,
    }

    pending = harness.runner.validate_regress_build(request)
    assert pending.contract_hashes == harness.builder.contract_hashes

    lifecycle_calls: list[str] = []
    launcher = TrustedLauncher(
        harness.store,
        harness.registry,
        repair_service=harness.repair_service,
        terminate_old_runner=FakeLifecycleEffect("terminate", lifecycle_calls),
        start_new_runner=FakeLifecycleEffect("start", lifecycle_calls),
        attest_new_runner=FakeLifecycleEffect("attest", lifecycle_calls),
    )
    launcher.reconcile_activation("run-1", request.content_hash)
    receipt = harness.registry.lookup_activation(request.content_hash)
    assert receipt.compatible_checkpoint_stages == (Stage.ANALYST,)


def test_contract_mismatch_invalidates_later_equal_descendants(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    request = replace(
        harness.request(),
        contract_hashes={Stage.ANALYST: "a" * 64, Stage.ARCHITECT_OUTLINE: "b" * 64},
    )
    harness.repair_service.request_hash = request.content_hash
    harness.builder.contract_hashes = {
        Stage.ANALYST: "c" * 64,
        Stage.ARCHITECT_OUTLINE: "b" * 64,
    }
    harness.runner.validate_regress_build(request)
    lifecycle_calls: list[str] = []
    TrustedLauncher(
        harness.store,
        harness.registry,
        repair_service=harness.repair_service,
        terminate_old_runner=FakeLifecycleEffect("terminate", lifecycle_calls),
        start_new_runner=FakeLifecycleEffect("start", lifecycle_calls),
        attest_new_runner=FakeLifecycleEffect("attest", lifecycle_calls),
    ).reconcile_activation("run-1", request.content_hash)

    assert harness.registry.lookup_activation(request.content_hash).compatible_checkpoint_stages == ()


def test_pending_build_record_recovers_a_missing_build_journal_completion(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    request = harness.request()
    pending = harness.runner.validate_regress_build(request)
    journal = RepairJournal(harness.state_root, request.content_hash)
    payload = {
        "request_hash": request.content_hash,
        "effects": {
            "source_manifest": {
                "input_hash": pending.repair_source_manifest_hash,
                "events": [
                    {"kind": "intention"},
                    {"kind": "observation", "evidence_hash": pending.repair_source_manifest_hash},
                    {"kind": "reconciliation", "evidence_hash": pending.repair_source_manifest_hash},
                ],
            },
            "regression": {
                "input_hash": pending.regression_evidence_hash,
                "events": [
                    {"kind": "intention"},
                    {"kind": "observation", "evidence_hash": pending.regression_evidence_hash},
                    {"kind": "reconciliation", "evidence_hash": pending.regression_evidence_hash},
                ],
            },
        },
    }
    from auto_code.state import _atomic_replace_json
    _atomic_replace_json(journal.path, payload)

    recovered = harness.runner.validate_regress_build(request)

    assert recovered == pending
    assert harness.builder.calls == 1
    assert RepairJournal(harness.state_root, request.content_hash).completed("build") == pending.build_evidence_hash


def test_registry_possession_alone_cannot_publish_an_activation(tmp_path: Path) -> None:
    registry = RunnerRegistry(tmp_path / "registry", repair_runner_identity=identity("e", repair=True))
    mutation_names = {
        name
        for name in dir(registry)
        if any(
            fragment in name
            for fragment in ("publish", "activate", "replace_pointer", "record", "issue")
        )
        and callable(getattr(registry, name))
    }

    assert mutation_names == set()
    assert not registry.pointer_path.exists()


def test_state_transition_verification_accepts_only_the_current_activation_pointer(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    request = harness.request()
    harness.runner.validate_regress_build(request)
    previous = harness.store.load()
    lifecycle_calls: list[str] = []
    launcher = TrustedLauncher(
        harness.store,
        harness.registry,
        repair_service=harness.repair_service,
        terminate_old_runner=FakeLifecycleEffect("terminate", lifecycle_calls),
        start_new_runner=FakeLifecycleEffect("start", lifecycle_calls),
        attest_new_runner=FakeLifecycleEffect("attest", lifecycle_calls),
        ticket_invoker=FakeTicketInvoker(),
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


def test_activation_receipt_persists_exact_release_and_invocation_reverifies_it(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    request = harness.request()
    pending = harness.runner.validate_regress_build(request)
    commands: list[tuple[str, ...]] = []
    lifecycle_calls: list[str] = []
    launcher = TrustedLauncher(
        harness.store,
        harness.registry,
        repair_service=harness.repair_service,
        terminate_old_runner=FakeLifecycleEffect("terminate", lifecycle_calls),
        start_new_runner=FakeLifecycleEffect("start", lifecycle_calls),
        attest_new_runner=FakeLifecycleEffect("attest", lifecycle_calls),
        ticket_invoker=FakeTicketInvoker(commands),
    )
    launcher.reconcile_activation("run-1", request.content_hash)

    receipt = harness.registry.lookup_activation(request.content_hash)
    assert receipt.release_root == pending.release_root
    assert receipt.release_manifest == pending.release_manifest
    assert receipt.runner_executable == "runner.py"
    assert launcher.invoke("run-1", ("status",)) == ("status",)
    assert commands == [("status",)]

    receipt.release_root.chmod(0o755)
    (receipt.release_root / "runner.py").chmod(0o644)
    (receipt.release_root / "runner.py").write_bytes(b"tampered runner\n")
    with pytest.raises(PermissionError, match="release"):
        launcher.invoke("run-1", ("status",))


def test_ticket_runner_executes_descriptor_held_release_after_path_replacement(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    request = harness.request()
    pending = harness.runner.validate_regress_build(request)
    calls: list[str] = []

    class ReplacingInvoker:
        def invoke(self, executable: VerifiedExecutable, argv: tuple[str, ...]) -> str:
            pending.release_root.chmod(0o755)
            replacement = pending.release_root / "replacement"
            replacement.write_bytes(b"#!/bin/sh\nprintf mutable-runner")
            replacement.chmod(0o555)
            replacement.replace(pending.release_root / pending.runner_executable)
            completed = subprocess.run(
                (f"/proc/self/fd/{executable.descriptor}", *argv),
                pass_fds=(executable.descriptor,),
                capture_output=True,
                check=False,
            )
            assert completed.returncode == 0
            return completed.stdout.decode("ascii")

    launcher = TrustedLauncher(
        harness.store,
        harness.registry,
        repair_service=harness.repair_service,
        terminate_old_runner=FakeLifecycleEffect("terminate", calls),
        start_new_runner=FakeLifecycleEffect("start", calls),
        attest_new_runner=FakeLifecycleEffect("attest", calls),
        ticket_invoker=ReplacingInvoker(),  # type: ignore[arg-type]
    )
    launcher.reconcile_activation("run-1", request.content_hash)

    assert launcher.invoke("run-1", ("status",)) == "immutable-runner"


def test_activation_receipt_rejects_missing_transaction_evidence() -> None:
    payload = activation_receipt("1" * 64, identity("a"), identity("b")).payload()
    del payload["termination_evidence_hash"]
    with pytest.raises(ValueError, match="invalid"):
        RunnerActivationReceipt.from_payload(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("run_id", "r" * 256),
        ("expected_revision", True),
        ("compatible_checkpoint_stages", [Stage.ANALYST.value, Stage.ANALYST.value]),
        ("compatible_checkpoint_stages", [Stage.ARCHITECT_OUTLINE.value, Stage.ANALYST.value]),
        ("release_manifest_hash", "f" * 64),
    ),
)
def test_activation_receipt_strictly_rejects_unbounded_duplicate_or_incoherent_fields(
    field: str,
    value: object,
) -> None:
    receipt = activation_receipt("1" * 64, identity("a"), identity("b"))
    payload = receipt.payload()
    payload[field] = value

    with pytest.raises(ValueError, match="activation receipt"):
        RunnerActivationReceipt.from_payload(payload)


def test_launcher_keeps_state_non_active_until_termination_start_and_attestation_are_durable(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    request = harness.request()
    harness.runner.validate_regress_build(request)
    calls: list[str] = []
    terminate = FakeLifecycleEffect("terminate", calls)
    start = FakeLifecycleEffect("start", calls)
    attest = FakeLifecycleEffect("attest", calls)
    launcher = TrustedLauncher(
        harness.store,
                harness.registry,
        repair_service=harness.repair_service,
        terminate_old_runner=terminate,
        start_new_runner=start,
        attest_new_runner=attest,
        ticket_invoker=FakeTicketInvoker(),
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
        repair_service=harness.repair_service,
        terminate_old_runner=terminate,
        start_new_runner=start,
        attest_new_runner=attest,
        ticket_invoker=FakeTicketInvoker(),
    )
    generation = recovered.reconcile_activation("run-1", request.content_hash)

    assert generation.state.disposition is RunDisposition.ACTIVE
    assert calls == ["terminate", "start", "attest"]
    assert recovered.invoke("run-1", ("status",))[-1] == "status"


@pytest.mark.parametrize(
    "phase",
    ("old_runner_terminated", "new_runner_started", "identity_attested"),
)
@pytest.mark.parametrize("point", ("before_invocation", "after_invocation", "after_observation"))
def test_launcher_lifecycle_recovery_observes_each_effect_before_reinvoking(
    tmp_path: Path,
    phase: str,
    point: str,
) -> None:
    harness = RepairHarness(tmp_path)
    request = harness.request()
    harness.runner.validate_regress_build(request)
    calls: list[str] = []
    launcher = TrustedLauncher(
        harness.store,
        harness.registry,
        repair_service=harness.repair_service,
        terminate_old_runner=FakeLifecycleEffect("terminate", calls),
        start_new_runner=FakeLifecycleEffect("start", calls),
        attest_new_runner=FakeLifecycleEffect("attest", calls),
    )
    launcher.crash_at(phase, point)

    with pytest.raises(InjectedCrash):
        launcher.reconcile_activation("run-1", request.content_hash)
    generation = launcher.reconcile_activation("run-1", request.content_hash)

    assert generation.state.disposition is RunDisposition.ACTIVE
    assert calls == ["terminate", "start", "attest"]


def test_recovery_after_state_cas_records_final_phase_without_repeating_lifecycle(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    request = harness.request()
    harness.runner.validate_regress_build(request)
    calls: list[str] = []
    terminate = FakeLifecycleEffect("terminate", calls)
    start = FakeLifecycleEffect("start", calls)
    attest = FakeLifecycleEffect("attest", calls)
    launcher = TrustedLauncher(
        harness.store,
        harness.registry,
        repair_service=harness.repair_service,
        terminate_old_runner=terminate,
        start_new_runner=start,
        attest_new_runner=attest,
        ticket_invoker=FakeTicketInvoker(),
    )
    launcher.crash_after("state_cas")

    with pytest.raises(InjectedCrash):
        launcher.reconcile_activation("run-1", request.content_hash)

    recovered = TrustedLauncher(
        harness.store,
        harness.registry,
        repair_service=harness.repair_service,
        terminate_old_runner=terminate,
        start_new_runner=start,
        attest_new_runner=attest,
        ticket_invoker=FakeTicketInvoker(),
    )
    generation = recovered.reconcile_activation("run-1", request.content_hash)

    assert generation.state.disposition is RunDisposition.ACTIVE
    assert calls == ["terminate", "start", "attest"]
    assert RepairJournal(harness.state_root, request.content_hash).completed("state_activated") == generation.state_hash
    assert recovered.invoke("run-1", ("status",))[-1] == "status"


def test_recovery_after_pointer_publication_completes_the_exact_state_transition(tmp_path: Path) -> None:
    harness = RepairHarness(tmp_path)
    request = harness.request()
    harness.runner.validate_regress_build(request)
    calls: list[str] = []
    launcher = TrustedLauncher(
        harness.store,
        harness.registry,
        repair_service=harness.repair_service,
        terminate_old_runner=FakeLifecycleEffect("terminate", calls),
        start_new_runner=FakeLifecycleEffect("start", calls),
        attest_new_runner=FakeLifecycleEffect("attest", calls),
    )
    launcher.crash_after("activation_pointer")

    with pytest.raises(InjectedCrash):
        launcher.reconcile_activation("run-1", request.content_hash)

    assert harness.registry.current_activation().request_hash == request.content_hash
    assert harness.store.load().state.disposition is RunDisposition.REPAIR_REQUIRED

    generation = launcher.reconcile_activation("run-1", request.content_hash)

    assert generation.state.disposition is RunDisposition.ACTIVE
    assert generation.state.runner_identity == harness.registry.current_activation().new_runner_identity
    assert RepairJournal(harness.state_root, request.content_hash).completed("state_activated") == generation.state_hash
    assert calls == ["terminate", "start", "attest"]


def test_protected_runtime_exposes_no_unbound_capability_injection(tmp_path: Path) -> None:
    descriptor = repair_entrypoint.RepairRuntimeDescriptor.from_payload(
        descriptor_payload(tmp_path, issued_at=NOW), now=NOW
    )

    assert not hasattr(repair_entrypoint.ProtectedRepairRuntime(descriptor), "with_capabilities")


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


def test_installed_ticket_cli_composes_repair_request_from_launcher_descriptor(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    harness = RepairHarness(tmp_path)
    project = tmp_path / "project"
    manifest_path = project / "manifests" / "product.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_bytes(canonical_json_bytes(product_manifest().model_dump(mode="json", round_trip=True)))
    runtime = TrustedRuntimeConfig(
        state_root=harness.state_root,
        project_root=project,
        project_policy_path=project / "auto-code.yaml",
        project_policy_hash="8" * 64,
        runner_identity=identity("a"),
        repair_registry_root=harness.state_root,
        repair_runner_identity=identity("e", repair=True),
        repair_repository_id="repair-repo",
    )

    result = ticket_main(
        [
            "repair-request", "--run", "run-1", "--expected-revision", str(harness.generation.revision),
            "--expected-hash", harness.generation.state_hash, "--workspace", str(harness.handle.path),
            "--plan", str(harness.plan_path), "--json",
        ],
        runtime=runtime,
    )

    assert result == 0
    request_hash = json.loads(capsys.readouterr().out)["request_hash"]
    assert RepairGuard(harness.handle.path).load_request(request_hash).run_id == "run-1"


def test_protected_cli_has_no_callback_only_production_composition() -> None:
    assert tuple(inspect.signature(repair_entrypoint.main).parameters) == ("argv", "runtime")
    assert not hasattr(repair_entrypoint.ProtectedRepairRuntime, "with_capabilities")
    assert "authorize" not in inspect.signature(RepairRunner).parameters
    assert "authorize" not in inspect.signature(TrustedLauncher).parameters


def test_installed_protected_prepare_composes_pinned_process_git_and_sandbox(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    harness = RepairHarness(tmp_path)
    repository = tmp_path / "repair-repository"
    repository.mkdir()
    executable = tmp_path / "trusted-tool"
    executable.write_bytes(b"trusted launcher tool\n")
    executable.chmod(0o755)
    executable_hash = sha256(executable.read_bytes()).hexdigest()
    for path in (tmp_path / "controlled-home", tmp_path / "secrets", tmp_path / "runner-releases"):
        path.mkdir(exist_ok=True)
    server = FakeSandboxServer(tmp_path / "launcher-sandbox.sock")
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    payload = descriptor_payload(tmp_path)
    payload.update(
        {
            "expected_revision": harness.generation.revision,
            "expected_state_hash": harness.generation.state_hash,
            "failure_hash": harness.failure_hash,
            "git_executable": str(executable),
            "git_executable_hash": executable_hash,
            "regression_command": [str(executable), "regression"],
            "regression_executable_hash": executable_hash,
            "build_command": [str(executable), "build"],
            "build_executable_hash": executable_hash,
            "terminate_command": [str(executable), "terminate"],
            "terminate_executable_hash": executable_hash,
            "start_command": [str(executable), "start"],
            "start_executable_hash": executable_hash,
            "attest_command": [str(executable), "attest"],
            "attest_executable_hash": executable_hash,
        }
    )
    payload["sandbox_policy_hash"] = hash_json(
        {
            "repair_repository_root": payload["repair_repository_root"],
            "repair_workspace_root": payload["repair_workspace_root"],
            "controlled_home": payload["controlled_home"],
            "secret_paths": payload["secret_paths"],
            "environment_allowlist": [],
            "dynamic_downloads_disabled": True,
        }
    )
    preparation_observation: dict[str, bool] = {}
    journal_path = harness.state_root / "repair-prepare-journals" / f'{payload["nonce"]}.json'
    server.before_worktree = lambda: preparation_observation.update(journal_exists=journal_path.exists())
    descriptor = signed_descriptor(tmp_path / "descriptor.json", payload, private_key)
    try:
        monkeypatch.setattr(repair_entrypoint, "_REPAIR_DESCRIPTOR_FD", descriptor)
        runtime = repair_entrypoint.load_protected_runtime(verification_key=public_key)
        result = repair_entrypoint.main(
            [
                "prepare", "--run", "run-1", "--expected-revision", str(harness.generation.revision),
                "--expected-hash", harness.generation.state_hash, "--failure", harness.failure_hash,
            ],
            runtime=runtime,
        )
        requests_before_recovery = len(server.requests)
        recovered = runtime.prepare(
            "run-1",
            harness.generation.revision,
            harness.generation.state_hash,
            harness.failure_hash,
        )
    finally:
        os.close(descriptor)
        server.close()

    assert result == 0
    output = json.loads(capsys.readouterr().out)
    assert preparation_observation == {"journal_exists": True}
    assert recovered.id == output["workspace"]["id"]
    assert recovered.path == Path(output["workspace"]["path"])
    assert len(server.requests) == requests_before_recovery
    assert output == {
        "schema_version": "v1",
        "operation": "prepare",
        "run_id": "run-1",
        "expected_revision": harness.generation.revision,
        "expected_state_hash": harness.generation.state_hash,
        "failure_hash": harness.failure_hash,
        "workspace": {
            "id": output["workspace"]["id"],
            "path": output["workspace"]["path"],
            "baseline_hash": "a" * 40,
        },
    }
    assert Path(output["workspace"]["path"]).name == output["workspace"]["id"]
    assert any("worktree" in request["argv"] for request in server.requests)
    assert all(request["sandbox_identity"] == "launcher-sandbox" for request in server.requests)
    nonce = harness.state_root / "repair-descriptor-nonces" / f'{payload["nonce"]}.json'
    assert json.loads(nonce.read_text(encoding="ascii"))["status"] == "completed"


def test_installed_protected_apply_builds_reconciles_and_activates_from_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    harness = RepairHarness(tmp_path)
    repository = tmp_path / "repair-repository"
    repository.mkdir()
    git_executable = Path(shutil.which("git") or "")
    assert git_executable.is_absolute()
    subprocess.run((str(git_executable), "init", "-q", str(repository)), check=True)
    subprocess.run((str(git_executable), "-C", str(repository), "config", "user.name", "Test"), check=True)
    subprocess.run((str(git_executable), "-C", str(repository), "config", "user.email", "test@example.com"), check=True)
    source = repository / "src" / "auto_code"
    source.mkdir(parents=True)
    (source / "runner.py").write_text("baseline\n", encoding="ascii")
    (repository / "pyproject.toml").write_text("[project]\nname='repair'\n", encoding="ascii")
    subprocess.run((str(git_executable), "-C", str(repository), "add", "."), check=True)
    subprocess.run((str(git_executable), "-C", str(repository), "commit", "-qm", "baseline"), check=True)
    tool = tmp_path / "trusted-tool"
    tool.write_bytes(b"trusted launcher tool\n")
    tool.chmod(0o755)
    tool_hash = sha256(tool.read_bytes()).hexdigest()
    git_hash = sha256(git_executable.read_bytes()).hexdigest()
    for path in (tmp_path / "controlled-home", tmp_path / "secrets", tmp_path / "runner-releases"):
        path.mkdir(exist_ok=True)
    server = FakeSandboxServer(tmp_path / "launcher-sandbox.sock")
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    def protected_payload(operation: str) -> dict[str, object]:
        payload = descriptor_payload(tmp_path, operation=operation)
        payload.update(
            {
                "expected_revision": harness.generation.revision,
                "expected_state_hash": harness.generation.state_hash,
                "failure_hash": harness.failure_hash,
                "git_executable": str(git_executable),
                "git_executable_hash": git_hash,
                "regression_command": [str(tool), "regression"],
                "regression_executable_hash": tool_hash,
                "build_command": [str(tool), "build"],
                "build_executable_hash": tool_hash,
                "terminate_command": [str(tool), "terminate"],
                "terminate_executable_hash": tool_hash,
                "start_command": [str(tool), "start"],
                "start_executable_hash": tool_hash,
                "attest_command": [str(tool), "attest"],
                "attest_executable_hash": tool_hash,
            }
        )
        payload["sandbox_policy_hash"] = hash_json(
            {
                "repair_repository_root": payload["repair_repository_root"],
                "repair_workspace_root": payload["repair_workspace_root"],
                "controlled_home": payload["controlled_home"],
                "secret_paths": payload["secret_paths"],
                "environment_allowlist": [],
                "dynamic_downloads_disabled": True,
            }
        )
        return payload

    prepare_payload = protected_payload("prepare")
    prepare_descriptor = signed_descriptor(tmp_path / "prepare.json", prepare_payload, private_key)
    try:
        monkeypatch.setattr(repair_entrypoint, "_REPAIR_DESCRIPTOR_FD", prepare_descriptor)
        prepare_runtime = repair_entrypoint.load_protected_runtime(verification_key=public_key)
        handle = prepare_runtime.prepare(
            "run-1", harness.generation.revision, harness.generation.state_hash, harness.failure_hash
        )
    finally:
        os.close(prepare_descriptor)

    (handle.path / "src" / "auto_code" / "runner.py").write_text("repaired\n", encoding="ascii")
    control = handle.path / ".repair-control"
    control.mkdir()
    plan = RepairPlan("cause", ("src/auto_code/runner.py",), "repair", ("d" * 64,))
    plan_path = control / "plan.json"
    plan_path.write_bytes(canonical_json_bytes(plan.payload()))
    project = tmp_path / "project"
    manifest_path = project / "manifests" / "product.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_bytes(canonical_json_bytes(product_manifest().model_dump(mode="json", round_trip=True)))
    request_runtime = TrustedRuntimeConfig(
        state_root=harness.state_root,
        project_root=project,
        project_policy_path=project / "auto-code.yaml",
        project_policy_hash="8" * 64,
        runner_identity=identity("a"),
        repair_registry_root=harness.state_root,
        repair_runner_identity=identity("e", repair=True),
        repair_repository_id="repair-repo",
    )
    assert ticket_main(
        [
            "repair-request", "--run", "run-1", "--expected-revision", str(harness.generation.revision),
            "--expected-hash", harness.generation.state_hash, "--workspace", str(handle.path),
            "--plan", str(plan_path), "--json",
        ],
        runtime=request_runtime,
    ) == 0
    capsys.readouterr()
    requests = tuple((handle.path / ".repair-control" / "requests").iterdir())
    request_hash = requests[0].stem
    observed_build: dict[str, object] = {}

    def mutate_after_snapshot(request: dict[str, object]) -> None:
        argv = request["argv"]
        assert isinstance(argv, list)
        build_workspace = Path(argv[argv.index("--workspace") + 1])
        (handle.path / "src" / "auto_code" / "runner.py").write_text("mutated after snapshot\n", encoding="ascii")
        observed_build["workspace"] = build_workspace
        observed_build["content"] = (build_workspace / "src" / "auto_code" / "runner.py").read_text(encoding="ascii")

    server.before_build = mutate_after_snapshot

    apply_payload = protected_payload("apply")
    apply_payload.pop("failure_hash", None)
    apply_payload.update(
        {
            "workspace_id": handle.id,
            "workspace_path": str(handle.path),
            "request_hash": request_hash,
            "nonce": "f" * 64,
        }
    )
    apply_descriptor = signed_descriptor(tmp_path / "apply.json", apply_payload, private_key)
    try:
        monkeypatch.setattr(repair_entrypoint, "_REPAIR_DESCRIPTOR_FD", apply_descriptor)
        runtime = repair_entrypoint.load_protected_runtime(verification_key=public_key)
        result = repair_entrypoint.main(
            ["apply", "--workspace", str(handle.path), "--request", request_hash],
            runtime=runtime,
        )
        sandbox_requests = len(server.requests)
        recovered = runtime.apply(str(handle.path), request_hash)
    finally:
        os.close(apply_descriptor)
        server.close()

    assert result == 0
    generation = harness.store.load()
    assert generation.state.disposition is RunDisposition.ACTIVE
    assert recovered == generation
    assert len(server.requests) == sandbox_requests
    receipt = harness.registry.current_activation()
    assert receipt.release_root.is_relative_to(tmp_path / "runner-releases")
    assert receipt.release_manifest
    assert observed_build == {
        "workspace": tmp_path / "repair-source-snapshots" / next(
            request["effect_id"]
            for request in server.requests
            if request.get("operation") == "invoke_effect" and request.get("argv", [None])[0] == "build"
        ),
        "content": "repaired\n",
    }
    effect_operations = [request.get("operation") for request in server.requests if request.get("operation")]
    assert effect_operations.count("observe_effect") == 5
    assert effect_operations.count("invoke_effect") == 5
    assert len(server.effects) == 5
    assert json.loads(capsys.readouterr().out) == {
        "schema_version": "v1",
        "operation": "apply",
        "run_id": "run-1",
        "request_hash": request_hash,
        "workspace_id": handle.id,
        "workspace_path": str(handle.path),
        "revision": generation.revision,
        "state_hash": generation.state_hash,
        "runner_identity_hash": generation.state.runner_identity.content_hash,
    }


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
