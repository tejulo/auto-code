from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import array
import fcntl
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auto_code.contracts import EvidenceRef
from auto_code.process import (
    SPAWN_FAILURE_RETURN_CODE,
    TIMEOUT_RETURN_CODE,
    CommandFailedError,
    CommandFailureKind,
    CommandResult,
    EvidenceSinkError,
    FilesystemEvidenceSink,
    HashVerifiedExecutables,
    LauncherSocketSandbox,
    ManagedProcessRunner,
    ManagedProcessStartError,
    ProcessConfigurationError,
    ProcessRunner,
    PythonArchiveTicketInvoker,
    SandboxCompleted,
    SandboxStartError,
    SandboxPolicyHandoff,
    SandboxPolicy,
    VerifiedExecutable,
)
from auto_code.hashing import canonical_json_bytes


def test_filesystem_evidence_sink_rejects_replaced_root(tmp_path: Path) -> None:
    root = tmp_path / "evidence"
    sink = FilesystemEvidenceSink(root)
    original = tmp_path / "original-evidence"
    root.rename(original)
    attacker = tmp_path / "attacker"
    attacker.mkdir()
    root.symlink_to(attacker, target_is_directory=True)
    result = CommandResult(("probe",), 0, "output", "", None, None, True)

    with pytest.raises(ProcessConfigurationError, match="symlinks|identity changed"):
        sink.write(result)

    assert tuple(attacker.iterdir()) == ()


class RecordingEvidenceSink:
    def __init__(self) -> None:
        self.results: list[CommandResult] = []

    def write(self, result: CommandResult) -> CommandResult:
        self.results.append(result)
        return replace(
            result,
            stdout_path=evidence_ref("stdout", result.stdout_text),
            stderr_path=evidence_ref("stderr", result.stderr_text),
        )


class RecordingVerifier:
    def __init__(self, executable: str = "/trusted/bin/probe") -> None:
        self.executable = executable
        self.requests: list[str] = []

    def require_absolute_verified(self, executable: str) -> VerifiedExecutable:
        self.requests.append(executable)
        return VerifiedExecutable(self.executable, os.open(os.devnull, os.O_RDONLY))


class UnpersistedEvidenceSink:
    def write(self, result: CommandResult) -> CommandResult:
        return result


class FailingOnceEvidenceSink(RecordingEvidenceSink):
    def __init__(self) -> None:
        super().__init__()
        self.failures_remaining = 1

    def write(self, result: CommandResult) -> CommandResult:
        if self.failures_remaining:
            self.failures_remaining -= 1
            raise OSError("evidence unavailable")
        return super().write(result)


class RecordingSandbox:
    def __init__(self, outcome: SandboxCompleted | BaseException) -> None:
        self.outcome = outcome
        self.run_calls: list[tuple[tuple[str, ...], Path, float, dict[str, str], SandboxPolicyHandoff, VerifiedExecutable]] = []
        self.start_calls: list[
            tuple[tuple[str, ...], Path, float, dict[str, str], SandboxPolicyHandoff, VerifiedExecutable, bool]
        ] = []
        self.handle: RecordingHandle | None = None

    def run(
        self,
        argv: tuple[str, ...],
        *,
        executable: VerifiedExecutable,
        timeout: float,
        env: dict[str, str],
        policy: SandboxPolicyHandoff,
    ) -> SandboxCompleted:
        self.run_calls.append((argv, policy.cwd.path, timeout, env, policy, executable))
        if isinstance(self.outcome, BaseException):
            raise self.outcome
        return self.outcome

    def start(
        self,
        argv: tuple[str, ...],
        *,
        executable: VerifiedExecutable,
        timeout: float,
        env: dict[str, str],
        policy: SandboxPolicyHandoff,
        new_process_group: bool,
    ) -> RecordingHandle:
        self.start_calls.append((argv, policy.cwd.path, timeout, env, policy, executable, new_process_group))
        assert self.handle is not None
        return self.handle


class RecordingHandle:
    def __init__(self, waits: list[SandboxCompleted | BaseException]) -> None:
        self.waits = waits
        self.actions: list[str] = []

    def poll(self) -> int | None:
        return None

    def wait(self, timeout: float | None = None) -> SandboxCompleted:
        self.actions.append(f"wait:{timeout}")
        outcome = self.waits.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def terminate_group(self) -> None:
        self.actions.append("terminate")

    def kill_group(self) -> None:
        self.actions.append("kill")


def evidence_ref(stream: str, content: str) -> EvidenceRef:
    return EvidenceRef(
        relative_path=f"process/{stream}.txt",
        sha256=sha256(content.encode("utf-8")).hexdigest(),
        media_type="text/plain",
        creator="process",
    )


@pytest.fixture
def sandbox_policy(tmp_path: Path) -> SandboxPolicy:
    repository = tmp_path / "repository"
    build = repository / "build"
    home = tmp_path / "controlled-home"
    state = tmp_path / "authoritative-state"
    secrets = tmp_path / "secrets"
    for directory in (repository, build, home, state, secrets):
        directory.mkdir(parents=True, exist_ok=True)
    return SandboxPolicy(
        project_root=repository,
        readable_roots=(repository,),
        writable_roots=(build,),
        authoritative_state_root=state,
        secret_paths=(secrets,),
        controlled_home=home,
        environment_allowlist=frozenset({"LANG"}),
    )


def test_runner_fails_closed_without_trusted_execution_capabilities(sandbox_policy: SandboxPolicy) -> None:
    evidence = RecordingEvidenceSink()

    result = ProcessRunner().run(
        ("/untrusted/bin/probe", "--check"),
        sandbox_policy.project_root,
        1,
        evidence,
        {"LANG": "C"},
        sandbox_policy,
    )

    assert result.returncode == SPAWN_FAILURE_RETURN_CODE
    assert result.failure_kind is CommandFailureKind.CONFIGURATION
    assert len(evidence.results) == 1
    assert evidence.results[0].stdout_path is None
    assert result.stdout_path is not None
    assert result.stderr_path is not None


def test_runner_uses_verified_executable_with_sanitized_bounded_evidence_and_explicit_environment(
    sandbox_policy: SandboxPolicy,
) -> None:
    verifier = RecordingVerifier()
    sandbox = RecordingSandbox(
        SandboxCompleted(
            returncode=0,
            stdout="token=not-for-results\n" + "x" * 20_000,
            stderr="Bearer also-not-for-results",
        )
    )
    evidence = RecordingEvidenceSink()

    result = ProcessRunner(verifier, sandbox).run(
        ("/requested/bin/probe", "--check"),
        sandbox_policy.project_root,
        3,
        evidence,
        {"LANG": "C"},
        sandbox_policy,
    )

    assert verifier.requests == ["/requested/bin/probe"]
    assert sandbox.run_calls[0][0] == ("/trusted/bin/probe", "--check")
    environment = sandbox.run_calls[0][3]
    assert environment["HOME"] == str(sandbox_policy.controlled_home)
    assert environment["LANG"] == "C"
    assert environment["PIP_NO_INDEX"] == "1"
    assert "PATH" not in environment
    assert "HOST_SECRET" not in environment
    assert result.redacted is True
    assert len(result.stdout_text) < 20_000
    assert "not-for-results" not in result.stdout_text
    assert "not-for-results" not in result.stderr_text
    assert result.stdout_path is not None
    assert result.stderr_path is not None
    assert all("not-for-results" not in str(item) for item in evidence.results)


def test_runner_redacts_positional_and_assignment_secrets_without_changing_the_sandbox_command(
    sandbox_policy: SandboxPolicy,
) -> None:
    sandbox = RecordingSandbox(SandboxCompleted(returncode=0, stdout="", stderr=""))
    evidence = RecordingEvidenceSink()
    command = (
        "/requested/bin/probe",
        "--token",
        "plain-secret-value",
        "--password=inline-secret-value",
        "api_key=assignment-secret-value",
    )

    result = ProcessRunner(RecordingVerifier(), sandbox).run(
        command,
        sandbox_policy.project_root,
        1,
        evidence,
        {"LANG": "C"},
        sandbox_policy,
    )

    assert sandbox.run_calls[0][0] == ("/trusted/bin/probe", *command[1:])
    assert "plain-secret-value" not in result.argv
    assert "inline-secret-value" not in result.argv
    assert "assignment-secret-value" not in result.argv
    assert "plain-secret-value" not in str(evidence.results)


def test_runner_rejects_secret_bearing_values_before_the_sandbox_can_receive_them(sandbox_policy: SandboxPolicy) -> None:
    sandbox = RecordingSandbox(SandboxCompleted(returncode=0, stdout="", stderr=""))
    evidence = RecordingEvidenceSink()

    result = ProcessRunner(RecordingVerifier(), sandbox).run(
        ("/requested/bin/probe",),
        sandbox_policy.project_root,
        1,
        evidence,
        {"LANG": "token=must-not-reach-product"},
        sandbox_policy,
    )

    assert result.failure_kind is CommandFailureKind.CONFIGURATION
    assert "must-not-reach-product" not in str(result)
    assert sandbox.run_calls == []


def test_runner_allows_only_fixed_safe_git_configuration_environment(sandbox_policy: SandboxPolicy) -> None:
    safe_git_environment = {
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    sandbox = RecordingSandbox(SandboxCompleted(returncode=0, stdout="", stderr=""))

    result = ProcessRunner(RecordingVerifier(), sandbox).run(
        ("/requested/bin/probe",),
        sandbox_policy.project_root,
        1,
        RecordingEvidenceSink(),
        {"LANG": "C", **safe_git_environment},
        sandbox_policy,
    )

    assert result.returncode == 0
    assert sandbox.run_calls[0][3] == {
        "HOME": str(sandbox_policy.controlled_home),
        "PIP_NO_INDEX": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "npm_config_offline": "true",
        "LANG": "C",
        **safe_git_environment,
    }
    rejected = ProcessRunner(RecordingVerifier(), RecordingSandbox(SandboxCompleted(returncode=0, stdout="", stderr=""))).run(
        ("/requested/bin/probe",),
        sandbox_policy.project_root,
        1,
        RecordingEvidenceSink(),
        {"LANG": "C", **safe_git_environment, "GIT_CONFIG_GLOBAL": "/tmp/unsafe"},
        sandbox_policy,
    )
    assert rejected.failure_kind is CommandFailureKind.CONFIGURATION


def test_runner_rejects_a_verifier_result_that_is_not_an_absolute_executable(sandbox_policy: SandboxPolicy) -> None:
    sandbox = RecordingSandbox(SandboxCompleted(returncode=0, stdout="", stderr=""))

    result = ProcessRunner(RecordingVerifier("relative/probe"), sandbox).run(
        ("/requested/bin/probe",),
        sandbox_policy.project_root,
        1,
        RecordingEvidenceSink(),
        {"LANG": "C"},
        sandbox_policy,
    )

    assert result.failure_kind is CommandFailureKind.CONFIGURATION
    assert sandbox.run_calls == []


def test_runner_hands_the_sandbox_a_verified_descriptor_after_executable_replacement(
    sandbox_policy: SandboxPolicy, tmp_path: Path
) -> None:
    executable = tmp_path / "trusted-probe"
    replacement = tmp_path / "replacement-probe"
    executable.write_bytes(b"trusted executable\n")
    replacement.write_bytes(b"replacement executable\n")
    executable.chmod(0o700)
    replacement.chmod(0o700)

    class ReplacingSandbox:
        def run(self, argv: tuple[str, ...], **kwargs: object) -> SandboxCompleted:
            verified = kwargs.get("executable")
            assert isinstance(getattr(verified, "descriptor", None), int)
            replacement.replace(executable)
            descriptor = getattr(verified, "descriptor")
            os.lseek(descriptor, 0, os.SEEK_SET)
            assert os.read(descriptor, len(b"trusted executable\n")) == b"trusted executable\n"
            return SandboxCompleted(returncode=0, stdout="", stderr="")

    verifier = HashVerifiedExecutables({executable: sha256(b"trusted executable\n").hexdigest()})
    result = ProcessRunner(verifier, ReplacingSandbox()).run(
        (str(executable), "--check"),
        sandbox_policy.project_root,
        1,
        RecordingEvidenceSink(),
        {"LANG": "C"},
        sandbox_policy,
    )

    assert result.returncode == 0
    assert executable.read_bytes() == b"replacement executable\n"


def test_launcher_socket_executes_the_verified_descriptor_after_path_replacement(
    sandbox_policy: SandboxPolicy,
    tmp_path: Path,
) -> None:
    executable = tmp_path / "probe"
    replacement = tmp_path / "replacement"
    executable.write_bytes(b"#!/bin/sh\nprintf trusted-descriptor")
    replacement.write_bytes(b"#!/bin/sh\nprintf mutable-path")
    executable.chmod(0o700)
    replacement.chmod(0o700)
    socket_path = tmp_path / "launcher.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(1)

    def serve() -> None:
        connection, _ = listener.accept()
        with connection:
            descriptors = array.array("i")
            raw, ancillary, _, _ = connection.recvmsg(65_536, socket.CMSG_SPACE(descriptors.itemsize))
            for level, kind, data in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    descriptors.frombytes(data[: len(data) - (len(data) % descriptors.itemsize)])
            while not raw.endswith(b"\n"):
                raw += connection.recv(65_536)
            request = json.loads(raw)
            replacement.replace(executable)
            if len(descriptors) != 1:
                completed = subprocess.CompletedProcess((), 97, b"", b"missing descriptor")
            else:
                descriptor = descriptors[0]
                completed = subprocess.run(
                    (f"/proc/self/fd/{descriptor}", *request["argv"]),
                    pass_fds=(descriptor,),
                    capture_output=True,
                    check=False,
                )
                os.close(descriptor)
            connection.sendall(
                canonical_json_bytes(
                    {
                        "returncode": completed.returncode,
                        "stdout": completed.stdout.decode("ascii"),
                        "stderr": completed.stderr.decode("ascii"),
                    }
                )
                + b"\n"
            )

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        result = ProcessRunner(
            HashVerifiedExecutables({executable: sha256(b"#!/bin/sh\nprintf trusted-descriptor").hexdigest()}),
            LauncherSocketSandbox(socket_path, "launcher"),
        ).run(
            (str(executable), "argument"),
            sandbox_policy.project_root,
            3,
            RecordingEvidenceSink(),
            {"LANG": "C"},
            sandbox_policy,
        )
    finally:
        thread.join(timeout=3)
        listener.close()

    assert result.returncode == 0
    assert result.stdout_text == "trusted-descriptor"
    assert executable.read_bytes() == b"#!/bin/sh\nprintf mutable-path"


def test_production_ticket_invoker_uses_pinned_interpreter_sealed_archive_and_sanitized_environment(
    tmp_path: Path,
    sandbox_policy: SandboxPolicy,
) -> None:
    socket_path = tmp_path / "ticket-launcher.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(1)
    observed: dict[str, object] = {}

    def serve() -> None:
        connection, _ = listener.accept()
        with connection:
            descriptors = array.array("i")
            raw, ancillary, _, _ = connection.recvmsg(
                65_536,
                socket.CMSG_SPACE(2 * descriptors.itemsize),
            )
            for level, kind, data in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    descriptors.frombytes(data[: len(data) - (len(data) % descriptors.itemsize)])
            while not raw.endswith(b"\n"):
                raw += connection.recv(65_536)
            observed.update(json.loads(raw))
            observed["descriptor_count"] = len(descriptors)
            observed["archive"] = os.pread(descriptors[1], 64, 0) if len(descriptors) == 2 else b""
            for descriptor in descriptors:
                os.close(descriptor)
            connection.sendall(canonical_json_bytes({"returncode": 0, "stdout": "ok", "stderr": ""}) + b"\n")

    thread = threading.Thread(target=serve)
    thread.start()
    archive_descriptor = os.memfd_create("runner.pyz", os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    os.write(archive_descriptor, b"immutable archive")
    required_seals = fcntl.F_SEAL_SEAL | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_GROW | fcntl.F_SEAL_WRITE
    fcntl.fcntl(archive_descriptor, fcntl.F_ADD_SEALS, required_seals)
    interpreter = Path(sys.executable).resolve()
    try:
        result = PythonArchiveTicketInvoker(
            interpreter=interpreter,
            interpreter_hash=sha256(interpreter.read_bytes()).hexdigest(),
            sandbox=LauncherSocketSandbox(socket_path, "launcher"),
            timeout=3,
            cwd=sandbox_policy.project_root,
            policy=sandbox_policy,
        ).invoke(VerifiedExecutable("/proc/self/fd/archive", archive_descriptor), ("status",))
    finally:
        os.close(archive_descriptor)
        thread.join(timeout=3)
        listener.close()

    assert result == SandboxCompleted(0, "ok", "")
    assert observed["operation"] == "run_python_archive"
    assert observed["argv"] == ["status"]
    assert observed["descriptor_count"] == 2
    assert observed["archive"] == b"immutable archive"
    assert observed["environment"] == {
        "HOME": str(sandbox_policy.controlled_home),
        "PIP_NO_INDEX": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "npm_config_offline": "true",
    }


def test_sandbox_exposes_no_authority_first_finalization_start(tmp_path: Path) -> None:
    socket_path = tmp_path / "launcher.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    try:
        sandbox = LauncherSocketSandbox(socket_path, "launcher")
    finally:
        listener.close()

    assert not hasattr(sandbox, "start_finalization_child")


def test_sandbox_prepares_a_child_only_after_verifying_signed_evidence(tmp_path: Path) -> None:
    socket_path = tmp_path / "launcher.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(1)
    signing_key = Ed25519PrivateKey.generate()
    observed: dict[str, object] = {}

    def serve() -> None:
        connection, _ = listener.accept()
        with connection:
            raw = connection.makefile("rb").readline()
            observed.update(json.loads(raw))
            child_id = "f" * 32
            unsigned_evidence = {
                "domain": "auto-code-sandbox-child-evidence/v1",
                "sandbox_identity": "launcher",
                "challenge": observed["challenge"],
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
                                for key, value in unsigned_evidence.items()
                                if key not in {"domain", "sandbox_identity"}
                            },
                            "signature": signing_key.sign(canonical_json_bytes(unsigned_evidence)).hex(),
                        },
                    }
                )
                + b"\n"
            )

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        child = LauncherSocketSandbox(
            socket_path,
            "launcher",
            signing_key.public_key().public_bytes_raw(),
        ).prepare_finalization_child((sys.executable, "-c", "pass"))
    finally:
        thread.join(timeout=3)
        listener.close()

    evidence = child.evidence
    assert child.pid == 124
    assert evidence.pid == 124
    assert evidence.child_id == "f" * 32
    assert evidence.challenge == observed["challenge"]
    assert evidence.pid_namespace_inode == 456
    assert evidence.mount_namespace_inode == 789
    assert evidence.fd_numbers == ()
    assert observed == {
        "schema_version": "v1",
        "sandbox_identity": "launcher",
        "operation": "prepare_finalization_child",
        "argv": [sys.executable, "-c", "pass"],
        "isolate_procfs": True,
        "challenge": observed["challenge"],
    }


def test_sandbox_returns_signed_post_transfer_evidence_for_only_456(
    tmp_path: Path,
) -> None:
    socket_path = tmp_path / "launcher.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(1)
    signing_key = Ed25519PrivateKey.generate()
    requests: list[dict[str, object]] = []
    capabilities: tuple[bytes, ...] = ()

    def serve() -> None:
        nonlocal capabilities
        connection, _ = listener.accept()
        with connection:
            request = json.loads(connection.makefile("rb").readline())
            requests.append(request)
            child_id = "f" * 32
            unsigned_evidence = {
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
                                for key, value in unsigned_evidence.items()
                                if key not in {"domain", "sandbox_identity"}
                            },
                            "signature": signing_key.sign(canonical_json_bytes(unsigned_evidence)).hex(),
                        },
                    }
                )
                + b"\n"
            )
            descriptors = array.array("i")
            raw, ancillary, _, _ = connection.recvmsg(65_536, socket.CMSG_SPACE(3 * descriptors.itemsize))
            for level, kind, data in ancillary:
                if level == socket.SOL_SOCKET and kind == socket.SCM_RIGHTS:
                    descriptors.frombytes(data[: len(data) - (len(data) % descriptors.itemsize)])
            while not raw.endswith(b"\n"):
                raw += connection.recv(65_536)
            transfer = json.loads(raw)
            requests.append(transfer)
            capabilities = tuple(os.pread(descriptor, 32, 0) for descriptor in descriptors)
            for descriptor in descriptors:
                os.close(descriptor)
            post_transfer_evidence = {
                "domain": "auto-code-sandbox-child-evidence/v1",
                "sandbox_identity": "launcher",
                "challenge": request["challenge"],
                "child_id": child_id,
                "pid": 124,
                "pid_namespace_inode": 456,
                "mount_namespace_inode": 789,
                "fd_numbers": [0, 1, 2, 4, 5, 6],
            }
            connection.sendall(
                canonical_json_bytes(
                    {
                        "child_id": child_id,
                        "evidence": {
                            **{
                                key: value
                                for key, value in post_transfer_evidence.items()
                                if key not in {"domain", "sandbox_identity"}
                            },
                            "signature": signing_key.sign(canonical_json_bytes(post_transfer_evidence)).hex(),
                        },
                    }
                )
                + b"\n"
            )

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    descriptor_fds = tuple(os.memfd_create(f"capability-{slot}", os.MFD_CLOEXEC) for slot in (4, 5, 6))
    child = None
    try:
        for descriptor, payload in zip(descriptor_fds, (b"descriptor", b"trust", b"binding"), strict=True):
            os.write(descriptor, payload)
        child = LauncherSocketSandbox(
            socket_path,
            "launcher",
            signing_key.public_key().public_bytes_raw(),
        ).prepare_finalization_child((sys.executable, "-c", "pass"))
        evidence = child.transfer_finalization_fds(descriptor_fds)
    finally:
        for descriptor in descriptor_fds:
            os.close(descriptor)
        if child is not None:
            child._transport.close()
        thread.join(timeout=3)
        listener.close()

    assert capabilities == (b"descriptor", b"trust", b"binding")
    assert [request["operation"] for request in requests] == [
        "prepare_finalization_child",
        "transfer_finalization_fds",
    ]
    assert requests[1]["child_id"] == "f" * 32
    assert requests[1]["challenge"] == requests[0]["challenge"]
    assert evidence.fd_numbers == (0, 1, 2, 4, 5, 6)


@pytest.mark.parametrize("cleanup_fails", (False, True), ids=("cleanup-succeeds", "kill-and-reap-fail"))
def test_sandbox_rejects_forged_post_transfer_evidence(tmp_path: Path, cleanup_fails: bool) -> None:
    socket_path = tmp_path / "launcher.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(3)
    signing_key = Ed25519PrivateKey.generate()
    forged_key = Ed25519PrivateKey.generate()
    cleanup_operations: list[str] = []

    def serve() -> None:
        connection, _ = listener.accept()
        with connection:
            request = json.loads(connection.makefile("rb").readline())
            child_id = "f" * 32
            pre_transfer_evidence = {
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
                                for key, value in pre_transfer_evidence.items()
                                if key not in {"domain", "sandbox_identity"}
                            },
                            "signature": signing_key.sign(canonical_json_bytes(pre_transfer_evidence)).hex(),
                        },
                    }
                )
                + b"\n"
            )
            raw = connection.recv(65_536)
            while not raw.endswith(b"\n"):
                raw += connection.recv(65_536)
            post_transfer_evidence = {**pre_transfer_evidence, "fd_numbers": [0, 1, 2, 4, 5, 6]}
            connection.sendall(
                canonical_json_bytes(
                    {
                        "child_id": child_id,
                        "evidence": {
                            **{
                                key: value
                                for key, value in post_transfer_evidence.items()
                                if key not in {"domain", "sandbox_identity"}
                            },
                            "signature": forged_key.sign(canonical_json_bytes(post_transfer_evidence)).hex(),
                        },
                    }
                )
                + b"\n"
            )
        for operation, response in (
            ("kill_finalization_child", {}),
            ("wait_finalization_child", {"returncode": -9, "stdout": "", "stderr": ""}),
        ):
            connection, _ = listener.accept()
            with connection:
                request = json.loads(connection.makefile("rb").readline())
                cleanup_operations.append(request["operation"])
                assert request["operation"] == operation
                if not cleanup_fails:
                    connection.sendall(canonical_json_bytes(response) + b"\n")

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    descriptor_fds = tuple(os.memfd_create(f"capability-{slot}", os.MFD_CLOEXEC) for slot in (4, 5, 6))
    try:
        child = LauncherSocketSandbox(
            socket_path,
            "launcher",
            signing_key.public_key().public_bytes_raw(),
        ).prepare_finalization_child((sys.executable, "-c", "pass"))
        with pytest.raises(ProcessConfigurationError, match="capability transfer") as raised:
            child.transfer_finalization_fds(descriptor_fds)
    finally:
        for descriptor in descriptor_fds:
            os.close(descriptor)
        thread.join(timeout=3)
        listener.close()

    assert cleanup_operations == ["kill_finalization_child", "wait_finalization_child"]
    if cleanup_fails:
        cleanup_error = raised.value.__cause__
        assert isinstance(cleanup_error, ProcessConfigurationError)
        assert isinstance(cleanup_error.__cause__, ExceptionGroup)
        assert len(cleanup_error.__cause__.exceptions) == 2


@pytest.mark.parametrize("signing_key", (None, Ed25519PrivateKey.generate()), ids=("unsigned", "wrong-key"))
def test_sandbox_rejects_unsigned_or_wrong_peer_evidence(tmp_path: Path, signing_key: Ed25519PrivateKey | None) -> None:
    socket_path = tmp_path / "launcher.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(1)
    pinned_key = Ed25519PrivateKey.generate()

    def serve() -> None:
        connection, _ = listener.accept()
        with connection:
            request = json.loads(connection.makefile("rb").readline())
            child_id = "f" * 32
            unsigned_evidence = {
                "domain": "auto-code-sandbox-child-evidence/v1",
                "sandbox_identity": "launcher",
                "challenge": request["challenge"],
                "child_id": child_id,
                "pid": 124,
                "pid_namespace_inode": 456,
                "mount_namespace_inode": 789,
                "fd_numbers": [],
            }
            signature = "" if signing_key is None else signing_key.sign(canonical_json_bytes(unsigned_evidence)).hex()
            connection.sendall(
                canonical_json_bytes(
                    {
                        "child_id": child_id,
                        "evidence": {
                            **{
                                key: value
                                for key, value in unsigned_evidence.items()
                                if key not in {"domain", "sandbox_identity"}
                            },
                            "signature": signature,
                        },
                    }
                )
                + b"\n"
            )

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        sandbox = LauncherSocketSandbox(socket_path, "launcher", pinned_key.public_key().public_bytes_raw())
        with pytest.raises(ProcessConfigurationError, match="Finalization child evidence is invalid"):
            sandbox.prepare_finalization_child((sys.executable, "-c", "pass"))
    finally:
        thread.join(timeout=3)
        listener.close()


@pytest.mark.parametrize(
    ("evidence_kind", "cleanup_fails"),
    (
        ("forged", False),
        ("forged", True),
        ("missing", False),
        ("malformed", False),
    ),
    ids=("forged-cleanup-succeeds", "forged-cleanup-fails", "missing", "malformed"),
)
def test_invalid_preparation_evidence_cleanup_kills_and_reaps_returned_child(
    tmp_path: Path,
    evidence_kind: str,
    cleanup_fails: bool,
) -> None:
    """Closing a malformed preparation response alone would leave its child running."""

    socket_path = tmp_path / "launcher.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(3)
    pinned_key = Ed25519PrivateKey.generate()
    forged_key = Ed25519PrivateKey.generate()
    calls: list[str] = []

    def serve() -> None:
        connection, _ = listener.accept()
        with connection:
            request = json.loads(connection.makefile("rb").readline())
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
            response: dict[str, object] = {"child_id": child_id}
            if evidence_kind == "forged":
                response["evidence"] = {
                    **{
                        key: value
                        for key, value in evidence.items()
                        if key not in {"domain", "sandbox_identity"}
                    },
                    "signature": forged_key.sign(canonical_json_bytes(evidence)).hex(),
                }
            elif evidence_kind == "malformed":
                response["evidence"] = []
            connection.sendall(canonical_json_bytes(response) + b"\n")
            for operation, response in (
                ("kill_finalization_child", {}),
                ("wait_finalization_child", {"returncode": -9, "stdout": "", "stderr": ""}),
            ):
                cleanup, _ = listener.accept()
                with cleanup:
                    cleanup_request = json.loads(cleanup.makefile("rb").readline())
                    calls.append(cleanup_request["operation"])
                    assert cleanup_request["operation"] == operation
                    assert cleanup_request["child_id"] == child_id
                    if not cleanup_fails:
                        cleanup.sendall(canonical_json_bytes(response) + b"\n")

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        sandbox = LauncherSocketSandbox(socket_path, "launcher", pinned_key.public_key().public_bytes_raw())
        with pytest.raises(ProcessConfigurationError, match="Finalization child evidence is invalid") as raised:
            sandbox.prepare_finalization_child((sys.executable, "-c", "pass"))
    finally:
        thread.join(timeout=3)
        listener.close()

    assert calls == ["kill_finalization_child", "wait_finalization_child"]
    if cleanup_fails:
        cleanup_error = raised.value.__cause__
        assert type(cleanup_error).__name__ == "PreparedChildCleanupError"
        assert isinstance(cleanup_error, ExceptionGroup)
        assert len(cleanup_error.exceptions) == 2


@pytest.mark.parametrize(
    ("returned_child_id", "signed_child_id", "challenge_source", "fd_numbers"),
    (
        ("f" * 32, "f" * 32, "stale", []),
        ("e" * 32, "f" * 32, "request", []),
        ("f" * 32, "f" * 32, "request", [0, 1, 2]),
    ),
    ids=("replayed-challenge", "child-identity-mismatch", "nonempty-fd-table"),
)
def test_sandbox_rejects_evidence_not_bound_to_the_exact_preparation(
    tmp_path: Path,
    returned_child_id: str,
    signed_child_id: str,
    challenge_source: str,
    fd_numbers: list[int],
) -> None:
    socket_path = tmp_path / "launcher.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(1)
    signing_key = Ed25519PrivateKey.generate()

    def serve() -> None:
        connection, _ = listener.accept()
        with connection:
            request = json.loads(connection.makefile("rb").readline())
            unsigned_evidence = {
                "domain": "auto-code-sandbox-child-evidence/v1",
                "sandbox_identity": "launcher",
                "challenge": request["challenge"] if challenge_source == "request" else "0" * 64,
                "child_id": signed_child_id,
                "pid": 124,
                "pid_namespace_inode": 456,
                "mount_namespace_inode": 789,
                "fd_numbers": fd_numbers,
            }
            connection.sendall(
                canonical_json_bytes(
                    {
                        "child_id": returned_child_id,
                        "evidence": {
                            **{
                                key: value
                                for key, value in unsigned_evidence.items()
                                if key not in {"domain", "sandbox_identity"}
                            },
                            "signature": signing_key.sign(canonical_json_bytes(unsigned_evidence)).hex(),
                        },
                    }
                )
                + b"\n"
            )

    thread = threading.Thread(target=serve)
    thread.start()
    try:
        sandbox = LauncherSocketSandbox(socket_path, "launcher", signing_key.public_key().public_bytes_raw())
        with pytest.raises(ProcessConfigurationError, match="Finalization child evidence is invalid"):
            sandbox.prepare_finalization_child((sys.executable, "-c", "pass"))
    finally:
        thread.join(timeout=3)
        listener.close()


def test_runner_rejects_a_working_directory_symlink_to_authoritative_state(sandbox_policy: SandboxPolicy) -> None:
    escaped_cwd = sandbox_policy.project_root / "state-link"
    escaped_cwd.symlink_to(sandbox_policy.authoritative_state_root, target_is_directory=True)
    sandbox = RecordingSandbox(SandboxCompleted(returncode=0, stdout="", stderr=""))

    result = ProcessRunner(RecordingVerifier(), sandbox).run(
        ("/requested/bin/probe",),
        escaped_cwd,
        1,
        RecordingEvidenceSink(),
        {"LANG": "C"},
        sandbox_policy,
    )

    assert result.failure_kind is CommandFailureKind.CONFIGURATION
    assert sandbox.run_calls == []


def test_runner_rejects_a_cwd_descendant_that_is_not_a_declared_readable_root(sandbox_policy: SandboxPolicy) -> None:
    descendant = sandbox_policy.project_root / "command-subdirectory"
    descendant.mkdir()
    sandbox = RecordingSandbox(SandboxCompleted(returncode=0, stdout="", stderr=""))

    result = ProcessRunner(RecordingVerifier(), sandbox).run(
        ("/requested/bin/probe",),
        descendant,
        1,
        RecordingEvidenceSink(),
        {"LANG": "C"},
        sandbox_policy,
    )

    assert result.failure_kind is CommandFailureKind.CONFIGURATION
    assert sandbox.run_calls == []


def test_runner_rejects_a_declared_cwd_root_replaced_after_policy_creation(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    command_root = repository / "command-root"
    build = repository / "build"
    home = tmp_path / "controlled-home"
    state = tmp_path / "authoritative-state"
    secrets = tmp_path / "secrets"
    for directory in (repository, command_root, build, home, state, secrets):
        directory.mkdir(parents=True, exist_ok=True)
    sandbox_policy = SandboxPolicy(
        project_root=repository,
        readable_roots=(repository, command_root),
        writable_roots=(build,),
        authoritative_state_root=state,
        secret_paths=(secrets,),
        controlled_home=home,
        environment_allowlist=frozenset({"LANG"}),
    )
    command_root.replace(tmp_path / "displaced-command-root")
    state.replace(command_root)
    sandbox = RecordingSandbox(SandboxCompleted(returncode=0, stdout="", stderr=""))

    result = ProcessRunner(RecordingVerifier(), sandbox).run(
        ("/requested/bin/probe",),
        command_root,
        1,
        RecordingEvidenceSink(),
        {"LANG": "C"},
        sandbox_policy,
    )

    assert result.failure_kind is CommandFailureKind.CONFIGURATION
    assert sandbox.run_calls == []


@pytest.mark.parametrize("denied_root", ("authoritative-state", "secrets"))
def test_sandbox_policy_rejects_readable_root_symlinks_to_denied_locations(tmp_path: Path, denied_root: str) -> None:
    repository = tmp_path / "repository"
    build = repository / "build"
    home = tmp_path / "controlled-home"
    state = tmp_path / "authoritative-state"
    secrets = tmp_path / "secrets"
    for directory in (repository, build, home, state, secrets):
        directory.mkdir(parents=True, exist_ok=True)
    redirected_root = repository / "redirected-root"
    redirected_root.symlink_to(tmp_path / denied_root, target_is_directory=True)

    with pytest.raises(ProcessConfigurationError, match="Sandbox policy overlaps a denied root"):
        SandboxPolicy(
            project_root=repository,
            readable_roots=(repository, redirected_root),
            writable_roots=(build,),
            authoritative_state_root=state,
            secret_paths=(secrets,),
            controlled_home=home,
            environment_allowlist=frozenset({"LANG"}),
        )


def test_runner_rejects_a_policy_root_replaced_with_a_state_symlink(sandbox_policy: SandboxPolicy) -> None:
    writable_root = sandbox_policy.writable_roots[0]
    writable_root.rmdir()
    writable_root.symlink_to(sandbox_policy.authoritative_state_root, target_is_directory=True)
    sandbox = RecordingSandbox(SandboxCompleted(returncode=0, stdout="", stderr=""))

    result = ProcessRunner(RecordingVerifier(), sandbox).run(
        ("/requested/bin/probe",),
        sandbox_policy.project_root,
        1,
        RecordingEvidenceSink(),
        {"LANG": "C"},
        sandbox_policy,
    )

    assert result.failure_kind is CommandFailureKind.CONFIGURATION
    assert sandbox.run_calls == []


def test_runner_hands_the_sandbox_pinned_policy_root_descriptors(sandbox_policy: SandboxPolicy) -> None:
    writable_root = sandbox_policy.writable_roots[0]
    expected_inode = writable_root.stat().st_ino

    class RootReplacingSandbox:
        def run(self, argv: tuple[str, ...], **kwargs: object) -> SandboxCompleted:
            handoff = kwargs["policy"]
            writable = getattr(handoff, "writable_roots")[0]
            descriptor = getattr(writable, "descriptor", None)
            assert isinstance(descriptor, int)
            writable_root.rmdir()
            writable_root.symlink_to(sandbox_policy.authoritative_state_root, target_is_directory=True)
            assert os.fstat(descriptor).st_ino == expected_inode
            return SandboxCompleted(returncode=0, stdout="", stderr="")

    result = ProcessRunner(RecordingVerifier(), RootReplacingSandbox()).run(
        ("/requested/bin/probe",),
        sandbox_policy.project_root,
        1,
        RecordingEvidenceSink(),
        {"LANG": "C"},
        sandbox_policy,
    )

    assert result.returncode == 0


def test_runner_requires_evidence_sink_references_for_every_result(sandbox_policy: SandboxPolicy) -> None:
    with pytest.raises(EvidenceSinkError):
        ProcessRunner(RecordingVerifier(), RecordingSandbox(SandboxCompleted(returncode=0, stdout="", stderr=""))).run(
            ("/requested/bin/probe",),
            sandbox_policy.project_root,
            1,
            UnpersistedEvidenceSink(),
            {"LANG": "C"},
            sandbox_policy,
        )


def test_sandbox_policy_requires_an_empty_controlled_home(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    build = repository / "build"
    home = tmp_path / "controlled-home"
    state = tmp_path / "authoritative-state"
    secrets = tmp_path / "secrets"
    for directory in (repository, build, home, state, secrets):
        directory.mkdir(parents=True, exist_ok=True)
    (home / "stale.txt").write_text("not empty", encoding="ascii")

    with pytest.raises(ProcessConfigurationError, match="controlled HOME"):
        SandboxPolicy(
            project_root=repository,
            readable_roots=(repository,),
            writable_roots=(build,),
            authoritative_state_root=state,
            secret_paths=(secrets,),
            controlled_home=home,
            environment_allowlist=frozenset({"LANG"}),
        )


@pytest.mark.parametrize(
    ("outcome", "returncode", "failure_kind"),
    (
        (SandboxCompleted(returncode=9, stdout="ordinary failure", stderr=""), 9, CommandFailureKind.EXIT),
        (
            subprocess.TimeoutExpired(("/trusted/bin/probe",), 1, output="token=timeout", stderr="token=timeout"),
            TIMEOUT_RETURN_CODE,
            CommandFailureKind.TIMEOUT,
        ),
        (OSError("token=spawn"), SPAWN_FAILURE_RETURN_CODE, CommandFailureKind.SPAWN),
        (SandboxCompleted(returncode=-15, stdout="", stderr="token=signal"), -15, CommandFailureKind.SIGNAL),
    ),
)
def test_runner_returns_evidence_bearing_results_for_process_failures(
    sandbox_policy: SandboxPolicy,
    outcome: SandboxCompleted | BaseException,
    returncode: int,
    failure_kind: CommandFailureKind,
) -> None:
    evidence = RecordingEvidenceSink()
    runner = ProcessRunner(RecordingVerifier(), RecordingSandbox(outcome))

    result = runner.run(
        ("/requested/bin/probe",),
        sandbox_policy.project_root,
        1,
        evidence,
        {"LANG": "C"},
        sandbox_policy,
    )

    assert result.returncode == returncode
    assert result.failure_kind is failure_kind
    assert result.stdout_path is not None
    assert result.stderr_path is not None
    assert "token=" not in str(result)
    with pytest.raises(CommandFailedError) as raised:
        result.require_success()
    assert raised.value.result is result
    assert "token=" not in str(raised.value)


def test_managed_process_uses_a_separate_group_and_escalates_before_reaping(sandbox_policy: SandboxPolicy) -> None:
    sandbox = RecordingSandbox(SandboxCompleted(returncode=0, stdout="", stderr=""))
    handle = RecordingHandle(
        [
            subprocess.TimeoutExpired(("/trusted/bin/server",), 0.1),
            SandboxCompleted(returncode=0, stdout="stopped", stderr=""),
        ]
    )
    sandbox.handle = handle
    evidence = RecordingEvidenceSink()

    process = ManagedProcessRunner(RecordingVerifier("/trusted/bin/server"), sandbox, termination_grace_seconds=0.1).start(
        ("/requested/bin/server",),
        sandbox_policy.project_root,
        5,
        evidence,
        {"LANG": "C"},
        sandbox_policy,
        readiness=lambda _: True,
        readiness_timeout=1,
    )
    result = process.stop_and_reap()

    assert sandbox.start_calls[0][-1] is True
    assert handle.actions == ["terminate", "wait:0.1", "kill", "wait:None"]
    assert result.returncode == 0
    assert result.stdout_path is not None


def test_managed_process_forces_cleanup_after_grace_evidence_persistence_fails(sandbox_policy: SandboxPolicy) -> None:
    sandbox = RecordingSandbox(SandboxCompleted(returncode=0, stdout="", stderr=""))
    handle = RecordingHandle(
        [
            subprocess.TimeoutExpired(("/trusted/bin/server",), 0.1),
            SandboxCompleted(returncode=0, stdout="stopped", stderr=""),
        ]
    )
    sandbox.handle = handle
    process = ManagedProcessRunner(RecordingVerifier("/trusted/bin/server"), sandbox, termination_grace_seconds=0.1).start(
        ("/requested/bin/server",),
        sandbox_policy.project_root,
        5,
        FailingOnceEvidenceSink(),
        {"LANG": "C"},
        sandbox_policy,
    )

    with pytest.raises(EvidenceSinkError):
        process.stop_and_reap()

    assert handle.actions == ["terminate", "wait:0.1", "kill", "wait:None"]
    assert process.reap().returncode == 0


def test_managed_process_forces_cleanup_after_a_grace_wait_error(sandbox_policy: SandboxPolicy) -> None:
    sandbox = RecordingSandbox(SandboxCompleted(returncode=0, stdout="", stderr=""))
    handle = RecordingHandle(
        [
            OSError("grace wait failed"),
            SandboxCompleted(returncode=0, stdout="stopped", stderr=""),
        ]
    )
    sandbox.handle = handle
    process = ManagedProcessRunner(RecordingVerifier("/trusted/bin/server"), sandbox, termination_grace_seconds=0.1).start(
        ("/requested/bin/server",),
        sandbox_policy.project_root,
        5,
        RecordingEvidenceSink(),
        {"LANG": "C"},
        sandbox_policy,
    )

    result = process.stop_and_reap()

    assert handle.actions == ["terminate", "wait:0.1", "kill", "wait:None"]
    assert result.returncode == 0


def test_managed_startup_reaps_a_handle_returned_with_a_start_failure(sandbox_policy: SandboxPolicy) -> None:
    handle = RecordingHandle(
        [
            subprocess.TimeoutExpired(("/trusted/bin/server",), 0.1),
            SandboxCompleted(returncode=-9, stdout="", stderr=""),
        ]
    )

    class PartiallyStartingSandbox:
        def start(self, argv: tuple[str, ...], **kwargs: object) -> RecordingHandle:
            raise SandboxStartError(handle)

    with pytest.raises(ManagedProcessStartError) as raised:
        ManagedProcessRunner(
            RecordingVerifier("/trusted/bin/server"), PartiallyStartingSandbox(), termination_grace_seconds=0.1
        ).start(
            ("/requested/bin/server",),
            sandbox_policy.project_root,
            5,
            RecordingEvidenceSink(),
            {"LANG": "C"},
            sandbox_policy,
        )

    assert handle.actions == ["terminate", "wait:0.1", "kill", "wait:None"]
    assert raised.value.result is not None
    assert raised.value.result.returncode == -9


def test_managed_startup_closes_an_opened_handoff_when_later_setup_fails(sandbox_policy: SandboxPolicy) -> None:
    class RecordingHandoff:
        def __init__(self) -> None:
            self.closed = False

        def close(self) -> None:
            self.closed = True

    class FailingPolicy:
        def __init__(self, handoff: RecordingHandoff) -> None:
            self.handoff = handoff

        def prepare_handoff(self, cwd: Path) -> RecordingHandoff:
            return self.handoff

        def command_environment(self, environment: object) -> dict[str, str]:
            raise ProcessConfigurationError("setup failed")

    handoff = RecordingHandoff()
    with pytest.raises(ManagedProcessStartError):
        ManagedProcessRunner(RecordingVerifier("/trusted/bin/server"), RecordingSandbox(SandboxCompleted(0))).start(
            ("/requested/bin/server",),
            sandbox_policy.project_root,
            5,
            RecordingEvidenceSink(),
            {"LANG": "C"},
            FailingPolicy(handoff),  # type: ignore[arg-type]
        )

    assert handoff.closed is True


def test_managed_startup_rejects_an_invalid_process_handle(sandbox_policy: SandboxPolicy) -> None:
    class InvalidHandleSandbox:
        def start(self, argv: tuple[str, ...], **kwargs: object) -> object:
            return object()

    with pytest.raises(ManagedProcessStartError):
        ManagedProcessRunner(RecordingVerifier("/trusted/bin/server"), InvalidHandleSandbox()).start(
            ("/requested/bin/server",),
            sandbox_policy.project_root,
            5,
            RecordingEvidenceSink(),
            {"LANG": "C"},
            sandbox_policy,
        )


def test_managed_startup_reaps_a_partially_started_process_when_readiness_fails(sandbox_policy: SandboxPolicy) -> None:
    sandbox = RecordingSandbox(SandboxCompleted(returncode=0, stdout="", stderr=""))
    handle = RecordingHandle(
        [
            subprocess.TimeoutExpired(("/trusted/bin/server",), 0.1),
            SandboxCompleted(returncode=-9, stdout="", stderr=""),
        ]
    )
    sandbox.handle = handle

    with pytest.raises(ManagedProcessStartError):
        ManagedProcessRunner(RecordingVerifier("/trusted/bin/server"), sandbox, termination_grace_seconds=0.1).start(
            ("/requested/bin/server",),
            sandbox_policy.project_root,
            5,
            RecordingEvidenceSink(),
            {"LANG": "C"},
            sandbox_policy,
            readiness=lambda _: False,
            readiness_timeout=0,
        )

    assert handle.actions == ["terminate", "wait:0.1", "kill", "wait:None"]
