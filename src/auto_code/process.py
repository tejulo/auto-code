from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
import hashlib
import hmac
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from typing import Protocol

from .contracts import EvidenceRef, sanitize_untrusted_text


MAX_CAPTURE_TEXT = 8_192
SPAWN_FAILURE_RETURN_CODE = 127
TIMEOUT_RETURN_CODE = 124
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_SECRET_ENVIRONMENT = re.compile(r"(?i)(?:key|token|secret|password|credential|authorization)")
_FIXED_GIT_ENVIRONMENT = {
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
}


class ProcessBoundaryError(RuntimeError):
    pass


class ProcessConfigurationError(ProcessBoundaryError):
    pass


class ExecutableVerificationError(ProcessConfigurationError):
    pass


class EvidenceSinkError(ProcessBoundaryError):
    pass


class CommandFailureKind(StrEnum):
    CONFIGURATION = "configuration"
    EXIT = "exit"
    SPAWN = "spawn"
    TIMEOUT = "timeout"
    SIGNAL = "signal"


@dataclass(frozen=True, slots=True)
class CommandResult:
    """Sanitized, bounded command evidence that exists before failure is raised."""

    argv: tuple[str, ...]
    returncode: int
    stdout_text: str
    stderr_text: str
    stdout_path: EvidenceRef | None
    stderr_path: EvidenceRef | None
    redacted: bool
    failure_kind: CommandFailureKind | None = None

    def require_success(self) -> CommandResult:
        if self.returncode != 0:
            raise CommandFailedError(self)
        return self


@dataclass(frozen=True, slots=True)
class TrustedCommandOutput:
    """Integrity-checked complete output for trusted structured parsers only."""

    stdout_sha256: str
    stderr_sha256: str
    _stdout: bytes = field(repr=False)
    _stderr: bytes = field(repr=False)

    def read_stdout(self) -> str:
        return _trusted_output_text(self._stdout, self.stdout_sha256)

    def read_stderr(self) -> str:
        return _trusted_output_text(self._stderr, self.stderr_sha256)


@dataclass(frozen=True, slots=True)
class CommandExecution:
    """A public result paired with an opaque full-output capability."""

    result: CommandResult
    output: TrustedCommandOutput


class CommandFailedError(ProcessBoundaryError):
    def __init__(self, result: CommandResult) -> None:
        self.result = result
        kind = result.failure_kind.value if result.failure_kind is not None else "exit"
        super().__init__(f"Command failed ({kind}, status {result.returncode})")


@dataclass(frozen=True, slots=True)
class SandboxCompleted:
    returncode: int
    stdout: str | bytes = ""
    stderr: str | bytes = ""


class EvidenceSink(Protocol):
    def write(self, result: CommandResult) -> CommandResult:
        """Persist already-redacted output outside the target repository."""


@dataclass(frozen=True, slots=True)
class VerifiedExecutable:
    """An already-open executable selected by the launcher verifier."""

    path: str
    descriptor: int

    def close(self) -> None:
        os.close(self.descriptor)


class ExecutableVerifier(Protocol):
    def require_absolute_verified(self, executable: str) -> VerifiedExecutable:
        """Open and hash-verify an executable before the sandbox receives its descriptor."""


class Sandbox(Protocol):
    def run(
        self,
        argv: tuple[str, ...],
        *,
        executable: VerifiedExecutable,
        timeout: float,
        env: Mapping[str, str],
        policy: SandboxPolicyHandoff,
    ) -> SandboxCompleted:
        """Run a finite command inside a launcher-trusted OS sandbox."""

    def start(
        self,
        argv: tuple[str, ...],
        *,
        executable: VerifiedExecutable,
        timeout: float,
        env: Mapping[str, str],
        policy: SandboxPolicyHandoff,
        new_process_group: bool,
    ) -> ProcessHandle:
        """Start an owned process or raise SandboxStartError with any created handle."""


class ProcessHandle(Protocol):
    def poll(self) -> int | None:
        """Return the process-group leader exit code when it has exited."""

    def wait(self, timeout: float | None = None) -> SandboxCompleted:
        """Reap the owned process group and return captured output."""

    def terminate_group(self) -> None:
        """Send graceful termination to the owned process group."""

    def kill_group(self) -> None:
        """Send forced termination to the owned process group."""


class SandboxStartError(OSError):
    """A sandbox startup failure that may still leave an owned process group."""

    def __init__(self, handle: ProcessHandle | None = None) -> None:
        self.handle = handle
        super().__init__("Sandbox process startup failed")


@dataclass(frozen=True, slots=True)
class SandboxDirectory:
    """An open, no-follow directory descriptor supplied to the trusted sandbox."""

    path: Path
    descriptor: int

    def close(self) -> None:
        os.close(self.descriptor)


@dataclass(frozen=True, slots=True)
class SandboxPolicyHandoff:
    """The only filesystem policy data passed to a sandbox invocation."""

    cwd: SandboxDirectory
    project_root: SandboxDirectory
    readable_roots: tuple[SandboxDirectory, ...]
    writable_roots: tuple[SandboxDirectory, ...]
    controlled_home: SandboxDirectory
    dynamic_downloads_disabled: bool

    def close(self) -> None:
        closed_descriptors: set[int] = set()
        for directory in (
            self.cwd,
            self.project_root,
            *self.readable_roots,
            *self.writable_roots,
            self.controlled_home,
        ):
            if directory.descriptor in closed_descriptors:
                continue
            closed_descriptors.add(directory.descriptor)
            try:
                directory.close()
            except OSError:
                pass


@dataclass(frozen=True, slots=True)
class _DirectoryIdentity:
    path: Path
    device: int
    inode: int


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    """The launcher-approved filesystem and environment shape for one command."""

    project_root: Path
    readable_roots: tuple[Path, ...]
    writable_roots: tuple[Path, ...]
    authoritative_state_root: Path
    secret_paths: tuple[Path, ...]
    controlled_home: Path
    environment_allowlist: frozenset[str]
    dynamic_downloads_disabled: bool = True
    _project_root_identity: _DirectoryIdentity = field(init=False, repr=False, compare=False)
    _readable_root_identities: tuple[_DirectoryIdentity, ...] = field(init=False, repr=False, compare=False)
    _writable_root_identities: tuple[_DirectoryIdentity, ...] = field(init=False, repr=False, compare=False)
    _controlled_home_identity: _DirectoryIdentity = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        project_root = _canonical_policy_path(self.project_root)
        readable_roots = _unique_policy_paths(self.readable_roots)
        writable_roots = _unique_policy_paths(self.writable_roots)
        state_root = _canonical_policy_path(self.authoritative_state_root)
        secret_paths = _unique_policy_paths(self.secret_paths)
        controlled_home = _canonical_policy_path(self.controlled_home)

        if not readable_roots:
            raise ProcessConfigurationError("Sandbox must declare readable roots")
        if not any(_is_relative_to(project_root, root) for root in readable_roots):
            raise ProcessConfigurationError("Sandbox must allow the project root as a readable root")
        if any(not any(_is_relative_to(writable, readable) for readable in readable_roots) for writable in writable_roots):
            raise ProcessConfigurationError("Writable sandbox paths must be readable policy roots")
        denied_roots = (state_root, *secret_paths)
        for allowed in (*readable_roots, *writable_roots, controlled_home):
            if any(_paths_overlap(allowed, denied) for denied in denied_roots):
                raise ProcessConfigurationError("Sandbox policy overlaps a denied root")
        if not _is_empty_directory(controlled_home):
            raise ProcessConfigurationError("Sandbox controlled HOME must be an empty real directory")
        if not self.dynamic_downloads_disabled:
            raise ProcessConfigurationError("Dynamic package downloads must be disabled")
        for name in self.environment_allowlist:
            if (
                not isinstance(name, str)
                or _ENVIRONMENT_NAME.fullmatch(name) is None
                or name in {"HOME", "PATH"}
                or _SECRET_ENVIRONMENT.search(name)
            ):
                raise ProcessConfigurationError("Sandbox environment allowlist is invalid")

        for path in (
            self.project_root,
            *self.readable_roots,
            *self.writable_roots,
            self.authoritative_state_root,
            *self.secret_paths,
            self.controlled_home,
        ):
            _directory_identity(_absolute_policy_path(path))

        object.__setattr__(self, "project_root", project_root)
        object.__setattr__(self, "readable_roots", readable_roots)
        object.__setattr__(self, "writable_roots", writable_roots)
        object.__setattr__(self, "authoritative_state_root", state_root)
        object.__setattr__(self, "secret_paths", secret_paths)
        object.__setattr__(self, "controlled_home", controlled_home)
        object.__setattr__(self, "_project_root_identity", _directory_identity(project_root))
        object.__setattr__(self, "_readable_root_identities", tuple(_directory_identity(path) for path in readable_roots))
        object.__setattr__(self, "_writable_root_identities", tuple(_directory_identity(path) for path in writable_roots))
        object.__setattr__(self, "_controlled_home_identity", _directory_identity(controlled_home))

    def command_cwd(self, cwd: Path) -> Path:
        candidate = _canonical_policy_path(cwd)
        if candidate not in self.readable_roots:
            raise ProcessConfigurationError("Command working directory must be a declared readable root")
        return candidate

    def command_environment(self, environment: Mapping[str, str]) -> dict[str, str]:
        if not isinstance(environment, Mapping):
            raise ProcessConfigurationError("Command environment must be explicit")
        result = {
            "HOME": str(self.controlled_home),
            "PIP_NO_INDEX": "1",
            "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            "npm_config_offline": "true",
        }
        for name, value in environment.items():
            if name in _FIXED_GIT_ENVIRONMENT:
                if value != _FIXED_GIT_ENVIRONMENT[name]:
                    raise ProcessConfigurationError("Command environment contains an unapproved value")
                result[name] = value
                continue
            if (
                not isinstance(name, str)
                or not isinstance(value, str)
                or name not in self.environment_allowlist
                or _SECRET_ENVIRONMENT.search(name)
                or _contains_sensitive_text(value)
            ):
                raise ProcessConfigurationError("Command environment contains an unapproved value")
            result[name] = value
        return result

    def prepare_handoff(self, cwd: Path) -> SandboxPolicyHandoff:
        command_cwd = self.command_cwd(cwd)
        opened: list[SandboxDirectory] = []
        try:
            project_root = _open_pinned_directory(self._project_root_identity)
            opened.append(project_root)
            readable_roots: list[SandboxDirectory] = []
            command_directory: SandboxDirectory | None = None
            for identity in self._readable_root_identities:
                directory = _open_pinned_directory(identity)
                opened.append(directory)
                readable_roots.append(directory)
                if directory.path == command_cwd:
                    command_directory = directory
            if command_directory is None:
                raise ProcessConfigurationError("Command working directory is not an approved sandbox root")
            writable_roots: list[SandboxDirectory] = []
            for identity in self._writable_root_identities:
                directory = _open_pinned_directory(identity)
                opened.append(directory)
                writable_roots.append(directory)
            controlled_home = _open_pinned_directory(self._controlled_home_identity)
            opened.append(controlled_home)
            return SandboxPolicyHandoff(
                cwd=command_directory,
                project_root=project_root,
                readable_roots=tuple(readable_roots),
                writable_roots=tuple(writable_roots),
                controlled_home=controlled_home,
                dynamic_downloads_disabled=self.dynamic_downloads_disabled,
            )
        except BaseException:
            for directory in opened:
                try:
                    directory.close()
                except OSError:
                    pass
            raise


class HashVerifiedExecutables:
    """A small verifier for launcher-pinned local executable hashes."""

    def __init__(self, expected_hashes: Mapping[str | Path, str]) -> None:
        hashes: dict[str, str] = {}
        for path, digest in expected_hashes.items():
            candidate = _absolute_policy_path(Path(path))
            if not isinstance(digest, str) or re.fullmatch(r"[0-9a-fA-F]{64}", digest) is None:
                raise ExecutableVerificationError("Executable hash is invalid")
            hashes[str(candidate)] = digest.lower()
        self._expected_hashes = hashes

    def require_absolute_verified(self, executable: str) -> VerifiedExecutable:
        if not isinstance(executable, str) or not executable:
            raise ExecutableVerificationError("Executable is invalid")
        candidate = Path(executable)
        if not candidate.is_absolute() or ".." in candidate.parts:
            raise ExecutableVerificationError("Executable must be an absolute pinned path")
        normalized = _absolute_policy_path(candidate)
        expected = self._expected_hashes.get(str(normalized))
        if expected is None:
            raise ExecutableVerificationError("Executable is not launcher-pinned")
        descriptor = _open_regular_file_no_follow(normalized)
        try:
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or not metadata.st_mode & stat.S_IXUSR:
                raise ExecutableVerificationError("Executable is not a regular executable")
            digest = _sha256_descriptor(descriptor)
            if not hmac.compare_digest(expected, digest):
                raise ExecutableVerificationError("Executable hash does not match the launcher pin")
            return VerifiedExecutable(str(normalized), descriptor)
        except BaseException:
            os.close(descriptor)
            raise


class ProcessRunner:
    """Finite-command boundary that only operates through injected trusted capabilities."""

    def __init__(self, executables: ExecutableVerifier | None = None, sandbox: Sandbox | None = None) -> None:
        self.executables = executables
        self.sandbox = sandbox

    def run(
        self,
        argv: Sequence[str],
        cwd: Path,
        timeout: float,
        evidence_sink: EvidenceSink,
        environment: Mapping[str, str],
        sandbox_policy: SandboxPolicy,
    ) -> CommandResult:
        return self.run_with_trusted_output(
            argv,
            cwd,
            timeout,
            evidence_sink,
            environment,
            sandbox_policy,
        ).result

    def run_with_trusted_output(
        self,
        argv: Sequence[str],
        cwd: Path,
        timeout: float,
        evidence_sink: EvidenceSink,
        environment: Mapping[str, str],
        sandbox_policy: SandboxPolicy,
        *,
        suppress_public_output: bool = False,
    ) -> CommandExecution:
        safe_argv = _safe_argv(argv)
        if self.executables is None or self.sandbox is None:
            return self._record_execution(
                safe_argv,
                SPAWN_FAILURE_RETURN_CODE,
                "",
                "Trusted command execution is unavailable",
                CommandFailureKind.CONFIGURATION,
                evidence_sink,
                suppress_public_output=suppress_public_output,
            )
        executable: VerifiedExecutable | None = None
        handoff: SandboxPolicyHandoff | None = None
        try:
            command = _command_argv(argv)
            handoff = sandbox_policy.prepare_handoff(cwd)
            command_timeout = _positive_timeout(timeout)
            command_environment = sandbox_policy.command_environment(environment)
            executable = _verified_executable(self.executables.require_absolute_verified(command[0]))
            completed = self.sandbox.run(
                (executable.path, *command[1:]),
                executable=executable,
                timeout=command_timeout,
                env=command_environment,
                policy=handoff,
            )
            if not isinstance(completed, SandboxCompleted):
                raise ProcessConfigurationError("Sandbox returned an invalid command result")
            failure_kind = _failure_kind_for_returncode(completed.returncode)
            return self._record_execution(
                safe_argv,
                completed.returncode,
                completed.stdout,
                completed.stderr,
                failure_kind,
                evidence_sink,
                suppress_public_output=suppress_public_output,
            )
        except subprocess.TimeoutExpired as error:
            return self._record_execution(
                safe_argv,
                TIMEOUT_RETURN_CODE,
                getattr(error, "output", ""),
                getattr(error, "stderr", ""),
                CommandFailureKind.TIMEOUT,
                evidence_sink,
                suppress_public_output=suppress_public_output,
            )
        except OSError:
            return self._record_execution(
                safe_argv,
                SPAWN_FAILURE_RETURN_CODE,
                "",
                "Command could not start",
                CommandFailureKind.SPAWN,
                evidence_sink,
                suppress_public_output=suppress_public_output,
            )
        except ProcessConfigurationError:
            return self._record_execution(
                safe_argv,
                SPAWN_FAILURE_RETURN_CODE,
                "",
                "Command execution is not configured",
                CommandFailureKind.CONFIGURATION,
                evidence_sink,
                suppress_public_output=suppress_public_output,
            )
        finally:
            if handoff is not None:
                handoff.close()
            if executable is not None:
                _close_verified_executable(executable)

    def _prepare(
        self,
        argv: Sequence[str],
        cwd: Path,
        timeout: float,
        environment: Mapping[str, str],
        sandbox_policy: SandboxPolicy,
    ) -> tuple[VerifiedExecutable, tuple[str, ...], SandboxPolicyHandoff, float, dict[str, str]]:
        if self.executables is None or self.sandbox is None:
            raise ProcessConfigurationError("Trusted command execution is unavailable")
        command = _command_argv(argv)
        executable = _verified_executable(self.executables.require_absolute_verified(command[0]))
        handoff: SandboxPolicyHandoff | None = None
        try:
            handoff = sandbox_policy.prepare_handoff(cwd)
            return (
                executable,
                (executable.path, *command[1:]),
                handoff,
                _positive_timeout(timeout),
                sandbox_policy.command_environment(environment),
            )
        except BaseException:
            if handoff is not None:
                handoff.close()
            _close_verified_executable(executable)
            raise

    def _record_execution(
        self,
        argv: tuple[str, ...],
        returncode: int,
        stdout: str | bytes | object,
        stderr: str | bytes | object,
        failure_kind: CommandFailureKind | None,
        evidence_sink: EvidenceSink,
        *,
        suppress_public_output: bool = False,
    ) -> CommandExecution:
        stdout_bytes = _output_bytes(stdout)
        stderr_bytes = _output_bytes(stderr)
        result = self._record(
            argv,
            returncode,
            "[REDACTED]" if suppress_public_output else stdout,
            "[REDACTED]" if suppress_public_output else stderr,
            failure_kind,
            evidence_sink,
        )
        return CommandExecution(
            result=result,
            output=TrustedCommandOutput(
                stdout_sha256=hashlib.sha256(stdout_bytes).hexdigest(),
                stderr_sha256=hashlib.sha256(stderr_bytes).hexdigest(),
                _stdout=stdout_bytes,
                _stderr=stderr_bytes,
            ),
        )

    def _record(
        self,
        argv: tuple[str, ...],
        returncode: int,
        stdout: str | bytes | object,
        stderr: str | bytes | object,
        failure_kind: CommandFailureKind | None,
        evidence_sink: EvidenceSink,
    ) -> CommandResult:
        result = CommandResult(
            argv=argv,
            returncode=returncode,
            stdout_text=_sanitize_and_cap(stdout),
            stderr_text=_sanitize_and_cap(stderr),
            stdout_path=None,
            stderr_path=None,
            redacted=True,
            failure_kind=failure_kind,
        )
        try:
            stored = evidence_sink.write(result)
        except BaseException as error:
            raise EvidenceSinkError("Command evidence could not be persisted") from error
        if not isinstance(stored, CommandResult):
            raise EvidenceSinkError("Command evidence sink returned an invalid result")
        if not isinstance(stored.stdout_path, EvidenceRef) or not isinstance(stored.stderr_path, EvidenceRef):
            raise EvidenceSinkError("Command evidence sink did not attach immutable references")
        # Evidence sinks may attach immutable references but cannot replace sanitized command data.
        return replace(result, stdout_path=stored.stdout_path, stderr_path=stored.stderr_path)


class ManagedProcessStartError(ProcessBoundaryError):
    def __init__(self, result: CommandResult | None = None) -> None:
        self.result = result
        super().__init__("Managed process could not be started safely")


class ManagedProcessRunner:
    """Starts only sandboxed process groups and owns their full shutdown lifecycle."""

    def __init__(
        self,
        executables: ExecutableVerifier | None = None,
        sandbox: Sandbox | None = None,
        *,
        termination_grace_seconds: float = 5,
    ) -> None:
        self._runner = ProcessRunner(executables, sandbox)
        self._sandbox = sandbox
        self.termination_grace_seconds = _positive_timeout(termination_grace_seconds)

    def start(
        self,
        argv: Sequence[str],
        cwd: Path,
        timeout: float,
        evidence_sink: EvidenceSink,
        environment: Mapping[str, str],
        sandbox_policy: SandboxPolicy,
        *,
        readiness: Callable[[ManagedProcess], bool] | None = None,
        readiness_timeout: float | None = None,
        readiness_poll_seconds: float = 0.05,
    ) -> ManagedProcess:
        safe_argv = _safe_argv(argv)
        executable: VerifiedExecutable | None = None
        handoff: SandboxPolicyHandoff | None = None
        try:
            executable, command, handoff, command_timeout, command_environment = self._runner._prepare(
                argv,
                cwd,
                timeout,
                environment,
                sandbox_policy,
            )
            assert self._sandbox is not None
            handle = self._sandbox.start(
                command,
                executable=executable,
                timeout=command_timeout,
                env=command_environment,
                policy=handoff,
                new_process_group=True,
            )
            if not _is_process_handle(handle):
                raise ProcessConfigurationError("Sandbox returned an invalid process handle")
            process = ManagedProcess(
                handle,
                self._runner,
                safe_argv,
                evidence_sink,
                self.termination_grace_seconds,
            )
            if readiness is not None:
                process.wait_until_ready(
                    readiness,
                    timeout=command_timeout if readiness_timeout is None else _nonnegative_timeout(readiness_timeout),
                    poll_seconds=readiness_poll_seconds,
                )
            return process
        except SandboxStartError as error:
            if error.handle is not None:
                cleanup = ManagedProcess(
                    error.handle,
                    self._runner,
                    safe_argv,
                    evidence_sink,
                    self.termination_grace_seconds,
                ).stop_and_reap()
                raise ManagedProcessStartError(cleanup) from None
            result = self._runner._record(
                safe_argv,
                SPAWN_FAILURE_RETURN_CODE,
                "",
                "Command could not start",
                CommandFailureKind.SPAWN,
                evidence_sink,
            )
            raise ManagedProcessStartError(result) from None
        except subprocess.TimeoutExpired as error:
            result = self._runner._record(
                safe_argv,
                TIMEOUT_RETURN_CODE,
                getattr(error, "output", ""),
                getattr(error, "stderr", ""),
                CommandFailureKind.TIMEOUT,
                evidence_sink,
            )
            raise ManagedProcessStartError(result) from None
        except OSError:
            result = self._runner._record(
                safe_argv,
                SPAWN_FAILURE_RETURN_CODE,
                "",
                "Command could not start",
                CommandFailureKind.SPAWN,
                evidence_sink,
            )
            raise ManagedProcessStartError(result) from None
        except ProcessBoundaryError as error:
            if isinstance(error, ManagedProcessStartError):
                raise
            result = self._runner._record(
                safe_argv,
                SPAWN_FAILURE_RETURN_CODE,
                "",
                "Managed command execution is not configured",
                CommandFailureKind.CONFIGURATION,
                evidence_sink,
            )
            raise ManagedProcessStartError(result) from error
        finally:
            if handoff is not None:
                handoff.close()
            if executable is not None:
                _close_verified_executable(executable)


class ManagedProcess:
    def __init__(
        self,
        handle: ProcessHandle,
        runner: ProcessRunner,
        argv: tuple[str, ...],
        evidence_sink: EvidenceSink,
        termination_grace_seconds: float,
    ) -> None:
        self._handle = handle
        self._runner = runner
        self._argv = argv
        self._evidence_sink = evidence_sink
        self._termination_grace_seconds = termination_grace_seconds
        self._reaped: CommandResult | None = None
        self._terminal_completed: SandboxCompleted | None = None

    def wait_until_ready(
        self,
        readiness: Callable[[ManagedProcess], bool],
        *,
        timeout: float,
        poll_seconds: float = 0.05,
    ) -> None:
        deadline = time.monotonic() + _nonnegative_timeout(timeout)
        poll = _positive_timeout(poll_seconds)
        try:
            while True:
                if readiness(self):
                    return
                if self._handle.poll() is not None:
                    result = self.reap()
                    raise ManagedProcessStartError(result)
                if time.monotonic() >= deadline:
                    raise ManagedProcessStartError()
                time.sleep(min(poll, max(0, deadline - time.monotonic())))
        except BaseException:
            if self._reaped is None:
                cleanup = self.stop_and_reap()
            else:
                cleanup = self._reaped
            if isinstance(cleanup, CommandResult) and cleanup.returncode != 0:
                raise ManagedProcessStartError(cleanup) from None
            raise

    def terminate(self) -> None:
        if self._terminal_completed is None:
            self._handle.terminate_group()

    def kill(self) -> None:
        if self._terminal_completed is None:
            self._handle.kill_group()

    def reap(self, timeout: float | None = None) -> CommandResult:
        if self._reaped is not None:
            return self._reaped
        if self._terminal_completed is not None:
            return self._record_terminal_completion(self._terminal_completed)
        try:
            completed = self._handle.wait(timeout=timeout)
            if not isinstance(completed, SandboxCompleted):
                raise ProcessConfigurationError("Sandbox returned an invalid process result")
            self._terminal_completed = completed
            return self._record_terminal_completion(completed)
        except subprocess.TimeoutExpired as error:
            return self._runner._record(
                self._argv,
                TIMEOUT_RETURN_CODE,
                getattr(error, "output", ""),
                getattr(error, "stderr", ""),
                CommandFailureKind.TIMEOUT,
                self._evidence_sink,
            )
        except OSError:
            return self._runner._record(
                self._argv,
                SPAWN_FAILURE_RETURN_CODE,
                "",
                "Managed process could not be reaped",
                CommandFailureKind.SPAWN,
                self._evidence_sink,
            )

    def _record_terminal_completion(self, completed: SandboxCompleted) -> CommandResult:
        result = self._runner._record(
            self._argv,
            completed.returncode,
            completed.stdout,
            completed.stderr,
            _failure_kind_for_returncode(completed.returncode),
            self._evidence_sink,
        )
        self._reaped = result
        return result

    def stop_and_reap(self) -> CommandResult:
        if self._reaped is not None:
            return self._reaped
        try:
            self.terminate()
        except OSError:
            # A failed graceful signal still requires a forced attempt and reap.
            pass
        cleanup_error: ProcessBoundaryError | None = None
        try:
            self.reap(timeout=self._termination_grace_seconds)
        except ProcessBoundaryError as error:
            cleanup_error = error
        if self._terminal_completed is None:
            try:
                self.kill()
            except OSError:
                pass
            try:
                self.reap(timeout=None)
            except ProcessBoundaryError as error:
                if cleanup_error is None:
                    cleanup_error = error
        if self._terminal_completed is None:
            if cleanup_error is not None:
                raise cleanup_error
            raise ProcessBoundaryError("Managed process could not be reaped")
        if cleanup_error is not None:
            raise cleanup_error
        if self._reaped is None:
            return self._record_terminal_completion(self._terminal_completed)
        return self._reaped


def _absolute_policy_path(path: Path) -> Path:
    if not isinstance(path, Path) or not path.is_absolute() or ".." in path.parts:
        raise ProcessConfigurationError("Sandbox paths must be validated absolute paths")
    return Path(os.path.abspath(path))


def _unique_policy_paths(paths: Sequence[Path]) -> tuple[Path, ...]:
    normalized = tuple(_canonical_policy_path(path) for path in paths)
    if len(set(normalized)) != len(normalized):
        raise ProcessConfigurationError("Sandbox paths must be unique")
    return normalized


def _canonical_policy_path(path: Path) -> Path:
    candidate = _absolute_policy_path(path)
    try:
        return Path(os.path.realpath(candidate, strict=True))
    except OSError as error:
        raise ProcessConfigurationError("Sandbox paths must resolve to existing directories") from error


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _paths_overlap(first: Path, second: Path) -> bool:
    return _is_relative_to(first, second) or _is_relative_to(second, first)


def _open_regular_file_no_follow(path: Path) -> int:
    parent = _open_directory_no_follow(path.parent)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | _required_no_follow_flag()
    try:
        return os.open(path.name, flags, dir_fd=parent)
    except OSError as error:
        raise ExecutableVerificationError("Executable cannot be inspected") from error
    finally:
        os.close(parent)


def _open_directory_no_follow(path: Path) -> int:
    candidate = _absolute_policy_path(path)
    flags = os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_CLOEXEC", 0) | _required_no_follow_flag()
    try:
        descriptor = os.open("/", flags)
        for part in candidate.parts[1:]:
            next_descriptor = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as error:
        try:
            os.close(descriptor)
        except (OSError, UnboundLocalError):
            pass
        raise ProcessConfigurationError("Sandbox paths must not traverse symlinks") from error


def _directory_identity(path: Path) -> _DirectoryIdentity:
    descriptor = _open_directory_no_follow(path)
    try:
        metadata = os.fstat(descriptor)
        return _DirectoryIdentity(path=Path(os.path.realpath(path, strict=True)), device=metadata.st_dev, inode=metadata.st_ino)
    finally:
        os.close(descriptor)


def _open_pinned_directory(identity: _DirectoryIdentity) -> SandboxDirectory:
    descriptor = _open_directory_no_follow(identity.path)
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_dev != identity.device or metadata.st_ino != identity.inode:
            raise ProcessConfigurationError("Sandbox policy root changed after validation")
        return SandboxDirectory(path=identity.path, descriptor=descriptor)
    except BaseException:
        os.close(descriptor)
        raise


def _required_no_follow_flag() -> int:
    flag = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(flag, int):
        raise ProcessConfigurationError("Platform does not support no-follow sandbox paths")
    return flag


def _sha256_descriptor(descriptor: int) -> str:
    digest = hashlib.sha256()
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        while chunk := os.read(descriptor, 65_536):
            digest.update(chunk)
        os.lseek(descriptor, 0, os.SEEK_SET)
    except OSError as error:
        raise ExecutableVerificationError("Executable cannot be hashed") from error
    return digest.hexdigest()


def _is_empty_directory(path: Path) -> bool:
    try:
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            return False
        with os.scandir(path) as entries:
            return next(entries, None) is None
    except OSError:
        return False


def _command_argv(argv: Sequence[str]) -> tuple[str, ...]:
    if isinstance(argv, (str, bytes)) or not isinstance(argv, Sequence) or not argv:
        raise ProcessConfigurationError("Command must be a non-empty argument array")
    command = tuple(argv)
    if any(not isinstance(argument, str) or not argument or "\x00" in argument for argument in command):
        raise ProcessConfigurationError("Command arguments are invalid")
    return command


def _verified_executable(value: object) -> VerifiedExecutable:
    if not isinstance(value, VerifiedExecutable):
        raise ExecutableVerificationError("Executable verifier returned an invalid resource")
    path = Path(value.path)
    if not path.is_absolute() or ".." in path.parts:
        _close_verified_executable(value)
        raise ExecutableVerificationError("Executable verifier returned a non-absolute path")
    if isinstance(value.descriptor, bool) or not isinstance(value.descriptor, int) or value.descriptor < 0:
        _close_verified_executable(value)
        raise ExecutableVerificationError("Executable verifier returned an invalid descriptor")
    return value


def _is_process_handle(value: object) -> bool:
    return all(callable(getattr(value, name, None)) for name in ("poll", "wait", "terminate_group", "kill_group"))


def _close_verified_executable(executable: VerifiedExecutable) -> None:
    try:
        executable.close()
    except OSError:
        pass


def _safe_argv(argv: object) -> tuple[str, ...]:
    if isinstance(argv, (str, bytes)) or not isinstance(argv, Sequence):
        return ("[REDACTED]",)
    result: list[str] = []
    redact_next = False
    for argument in tuple(argv)[:64]:
        if redact_next:
            result.append("[REDACTED]")
            redact_next = False
            continue
        if not isinstance(argument, str):
            result.append("[REDACTED]")
            continue
        name, separator, _ = argument.partition("=")
        if _SECRET_ENVIRONMENT.search(name):
            result.append("[REDACTED]")
            redact_next = not separator
            continue
        result.append(_sanitize_and_cap(argument, limit=512))
    return tuple(result) or ("[REDACTED]",)


def _output_bytes(value: str | bytes | object) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return value.encode("utf-8")
    return b""


def _trusted_output_text(value: bytes, expected_sha256: str) -> str:
    actual_sha256 = hashlib.sha256(value).hexdigest()
    if not hmac.compare_digest(actual_sha256, expected_sha256):
        raise ProcessBoundaryError("Trusted command output integrity check failed")
    return value.decode("utf-8", errors="replace")


def _sanitize_and_cap(value: str | bytes | object, *, limit: int = MAX_CAPTURE_TEXT) -> str:
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    elif isinstance(value, str):
        text = value
    else:
        text = ""
    if len(text) > limit:
        text = f"{text[:limit]}\n[TRUNCATED]"
    try:
        return sanitize_untrusted_text(text)
    except ValueError:
        return "[REDACTED]"


def _contains_sensitive_text(value: str) -> bool:
    try:
        return sanitize_untrusted_text(value) != value
    except ValueError:
        return True


def _failure_kind_for_returncode(returncode: int) -> CommandFailureKind | None:
    if returncode == 0:
        return None
    if returncode < 0:
        return CommandFailureKind.SIGNAL
    return CommandFailureKind.EXIT


def _positive_timeout(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
        raise ProcessConfigurationError("Command timeout must be positive")
    return float(value)


def _nonnegative_timeout(value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value < 0:
        raise ProcessConfigurationError("Command timeout must be non-negative")
    return float(value)
