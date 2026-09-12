from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import unicodedata
from typing import TYPE_CHECKING, Protocol

from .process import CommandResult, EvidenceSink, ProcessRunner, SandboxPolicy, TrustedCommandOutput

if TYPE_CHECKING:
    from .project_config import ProjectConfig


_GIT_SHA = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
_RAW_HEADER = re.compile(
    r"^:(?P<old_mode>[0-7]{6}) (?P<new_mode>[0-7]{6}) "
    r"(?P<old_oid>[0-9a-f]{40,64}) (?P<new_oid>[0-9a-f]{40,64}) (?P<status>[A-Z][0-9]*)$"
)
_SAFE_REMOTE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SAFE_TICKET = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SAFE_GIT_OPTIONS = ("-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false")
_SAFE_GIT_ENVIRONMENT = {
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "GIT_CONFIG_SYSTEM": "/dev/null",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
}


class GitGuardError(RuntimeError):
    pass


class GitExecutorUnavailableError(GitGuardError):
    pass


class GitCommandError(GitGuardError):
    def __init__(self, returncode: int) -> None:
        self.returncode = returncode
        super().__init__(f"Git command failed with status {returncode}")


class GitPreflightError(GitGuardError):
    pass


class DirtyWorktreeError(GitPreflightError):
    pass


class ProtectedPathError(GitGuardError):
    pass


class CommitExcludedPathError(GitGuardError):
    pass


class UnauthorizedUntrackedPathError(GitGuardError):
    pass


class BranchReuseError(GitGuardError):
    pass


class ManifestMismatchError(GitGuardError):
    pass


class PushNotAuthorizedError(GitGuardError):
    pass


class GitExecutor(Protocol):
    def run(self, argv: Sequence[str], *, cwd: Path, redact_output: bool = False) -> CommandResult:
        """Execute a fixed Git argument array through a trusted boundary."""

    def read_stdout(self, result: CommandResult) -> str:
        """Read complete integrity-checked stdout for a structured Git parser."""


@dataclass(frozen=True, slots=True)
class ProcessGitExecutor:
    """Production adapter: Git inherits ProcessRunner's verified sandbox boundary."""

    process_runner: ProcessRunner
    git_executable: str
    timeout: float
    evidence_sink: EvidenceSink
    environment: Mapping[str, str]
    sandbox_policy: SandboxPolicy
    _trusted_outputs: dict[int, TrustedCommandOutput] = field(default_factory=dict, init=False, repr=False, compare=False)

    def run(self, argv: Sequence[str], *, cwd: Path, redact_output: bool = False) -> CommandResult:
        if not isinstance(self.environment, Mapping) or any(name in _SAFE_GIT_ENVIRONMENT for name in self.environment):
            raise GitExecutorUnavailableError("Git execution environment is invalid")
        command = tuple(argv)
        if not command or not isinstance(command[0], str) or command[0].startswith("-"):
            raise GitExecutorUnavailableError("Git configuration overrides are not allowed")
        execution = self.process_runner.run_with_trusted_output(
            (self.git_executable, *_SAFE_GIT_OPTIONS, *command),
            cwd,
            self.timeout,
            self.evidence_sink,
            {**self.environment, **_SAFE_GIT_ENVIRONMENT},
            self.sandbox_policy,
            suppress_public_output=redact_output,
        )
        if not isinstance(execution.result, CommandResult) or not isinstance(execution.output, TrustedCommandOutput):
            raise GitExecutorUnavailableError("Git process runner returned an invalid trusted output")
        self._trusted_outputs[id(execution.result)] = execution.output
        return execution.result

    def read_stdout(self, result: CommandResult) -> str:
        output = self._trusted_outputs.get(id(result))
        if output is None:
            raise GitExecutorUnavailableError("Git command has no trusted output")
        return output.read_stdout()


@dataclass(frozen=True, slots=True)
class BranchBinding:
    ticket_id: str
    branch: str
    base_sha: str
    repository_identity: str
    remote_fingerprint: str
    default_branch: str
    checkpoint_lineage: str

    def __post_init__(self) -> None:
        if _SAFE_TICKET.fullmatch(self.ticket_id) is None or not self.checkpoint_lineage:
            raise BranchReuseError("Branch binding is incomplete")
        _validate_branch_name(self.branch)
        if not self.branch.startswith(f"{self.ticket_id}-"):
            raise BranchReuseError("Branch binding does not match its ticket identifier")
        _validate_sha(self.base_sha)
        if not re.fullmatch(r"[0-9a-f]{64}", self.repository_identity):
            raise BranchReuseError("Branch binding repository identity is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", self.remote_fingerprint):
            raise BranchReuseError("Branch binding remote fingerprint is invalid")
        _validate_branch_name(self.default_branch)


@dataclass(frozen=True, slots=True)
class _RemoteSnapshot:
    fingerprint: str
    default_branch: str
    base_sha: str

    def __post_init__(self) -> None:
        if not re.fullmatch(r"[0-9a-f]{64}", self.fingerprint):
            raise GitPreflightError("Remote fingerprint is invalid")
        _validate_branch_name(self.default_branch)
        _validate_sha(self.base_sha)


@dataclass(frozen=True, slots=True)
class GitManifestFile:
    path: str
    status: str
    old_path: str | None
    old_mode: str
    new_mode: str
    old_object_id: str | None
    object_id: str | None
    binary: bool
    untracked: bool = False

    def __post_init__(self) -> None:
        _validate_relative_path(self.path)
        if self.old_path is not None:
            _validate_relative_path(self.old_path)
        if not self.status or self.status[0] not in {"A", "C", "D", "M", "R", "T"}:
            raise ManifestMismatchError("Git manifest status is invalid")
        if not re.fullmatch(r"[0-7]{6}", self.old_mode) or not re.fullmatch(r"[0-7]{6}", self.new_mode):
            raise ManifestMismatchError("Git manifest mode is invalid")
        for object_id in (self.old_object_id, self.object_id):
            if object_id is not None:
                _validate_sha(object_id)
        if self.status[0] == "D" and self.object_id is not None:
            raise ManifestMismatchError("Deleted manifest entry has a new object")


@dataclass(frozen=True, slots=True)
class GitRename:
    old_path: str
    new_path: str


@dataclass(frozen=True, slots=True)
class GitManifestInputs:
    baseline_sha: str
    files: tuple[GitManifestFile, ...]

    def __post_init__(self) -> None:
        _validate_sha(self.baseline_sha)
        paths = [entry.path for entry in self.files]
        if len(paths) != len(set(paths)):
            raise ManifestMismatchError("Git manifest paths must be unique")

    @property
    def renames(self) -> tuple[GitRename, ...]:
        return tuple(
            GitRename(entry.old_path, entry.path)
            for entry in self.files
            if entry.status.startswith("R") and entry.old_path is not None
        )

    @property
    def authorized_untracked_paths(self) -> tuple[str, ...]:
        return tuple(entry.path for entry in self.files if entry.untracked)


class GitGuard:
    """Git boundary with no implicit host executor and no destructive recovery path."""

    def __init__(
        self,
        repository: Path,
        *,
        executor: GitExecutor | None = None,
        remote: str = "origin",
        base_branch: str | None = None,
        protected_paths: Iterable[str] = (),
        commit_excluded_paths: Iterable[str] = (),
    ) -> None:
        self.repository = _absolute_directory(repository)
        if not isinstance(remote, str) or _SAFE_REMOTE.fullmatch(remote) is None:
            raise GitGuardError("Git remote is invalid")
        if base_branch is not None:
            _validate_branch_name(base_branch)
        self.executor = executor
        self.remote = remote
        self.base_branch = base_branch
        self.protected_paths = _policy_paths(protected_paths)
        self.commit_excluded_paths = _policy_paths(commit_excluded_paths)
        self._ticket_branch: str | None = None
        self._approved_commit: str | None = None
        self._prepared_remote: _RemoteSnapshot | None = None

    @classmethod
    def from_project_config(
        cls,
        repository: Path,
        config: ProjectConfig,
        *,
        executor: GitExecutor,
    ) -> GitGuard:
        if not isinstance(executor, ProcessGitExecutor):
            raise GitGuardError("Project Policy requires a ProcessGitExecutor")
        policy = executor.sandbox_policy
        try:
            project_root = Path(os.path.realpath(_absolute_directory(repository), strict=True))
            writable_roots = tuple(
                Path(os.path.realpath(project_root / root, strict=True)) for root in config.writable_roots
            )
        except OSError as error:
            raise GitGuardError("Project Policy writable roots cannot be resolved") from error
        if policy.project_root != project_root:
            raise GitGuardError("Process sandbox project root does not match the Project Policy")
        if policy.environment_allowlist != frozenset(config.environment_allowlist):
            raise GitGuardError("Process sandbox environment does not match the Project Policy")
        if not isinstance(executor.environment, Mapping) or any(name not in config.environment_allowlist for name in executor.environment):
            raise GitGuardError("Process environment does not match the Project Policy")
        if set(policy.writable_roots) != set(writable_roots):
            raise GitGuardError("Process writable roots do not match the Project Policy")
        return cls(
            repository,
            executor=executor,
            remote=config.git.remote,
            base_branch=config.git.base_branch,
            protected_paths=config.protected_paths,
            commit_excluded_paths=config.commit_excluded_paths,
        )

    def preflight(self) -> None:
        """Perform only local, read-only Git checks; Linear is deliberately absent."""

        inside = self._run("rev-parse", "--is-inside-work-tree")
        if self._stdout(inside).strip() != "true":
            raise GitPreflightError("Repository is not a working tree")
        status = self._run("status", "--porcelain=v1", "-z", "--untracked-files=all")
        entries = _parse_status(self._stdout(status))
        for _, paths in entries:
            for path in paths:
                self._check_path_role(path)
        if entries:
            raise DirtyWorktreeError("Repository worktree is not clean")
        self._remote_fingerprint()

    def repository_identity(self) -> str:
        common = self._stdout(self._run("rev-parse", "--git-common-dir")).strip()
        if not common:
            raise GitPreflightError("Git common directory is unavailable")
        common_path = Path(common)
        if not common_path.is_absolute():
            common_path = self.repository / common_path
        try:
            metadata = os.stat(common_path)
        except OSError as error:
            raise GitPreflightError("Git common directory cannot be inspected") from error
        payload = f"{os.path.realpath(common_path)}:{metadata.st_dev}:{metadata.st_ino}".encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def create_ticket_branch(
        self,
        ticket_id: str,
        title: str,
        *,
        reuse_binding: BranchBinding | None = None,
        checkpoint_lineage: str | None = None,
    ) -> str:
        branch = _ticket_branch_name(ticket_id, title)
        self.preflight()
        self._run("fetch", self.remote, redact_output=True)
        snapshot = self._remote_snapshot()
        base_ref = f"{self.remote}/{snapshot.default_branch}"
        base_sha = self._rev_parse(f"{base_ref}^{{commit}}")
        if base_sha != snapshot.base_sha:
            raise GitPreflightError("Fetched remote base does not match the current remote base")
        if self._branch_exists(branch):
            if reuse_binding is None or checkpoint_lineage is None:
                raise BranchReuseError("Existing branch has no trusted reuse binding")
            if reuse_binding.branch != branch or reuse_binding.ticket_id != ticket_id:
                raise BranchReuseError("Existing branch does not match its trusted binding")
            return self.reconcile_branch(reuse_binding, checkpoint_lineage=checkpoint_lineage)
        self._run("switch", "-c", branch, base_ref)
        self._ticket_branch = branch
        self._prepared_remote = snapshot
        return branch

    def prepare_ticket_branch(self, ticket_id: str, title: str, *, checkpoint_lineage: str) -> BranchBinding:
        """Capture the exact remote lineage that a later creation is authorized to use."""

        branch = _ticket_branch_name(ticket_id, title)
        self.preflight()
        self._run("fetch", self.remote, redact_output=True)
        snapshot = self._remote_snapshot()
        base_ref = f"{self.remote}/{snapshot.default_branch}"
        base_sha = self._rev_parse(f"{base_ref}^{{commit}}")
        if base_sha != snapshot.base_sha:
            raise GitPreflightError("Fetched remote base does not match the current remote base")
        self._prepared_remote = snapshot
        return BranchBinding(
            ticket_id=ticket_id,
            branch=branch,
            base_sha=base_sha,
            repository_identity=self.repository_identity(),
            remote_fingerprint=snapshot.fingerprint,
            default_branch=snapshot.default_branch,
            checkpoint_lineage=checkpoint_lineage,
        )

    def create_bound_ticket_branch(self, binding: BranchBinding) -> str:
        """Create only from a persisted binding, or reconcile an already-created bound branch."""

        if binding.repository_identity != self.repository_identity():
            raise BranchReuseError("Repository identity does not match the branch binding")
        self.preflight()
        self._run("fetch", self.remote, redact_output=True)
        snapshot = self._remote_snapshot()
        if (
            binding.remote_fingerprint != snapshot.fingerprint
            or binding.default_branch != snapshot.default_branch
            or binding.base_sha.lower() != snapshot.base_sha
            or self._rev_parse(f"{self.remote}/{snapshot.default_branch}^{{commit}}") != snapshot.base_sha
        ):
            raise BranchReuseError("Remote state does not match the branch binding")
        if self._branch_exists(binding.branch):
            return self.reconcile_branch(binding, checkpoint_lineage=binding.checkpoint_lineage)
        self._run("switch", "-c", binding.branch, binding.base_sha)
        self._ticket_branch = binding.branch
        self._prepared_remote = snapshot
        return binding.branch

    def reconcile_branch(self, binding: BranchBinding, *, checkpoint_lineage: str) -> str:
        """Reuse only a branch bound by the Active Run's immutable lineage data."""

        if not isinstance(checkpoint_lineage, str) or not checkpoint_lineage:
            raise BranchReuseError("Checkpoint lineage is required for branch reuse")
        if binding.checkpoint_lineage != checkpoint_lineage:
            raise BranchReuseError("Checkpoint lineage does not match the branch binding")
        if binding.repository_identity != self.repository_identity():
            raise BranchReuseError("Repository identity does not match the branch binding")
        self.preflight()
        self._run("fetch", self.remote, redact_output=True)
        snapshot = self._remote_snapshot()
        if (
            binding.remote_fingerprint != snapshot.fingerprint
            or binding.default_branch != snapshot.default_branch
            or binding.base_sha.lower() != snapshot.base_sha
        ):
            raise BranchReuseError("Remote state does not match the branch binding")
        local_base = self._rev_parse(f"{self.remote}/{snapshot.default_branch}^{{commit}}")
        if local_base != snapshot.base_sha:
            raise BranchReuseError("Fetched remote base does not match the branch binding")
        if not self._branch_exists(binding.branch):
            raise BranchReuseError("Bound branch does not exist")
        ancestor = self._run(
            "merge-base",
            "--is-ancestor",
            binding.base_sha,
            f"refs/heads/{binding.branch}",
            allow_failure=True,
        )
        if ancestor.returncode != 0:
            raise BranchReuseError("Bound branch no longer contains its approved base")
        self._run("switch", binding.branch)
        self._ticket_branch = binding.branch
        self._prepared_remote = snapshot
        return binding.branch

    def collect_manifest_inputs(
        self,
        baseline_sha: str,
        *,
        authorized_untracked: Iterable[str] = (),
    ) -> GitManifestInputs:
        baseline = self._verify_baseline(baseline_sha)
        authorized = frozenset(_validate_relative_path(path) for path in authorized_untracked)
        raw_entries = self._raw_diff(baseline)
        binary_paths = self._binary_paths(baseline)
        files: list[GitManifestFile] = []
        for raw in raw_entries:
            for path in (raw.path, raw.old_path):
                if path is not None:
                    self._check_path_role(path)
            object_id = None if raw.status.startswith("D") else self._hash_worktree_object(raw.path)
            files.append(
                GitManifestFile(
                    path=raw.path,
                    status=raw.status,
                    old_path=raw.old_path,
                    old_mode=raw.old_mode,
                    new_mode=raw.new_mode,
                    old_object_id=_none_if_zero(raw.old_object_id),
                    object_id=object_id,
                    binary=raw.path in binary_paths,
                )
            )
        deleted_by_object = {
            entry.old_object_id: index
            for index, entry in enumerate(files)
            if entry.status.startswith("D") and entry.old_object_id is not None
        }
        unmatched_untracked: list[tuple[str, str, str, bool]] = []
        for path in self._untracked_paths():
            self._check_path_role(path)
            object_id = self._hash_worktree_object(path)
            mode = _worktree_mode(self.repository / path)
            deleted_index = deleted_by_object.pop(object_id, None)
            if deleted_index is not None:
                deleted = files[deleted_index]
                files[deleted_index] = GitManifestFile(
                    path=path,
                    status="R100",
                    old_path=deleted.path,
                    old_mode=deleted.old_mode,
                    new_mode=mode,
                    old_object_id=deleted.old_object_id,
                    object_id=object_id,
                    binary=_worktree_is_binary(self.repository / path),
                )
            else:
                unmatched_untracked.append((path, object_id, mode, _worktree_is_binary(self.repository / path)))
        tracked_paths = {entry.path for entry in files}
        for path, object_id, mode, binary in unmatched_untracked:
            if path not in authorized:
                raise UnauthorizedUntrackedPathError("Untracked path is not authorized for the product manifest")
            if path in tracked_paths:
                continue
            files.append(
                GitManifestFile(
                    path=path,
                    status="A",
                    old_path=None,
                    old_mode="000000",
                    new_mode=mode,
                    old_object_id=None,
                    object_id=object_id,
                    binary=binary,
                    untracked=True,
                )
            )
        return GitManifestInputs(baseline_sha=baseline, files=tuple(sorted(files, key=lambda entry: entry.path)))

    def commit_manifest(self, manifest: GitManifestInputs, message: str) -> str:
        if not isinstance(manifest, GitManifestInputs) or not manifest.files:
            raise ManifestMismatchError("Approved Git manifest is required")
        if not isinstance(message, str) or not message.strip() or len(message) > 4_096 or "\x00" in message:
            raise ManifestMismatchError("Commit message is invalid")
        if self._ticket_branch is None or self._current_branch() != self._ticket_branch:
            raise ManifestMismatchError("Commit is not on the prepared ticket branch")
        if self._rev_parse("HEAD") != manifest.baseline_sha:
            raise ManifestMismatchError("Commit baseline no longer matches HEAD")
        current = self.collect_manifest_inputs(
            manifest.baseline_sha,
            authorized_untracked=manifest.authorized_untracked_paths,
        )
        if current != manifest:
            raise ManifestMismatchError("Worktree no longer matches the approved Git manifest")
        expected_paths = _manifest_stage_paths(manifest)
        if self._index_changed_paths(manifest.baseline_sha) - expected_paths:
            raise ManifestMismatchError("Index contains changes outside the approved Git manifest")
        self._run("update-index", "--add", "--remove", "--", *sorted(expected_paths))
        if self._index_changed_paths(manifest.baseline_sha) != expected_paths:
            raise ManifestMismatchError("Index does not match the approved Git manifest")
        index_matches_worktree = self._run(
            "diff",
            "--quiet",
            "--",
            *sorted(expected_paths),
            allow_failure=True,
        )
        if index_matches_worktree.returncode != 0:
            raise ManifestMismatchError("Index content does not match the approved worktree data")
        self._run("commit", "--no-verify", "-m", message)
        commit = self._rev_parse("HEAD")
        self._verify_commit(manifest, commit)
        self._approved_commit = commit
        return commit

    def push(self) -> str:
        if self._ticket_branch is None or self._approved_commit is None or self._prepared_remote is None:
            raise PushNotAuthorizedError("Push requires an approved ticket commit")
        if self._current_branch() != self._ticket_branch or self._rev_parse("HEAD") != self._approved_commit:
            raise PushNotAuthorizedError("Prepared ticket branch no longer matches the approved commit")
        if self._remote_snapshot() != self._prepared_remote:
            raise PushNotAuthorizedError("Remote state changed after branch preparation")
        reference = f"refs/heads/{self._ticket_branch}"
        self._run("push", "--porcelain", "--set-upstream", self.remote, f"{reference}:{reference}", redact_output=True)
        remote = self._stdout(self._run("ls-remote", "--heads", self.remote, reference, redact_output=True)).splitlines()
        if len(remote) != 1:
            raise PushNotAuthorizedError("Remote ticket branch could not be reconciled")
        remote_sha = remote[0].split(maxsplit=1)[0].lower()
        if remote_sha != self._approved_commit:
            raise PushNotAuthorizedError("Remote ticket branch does not match the approved commit")
        return self._approved_commit

    def _run(self, *argv: str, allow_failure: bool = False, redact_output: bool = False) -> CommandResult:
        if self.executor is None:
            raise GitExecutorUnavailableError("Git requires an explicit trusted executor")
        result = self.executor.run(argv, cwd=self.repository, redact_output=redact_output)
        if not isinstance(result, CommandResult):
            raise GitGuardError("Git executor returned an invalid result")
        if result.returncode != 0 and not allow_failure:
            raise GitCommandError(result.returncode)
        return result

    def _stdout(self, result: CommandResult) -> str:
        if self.executor is None:
            raise GitExecutorUnavailableError("Git requires an explicit trusted executor")
        try:
            output = self.executor.read_stdout(result)
        except Exception as error:
            raise GitGuardError("Trusted Git output cannot be read") from error
        if not isinstance(output, str):
            raise GitGuardError("Trusted Git output is invalid")
        return output

    def _remote_fingerprint(self) -> str:
        output = self._stdout(self._run("remote", "get-url", self.remote, redact_output=True))
        lines = output.splitlines()
        if len(lines) != 1 or not lines[0]:
            raise GitPreflightError("Remote URL cannot be resolved")
        return hashlib.sha256(lines[0].encode("utf-8")).hexdigest()

    def _default_branch(self) -> str:
        return self._remote_snapshot().default_branch

    def _remote_snapshot(self) -> _RemoteSnapshot:
        fingerprint = self._remote_fingerprint()
        default_branch = self.base_branch or self._discover_remote_default_branch()
        reference = f"refs/heads/{default_branch}"
        output = self._stdout(self._run("ls-remote", "--heads", self.remote, reference, redact_output=True))
        lines = output.splitlines()
        if len(lines) != 1:
            raise GitPreflightError("Remote default base cannot be resolved")
        try:
            base_sha, returned_reference = lines[0].split("\t", maxsplit=1)
        except ValueError as error:
            raise GitPreflightError("Remote default base is malformed") from error
        if returned_reference != reference:
            raise GitPreflightError("Remote default base does not match its branch")
        return _RemoteSnapshot(
            fingerprint=fingerprint,
            default_branch=default_branch,
            base_sha=_validate_sha(base_sha),
        )

    def _discover_remote_default_branch(self) -> str:
        output = self._stdout(self._run("ls-remote", "--symref", self.remote, "HEAD", redact_output=True))
        branches = [
            line[len("ref: refs/heads/") : -len("\tHEAD")]
            for line in output.splitlines()
            if line.startswith("ref: refs/heads/") and line.endswith("\tHEAD")
        ]
        if len(branches) != 1:
            raise GitPreflightError("Remote default branch cannot be discovered")
        return _validate_branch_name(branches[0])

    def _branch_exists(self, branch: str) -> bool:
        _validate_branch_name(branch)
        return self._run("show-ref", "--verify", "--quiet", f"refs/heads/{branch}", allow_failure=True).returncode == 0

    def _verify_baseline(self, baseline_sha: str) -> str:
        _validate_sha(baseline_sha)
        return self._rev_parse(f"{baseline_sha}^{{commit}}")

    def _rev_parse(self, reference: str) -> str:
        value = self._stdout(self._run("rev-parse", "--verify", reference)).strip().lower()
        _validate_sha(value)
        return value

    def _current_branch(self) -> str:
        branch = self._stdout(self._run("symbolic-ref", "--quiet", "--short", "HEAD")).strip()
        _validate_branch_name(branch)
        return branch

    def _raw_diff(self, baseline_sha: str, target: str | None = None) -> tuple[_RawDiffEntry, ...]:
        argv = ["diff", "--raw", "-z", "--no-abbrev", "--find-renames", baseline_sha]
        if target is not None:
            argv.append(target)
        argv.append("--")
        return _parse_raw_diff(self._stdout(self._run(*argv)))

    def _binary_paths(self, baseline_sha: str) -> frozenset[str]:
        result = self._run("diff", "--numstat", "-z", "--no-renames", baseline_sha, "--")
        return _parse_binary_numstat(self._stdout(result))

    def _untracked_paths(self) -> tuple[str, ...]:
        output = self._stdout(self._run("ls-files", "--others", "--exclude-standard", "-z"))
        paths = tuple(_validate_relative_path(path) for path in output.split("\0") if path)
        if len(paths) != len(set(paths)):
            raise GitGuardError("Git returned duplicate untracked paths")
        return paths

    def _hash_worktree_object(self, path: str) -> str:
        object_id = self._stdout(self._run("hash-object", "--no-filters", "--", path)).strip().lower()
        _validate_sha(object_id)
        return object_id

    def _index_changed_paths(self, baseline_sha: str) -> set[str]:
        output = self._stdout(self._run("diff", "--cached", "--name-only", "--no-renames", "-z", baseline_sha, "--"))
        return {_validate_relative_path(path) for path in output.split("\0") if path}

    def _verify_commit(self, manifest: GitManifestInputs, commit: str) -> None:
        parent = self._rev_parse(f"{commit}^")
        if parent != manifest.baseline_sha:
            raise ManifestMismatchError("Commit parent does not match the approved baseline")
        if self._index_changed_paths(commit):
            raise ManifestMismatchError("Commit left staged data behind")
        expected_paths = _manifest_stage_paths(manifest)
        committed_paths = {
            _validate_relative_path(path)
            for path in self._stdout(
                self._run(
                    "diff-tree",
                    "--no-commit-id",
                    "--name-only",
                    "--no-renames",
                    "-r",
                    "-z",
                    commit,
                )
            ).split("\0")
            if path
        }
        if committed_paths != expected_paths:
            raise ManifestMismatchError("Commit paths do not match the approved manifest")
        for entry in manifest.files:
            if entry.status.startswith("D"):
                if self._stdout(self._run("ls-tree", commit, "--", entry.path)):
                    raise ManifestMismatchError("Deleted manifest path remains in the commit tree")
                continue
            tree = self._stdout(self._run("ls-tree", commit, "--", entry.path)).strip()
            try:
                mode_and_object, path = tree.split("\t", maxsplit=1)
                mode, _, object_id = mode_and_object.split(maxsplit=2)
            except ValueError as error:
                raise ManifestMismatchError("Commit tree cannot be verified") from error
            if path != entry.path or mode != entry.new_mode or object_id.lower() != entry.object_id:
                raise ManifestMismatchError("Commit tree does not match the approved object data")
        expected_renames = {(rename.old_path, rename.new_path) for rename in manifest.renames}
        actual_renames = {
            (entry.old_path, entry.path)
            for entry in self._raw_diff(manifest.baseline_sha, commit)
            if entry.status.startswith("R") and entry.old_path is not None
        }
        if actual_renames != expected_renames:
            raise ManifestMismatchError("Commit renames do not match the approved manifest")

    def _check_path_role(self, path: str) -> None:
        normalized = _validate_relative_path(path)
        if _matches_policy_path(normalized, self.protected_paths):
            raise ProtectedPathError("Git operation references a protected path")
        if _matches_policy_path(normalized, self.commit_excluded_paths):
            raise CommitExcludedPathError("Git operation references a commit-excluded path")


@dataclass(frozen=True, slots=True)
class _RawDiffEntry:
    old_mode: str
    new_mode: str
    old_object_id: str
    new_object_id: str
    status: str
    old_path: str | None
    path: str


def _parse_status(output: str) -> tuple[tuple[str, tuple[str, ...]], ...]:
    fields = [field for field in output.split("\0") if field]
    entries: list[tuple[str, tuple[str, ...]]] = []
    index = 0
    while index < len(fields):
        record = fields[index]
        index += 1
        if len(record) < 4:
            raise GitPreflightError("Git status output is malformed")
        status = record[:2]
        path = _validate_relative_path(record[3:])
        paths = [path]
        if "R" in status or "C" in status:
            if index >= len(fields):
                raise GitPreflightError("Git rename status output is malformed")
            paths.append(_validate_relative_path(fields[index]))
            index += 1
        entries.append((status, tuple(paths)))
    return tuple(entries)


def _parse_raw_diff(output: str) -> tuple[_RawDiffEntry, ...]:
    fields = output.split("\0")
    entries: list[_RawDiffEntry] = []
    index = 0
    while index < len(fields):
        header = fields[index]
        index += 1
        if not header:
            continue
        inline_path: str | None = None
        if "\t" in header:
            header, inline_path = header.split("\t", maxsplit=1)
        match = _RAW_HEADER.fullmatch(header)
        if match is None:
            raise GitGuardError("Git raw diff output is malformed")
        if inline_path is None:
            if index >= len(fields):
                raise GitGuardError("Git raw diff path is missing")
            first_path = fields[index]
            index += 1
        else:
            first_path = inline_path
        status = match.group("status")
        old_path: str | None = None
        path = _validate_relative_path(first_path)
        if status.startswith(("R", "C")):
            if index >= len(fields):
                raise GitGuardError("Git rename diff path is missing")
            old_path = path
            path = _validate_relative_path(fields[index])
            index += 1
        entries.append(
            _RawDiffEntry(
                old_mode=match.group("old_mode"),
                new_mode=match.group("new_mode"),
                old_object_id=match.group("old_oid").lower(),
                new_object_id=match.group("new_oid").lower(),
                status=status,
                old_path=old_path,
                path=path,
            )
        )
    return tuple(entries)


def _parse_binary_numstat(output: str) -> frozenset[str]:
    paths: set[str] = set()
    for record in output.split("\0"):
        if not record:
            continue
        added, deleted, path = record.split("\t", maxsplit=2)
        if added == "-" and deleted == "-":
            paths.add(_validate_relative_path(path))
    return frozenset(paths)


def _ticket_branch_name(ticket_id: str, title: str) -> str:
    if not isinstance(ticket_id, str) or _SAFE_TICKET.fullmatch(ticket_id) is None:
        raise GitGuardError("Ticket identifier is invalid")
    if not isinstance(title, str):
        raise GitGuardError("Ticket title is invalid")
    normalized = unicodedata.normalize("NFKD", title).encode("ascii", "ignore").decode("ascii").lower()
    slug = re.sub(r"[^a-z0-9]+", "-", normalized).strip("-")[:96].rstrip("-")
    if not slug:
        raise GitGuardError("Ticket title cannot produce a branch slug")
    branch = f"{ticket_id}-{slug}"
    _validate_branch_name(branch)
    return branch


def _validate_branch_name(value: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 255
        or value.startswith("-")
        or value.endswith((".", "/", ".lock"))
        or ".." in value
        or "@{" in value
        or "//" in value
        or any(character.isspace() or character in "~^:?*[\\\x00" for character in value)
    ):
        raise GitGuardError("Git branch is invalid")
    return value


def _validate_sha(value: str) -> str:
    if not isinstance(value, str) or _GIT_SHA.fullmatch(value.lower()) is None:
        raise GitGuardError("Git object identifier is invalid")
    return value.lower()


def _validate_relative_path(value: str) -> str:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise GitGuardError("Git path is invalid")
    path = PurePosixPath(value)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise GitGuardError("Git path escapes the repository")
    return value


def _policy_paths(paths: Iterable[str]) -> tuple[str, ...]:
    result = tuple(_validate_relative_path(path) for path in paths)
    if len(result) != len(set(result)):
        raise GitGuardError("Git path policy contains duplicates")
    return result


def _matches_policy_path(path: str, roots: Iterable[str]) -> bool:
    return any(path == root or path.startswith(f"{root}/") for root in roots)


def _absolute_directory(path: Path) -> Path:
    if not isinstance(path, Path):
        raise GitGuardError("Repository path is invalid")
    result = Path(os.path.abspath(path))
    if not result.is_dir():
        raise GitGuardError("Repository path is not a directory")
    return result


def _none_if_zero(value: str) -> str | None:
    return None if set(value) == {"0"} else value


def _worktree_mode(path: Path) -> str:
    try:
        metadata = os.lstat(path)
    except OSError as error:
        raise GitGuardError("Untracked path cannot be inspected") from error
    if os.path.islink(path):
        return "120000"
    if not os.path.isfile(path):
        raise GitGuardError("Untracked path is not a regular file")
    return "100755" if metadata.st_mode & 0o111 else "100644"


def _worktree_is_binary(path: Path) -> bool:
    if os.path.islink(path):
        return False
    try:
        with path.open("rb") as stream:
            return b"\x00" in stream.read(8_192)
    except OSError as error:
        raise GitGuardError("Worktree path cannot be read") from error


def _manifest_stage_paths(manifest: GitManifestInputs) -> set[str]:
    paths: set[str] = set()
    for entry in manifest.files:
        paths.add(entry.path)
        if entry.status.startswith("R") and entry.old_path is not None:
            paths.add(entry.old_path)
    return paths
