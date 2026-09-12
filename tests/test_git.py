from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
import os
from pathlib import Path
import shutil
import subprocess
from typing import Sequence

import pytest

from auto_code.git import (
    BranchBinding,
    BranchReuseError,
    CommitExcludedPathError,
    DirtyWorktreeError,
    GitGuard,
    GitGuardError,
    ManifestMismatchError,
    ProcessGitExecutor,
    ProtectedPathError,
    PushNotAuthorizedError,
    UnauthorizedUntrackedPathError,
)
from auto_code.process import CommandExecution, MAX_CAPTURE_TEXT, CommandResult, SandboxPolicy, TrustedCommandOutput
from auto_code.project_config import ProjectConfig


@dataclass
class TemporaryGitExecutor:
    """Explicit test-only executor for real Git commands in temporary repositories."""

    calls: list[tuple[str, ...]]

    def __init__(self) -> None:
        self.calls = []
        self.full_stdout: dict[int, str] = {}
        executable = shutil.which("git")
        assert executable is not None
        self.executable = executable

    def run(self, argv: Sequence[str], *, cwd: Path, redact_output: bool = False) -> CommandResult:
        command = tuple(argv)
        self.calls.append(command)
        completed = subprocess.run(
            (self.executable, *command),
            cwd=cwd,
            env={
                "HOME": str(cwd / ".test-home"),
                "PATH": os.environ.get("PATH", ""),
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_TERMINAL_PROMPT": "0",
            },
            check=False,
            shell=False,
            text=True,
            capture_output=True,
        )
        result = CommandResult(
            argv=(self.executable, *command),
            returncode=completed.returncode,
            stdout_text="[REDACTED]" if redact_output else completed.stdout,
            stderr_text="[REDACTED]" if redact_output else completed.stderr,
            stdout_path=None,
            stderr_path=None,
            redacted=True,
        )
        self.full_stdout[id(result)] = completed.stdout
        return result

    def read_stdout(self, result: CommandResult) -> str:
        return self.full_stdout[id(result)]


@dataclass
class RecordingProcessRunner:
    calls: list[tuple[tuple[str, ...], dict[str, str]]]

    def __init__(self) -> None:
        self.calls = []

    def run(
        self,
        argv: Sequence[str],
        cwd: Path,
        timeout: float,
        evidence_sink: object,
        environment: dict[str, str],
        sandbox_policy: SandboxPolicy,
    ) -> CommandResult:
        command = tuple(argv)
        self.calls.append((command, dict(environment)))
        return CommandResult(
            argv=command,
            returncode=0,
            stdout_text="",
            stderr_text="",
            stdout_path=None,
            stderr_path=None,
            redacted=True,
        )

    def run_with_trusted_output(
        self,
        argv: Sequence[str],
        cwd: Path,
        timeout: float,
        evidence_sink: object,
        environment: dict[str, str],
        sandbox_policy: SandboxPolicy,
        *,
        suppress_public_output: bool = False,
    ) -> CommandExecution:
        result = self.run(argv, cwd, timeout, evidence_sink, environment, sandbox_policy)
        return CommandExecution(
            result=result,
            output=TrustedCommandOutput(
                stdout_sha256=sha256(b"").hexdigest(),
                stderr_sha256=sha256(b"").hexdigest(),
                _stdout=b"",
                _stderr=b"",
            ),
        )


@dataclass
class RemoteRecordingProcessRunner:
    calls: list[tuple[tuple[str, ...], bool, CommandResult]]

    def __init__(self) -> None:
        self.calls = []

    def run_with_trusted_output(
        self,
        argv: Sequence[str],
        cwd: Path,
        timeout: float,
        evidence_sink: object,
        environment: dict[str, str],
        sandbox_policy: SandboxPolicy,
        *,
        suppress_public_output: bool = False,
    ) -> CommandExecution:
        command = tuple(argv)[5:]
        output = {
            ("rev-parse", "--is-inside-work-tree"): "true\n",
            ("status", "--porcelain=v1", "-z", "--untracked-files=all"): "",
            ("remote", "get-url", "origin"): "https://token@example.invalid/private/repository.git\n",
        }[command]
        result = CommandResult(
            argv=tuple(argv),
            returncode=0,
            stdout_text="[REDACTED]" if suppress_public_output else output,
            stderr_text="[REDACTED]" if suppress_public_output else "",
            stdout_path=None,
            stderr_path=None,
            redacted=True,
        )
        self.calls.append((command, suppress_public_output, result))
        raw = output.encode("utf-8")
        return CommandExecution(
            result=result,
            output=TrustedCommandOutput(
                stdout_sha256=sha256(raw).hexdigest(),
                stderr_sha256=sha256(b"").hexdigest(),
                _stdout=raw,
                _stderr=b"",
            ),
        )


class CappedGitExecutor(TemporaryGitExecutor):
    def __init__(self) -> None:
        super().__init__()
        self.full_stdout: dict[int, str] = {}
        self.public_results: list[CommandResult] = []
        self.reader_calls = 0

    def run(self, argv: Sequence[str], *, cwd: Path, redact_output: bool = False) -> CommandResult:
        result = super().run(argv, cwd=cwd, redact_output=redact_output)
        output = self.full_stdout[id(result)]
        public = replace(
            result,
            stdout_text=(
                result.stdout_text
                if redact_output or len(output) <= MAX_CAPTURE_TEXT
                else f"{output[:MAX_CAPTURE_TEXT]}\n[TRUNCATED]"
            ),
        )
        self.full_stdout[id(public)] = output
        self.public_results.append(public)
        return public

    def read_stdout(self, result: CommandResult) -> str:
        self.reader_calls += 1
        return self.full_stdout[id(result)]


@dataclass
class GitRepository:
    root: Path
    executor: TemporaryGitExecutor

    def git(self, *argv: str) -> CommandResult:
        result = self.executor.run(argv, cwd=self.root)
        result.require_success()
        return result

    def guard(self, **overrides: object) -> GitGuard:
        values: dict[str, object] = {
            "executor": self.executor,
            "remote": "origin",
            "protected_paths": (".env", ".auto-code"),
            "commit_excluded_paths": ("run-local",),
        }
        values.update(overrides)
        return GitGuard(self.root, **values)


def remote_fingerprint(repository: GitRepository) -> str:
    url = repository.git("remote", "get-url", "origin").stdout_text.strip()
    return sha256(url.encode("utf-8")).hexdigest()


def _initialize_repository(root: Path, executor: TemporaryGitExecutor) -> GitRepository:
    root.mkdir()
    repository = GitRepository(root=root, executor=executor)
    repository.git("init")
    repository.git("config", "user.name", "Test User")
    repository.git("config", "user.email", "test@example.invalid")
    (root / "old.txt").write_text("old content\n", encoding="ascii")
    script = root / "script.sh"
    script.write_text("#!/bin/sh\necho safe\n", encoding="ascii")
    script.chmod(0o644)
    (root / "image.bin").write_bytes(b"\x00\x01")
    repository.git("add", "old.txt", "script.sh", "image.bin")
    repository.git("commit", "-m", "baseline")
    repository.git("branch", "-M", "main")
    return repository


@pytest.fixture
def git_repo(tmp_path: Path) -> GitRepository:
    return _initialize_repository(tmp_path / "repository", TemporaryGitExecutor())


@pytest.fixture
def git_repo_with_remote(tmp_path: Path) -> GitRepository:
    executor = TemporaryGitExecutor()
    remote = tmp_path / "remote.git"
    remote.mkdir()
    executor.run(("init", "--bare"), cwd=remote).require_success()
    repository = _initialize_repository(tmp_path / "repository", executor)
    repository.git("remote", "add", "origin", str(remote))
    repository.git("push", "-u", "origin", "main")
    executor.run(("--git-dir", str(remote), "symbolic-ref", "HEAD", "refs/heads/main"), cwd=tmp_path).require_success()
    return repository


def test_preflight_rejects_dirty_worktree_without_modifying_it(git_repo: GitRepository) -> None:
    dirty = git_repo.root / "dirty.txt"
    dirty.write_text("x", encoding="ascii")
    before_head = git_repo.git("rev-parse", "HEAD").stdout_text.strip()
    first_call = len(git_repo.executor.calls)

    with pytest.raises(DirtyWorktreeError):
        git_repo.guard().preflight()

    assert dirty.read_text(encoding="ascii") == "x"
    assert git_repo.git("rev-parse", "HEAD").stdout_text.strip() == before_head
    assert all(
        call[0] not in {"add", "commit", "fetch", "push", "switch", "reset", "restore"}
        for call in git_repo.executor.calls[first_call:]
    )


def test_preflight_prioritizes_protected_paths(git_repo: GitRepository) -> None:
    (git_repo.root / ".env").write_text("TOKEN=not-for-git\n", encoding="ascii")

    with pytest.raises(ProtectedPathError):
        git_repo.guard().preflight()


def test_process_git_executor_pins_safe_config_for_preflight_and_switch(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    build = repository / "build"
    home = tmp_path / "controlled-home"
    state = tmp_path / "state"
    secrets = tmp_path / "secrets"
    for directory in (repository, build, home, state, secrets):
        directory.mkdir(parents=True, exist_ok=True)
    runner = RecordingProcessRunner()
    executor = ProcessGitExecutor(
        process_runner=runner,  # type: ignore[arg-type]
        git_executable="/trusted/bin/git",
        timeout=5,
        evidence_sink=object(),  # type: ignore[arg-type]
        environment={"LANG": "C"},
        sandbox_policy=SandboxPolicy(
            project_root=repository,
            readable_roots=(repository,),
            writable_roots=(build,),
            authoritative_state_root=state,
            secret_paths=(secrets,),
            controlled_home=home,
            environment_allowlist=frozenset({"LANG"}),
        ),
    )

    executor.run(("status", "--porcelain=v1"), cwd=repository)
    executor.run(("switch", "-c", "ENG-42-safe", "origin/main"), cwd=repository)

    expected_prefix = (
        "/trusted/bin/git",
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
    )
    expected_environment = {
        "LANG": "C",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }
    assert [command[: len(expected_prefix)] for command, _ in runner.calls] == [expected_prefix, expected_prefix]
    assert [environment for _, environment in runner.calls] == [expected_environment, expected_environment]


def test_preflight_reads_the_remote_url_only_as_suppressed_trusted_output(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    build = repository / "build"
    home = tmp_path / "controlled-home"
    state = tmp_path / "state"
    secrets = tmp_path / "secrets"
    for directory in (repository, build, home, state, secrets):
        directory.mkdir(parents=True, exist_ok=True)
    runner = RemoteRecordingProcessRunner()
    guard = GitGuard(
        repository,
        executor=ProcessGitExecutor(
            process_runner=runner,  # type: ignore[arg-type]
            git_executable="/trusted/bin/git",
            timeout=5,
            evidence_sink=object(),  # type: ignore[arg-type]
            environment={"LANG": "C"},
            sandbox_policy=SandboxPolicy(
                project_root=repository,
                readable_roots=(repository,),
                writable_roots=(build,),
                authoritative_state_root=state,
                secret_paths=(secrets,),
                controlled_home=home,
                environment_allowlist=frozenset({"LANG"}),
            ),
        ),
    )

    guard.preflight()

    remote_call = next(call for call in runner.calls if call[0] == ("remote", "get-url", "origin"))
    assert remote_call[1] is True
    assert "example.invalid" not in remote_call[2].stdout_text


def test_from_project_config_requires_an_exact_process_environment_and_writable_policy(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    build = repository / "build"
    home = tmp_path / "controlled-home"
    state = tmp_path / "state"
    secrets = tmp_path / "secrets"
    for directory in (repository, build, home, state, secrets):
        directory.mkdir(parents=True, exist_ok=True)
    config = ProjectConfig.load(Path(__file__).resolve().parents[1] / "auto-code.example.yaml").model_copy(
        update={"environment_allowlist": ("LANG",), "writable_roots": ("build",)}
    )

    def executor(*, environment_allowlist: frozenset[str], writable_roots: tuple[Path, ...], environment: dict[str, str]) -> ProcessGitExecutor:
        return ProcessGitExecutor(
            process_runner=RecordingProcessRunner(),  # type: ignore[arg-type]
            git_executable="/trusted/bin/git",
            timeout=5,
            evidence_sink=object(),  # type: ignore[arg-type]
            environment=environment,
            sandbox_policy=SandboxPolicy(
                project_root=repository,
                readable_roots=(repository,),
                writable_roots=writable_roots,
                authoritative_state_root=state,
                secret_paths=(secrets,),
                controlled_home=home,
                environment_allowlist=environment_allowlist,
            ),
        )

    matching = executor(environment_allowlist=frozenset({"LANG"}), writable_roots=(build,), environment={"LANG": "C"})
    guard = GitGuard.from_project_config(repository, config, executor=matching)
    assert guard.remote == "origin"

    broader_environment = executor(
        environment_allowlist=frozenset({"LANG", "EXTRA"}),
        writable_roots=(build,),
        environment={"LANG": "C", "EXTRA": "1"},
    )
    with pytest.raises(GitGuardError, match="Project Policy"):
        GitGuard.from_project_config(repository, config, executor=broader_environment)

    broader_writable_roots = executor(
        environment_allowlist=frozenset({"LANG"}),
        writable_roots=(),
        environment={"LANG": "C"},
    )
    with pytest.raises(GitGuardError, match="Project Policy"):
        GitGuard.from_project_config(repository, config, executor=broader_writable_roots)


def test_branch_name_uses_ticket_id_slug_remote_default_and_fetches_before_switch(git_repo_with_remote: GitRepository) -> None:
    guard = git_repo_with_remote.guard()
    base = git_repo_with_remote.git("rev-parse", "origin/main").stdout_text.strip()
    first_call = len(git_repo_with_remote.executor.calls)

    branch = guard.create_ticket_branch("ENG-42", "Add safer retries")

    assert branch == "ENG-42-add-safer-retries"
    assert git_repo_with_remote.git("branch", "--show-current").stdout_text.strip() == branch
    assert git_repo_with_remote.git("merge-base", base, branch).stdout_text.strip() == base
    commands = git_repo_with_remote.executor.calls[first_call:]
    assert next(index for index, call in enumerate(commands) if call[0] == "fetch") < next(
        index for index, call in enumerate(commands) if call[0] == "switch"
    )
    assert next(call for call in commands if call[0] == "fetch") == ("fetch", "origin")


def test_branch_creation_uses_the_current_remote_default_not_a_stale_local_head(git_repo_with_remote: GitRepository) -> None:
    repository = git_repo_with_remote
    remote = Path(repository.git("remote", "get-url", "origin").stdout_text.strip())
    repository.git("switch", "-c", "trunk")
    (repository.root / "trunk.txt").write_text("remote default\n", encoding="ascii")
    repository.git("add", "trunk.txt")
    repository.git("commit", "-m", "advance trunk")
    repository.git("push", "-u", "origin", "trunk")
    repository.executor.run(("--git-dir", str(remote), "symbolic-ref", "HEAD", "refs/heads/trunk"), cwd=repository.root).require_success()
    repository.git("symbolic-ref", "refs/remotes/origin/HEAD", "refs/remotes/origin/main")
    repository.git("switch", "main")

    branch = repository.guard().create_ticket_branch("ENG-42", "Use current remote default")

    assert repository.git("merge-base", branch, "origin/trunk").stdout_text.strip() == repository.git(
        "rev-parse", "origin/trunk"
    ).stdout_text.strip()
    assert repository.git("merge-base", branch, "origin/main").stdout_text.strip() != repository.git(
        "rev-parse", "origin/trunk"
    ).stdout_text.strip()


def test_existing_branch_requires_complete_matching_reuse_binding(git_repo_with_remote: GitRepository) -> None:
    guard = git_repo_with_remote.guard()
    branch = guard.create_ticket_branch("ENG-42", "Add safer retries")
    base = git_repo_with_remote.git("rev-parse", "origin/main").stdout_text.strip()
    binding = BranchBinding(
        ticket_id="ENG-42",
        branch=branch,
        base_sha=base,
        repository_identity=guard.repository_identity(),
        remote_fingerprint=remote_fingerprint(git_repo_with_remote),
        default_branch="main",
        checkpoint_lineage="checkpoint-1",
    )

    assert guard.reconcile_branch(binding, checkpoint_lineage="checkpoint-1") == branch
    with pytest.raises(BranchReuseError):
        guard.reconcile_branch(binding, checkpoint_lineage="checkpoint-2")


def test_branch_binding_rejects_a_branch_not_named_for_its_ticket(git_repo_with_remote: GitRepository) -> None:
    guard = git_repo_with_remote.guard()
    base = git_repo_with_remote.git("rev-parse", "HEAD").stdout_text.strip()

    with pytest.raises(BranchReuseError):
        BranchBinding(
            ticket_id="ENG-42",
            branch="ENG-7-someone-elses-branch",
            base_sha=base,
            repository_identity=guard.repository_identity(),
            remote_fingerprint=remote_fingerprint(git_repo_with_remote),
            default_branch="main",
            checkpoint_lineage="checkpoint-1",
        )


def test_reconcile_branch_rejects_a_changed_remote_default_base(git_repo_with_remote: GitRepository) -> None:
    repository = git_repo_with_remote
    guard = repository.guard()
    branch = guard.create_ticket_branch("ENG-42", "Reject default base drift")
    base = repository.git("rev-parse", "origin/main").stdout_text.strip()
    binding = BranchBinding(
        ticket_id="ENG-42",
        branch=branch,
        base_sha=base,
        repository_identity=guard.repository_identity(),
        remote_fingerprint=remote_fingerprint(repository),
        default_branch="main",
        checkpoint_lineage="checkpoint-1",
    )
    repository.git("switch", "main")
    (repository.root / "main.txt").write_text("advanced\n", encoding="ascii")
    repository.git("add", "main.txt")
    repository.git("commit", "-m", "advance main")
    repository.git("push", "origin", "main")
    repository.git("switch", branch)

    with pytest.raises(BranchReuseError):
        guard.reconcile_branch(binding, checkpoint_lineage="checkpoint-1")


def test_collect_manifest_inputs_preserves_modes_renames_binaries_and_authorized_untracked_files(
    git_repo_with_remote: GitRepository,
) -> None:
    guard = git_repo_with_remote.guard()
    baseline = git_repo_with_remote.git("rev-parse", "HEAD").stdout_text.strip()
    (git_repo_with_remote.root / "old.txt").rename(git_repo_with_remote.root / "new.txt")
    (git_repo_with_remote.root / "script.sh").chmod(0o755)
    (git_repo_with_remote.root / "image.bin").write_bytes(b"\x00\x02")
    (git_repo_with_remote.root / "generated.txt").write_text("generated\n", encoding="ascii")

    manifest = guard.collect_manifest_inputs(baseline, authorized_untracked=("generated.txt",))
    files = {entry.path: entry for entry in manifest.files}

    assert files["new.txt"].old_path == "old.txt"
    assert files["script.sh"].new_mode == "100755"
    assert files["image.bin"].binary is True
    assert files["generated.txt"].untracked is True
    assert files["generated.txt"].object_id == git_repo_with_remote.git(
        "hash-object", "--no-filters", "--", "generated.txt"
    ).stdout_text.strip()


def test_collect_manifest_inputs_uses_trusted_full_output_when_public_evidence_is_capped(
    git_repo_with_remote: GitRepository,
) -> None:
    executor = CappedGitExecutor()
    guard = GitGuard(
        git_repo_with_remote.root,
        executor=executor,
        remote="origin",
        protected_paths=(".env", ".auto-code"),
        commit_excluded_paths=("run-local",),
    )
    baseline = git_repo_with_remote.git("rev-parse", "HEAD").stdout_text.strip()
    paths = tuple(f"generated-{index:04d}-long-manifest-entry.txt" for index in range(500))
    for path in paths:
        (git_repo_with_remote.root / path).write_text("generated\n", encoding="ascii")

    manifest = guard.collect_manifest_inputs(baseline, authorized_untracked=paths)

    assert manifest.authorized_untracked_paths == paths
    assert executor.reader_calls > 0
    assert any(result.stdout_text.endswith("[TRUNCATED]") for result in executor.public_results)


def test_collect_manifest_inputs_rejects_untracked_or_commit_excluded_paths(git_repo_with_remote: GitRepository) -> None:
    guard = git_repo_with_remote.guard()
    baseline = git_repo_with_remote.git("rev-parse", "HEAD").stdout_text.strip()
    (git_repo_with_remote.root / "unapproved.txt").write_text("no\n", encoding="ascii")

    with pytest.raises(UnauthorizedUntrackedPathError):
        guard.collect_manifest_inputs(baseline)

    (git_repo_with_remote.root / "unapproved.txt").unlink()
    run_local = git_repo_with_remote.root / "run-local"
    run_local.mkdir()
    (run_local / "state.json").write_text("{}", encoding="ascii")
    with pytest.raises(CommitExcludedPathError):
        guard.collect_manifest_inputs(baseline, authorized_untracked=("run-local/state.json",))


def test_commit_manifest_refuses_drift_outside_the_approved_manifest(git_repo_with_remote: GitRepository) -> None:
    guard = git_repo_with_remote.guard()
    guard.create_ticket_branch("ENG-42", "Add safer retries")
    baseline = git_repo_with_remote.git("rev-parse", "HEAD").stdout_text.strip()
    (git_repo_with_remote.root / "old.txt").write_text("approved\n", encoding="ascii")
    manifest = guard.collect_manifest_inputs(baseline)
    (git_repo_with_remote.root / "script.sh").write_text("#!/bin/sh\necho unrelated\n", encoding="ascii")
    git_repo_with_remote.git("add", "script.sh")
    before_head = git_repo_with_remote.git("rev-parse", "HEAD").stdout_text.strip()

    with pytest.raises(ManifestMismatchError):
        guard.commit_manifest(manifest, "Commit approved files")

    assert git_repo_with_remote.git("rev-parse", "HEAD").stdout_text.strip() == before_head
    assert git_repo_with_remote.git("diff", "--cached", "--name-only").stdout_text.strip() == "script.sh"


def test_commit_and_push_are_limited_to_the_approved_manifest(git_repo_with_remote: GitRepository) -> None:
    guard = git_repo_with_remote.guard()
    branch = guard.create_ticket_branch("ENG-42", "Add safer retries")
    baseline = git_repo_with_remote.git("rev-parse", "HEAD").stdout_text.strip()
    (git_repo_with_remote.root / "old.txt").write_text("approved\n", encoding="ascii")
    manifest = guard.collect_manifest_inputs(baseline)

    commit = guard.commit_manifest(manifest, "Commit approved files")
    pushed = guard.push()
    remote = git_repo_with_remote.git("ls-remote", "--heads", "origin", f"refs/heads/{branch}").stdout_text.split()[0]

    assert commit == git_repo_with_remote.git("rev-parse", "HEAD").stdout_text.strip()
    assert pushed == commit == remote
    assert all("--force" not in call and "-f" not in call for call in git_repo_with_remote.executor.calls)


def test_push_rejects_a_changed_remote_url_before_publishing_the_ticket_branch(
    git_repo_with_remote: GitRepository, tmp_path: Path
) -> None:
    repository = git_repo_with_remote
    guard = repository.guard()
    branch = guard.create_ticket_branch("ENG-42", "Reject remote URL drift")
    baseline = repository.git("rev-parse", "HEAD").stdout_text.strip()
    (repository.root / "old.txt").write_text("approved\n", encoding="ascii")
    manifest = guard.collect_manifest_inputs(baseline)
    guard.commit_manifest(manifest, "Commit approved files")

    alternate = tmp_path / "alternate.git"
    alternate.mkdir()
    repository.executor.run(("init", "--bare", str(alternate)), cwd=tmp_path).require_success()
    repository.git("push", str(alternate), "main:main")
    repository.executor.run(("--git-dir", str(alternate), "symbolic-ref", "HEAD", "refs/heads/main"), cwd=tmp_path).require_success()
    repository.git("remote", "set-url", "origin", str(alternate))

    with pytest.raises(PushNotAuthorizedError):
        guard.push()

    pushed = repository.executor.run(
        ("--git-dir", str(alternate), "show-ref", "--verify", "--quiet", f"refs/heads/{branch}"), cwd=tmp_path
    )
    assert pushed.returncode != 0
