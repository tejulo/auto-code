from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path

import pytest

from auto_code.contracts import Stage
from auto_code.process import CommandResult
import auto_code.programmer_tools as programmer_tools
from auto_code.programmer_tools import (
    MAX_REPO_READ_BYTES,
    MAX_SEARCH_LINE_CHARS,
    MAX_SEARCH_MATCHES,
    ProgrammerTools,
    ProtectedPathError,
    RepoToolPolicy,
)
from auto_code.project_config import (
    AutomationPolicy,
    BrowserPolicy,
    CatalogPreflightPolicy,
    FinalizationPolicy,
    GitPolicy,
    LinearPolicy,
    ProcessPolicy,
    ProjectConfig,
    ReviewPolicy,
    TransportPolicy,
    VerificationPolicy,
)
from auto_code.tool_broker import ToolBroker, ToolManifest


@dataclass
class RecordingProcess:
    argvs: list[tuple[str, ...]] = field(default_factory=list)

    def run(
        self,
        argv: tuple[str, ...],
        cwd: Path,
        timeout: float,
        evidence_sink: object,
        environment: dict[str, str],
        sandbox_policy: object,
    ) -> CommandResult:
        del cwd, timeout, evidence_sink, environment, sandbox_policy
        self.argvs.append(argv)
        raise AssertionError("The fake process result is not needed by this test")


def config() -> ProjectConfig:
    return ProjectConfig(
        git=GitPolicy(remote="origin", base_branch=None),
        verification=VerificationPolicy(commands=(("/bin/true",),)),
        browser=BrowserPolicy(
            start_command=None,
            base_url=None,
            ready_timeout_seconds=1,
            command_timeout_seconds=1,
            playwright_command_prefix=("/bin/true",),
            allowed_operations=(),
        ),
        process=ProcessPolicy(command_timeout_seconds=1, termination_grace_seconds=1),
        transport=TransportPolicy(total_retry_wait_seconds=0),
        preflight=CatalogPreflightPolicy(
            catalog_timeout_seconds=1,
            max_catalog_response_bytes=1024,
            catalog_retry_budget=0,
            catalog_cache_validity_seconds=1,
        ),
        finalization=FinalizationPolicy(max_invocations_per_effect=1, total_retry_wait_seconds=0),
        automation=AutomationPolicy(regression_command=("/bin/true",)),
        protected_paths=(".env", ".auto-code", ".git"),
        commit_excluded_paths=(".superpowers",),
        writable_roots=("src",),
        environment_allowlist=(),
        linear=LinearPolicy(started_state_id=None, completed_state_id=None),
        review=ReviewPolicy(),
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    root = tmp_path / "repository"
    root.mkdir()
    return root


def test_repo_policy_rejects_escape_protected_symlink_and_non_regular_paths(repo: Path) -> None:
    state = repo.parent / "launcher-state"
    state.mkdir()
    (state / "current.json").write_text("secret", encoding="ascii")
    (repo / "link").symlink_to(state / "current.json")
    os.mkfifo(repo / "fifo")
    policy = RepoToolPolicy(repo, writable_roots=("src",), protected_paths=(".env", ".auto-code", ".git"))

    for path in ("../launcher-state/current.json", ".env", "link", "fifo"):
        with pytest.raises(ProtectedPathError):
            policy.open_read(path)


def test_repo_policy_writes_only_under_configured_roots_and_searches_sorted_matches(repo: Path) -> None:
    policy = RepoToolPolicy(repo, writable_roots=("src",), protected_paths=(".env", ".auto-code", ".git"))
    (repo / "src").mkdir()

    policy.atomic_write("src/z.py", b"one needle\n")
    policy.atomic_write("src/a.py", b"needle\nneedle\n")

    assert (repo / "src" / "a.py").read_bytes() == b"needle\nneedle\n"
    assert tuple((match.relative_path, match.line_number) for match in policy.search("src", "needle")) == (
        ("src/a.py", 1),
        ("src/a.py", 2),
        ("src/z.py", 1),
    )
    with pytest.raises(ProtectedPathError):
        policy.atomic_write("notes.txt", b"outside writable root")
    with pytest.raises(ProtectedPathError):
        policy.atomic_write(".env", b"secret")


def test_repo_policy_denies_commit_excluded_paths_that_overlap_writable_roots(repo: Path) -> None:
    source = repo / "src"
    source.mkdir()
    project_config = config().model_copy(update={"commit_excluded_paths": ("src",)})
    policy = RepoToolPolicy(
        repo,
        writable_roots=project_config.writable_roots,
        protected_paths=project_config.protected_paths,
        commit_excluded_paths=project_config.commit_excluded_paths,
    )
    write_tool = ProgrammerTools(
        policy,
        project_config,
        RecordingProcess(),
        evidence_sink=object(),
        sandbox_policy=object(),
        environment={},
        timeout=1,
    ).for_manifest(ToolManifest())[1]

    with pytest.raises(ProtectedPathError):
        write_tool._run(path="src/generated.py", content="denied")


def test_repo_policy_rejects_symlinked_and_non_regular_write_targets(repo: Path) -> None:
    source = repo / "src"
    source.mkdir()
    outside = repo.parent / "outside.py"
    outside.write_text("safe", encoding="ascii")
    (source / "linked.py").symlink_to(outside)
    os.mkfifo(source / "pipe.py")
    policy = RepoToolPolicy(
        repo,
        writable_roots=("src",),
        protected_paths=(".env", ".auto-code", ".git"),
        commit_excluded_paths=config().commit_excluded_paths,
    )

    for path in ("src/linked.py", "src/pipe.py"):
        with pytest.raises(ProtectedPathError):
            policy.atomic_write(path, b"replacement")

    assert outside.read_text(encoding="ascii") == "safe"


def test_repo_policy_retains_the_opened_root_after_its_path_is_replaced(repo: Path) -> None:
    source = repo / "src"
    source.mkdir()
    (source / "existing.py").write_text("pinned", encoding="ascii")
    policy = RepoToolPolicy(repo, writable_roots=("src",), protected_paths=(".env", ".auto-code", ".git"))
    pinned_root = repo.parent / "pinned-repository"
    repo.rename(pinned_root)
    repo.mkdir()
    replacement_source = repo / "src"
    replacement_source.mkdir()
    (replacement_source / "existing.py").write_text("replacement", encoding="ascii")

    with policy.open_read("src/existing.py") as content:
        assert content.read() == b"pinned"
    policy.atomic_write("src/new.py", b"pinned write")

    assert (pinned_root / "src" / "new.py").read_bytes() == b"pinned write"
    assert not (replacement_source / "new.py").exists()
    policy.close()


def test_repo_tools_cap_read_and_search_results(repo: Path) -> None:
    source = repo / "src"
    source.mkdir()
    (source / "large.txt").write_bytes(b"x" * (MAX_REPO_READ_BYTES + 1))
    (source / "matches.txt").write_text(
        "".join(f"needle {'x' * (MAX_SEARCH_LINE_CHARS + 1)}\n" for _ in range(MAX_SEARCH_MATCHES + 2)),
        encoding="ascii",
    )
    policy = RepoToolPolicy(
        repo,
        writable_roots=("src",),
        protected_paths=(".env", ".auto-code", ".git"),
        commit_excluded_paths=config().commit_excluded_paths,
    )
    read_tool = ProgrammerTools(
        policy,
        config(),
        RecordingProcess(),
        evidence_sink=object(),
        sandbox_policy=object(),
        environment={},
        timeout=1,
    ).for_manifest(ToolManifest())[0]

    assert len(read_tool._run(path="src/large.txt")) <= MAX_REPO_READ_BYTES
    matches = policy.search("src", "needle")
    assert len(matches) == MAX_SEARCH_MATCHES
    assert all(len(match.text) <= MAX_SEARCH_LINE_CHARS for match in matches)


def test_repo_policy_closes_its_retained_root_descriptor(repo: Path) -> None:
    document = repo / "document.txt"
    document.write_text("content", encoding="ascii")
    policy = RepoToolPolicy(repo, writable_roots=("src",), protected_paths=(".env", ".auto-code", ".git"))

    policy.close()

    with pytest.raises(ProtectedPathError):
        policy.open_read("document.txt")


def test_repo_policy_fsyncs_atomic_writes_and_removes_temporary_files_on_failure(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = repo / "src"
    source.mkdir()
    policy = RepoToolPolicy(repo, writable_roots=("src",), protected_paths=(".env", ".auto-code", ".git"))
    fsync_calls: list[int] = []
    real_fsync = os.fsync

    def record_fsync(descriptor: int) -> None:
        fsync_calls.append(descriptor)
        real_fsync(descriptor)

    monkeypatch.setattr(programmer_tools.os, "fsync", record_fsync)
    policy.atomic_write("src/persisted.py", b"persisted")

    def fail_replace(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise OSError("replace failed")

    monkeypatch.setattr(programmer_tools.os, "replace", fail_replace)
    with pytest.raises(ProtectedPathError):
        policy.atomic_write("src/failed.py", b"failed")

    assert len(fsync_calls) == 3
    assert not tuple(source.glob(".failed.py.*.tmp"))


def test_programmer_tools_expose_only_fixed_tools_and_configured_indexes(repo: Path) -> None:
    project_config = config()
    process = RecordingProcess()
    policy = RepoToolPolicy(
        repo,
        writable_roots=project_config.writable_roots,
        protected_paths=project_config.protected_paths,
        commit_excluded_paths=project_config.commit_excluded_paths,
    )
    programmer_tools = ProgrammerTools(
        policy,
        project_config,
        process,
        evidence_sink=object(),
        sandbox_policy=object(),
        environment={},
        timeout=1,
    )
    broker = ToolBroker(repository_root=repo, programmer_tools=programmer_tools)

    tools = programmer_tools.for_manifest(ToolManifest())

    assert tuple(tool.name for tool in tools) == ("read_repo", "write_repo", "search_repo", "run_authorized")
    assert tuple(tool.name for tool in broker.for_stage(Stage.PROGRAMMER, ToolManifest())) == (
        "read_repo",
        "write_repo",
        "search_repo",
        "run_authorized",
    )
    with pytest.raises(AssertionError, match="not needed"):
        tools[3]._run(index=0)
    assert process.argvs == [project_config.verification.commands[0]]
