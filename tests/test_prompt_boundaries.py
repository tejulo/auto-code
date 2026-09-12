from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path

from crewai.tools.base_tool import BaseTool
from crewai.tools import ToolFailurePolicy
from crewai.utilities.agent_utils import convert_tools_to_openai_schema
from pydantic import ValidationError
import pytest

from auto_code.contracts import BrowserE2EDecision, BrowserScenario, BuildIdentity, Stage
from auto_code.crew import UnitContext, build_prompt
from auto_code.read_tools import HashedReadFile, HashedReadManifest, HashedReadTool, ReadAccessDenied
from auto_code.tool_broker import ToolAccessDenied, ToolBroker, ToolManifest


class NamedTool(BaseTool):
    name: str
    description: str = "Test-only bounded tool."
    max_usage_count: int | None = 2

    def _run(self) -> str:
        return "ok"


@dataclass(frozen=True)
class FakeProgrammerTools:
    tools: tuple[BaseTool, ...]

    def for_manifest(self, manifest: ToolManifest) -> tuple[BaseTool, ...]:
        return self.tools


@dataclass(frozen=True)
class FakePlaywrightTools:
    tools: tuple[BaseTool, ...]

    def for_manifest(self, manifest: ToolManifest) -> tuple[BaseTool, ...]:
        return self.tools


def hashed_file(path: Path, relative_path: str) -> HashedReadFile:
    return HashedReadFile(
        relative_path=relative_path,
        sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
    )


def manifest_for_paths(*paths: str, digest: str = "a" * 64) -> ToolManifest:
    return ToolManifest(
        read_manifest=HashedReadManifest(
            files=tuple(HashedReadFile(relative_path=path, sha256=digest) for path in paths),
        )
    )


def tool_names(tools: tuple[BaseTool, ...]) -> set[str]:
    return {tool.name for tool in tools}


def test_hashed_read_tool_reads_only_the_explicit_hash_bound_manifest(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    document = root / "docs" / "approved.md"
    document.parent.mkdir(parents=True)
    document.write_text("approved content\n", encoding="utf-8")
    tool = HashedReadTool(
        root=root,
        manifest=HashedReadManifest(files=(hashed_file(document, "docs/approved.md"),)),
        max_bytes=1024,
    )

    assert tool.read("docs/approved.md") == "approved content\n"
    with pytest.raises(ReadAccessDenied, match="not allowlisted"):
        tool.read("docs/missing.md")


def test_hashed_read_tool_rejects_symlink_escapes_and_oversize_files(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    linked = root / "linked.txt"
    os.symlink(outside, linked)
    oversized = root / "large.txt"
    oversized.write_text("x" * 33, encoding="utf-8")
    tool = HashedReadTool(
        root=root,
        manifest=HashedReadManifest(
            files=(hashed_file(linked, "linked.txt"), hashed_file(oversized, "large.txt")),
        ),
        max_bytes=32,
    )

    with pytest.raises(ReadAccessDenied, match="symlink"):
        tool.read("linked.txt")
    with pytest.raises(ReadAccessDenied, match="size"):
        tool.read("large.txt")


def test_hashed_read_tool_rejects_a_listed_file_when_its_content_hash_changes(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    document = root / "docs" / "approved.md"
    document.parent.mkdir(parents=True)
    document.write_text("approved content\n", encoding="utf-8")
    manifest = HashedReadManifest(files=(hashed_file(document, "docs/approved.md"),))
    document.write_text("changed content\n", encoding="utf-8")

    with pytest.raises(ReadAccessDenied, match="hash"):
        HashedReadTool(root=root, manifest=manifest, max_bytes=1024).read("docs/approved.md")


def test_hashed_read_tool_keeps_the_opened_descriptor_when_the_path_is_replaced(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repository"
    document = root / "docs" / "approved.md"
    replacement = tmp_path / "replacement.md"
    document.parent.mkdir(parents=True)
    document.write_text("approved content\n", encoding="utf-8")
    replacement.write_text("replacement content\n", encoding="utf-8")
    tool = HashedReadTool(
        root=root,
        manifest=HashedReadManifest(files=(hashed_file(document, "docs/approved.md"),)),
        max_bytes=1024,
    )
    original_open = os.open
    replaced = False

    def replace_after_open(
        path: str | bytes | os.PathLike[str],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal replaced
        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        if path == "approved.md" and dir_fd is not None and not replaced:
            os.replace(replacement, document)
            replaced = True
        return descriptor

    monkeypatch.setattr(os, "open", replace_after_open)

    assert tool.read("docs/approved.md") == "approved content\n"
    assert replaced is True


def test_hashed_read_tool_fails_closed_for_a_symlinked_denied_root(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    document = root / "approved.md"
    document.write_text("approved content\n", encoding="utf-8")
    state_root = tmp_path / "state"
    state_root.mkdir()
    denied_link = tmp_path / "state-link"
    os.symlink(state_root, denied_link)

    with pytest.raises(ValueError, match="Denied root"):
        HashedReadTool(
            root=root,
            manifest=HashedReadManifest(files=(hashed_file(document, "approved.md"),)),
            denied_roots=(denied_link,),
        )


def test_hashed_read_tool_forbids_extra_configuration(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()

    with pytest.raises(ValidationError, match="Extra"):
        HashedReadTool(root=root, manifest=HashedReadManifest(files=()), unbounded=True)


def test_hashed_read_tool_renders_an_explicit_crewai_input_schema(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    tool = HashedReadTool(root=root, manifest=HashedReadManifest(files=()))

    schema = tool.args_schema.model_json_schema()
    rendered, _, _ = convert_tools_to_openai_schema([tool])

    assert schema["additionalProperties"] is False
    assert schema["properties"]["path"]["maxLength"] == 512
    assert schema["required"] == ["path"]
    assert rendered[0]["function"]["parameters"]["properties"]["path"]["maxLength"] == 512


def test_architect_requires_openspec_instructions_path() -> None:
    with pytest.raises(ValueError, match="OpenSpec instructions"):
        build_prompt(
            Stage.ARCHITECT_DESIGN,
            UnitContext(requirements_path="requirements.json", dependency_paths=("proposal.md",)),
        )


@pytest.mark.parametrize(
    ("stage", "outline_path", "dependency_paths", "expected_paths"),
    (
        (Stage.ARCHITECT_OUTLINE, None, (), ("requirements.json", "openspec.md")),
        (Stage.ARCHITECT_PROPOSAL, "outline.json", (), ("requirements.json", "openspec.md", "outline.json")),
        (Stage.ARCHITECT_SPECS, None, ("proposal.md",), ("requirements.json", "openspec.md", "proposal.md")),
        (Stage.ARCHITECT_DESIGN, None, ("proposal.md",), ("requirements.json", "openspec.md", "proposal.md")),
        (
            Stage.ARCHITECT_TASKS,
            None,
            ("specs.md", "design.md"),
            ("requirements.json", "openspec.md", "specs.md", "design.md"),
        ),
        (Stage.REVIEWER, None, ("review-manifest.json",), ("review-manifest.json",)),
    ),
)
def test_hashed_read_manifest_matches_only_stage_prompt_paths(
    tmp_path: Path,
    stage: Stage,
    outline_path: str | None,
    dependency_paths: tuple[str, ...],
    expected_paths: tuple[str, ...],
) -> None:
    digest = "a" * 64
    context_kwargs: dict[str, object] = {
        "dependency_paths": dependency_paths,
        "tool_manifest": manifest_for_paths(*expected_paths, digest=digest),
    }
    if stage is Stage.REVIEWER:
        context_kwargs["review_manifest_hash"] = digest
    else:
        context_kwargs.update(
            requirements_path="requirements.json",
            openspec_instructions_path="openspec.md",
            outline_path=outline_path,
        )
    context = UnitContext(**context_kwargs)
    extra_context = UnitContext(
        **{**context_kwargs, "tool_manifest": manifest_for_paths(*expected_paths, "unrelated.json", digest=digest)}
    )

    prompt = build_prompt(stage, context)
    assert all(path in prompt for path in expected_paths)
    with pytest.raises(ValueError, match="read manifest"):
        build_prompt(stage, extra_context)

    root = tmp_path / "repository"
    root.mkdir()
    with pytest.raises(ToolAccessDenied, match="read manifest"):
        ToolBroker(repository_root=root).for_stage(
            stage,
            extra_context.tool_manifest,
            expected_read_paths=expected_paths,
        )


def test_tool_broker_enforces_effective_role_access_and_exact_tool_sets(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    architect_context = UnitContext(
        requirements_path="requirements.json",
        openspec_instructions_path="openspec.md",
        dependency_paths=("proposal.md",),
        tool_manifest=manifest_for_paths("requirements.json", "openspec.md", "proposal.md"),
    )
    reviewer_context = UnitContext(
        dependency_paths=("review-manifest.json",),
        review_manifest_hash="a" * 64,
        tool_manifest=manifest_for_paths("review-manifest.json"),
    )
    manifest = ToolManifest()
    broker = ToolBroker(
        repository_root=root,
        programmer_tools=FakeProgrammerTools(
            (
                NamedTool(name="read_repo"),
                NamedTool(name="write_repo"),
                NamedTool(name="search_repo"),
                NamedTool(name="run_authorized"),
            )
        ),
        playwright_tools=FakePlaywrightTools((NamedTool(name="playwright"),)),
    )

    assert broker.for_stage(Stage.ANALYST, manifest) == ()
    assert tool_names(
        broker.for_stage(
            Stage.ARCHITECT_DESIGN,
            architect_context.tool_manifest,
            expected_read_paths=("requirements.json", "openspec.md", "proposal.md"),
        )
    ) == {"read_hashed"}
    assert tuple(tool.name for tool in broker.for_stage(Stage.PROGRAMMER, manifest)) == (
        "read_repo",
        "write_repo",
        "search_repo",
        "run_authorized",
    )
    assert tool_names(broker.for_stage(Stage.TESTER, manifest)) == {"playwright"}
    assert tool_names(
        broker.for_stage(
            Stage.REVIEWER,
            reviewer_context.tool_manifest,
            expected_read_paths=("review-manifest.json",),
        )
    ) == {"read_hashed"}


def test_tool_broker_returns_only_tools_with_finite_two_call_native_usage_limits(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    broker = ToolBroker(
        repository_root=root,
        programmer_tools=FakeProgrammerTools(
            (
                NamedTool(name="read_repo"),
                NamedTool(name="write_repo"),
                NamedTool(name="search_repo"),
                NamedTool(name="run_authorized"),
            )
        ),
        playwright_tools=FakePlaywrightTools((NamedTool(name="playwright"),)),
    )
    architect_tools = broker.for_stage(
        Stage.ARCHITECT_OUTLINE,
        manifest_for_paths("requirements.json", "openspec.md"),
        expected_read_paths=("requirements.json", "openspec.md"),
    )
    programmer_tools = broker.for_stage(Stage.PROGRAMMER, ToolManifest())
    tester_tools = broker.for_stage(Stage.TESTER, ToolManifest())

    assert all(
        isinstance(tool.max_usage_count, int)
        and not isinstance(tool.max_usage_count, bool)
        and 0 < tool.max_usage_count <= 2
        for tool in (*architect_tools, *programmer_tools, *tester_tools)
    )


@pytest.mark.parametrize(("stage", "limit"), ((Stage.PROGRAMMER, None), (Stage.PROGRAMMER, 3), (Stage.TESTER, None), (Stage.TESTER, 3)))
def test_tool_broker_rejects_injected_native_usage_limits_outside_the_two_call_bound(
    tmp_path: Path,
    stage: Stage,
    limit: int | None,
) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    if stage is Stage.PROGRAMMER:
        broker = ToolBroker(
            repository_root=root,
            programmer_tools=FakeProgrammerTools(
                (
                    NamedTool(name="read_repo", max_usage_count=limit),
                    NamedTool(name="write_repo", max_usage_count=limit),
                    NamedTool(name="search_repo", max_usage_count=limit),
                    NamedTool(name="run_authorized", max_usage_count=limit),
                )
            ),
        )
    else:
        broker = ToolBroker(
            repository_root=root,
            playwright_tools=FakePlaywrightTools((NamedTool(name="playwright", max_usage_count=limit),)),
        )

    with pytest.raises(ToolAccessDenied, match="usage limit"):
        broker.for_stage(stage, ToolManifest())


def test_tool_broker_rejects_state_root_secret_paths_and_mismatched_injected_tools(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    state_root = root / "state"
    state_root.mkdir(parents=True)
    state_file = state_root / "current.json"
    state_file.write_text("private", encoding="utf-8")
    secret_file = root / "secrets" / "provider-key.txt"
    secret_file.parent.mkdir()
    secret_file.write_text("OPENCODE_API_KEY=secret", encoding="utf-8")
    state_manifest = ToolManifest(read_manifest=HashedReadManifest(files=(hashed_file(state_file, "state/current.json"),)))
    secret_manifest = ToolManifest(
        read_manifest=HashedReadManifest(files=(hashed_file(secret_file, "secrets/provider-key.txt"),))
    )
    invalid_programmer = FakeProgrammerTools((NamedTool(name="read_repo"),))
    broker = ToolBroker(
        repository_root=root,
        state_root=state_root,
        programmer_tools=invalid_programmer,
        playwright_tools=FakePlaywrightTools((NamedTool(name="playwright"),)),
    )

    with pytest.raises(ToolAccessDenied, match="state root"):
        broker.for_stage(Stage.ARCHITECT_DESIGN, state_manifest, expected_read_paths=("state/current.json",))
    with pytest.raises(ToolAccessDenied, match="secret"):
        broker.for_stage(Stage.REVIEWER, secret_manifest, expected_read_paths=("secrets/provider-key.txt",))
    with pytest.raises(ToolAccessDenied, match="exact"):
        broker.for_stage(Stage.PROGRAMMER, ToolManifest())
    with pytest.raises(ToolAccessDenied, match="cognitive"):
        broker.for_stage(Stage.VERIFICATION, ToolManifest())


@pytest.mark.parametrize("policy", (ToolFailurePolicy.WARN, ToolFailurePolicy.IGNORE))
def test_tool_broker_rejects_an_injected_tool_policy_lower_than_raise(
    tmp_path: Path,
    policy: ToolFailurePolicy,
) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    broker = ToolBroker(
        repository_root=root,
        playwright_tools=FakePlaywrightTools((NamedTool(name="playwright", tool_failure_policy=policy),)),
    )

    with pytest.raises(ToolAccessDenied, match="failure policy"):
        broker.for_stage(Stage.TESTER, ToolManifest())


def test_architect_design_receives_only_direct_dependencies() -> None:
    context = UnitContext(
        ticket_snapshot="forbidden ticket body",
        requirements_path="requirements.json",
        outline_path="outline.json",
        dependency_paths=("proposal.md",),
        latest_failure_path=None,
        openspec_instructions_path="openspec.md",
        tool_manifest=manifest_for_paths("requirements.json", "openspec.md", "proposal.md"),
    )

    prompt = build_prompt(Stage.ARCHITECT_DESIGN, context)

    assert "requirements.json" in prompt
    assert "openspec.md" in prompt
    assert "proposal.md" in prompt
    assert "forbidden ticket body" not in prompt
    assert "outline.json" not in prompt


def test_programmer_gets_the_latest_failure_without_ticket_snapshot_or_unbounded_context() -> None:
    context = UnitContext(
        ticket_snapshot="forbidden ticket body",
        requirements_path="requirements.json",
        outline_path=None,
        dependency_paths=("proposal.md", "specs/feature.md", "design.md", "tasks.md"),
        latest_failure_path="failure-3.json",
        task_definition_path="task-definition.json",
        task_definition_hash="a" * 64,
        task_status_path="task-status.json",
        task_status_hash="b" * 64,
        known_task_ids=("1.1", "1.2"),
    )

    prompt = build_prompt(Stage.PROGRAMMER, context)

    assert "failure-3.json" in prompt
    assert "proposal.md" in prompt
    assert "task-definition.json" in prompt
    assert "task-status.json" in prompt
    assert "1.1" in prompt
    assert "forbidden ticket body" not in prompt


def test_tester_prompt_includes_only_the_declared_latest_failure_path() -> None:
    prompt = build_prompt(
        Stage.TESTER,
        UnitContext(
            dependency_paths=("browser-decision.json", "build-identity.json"),
            latest_failure_path="evidence/failures/latest.json",
        ),
    )

    assert "Latest failure evidence: evidence/failures/latest.json" in prompt
    assert "evidence/failures/earlier.json" not in prompt


def test_tester_prompt_exposes_each_declared_browser_scenario_without_new_read_paths() -> None:
    decision = BrowserE2EDecision(
        required=True,
        reason="The browser flow changed.",
        scenarios=(
            BrowserScenario(
                scenario_id="BROWSER-1",
                description="Open the profile form.",
                expected_result="The profile form is visible.",
            ),
            BrowserScenario(
                scenario_id="BROWSER-2",
                description="Submit the saved profile.",
                expected_result="A saved confirmation is visible.",
            ),
        ),
    )
    build = BuildIdentity(
        baseline_sha="a" * 40,
        product_manifest_hash="b" * 64,
        project_policy_hash="c" * 64,
        command_hashes={"pytest": "d" * 64},
        runtime_hash="e" * 64,
    )

    context = UnitContext.for_browser_tester(decision, build, "run-1")
    prompt = build_prompt(Stage.TESTER, context)

    assert "BROWSER-1: Open the profile form. Expected result: The profile form is visible." in prompt
    assert "BROWSER-2: Submit the saved profile. Expected result: A saved confirmation is visible." in prompt
    assert "browser-decision.json" in prompt
    assert "build-identity.json" in prompt


def test_reviewer_prompt_hash_binds_the_declared_latest_failure_path() -> None:
    latest_failure = "evidence/failures/latest.json"
    context = UnitContext(
        dependency_paths=("review-manifest.json",),
        latest_failure_path=latest_failure,
        review_manifest_hash="a" * 64,
        tool_manifest=manifest_for_paths("review-manifest.json", latest_failure),
    )

    prompt = build_prompt(Stage.REVIEWER, context)

    assert "Latest failure evidence: evidence/failures/latest.json" in prompt
    assert "evidence/failures/earlier.json" not in prompt
    with pytest.raises(ValueError, match="read manifest"):
        build_prompt(
            Stage.REVIEWER,
            UnitContext(
                dependency_paths=("review-manifest.json",),
                latest_failure_path=latest_failure,
                review_manifest_hash="a" * 64,
                tool_manifest=manifest_for_paths("review-manifest.json"),
            ),
        )


def test_programmer_requires_task_manifest_context() -> None:
    with pytest.raises(ValueError, match="Task Definition"):
        build_prompt(
            Stage.PROGRAMMER,
            UnitContext(
                requirements_path="requirements.json",
                dependency_paths=("proposal.md", "specs.md", "design.md", "tasks.md"),
            ),
        )


def test_prompt_rejects_non_direct_dependencies_and_unapproved_tool_claims() -> None:
    with pytest.raises(ValueError, match="direct dependencies"):
        build_prompt(
            Stage.ARCHITECT_DESIGN,
            UnitContext(
                requirements_path="requirements.json",
                openspec_instructions_path="openspec.md",
                dependency_paths=("proposal.md", "specs.md"),
            ),
        )
    with pytest.raises(ValueError, match="tool"):
        build_prompt(
            Stage.ANALYST,
            UnitContext(ticket_snapshot="ticket", tool_names=("read_hashed",)),
        )
    with pytest.raises(ValueError, match="deterministic"):
        build_prompt(Stage.VERIFICATION, UnitContext())
