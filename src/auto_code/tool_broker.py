from __future__ import annotations

from collections.abc import Mapping
import os
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Protocol

from crewai.tools import ToolFailurePolicy
from crewai.tools.base_tool import BaseTool
from pydantic import Field

from .contracts import ContractModel, Stage
from .model_config import RoleName
from .read_tools import DEFAULT_MAX_READ_BYTES, HashedReadManifest, HashedReadTool

if TYPE_CHECKING:
    from .crew import UnitContext


class ToolAccessDenied(PermissionError):
    """The requested stage or injected tool set exceeds its capability boundary."""


MAX_NATIVE_TOOL_CALLS = 2


class ProgrammerTools(Protocol):
    """Plan 03 supplies the sandboxed repository and command tool adapters."""

    def for_manifest(self, manifest: ToolManifest) -> tuple[BaseTool, ...]: ...


class PlaywrightTools(Protocol):
    """Plan 03 supplies the localhost-only Playwright wrapper."""

    def for_manifest(self, manifest: ToolManifest) -> tuple[BaseTool, ...]: ...


class ToolManifest(ContractModel):
    read_manifest: HashedReadManifest = Field(default_factory=lambda: HashedReadManifest(files=()))


_ROLE_STAGE: Mapping[RoleName, Stage] = MappingProxyType(
    {
        RoleName.ANALYST: Stage.ANALYST,
        RoleName.ARCHITECT: Stage.ARCHITECT_OUTLINE,
        RoleName.PROGRAMMER: Stage.PROGRAMMER,
        RoleName.TESTER: Stage.TESTER,
        RoleName.REVIEWER: Stage.REVIEWER,
    }
)


class RoleCapabilityMatrix:
    _REQUIRED: Mapping[Stage, frozenset[str]] = {
        Stage.ANALYST: frozenset({"structured_output", "text"}),
        Stage.ARCHITECT_OUTLINE: frozenset({"structured_output", "text", "tool_calling"}),
        Stage.ARCHITECT_PROPOSAL: frozenset({"structured_output", "text", "tool_calling"}),
        Stage.ARCHITECT_SPECS: frozenset({"structured_output", "text", "tool_calling"}),
        Stage.ARCHITECT_DESIGN: frozenset({"structured_output", "text", "tool_calling"}),
        Stage.ARCHITECT_TASKS: frozenset({"structured_output", "text", "tool_calling"}),
        Stage.PROGRAMMER: frozenset({"structured_output", "text", "tool_calling"}),
        Stage.VERIFICATION: frozenset(),
        Stage.TESTER: frozenset({"structured_output", "text", "tool_calling"}),
        Stage.REVIEWER: frozenset({"structured_output", "text", "tool_calling"}),
    }

    @classmethod
    def required(cls, stage: Stage) -> frozenset[str]:
        if not isinstance(stage, Stage):
            raise ValueError("Capabilities require a canonical stage")
        return cls._REQUIRED[stage]

    @classmethod
    def required_for_role(cls, role: RoleName) -> frozenset[str]:
        if not isinstance(role, RoleName):
            raise ValueError("Capabilities require a canonical role")
        return cls.required(_ROLE_STAGE[role])


_READ_STAGES = frozenset(
    {
        Stage.ARCHITECT_OUTLINE,
        Stage.ARCHITECT_PROPOSAL,
        Stage.ARCHITECT_SPECS,
        Stage.ARCHITECT_DESIGN,
        Stage.ARCHITECT_TASKS,
        Stage.REVIEWER,
    }
)
_ARCHITECT_READ_STAGES = _READ_STAGES.difference({Stage.REVIEWER})
_EXPECTED_TOOL_NAMES: Mapping[Stage, frozenset[str]] = {
    Stage.ANALYST: frozenset(),
    Stage.ARCHITECT_OUTLINE: frozenset({"read_hashed"}),
    Stage.ARCHITECT_PROPOSAL: frozenset({"read_hashed"}),
    Stage.ARCHITECT_SPECS: frozenset({"read_hashed"}),
    Stage.ARCHITECT_DESIGN: frozenset({"read_hashed"}),
    Stage.ARCHITECT_TASKS: frozenset({"read_hashed"}),
    Stage.PROGRAMMER: frozenset({"read_repo", "write_repo", "search_repo", "run_authorized"}),
    Stage.TESTER: frozenset({"playwright"}),
    Stage.REVIEWER: frozenset({"read_hashed"}),
}
_SENSITIVE_PARTS = frozenset({".auto-code", ".env", ".git", "secrets"})


def expected_hashed_read_paths(stage: Stage, context: UnitContext) -> tuple[str, ...]:
    """Return the only paths a hash-read stage may expose through its prompt."""

    if stage not in _READ_STAGES:
        return ()
    if stage in _ARCHITECT_READ_STAGES:
        paths = (
            _require_context_path(context.requirements_path, "Requirements Package"),
            _require_context_path(context.openspec_instructions_path, "OpenSpec instructions"),
        )
        if stage is Stage.ARCHITECT_PROPOSAL:
            paths += (_require_context_path(context.outline_path, "Change Outline"),)
        paths += context.dependency_paths
        if context.latest_failure_path is not None:
            paths += (context.latest_failure_path,)
    else:
        paths = context.dependency_paths
        if context.latest_failure_path is not None:
            paths += (context.latest_failure_path,)
    if not isinstance(paths, tuple) or any(not isinstance(path, str) or not path for path in paths):
        raise ValueError("Prompt-readable paths must be bounded references")
    if len(set(paths)) != len(paths):
        raise ValueError("Prompt-readable paths must be unique")
    return paths


def validate_hashed_read_manifest(manifest: ToolManifest, expected_paths: tuple[str, ...]) -> None:
    if not isinstance(manifest, ToolManifest) or not isinstance(expected_paths, tuple):
        raise ValueError("Hash-bound read manifests require bounded paths")
    if any(not isinstance(path, str) or not path for path in expected_paths) or len(set(expected_paths)) != len(expected_paths):
        raise ValueError("Prompt-readable paths must be unique bounded references")
    actual_paths = tuple(entry.relative_path for entry in manifest.read_manifest.files)
    if len(actual_paths) != len(expected_paths) or set(actual_paths) != set(expected_paths):
        raise ValueError("Hash-bound read manifest must match the prompt-readable paths exactly")


def _require_context_path(value: str | None, name: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} is required")
    return value


class ToolBroker:
    """Bind each cognitive stage to exactly its approved tool capabilities."""

    def __init__(
        self,
        *,
        repository_root: Path,
        state_root: Path | None = None,
        programmer_tools: ProgrammerTools | None = None,
        playwright_tools: PlaywrightTools | None = None,
        max_read_bytes: int = DEFAULT_MAX_READ_BYTES,
    ) -> None:
        if not isinstance(repository_root, Path) or repository_root.is_symlink() or not repository_root.is_dir():
            raise ValueError("Tool broker requires a real repository root")
        if state_root is not None and not isinstance(state_root, Path):
            raise ValueError("State root must be a path")
        if isinstance(max_read_bytes, bool) or max_read_bytes <= 0 or max_read_bytes > DEFAULT_MAX_READ_BYTES:
            raise ValueError("Hashed read byte limit is invalid")
        self._repository_root = _absolute_path(repository_root)
        self._state_root = _absolute_path(state_root) if state_root is not None else None
        self._programmer_tools = programmer_tools
        self._playwright_tools = playwright_tools
        self._max_read_bytes = max_read_bytes

    def for_stage(
        self,
        stage: Stage,
        manifest: ToolManifest,
        *,
        expected_read_paths: tuple[str, ...] | None = None,
    ) -> tuple[BaseTool, ...]:
        if not isinstance(stage, Stage) or stage is Stage.VERIFICATION:
            raise ToolAccessDenied("Only cognitive stages can receive model tools")
        if not isinstance(manifest, ToolManifest):
            raise ToolAccessDenied("Tool manifests must use the bounded manifest contract")
        self._validate_manifest(stage, manifest, expected_read_paths)
        if stage is Stage.ANALYST:
            return ()
        if stage in _READ_STAGES:
            tools: tuple[BaseTool, ...] = (
                HashedReadTool(
                    root=self._repository_root,
                    manifest=manifest.read_manifest,
                    max_bytes=self._max_read_bytes,
                    denied_roots=(self._state_root,) if self._state_root is not None else (),
                    max_usage_count=MAX_NATIVE_TOOL_CALLS,
                ),
            )
        elif stage is Stage.PROGRAMMER:
            if self._programmer_tools is None:
                raise ToolAccessDenied("Programmer tools have not been injected")
            tools = self._programmer_tools.for_manifest(manifest)
        elif stage is Stage.TESTER:
            if self._playwright_tools is None:
                raise ToolAccessDenied("Playwright tools have not been injected")
            tools = self._playwright_tools.for_manifest(manifest)
        else:
            raise ToolAccessDenied("Stage does not have an approved tool set")
        return self._validate_exact_tools(stage, tools)

    def _validate_manifest(
        self,
        stage: Stage,
        manifest: ToolManifest,
        expected_read_paths: tuple[str, ...] | None,
    ) -> None:
        for entry in manifest.read_manifest.files:
            parts = entry.relative_path.split("/")
            if any(part in _SENSITIVE_PARTS or part.startswith(".env") for part in parts):
                raise ToolAccessDenied("Tool manifest cannot expose secret paths")
            candidate = self._repository_root / entry.relative_path
            if self._state_root is not None and _is_relative_to(candidate, self._state_root):
                raise ToolAccessDenied("Tool manifest cannot expose the state root")
        if stage in _READ_STAGES:
            if expected_read_paths is None:
                raise ToolAccessDenied("Hash-read stages require prompt-readable paths")
            try:
                validate_hashed_read_manifest(manifest, expected_read_paths)
            except ValueError as error:
                raise ToolAccessDenied(str(error)) from None
        elif expected_read_paths is not None:
            raise ToolAccessDenied("Only hash-read stages can receive prompt-readable paths")

    def _validate_exact_tools(self, stage: Stage, tools: tuple[BaseTool, ...]) -> tuple[BaseTool, ...]:
        if not isinstance(tools, tuple) or not all(isinstance(tool, BaseTool) for tool in tools):
            raise ToolAccessDenied("Injected tools must be a tuple of CrewAI tools")
        expected = _EXPECTED_TOOL_NAMES[stage]
        names = tuple(tool.name for tool in tools)
        if len(set(names)) != len(names) or frozenset(names) != expected or len(names) != len(expected):
            raise ToolAccessDenied("Injected tools must provide the exact approved tool set")
        if any(tool.tool_failure_policy not in {None, ToolFailurePolicy.RAISE} for tool in tools):
            raise ToolAccessDenied("Injected tools cannot lower the required tool failure policy")
        if any(
            isinstance(tool.max_usage_count, bool)
            or not isinstance(tool.max_usage_count, int)
            or not 0 < tool.max_usage_count <= MAX_NATIVE_TOOL_CALLS
            for tool in tools
        ):
            raise ToolAccessDenied("Injected tools must have a finite native usage limit at or below two")
        return tools


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(path))
