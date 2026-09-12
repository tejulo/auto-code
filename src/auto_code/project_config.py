from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator
import yaml
from yaml.constructor import ConstructorError
from yaml.events import AliasEvent
from yaml.nodes import MappingNode
from yaml.resolver import BaseResolver

from .hashing import hash_json


class ProjectConfigError(ValueError):
    pass


class _StrictSafeLoader(yaml.SafeLoader):
    """Safe YAML with no aliases or duplicate keys, so policy hashes are unambiguous."""

    def compose_node(self, parent: object, index: object) -> object:
        if self.check_event(AliasEvent):
            event = self.get_event()
            raise ConstructorError(None, None, "YAML aliases are not allowed", event.start_mark)
        event = self.peek_event()
        if getattr(event, "anchor", None) is not None:
            raise ConstructorError(None, None, "YAML anchors are not allowed", event.start_mark)
        return super().compose_node(parent, index)


def _construct_strict_mapping(loader: _StrictSafeLoader, node: MappingNode, deep: bool = False) -> dict[str, object]:
    if not isinstance(node, MappingNode):
        raise ConstructorError(None, None, "expected a mapping", node.start_mark)
    mapping: dict[str, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if not isinstance(key, str):
            raise ConstructorError(None, None, "policy keys must be strings", key_node.start_mark)
        if key in mapping:
            raise ConstructorError(None, None, "duplicate policy key", key_node.start_mark)
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictSafeLoader.add_constructor(BaseResolver.DEFAULT_MAPPING_TAG, _construct_strict_mapping)

_TOKEN = re.compile(r"\$\{(PROJECT|RUNNER|REPAIR_WORKTREE)\}")
_SHELL_SYNTAX = re.compile(r"[;&|`\r\n\x00]")
_SECRET_COMMAND_VALUE = re.compile(
    r"(?i)(?:^|[^a-z0-9])(?:api[_-]?key|access[_-]?key|private[_-]?key|token|password|secret|credential|authorization)(?:$|[^a-z0-9])"
)
_CAMEL_CASE_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_COMMAND_ARGUMENT_NAME = re.compile(
    r"^(?:-{1,2}[A-Za-z][A-Za-z0-9_-]*(?=$|=)|[A-Za-z_][A-Za-z0-9_-]*(?==))"
)
_SAFE_REMOTE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SAFE_ENVIRONMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_FORBIDDEN_ENVIRONMENT = re.compile(r"(?i)(?:key|token|secret|password|credential|authorization)")
_FORBIDDEN_LAUNCHER_KEYS = frozenset(
    {
        "active_run_index",
        "authoritative_state_root",
        "authorization_key",
        "authorization_keys",
        "authorization_public_key",
        "authorization_public_keys",
        "bridge_signing_key",
        "launcher_config",
        "receipt_signing_key",
        "receipt_trust_root",
        "registry_location",
        "repair_runner_identity",
        "runner_identity",
        "state_root",
    }
)
_ALLOWED_PLAYWRIGHT_OPERATIONS = frozenset(
    {"open", "goto", "snapshot", "click", "fill", "type", "press", "screenshot", "close"}
)
_SHELL_EXECUTABLES = frozenset({"bash", "csh", "dash", "fish", "ksh", "sh", "tcsh", "zsh", "cmd", "cmd.exe", "powershell", "pwsh"})


def _normalize_launcher_key(key: str) -> str:
    return key.lower().replace("-", "_")


def _reject_launcher_owned_fields(value: object) -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValueError("Policy keys must be strings")
            if _normalize_launcher_key(key) in _FORBIDDEN_LAUNCHER_KEYS:
                raise ValueError("Launcher-owned configuration is forbidden")
            _reject_launcher_owned_fields(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _reject_launcher_owned_fields(item)


def _normalize_command_argument_name(argument: str) -> str:
    match = _COMMAND_ARGUMENT_NAME.match(argument)
    if match is None:
        return argument
    return _CAMEL_CASE_BOUNDARY.sub("_", match.group()) + argument[match.end() :]


def _command(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not value:
        raise ValueError("Commands must be non-empty argument arrays")
    command = tuple(value)
    if any(not isinstance(argument, str) or not argument for argument in command):
        raise ValueError("Command arguments must be non-empty text")
    if Path(command[0]).name.lower() in _SHELL_EXECUTABLES:
        raise ValueError("Shell executables are not allowed in policy commands")
    for argument in command:
        if _SHELL_SYNTAX.search(argument):
            raise ValueError("Shell syntax is not allowed in policy commands")
        if _SECRET_COMMAND_VALUE.search(argument) or _SECRET_COMMAND_VALUE.search(
            _normalize_command_argument_name(argument)
        ):
            raise ValueError("Policy commands cannot contain secret data")
        remainder = _TOKEN.sub("", argument)
        if "$" in remainder:
            raise ValueError("Policy commands use only launcher tokens")
    return command


def _command_list(value: object) -> tuple[tuple[str, ...], ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("Commands must be a list")
    return tuple(_command(command) for command in value)


def _relative_path(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 512 or "\x00" in value:
        raise ValueError("Policy paths must be bounded relative paths")
    if value.startswith("/") or "\\" in value:
        raise ValueError("Policy paths must be relative")
    parts = value.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError("Policy paths must not traverse")
    return value


def _path_list(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("Policy paths must be a list")
    paths = tuple(_relative_path(path) for path in value)
    if len(set(paths)) != len(paths):
        raise ValueError("Policy paths must be unique")
    return paths


def _path_overlaps(first: str, second: str) -> bool:
    return first == second or first.startswith(f"{second}/") or second.startswith(f"{first}/")


def _environment_list(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError("Environment allowlist must be a list")
    variables = tuple(value)
    if any(not isinstance(variable, str) or _SAFE_ENVIRONMENT.fullmatch(variable) is None for variable in variables):
        raise ValueError("Environment allowlist contains an invalid name")
    if any(variable in {"HOME", "PATH"} or _FORBIDDEN_ENVIRONMENT.search(variable) for variable in variables):
        raise ValueError("Environment allowlist cannot expose launcher or secret values")
    if len(set(variables)) != len(variables):
        raise ValueError("Environment allowlist values must be unique")
    return variables


class _PolicyModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class GitPolicy(_PolicyModel):
    remote: str
    base_branch: str | None

    @field_validator("remote")
    @classmethod
    def validate_remote(cls, value: str) -> str:
        if _SAFE_REMOTE.fullmatch(value) is None:
            raise ValueError("Git remote is invalid")
        return value

    @field_validator("base_branch")
    @classmethod
    def validate_base_branch(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value or len(value) > 255 or any(character.isspace() for character in value):
            raise ValueError("Git base branch is invalid")
        if value.startswith("-") or ".." in value or "@{" in value or "\\" in value:
            raise ValueError("Git base branch is invalid")
        return value


class VerificationPolicy(_PolicyModel):
    allow_empty: bool = False
    commands: tuple[tuple[str, ...], ...]
    mutation_commands: tuple[tuple[str, ...], ...] = ()

    @field_validator("commands", "mutation_commands", mode="before")
    @classmethod
    def validate_command_lists(cls, value: object) -> tuple[tuple[str, ...], ...]:
        return _command_list(value)

    @model_validator(mode="after")
    def validate_empty_commands(self) -> VerificationPolicy:
        if not self.commands and not self.allow_empty:
            raise ValueError("Empty verification commands require explicit authorization")
        return self


class BrowserPolicy(_PolicyModel):
    start_command: tuple[str, ...] | None
    base_url: str | None
    ready_timeout_seconds: int = Field(gt=0)
    command_timeout_seconds: int = Field(gt=0)
    playwright_command_prefix: tuple[str, ...]
    allowed_operations: tuple[str, ...]

    @field_validator("start_command", mode="before")
    @classmethod
    def validate_start_command(cls, value: object) -> tuple[str, ...] | None:
        return None if value is None else _command(value)

    @field_validator("playwright_command_prefix", mode="before")
    @classmethod
    def validate_playwright_prefix(cls, value: object) -> tuple[str, ...]:
        return _command(value)

    @field_validator("allowed_operations", mode="before")
    @classmethod
    def validate_browser_operations(cls, value: object) -> tuple[str, ...]:
        if not isinstance(value, (list, tuple)) or any(not isinstance(item, str) for item in value):
            raise ValueError("Browser operations must be text")
        operations = tuple(value)
        if len(set(operations)) != len(operations) or not set(operations).issubset(_ALLOWED_PLAYWRIGHT_OPERATIONS):
            raise ValueError("Browser operations are not allowlisted")
        return operations

    @field_validator("base_url")
    @classmethod
    def validate_base_url(cls, value: str | None) -> str | None:
        if value is None:
            return None
        parsed = urlsplit(value)
        if (
            parsed.scheme != "http"
            or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("Browser URL must be a local HTTP URL without credentials")
        return value

    @model_validator(mode="after")
    def validate_browser_pair(self) -> BrowserPolicy:
        if (self.start_command is None) != (self.base_url is None):
            raise ValueError("Browser start command and URL must be configured together")
        return self


class ProcessPolicy(_PolicyModel):
    command_timeout_seconds: int = Field(gt=0)
    termination_grace_seconds: int = Field(gt=0)


class TransportPolicy(_PolicyModel):
    total_retry_wait_seconds: int = Field(ge=0)


class CatalogPreflightPolicy(_PolicyModel):
    catalog_timeout_seconds: int = Field(ge=1, le=300)
    max_catalog_response_bytes: int = Field(ge=1_024, le=8_388_608)
    catalog_retry_budget: int = Field(ge=0, le=3)
    catalog_cache_validity_seconds: int = Field(ge=1, le=3_600)


class FinalizationPolicy(_PolicyModel):
    max_invocations_per_effect: int = Field(gt=0)
    total_retry_wait_seconds: int = Field(ge=0)


class AutomationPolicy(_PolicyModel):
    regression_command: tuple[str, ...]

    @field_validator("regression_command", mode="before")
    @classmethod
    def validate_regression_command(cls, value: object) -> tuple[str, ...]:
        return _command(value)


class LinearPolicy(_PolicyModel):
    started_state_id: str | None
    completed_state_id: str | None

    @field_validator("started_state_id", "completed_state_id")
    @classmethod
    def validate_state_id(cls, value: str | None) -> str | None:
        if value is None:
            return None
        if not value or len(value) > 256 or any(character.isspace() for character in value):
            raise ValueError("Linear state ID is invalid")
        return value


class ReviewPolicy(_PolicyModel):
    require_distinct_model: bool = False


class ProjectConfig(_PolicyModel):
    git: GitPolicy
    verification: VerificationPolicy
    browser: BrowserPolicy
    process: ProcessPolicy
    transport: TransportPolicy
    preflight: CatalogPreflightPolicy
    finalization: FinalizationPolicy
    automation: AutomationPolicy
    protected_paths: tuple[str, ...]
    evidence_readable_paths: tuple[str, ...] = ()
    commit_excluded_paths: tuple[str, ...]
    writable_roots: tuple[str, ...] = ()
    environment_allowlist: tuple[str, ...]
    linear: LinearPolicy
    review: ReviewPolicy

    @field_validator(
        "protected_paths",
        "evidence_readable_paths",
        "commit_excluded_paths",
        "writable_roots",
        mode="before",
    )
    @classmethod
    def validate_path_lists(cls, value: object) -> tuple[str, ...]:
        return _path_list(value)

    @field_validator("environment_allowlist", mode="before")
    @classmethod
    def validate_environment_allowlist(cls, value: object) -> tuple[str, ...]:
        return _environment_list(value)

    @model_validator(mode="after")
    def validate_path_roles(self) -> ProjectConfig:
        for readable in self.evidence_readable_paths:
            if any(_path_overlaps(readable, protected) for protected in self.protected_paths):
                raise ValueError("Evidence-readable paths cannot overlap protected paths")
        for writable in self.writable_roots:
            if any(_path_overlaps(writable, protected) for protected in self.protected_paths):
                raise ValueError("Writable roots cannot overlap protected paths")
        return self

    @property
    def policy_hash(self) -> str:
        return hash_json(self.model_dump(mode="json", round_trip=True))

    @property
    def content_hash(self) -> str:
        return self.policy_hash

    @classmethod
    def load(cls, path: Path) -> ProjectConfig:
        try:
            raw_text = Path(path).read_text(encoding="utf-8")
            if len(raw_text) > 1_048_576:
                raise ValueError("Policy is too large")
            raw = yaml.load(raw_text, Loader=_StrictSafeLoader)
            if not isinstance(raw, Mapping):
                raise ValueError("Policy must be an object")
            _reject_launcher_owned_fields(raw)
            return cls.model_validate(raw)
        except (OSError, TypeError, ValueError, ValidationError, yaml.YAMLError) as error:
            raise ProjectConfigError("Project Policy is invalid") from error


@dataclass(frozen=True)
class LauncherRoots:
    project_root: Path
    runner_root: Path
    repair_worktree: Path

    def __post_init__(self) -> None:
        for root in (self.project_root, self.runner_root, self.repair_worktree):
            if not isinstance(root, Path) or not root.is_absolute() or ".." in root.parts:
                raise ValueError("Launcher roots must be validated absolute paths")


def expand_launcher_tokens(argv: Sequence[str], roots: LauncherRoots) -> tuple[str, ...]:
    if isinstance(argv, (str, bytes)):
        raise ValueError("Command must be an argument array")
    replacements = {
        "PROJECT": str(roots.project_root),
        "RUNNER": str(roots.runner_root),
        "REPAIR_WORKTREE": str(roots.repair_worktree),
    }

    def replace(match: re.Match[str]) -> str:
        return replacements[match.group(1)]

    expanded: list[str] = []
    for argument in argv:
        if not isinstance(argument, str):
            raise ValueError("Command arguments must be text")
        if _SHELL_SYNTAX.search(argument):
            raise ValueError("Shell syntax is not allowed in policy commands")
        value = _TOKEN.sub(replace, argument)
        if "$" in value:
            raise ValueError("Command contains an unrecognized launcher token")
        expanded.append(value)
    return tuple(expanded)
