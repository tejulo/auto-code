from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
import errno
import math
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Annotated, BinaryIO
from uuid import uuid4

from crewai.tools import ToolFailurePolicy
from crewai.tools.base_tool import BaseTool
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from .process import CommandResult, EvidenceSink, ProcessRunner, SandboxPolicy
from .project_config import ProjectConfig
from .tool_broker import MAX_NATIVE_TOOL_CALLS, ToolAccessDenied, ToolManifest


MAX_REPO_READ_BYTES = 262_144
MAX_SEARCH_MATCHES = 128
MAX_SEARCH_LINE_CHARS = 1_024
_MAX_PATH_LENGTH = 512
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_READ_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_WRITE_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_SENSITIVE_PARTS = frozenset({".auto-code", ".git", "secrets"})


class ProtectedPathError(PermissionError):
    """A repository tool path is outside its descriptor-relative capability."""


@dataclass(frozen=True)
class SearchMatch:
    relative_path: str
    line_number: int
    text: str

    def __post_init__(self) -> None:
        if not isinstance(self.relative_path, str) or not self.relative_path or len(self.relative_path) > _MAX_PATH_LENGTH:
            raise ValueError("Search match path is invalid")
        if isinstance(self.line_number, bool) or not isinstance(self.line_number, int) or self.line_number <= 0:
            raise ValueError("Search match line number is invalid")
        if not isinstance(self.text, str) or len(self.text) > MAX_SEARCH_LINE_CHARS:
            raise ValueError("Search match text is invalid")


@dataclass(frozen=True)
class RepoToolPolicy:
    root: Path
    writable_roots: tuple[str, ...]
    protected_paths: tuple[str, ...]
    commit_excluded_paths: tuple[str, ...] = ()
    _root_descriptor: int = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        if not isinstance(self.root, Path):
            raise ValueError("Repository root must be a path")
        normalized = Path(os.path.abspath(self.root))
        writable_roots = _validate_policy_paths(self.writable_roots, "Writable roots")
        protected_paths = _validate_policy_paths(self.protected_paths, "Protected paths")
        commit_excluded_paths = _validate_optional_policy_paths(self.commit_excluded_paths, "Commit-excluded paths")
        try:
            descriptor = _open_directory(normalized)
        except OSError as error:
            raise ValueError("Repository root must be a real directory") from error
        object.__setattr__(self, "root", normalized)
        object.__setattr__(self, "writable_roots", writable_roots)
        object.__setattr__(self, "protected_paths", protected_paths)
        object.__setattr__(self, "commit_excluded_paths", commit_excluded_paths)
        object.__setattr__(self, "_root_descriptor", descriptor)

    def close(self) -> None:
        """Release the pinned root descriptor when this policy is no longer needed."""

        descriptor = self._root_descriptor
        if descriptor < 0:
            return
        object.__setattr__(self, "_root_descriptor", -1)
        os.close(descriptor)

    def __enter__(self) -> RepoToolPolicy:
        return self

    def __exit__(self, exception_type: object, exception: object, traceback: object) -> None:
        del exception_type, exception, traceback
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass

    def open_read(self, relative: str) -> BinaryIO:
        parts = self._validated_parts(relative, require_writable=False)
        parent_descriptor = self._walk_parent(parts[:-1])
        try:
            descriptor = os.open(parts[-1], _READ_FLAGS, dir_fd=parent_descriptor)
        except OSError as error:
            raise _path_error(error) from None
        finally:
            os.close(parent_descriptor)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ProtectedPathError("Repository path is not a regular file")
            return os.fdopen(descriptor, "rb")
        except BaseException:
            os.close(descriptor)
            raise

    def atomic_write(self, relative: str, content: bytes) -> None:
        if not isinstance(content, bytes):
            raise TypeError("Repository content must be bytes")
        parts = self._validated_parts(relative, require_writable=True)
        parent_descriptor = self._walk_parent(parts[:-1])
        temporary_name = f".{parts[-1]}.{uuid4().hex}.tmp"
        temporary_created = False
        try:
            self._validate_existing_write_target(parent_descriptor, parts[-1])
            descriptor = os.open(temporary_name, _WRITE_FLAGS, 0o600, dir_fd=parent_descriptor)
            temporary_created = True
            try:
                _write_all(descriptor, content)
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.replace(temporary_name, parts[-1], src_dir_fd=parent_descriptor, dst_dir_fd=parent_descriptor)
            temporary_created = False
            os.fsync(parent_descriptor)
        except OSError as error:
            raise _path_error(error) from None
        finally:
            if temporary_created:
                try:
                    os.unlink(temporary_name, dir_fd=parent_descriptor)
                except OSError:
                    pass
            os.close(parent_descriptor)

    def search(self, relative: str, query: str) -> tuple[SearchMatch, ...]:
        if not isinstance(query, str) or not query or len(query) > MAX_SEARCH_LINE_CHARS:
            raise ProtectedPathError("Search query is invalid")
        parts = self._validated_parts(relative, require_writable=False)
        descriptor = self._walk_parent(parts[:-1])
        try:
            target = os.open(parts[-1], _DIRECTORY_FLAGS, dir_fd=descriptor)
        except OSError as error:
            raise _path_error(error) from None
        finally:
            os.close(descriptor)
        try:
            matches: list[SearchMatch] = []
            self._search_directory(target, parts, query, matches)
            return tuple(sorted(matches, key=lambda match: (match.relative_path, match.line_number)))
        finally:
            os.close(target)

    def _search_directory(self, descriptor: int, parts: tuple[str, ...], query: str, matches: list[SearchMatch]) -> None:
        try:
            names = sorted(os.listdir(descriptor))
        except OSError as error:
            raise _path_error(error) from None
        for name in names:
            if len(matches) >= MAX_SEARCH_MATCHES:
                return
            child_parts = (*parts, name)
            if self._is_protected(child_parts):
                continue
            try:
                metadata = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            except OSError as error:
                raise _path_error(error) from None
            if stat.S_ISDIR(metadata.st_mode):
                try:
                    child = os.open(name, _DIRECTORY_FLAGS, dir_fd=descriptor)
                except OSError as error:
                    raise _path_error(error) from None
                try:
                    self._search_directory(child, child_parts, query, matches)
                finally:
                    os.close(child)
            elif stat.S_ISREG(metadata.st_mode):
                self._search_file(descriptor, name, "/".join(child_parts), query, matches)

    def _search_file(
        self,
        parent_descriptor: int,
        name: str,
        relative_path: str,
        query: str,
        matches: list[SearchMatch],
    ) -> None:
        try:
            descriptor = os.open(name, _READ_FLAGS, dir_fd=parent_descriptor)
        except OSError as error:
            raise _path_error(error) from None
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                return
            content = _read_bounded(descriptor, MAX_REPO_READ_BYTES)
        finally:
            os.close(descriptor)
        for line_number, line in enumerate(content.decode("utf-8", errors="replace").splitlines(), start=1):
            if query in line:
                matches.append(SearchMatch(relative_path, line_number, line[:MAX_SEARCH_LINE_CHARS]))
                if len(matches) >= MAX_SEARCH_MATCHES:
                    return

    def _validated_parts(self, relative: str, *, require_writable: bool) -> tuple[str, ...]:
        if not isinstance(relative, str) or not relative or len(relative) > _MAX_PATH_LENGTH or "\x00" in relative:
            raise ProtectedPathError("Repository path is invalid")
        path = PurePosixPath(relative)
        if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
            raise ProtectedPathError("Repository path escapes the repository root")
        parts = path.parts
        if self._is_protected(parts):
            raise ProtectedPathError("Repository path is protected")
        if require_writable and not any(_contains(tuple(root.split("/")), parts) for root in self.writable_roots):
            raise ProtectedPathError("Repository path is outside writable roots")
        return parts

    def _is_protected(self, parts: tuple[str, ...]) -> bool:
        if any(part in _SENSITIVE_PARTS or part.startswith(".env") for part in parts):
            return True
        return any(
            _overlaps(tuple(path.split("/")), parts)
            for path in self.protected_paths + self.commit_excluded_paths
        )

    def _validate_existing_write_target(self, parent_descriptor: int, name: str) -> None:
        try:
            descriptor = os.open(name, _READ_FLAGS, dir_fd=parent_descriptor)
        except FileNotFoundError:
            return
        except OSError as error:
            raise _path_error(error) from None
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise ProtectedPathError("Repository write target is not a regular file")
        finally:
            os.close(descriptor)

    def _walk_parent(self, parts: tuple[str, ...]) -> int:
        if self._root_descriptor < 0:
            raise ProtectedPathError("Repository policy is closed")
        try:
            descriptor = os.dup(self._root_descriptor)
            for part in parts:
                child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = child
            return descriptor
        except OSError as error:
            try:
                os.close(descriptor)
            except (OSError, UnboundLocalError):
                pass
            raise _path_error(error) from None


class _ReadRepoInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: Annotated[str, StringConstraints(max_length=_MAX_PATH_LENGTH)]


class _WriteRepoInput(_ReadRepoInput):
    content: Annotated[str, StringConstraints(max_length=MAX_REPO_READ_BYTES)]


class _SearchRepoInput(_ReadRepoInput):
    query: Annotated[str, StringConstraints(max_length=MAX_SEARCH_LINE_CHARS)]


class _RunAuthorizedInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    index: int = Field(ge=0)


class _ReadRepoTool(BaseTool):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    name: str = "read_repo"
    description: str = "Read one regular UTF-8 repository file through the approved repository policy."
    args_schema: type[BaseModel] = _ReadRepoInput
    policy: RepoToolPolicy = Field(exclude=True)
    max_usage_count: int = MAX_NATIVE_TOOL_CALLS
    tool_failure_policy: ToolFailurePolicy = ToolFailurePolicy.RAISE

    def _run(self, path: str) -> str:
        with self.policy.open_read(path) as content:
            data = _read_bounded(content.fileno(), MAX_REPO_READ_BYTES + 1)
        if len(data) <= MAX_REPO_READ_BYTES:
            return data.decode("utf-8", errors="replace")
        marker = "\n[TRUNCATED]"
        return f"{data[: MAX_REPO_READ_BYTES - len(marker)].decode('utf-8', errors='replace')}{marker}"


class _WriteRepoTool(BaseTool):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    name: str = "write_repo"
    description: str = "Atomically write UTF-8 text only below the configured writable repository roots."
    args_schema: type[BaseModel] = _WriteRepoInput
    policy: RepoToolPolicy = Field(exclude=True)
    max_usage_count: int = MAX_NATIVE_TOOL_CALLS
    tool_failure_policy: ToolFailurePolicy = ToolFailurePolicy.RAISE

    def _run(self, path: str, content: str) -> str:
        self.policy.atomic_write(path, content.encode("utf-8"))
        return f"Wrote {path}"


class _SearchRepoTool(BaseTool):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    name: str = "search_repo"
    description: str = "Search regular files under one approved repository directory."
    args_schema: type[BaseModel] = _SearchRepoInput
    policy: RepoToolPolicy = Field(exclude=True)
    max_usage_count: int = MAX_NATIVE_TOOL_CALLS
    tool_failure_policy: ToolFailurePolicy = ToolFailurePolicy.RAISE

    def _run(self, path: str, query: str) -> tuple[SearchMatch, ...]:
        return self.policy.search(path, query)


class _RunAuthorizedTool(BaseTool):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    name: str = "run_authorized"
    description: str = "Run one Project Policy verification command by its configured index."
    args_schema: type[BaseModel] = _RunAuthorizedInput
    programmer_tools: ProgrammerTools = Field(exclude=True)
    max_usage_count: int = MAX_NATIVE_TOOL_CALLS
    tool_failure_policy: ToolFailurePolicy = ToolFailurePolicy.RAISE

    def _run(self, index: int) -> CommandResult:
        return self.programmer_tools.run_configured(index)


class ProgrammerTools:
    """Adapt one pinned repository and Project Policy to the four Programmer tools."""

    def __init__(
        self,
        policy: RepoToolPolicy,
        config: ProjectConfig,
        process: ProcessRunner,
        *,
        evidence_sink: EvidenceSink,
        sandbox_policy: SandboxPolicy,
        environment: Mapping[str, str],
        timeout: float,
    ) -> None:
        if not isinstance(policy, RepoToolPolicy) or not isinstance(config, ProjectConfig):
            raise ValueError("Programmer tools require a repository and Project Policy")
        if (
            policy.writable_roots != config.writable_roots
            or policy.protected_paths != config.protected_paths
            or policy.commit_excluded_paths != config.commit_excluded_paths
        ):
            raise ValueError("Repository policy must match the pinned Project Policy")
        if not callable(getattr(process, "run", None)):
            raise ValueError("Programmer tools require a process runner")
        if not isinstance(environment, Mapping) or any(not isinstance(name, str) or not isinstance(value, str) for name, value in environment.items()):
            raise ValueError("Programmer tools require an explicit environment")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Programmer tools require a positive timeout")
        self._policy = policy
        self._config = config
        self._process = process
        self._evidence_sink = evidence_sink
        self._sandbox_policy = sandbox_policy
        self._environment = dict(environment)
        self._timeout = float(timeout)

    def for_manifest(self, manifest: ToolManifest) -> tuple[BaseTool, ...]:
        if not isinstance(manifest, ToolManifest):
            raise ToolAccessDenied("Tool manifests must use the bounded manifest contract")
        return (
            _ReadRepoTool(policy=self._policy),
            _WriteRepoTool(policy=self._policy),
            _SearchRepoTool(policy=self._policy),
            _RunAuthorizedTool(programmer_tools=self),
        )

    def run_configured(self, index: int) -> CommandResult:
        if isinstance(index, bool) or index not in range(len(self._config.verification.commands)):
            raise ToolAccessDenied("Command index is not authorized")
        return self._process.run(
            self._config.verification.commands[index],
            self._policy.root,
            self._timeout,
            self._evidence_sink,
            self._environment,
            self._sandbox_policy,
        )


def _validate_policy_paths(value: tuple[str, ...], name: str) -> tuple[str, ...]:
    if not isinstance(value, tuple) or not value:
        raise ValueError(f"{name} must be a non-empty tuple")
    paths: list[str] = []
    for path in value:
        if not isinstance(path, str) or not path or len(path) > _MAX_PATH_LENGTH:
            raise ValueError(f"{name} must contain bounded relative paths")
        candidate = PurePosixPath(path)
        if candidate.is_absolute() or any(part in {"", ".", ".."} for part in candidate.parts):
            raise ValueError(f"{name} must contain bounded relative paths")
        paths.append(path)
    if len(set(paths)) != len(paths):
        raise ValueError(f"{name} must be unique")
    return tuple(paths)


def _validate_optional_policy_paths(value: tuple[str, ...], name: str) -> tuple[str, ...]:
    if value == ():
        return ()
    return _validate_policy_paths(value, name)


def _open_directory(path: Path) -> int:
    if not path.is_absolute():
        raise OSError(errno.EINVAL, "Repository root must be absolute")
    descriptor = os.open(path.anchor, _DIRECTORY_FLAGS)
    try:
        for part in path.parts[1:]:
            child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _read_bounded(descriptor: int, limit: int) -> bytes:
    chunks: list[bytes] = []
    remaining = limit
    while remaining:
        chunk = os.read(descriptor, min(65_536, remaining))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise OSError(errno.EIO, "Repository write did not progress")
        view = view[written:]


def _contains(root: tuple[str, ...], parts: tuple[str, ...]) -> bool:
    return len(root) <= len(parts) and parts[: len(root)] == root


def _overlaps(first: tuple[str, ...], second: tuple[str, ...]) -> bool:
    return _contains(first, second) or _contains(second, first)


def _path_error(error: OSError) -> ProtectedPathError:
    if error.errno == errno.ELOOP:
        return ProtectedPathError("Repository path contains a symlink")
    return ProtectedPathError("Repository path cannot be opened safely")
