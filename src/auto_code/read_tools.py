from __future__ import annotations

import errno
import hashlib
import os
from pathlib import Path, PurePosixPath
import stat
from typing import Annotated

from crewai.tools.base_tool import BaseTool
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, field_validator, model_validator

from .contracts import ContractModel, EvidencePath, Sha256, reject_unsafe_persisted_value


DEFAULT_MAX_READ_BYTES = 262_144
_READ_CHUNK_BYTES = 65_536
_DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
_FILE_FLAGS = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)


class ReadAccessDenied(PermissionError):
    """A model requested content outside its hash-bound read manifest."""


class HashedReadFile(ContractModel):
    relative_path: EvidencePath
    sha256: Sha256

    @field_validator("relative_path")
    @classmethod
    def validate_relative_path(cls, value: str) -> str:
        return reject_unsafe_persisted_value(value)


class HashedReadManifest(ContractModel):
    files: tuple[HashedReadFile, ...] = Field(max_length=128)

    @model_validator(mode="after")
    def validate_unique_paths(self) -> HashedReadManifest:
        if len({entry.relative_path for entry in self.files}) != len(self.files):
            raise ValueError("Hashed read manifest paths must be unique")
        return self


class HashedReadToolInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: Annotated[str, StringConstraints(max_length=512)]


class HashedReadTool(BaseTool):
    """Read only explicit, immutable, text files under one repository root."""

    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    name: str = "read_hashed"
    description: str = "Read one explicitly allowlisted repository file after SHA-256 verification."
    args_schema: type[BaseModel] = HashedReadToolInput
    root: Path = Field(exclude=True)
    manifest: HashedReadManifest = Field(exclude=True)
    max_bytes: int = DEFAULT_MAX_READ_BYTES
    denied_roots: tuple[Path, ...] = Field(default=(), exclude=True)

    @model_validator(mode="after")
    def validate_configuration(self) -> HashedReadTool:
        try:
            descriptor = _open_directory(self.root)
        except OSError:
            raise ValueError("Hashed read root must be a real directory")
        else:
            os.close(descriptor)
        if isinstance(self.max_bytes, bool) or self.max_bytes <= 0 or self.max_bytes > DEFAULT_MAX_READ_BYTES:
            raise ValueError("Hashed read byte limit is invalid")
        if any(not isinstance(root, Path) for root in self.denied_roots):
            raise ValueError("Denied roots must be paths")
        for denied_root in self.denied_roots:
            try:
                descriptor = _open_directory(denied_root)
            except OSError:
                raise ValueError("Denied root must be a real directory") from None
            else:
                os.close(descriptor)
        return self

    def _run(self, path: str) -> str:
        return self.read(path)

    def read(self, path: str) -> str:
        expected_hashes = {entry.relative_path: entry.sha256 for entry in self.manifest.files}
        if not isinstance(path, str) or path not in expected_hashes:
            raise ReadAccessDenied("Requested path is not allowlisted")

        relative = PurePosixPath(path)
        if relative.is_absolute() or not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
            raise ReadAccessDenied("Requested path escapes the read root")
        if _is_under_denied_root(self.root, relative.parts, self.denied_roots):
            raise ReadAccessDenied("Requested path is inside the state root")

        try:
            root_descriptor = _open_directory(self.root)
        except OSError:
            raise ReadAccessDenied("Requested path cannot be opened safely") from None
        try:
            try:
                descriptor = _open_regular_file(root_descriptor, relative.parts)
            except OSError as error:
                if error.errno == errno.ELOOP:
                    raise ReadAccessDenied("Requested path contains a symlink") from None
                raise ReadAccessDenied("Requested path cannot be opened safely") from None
        finally:
            os.close(root_descriptor)
        try:
            try:
                info = os.fstat(descriptor)
            except OSError:
                raise ReadAccessDenied("Requested path cannot be inspected") from None
            if not stat.S_ISREG(info.st_mode):
                raise ReadAccessDenied("Requested path is not a regular file")
            if info.st_size > self.max_bytes:
                raise ReadAccessDenied("Requested file exceeds the configured size limit")
            try:
                content = _read_bounded(descriptor, self.max_bytes)
            except ReadAccessDenied:
                raise
            except OSError:
                raise ReadAccessDenied("Requested path cannot be read") from None
        finally:
            os.close(descriptor)
        if hashlib.sha256(content).hexdigest() != expected_hashes[path].lower():
            raise ReadAccessDenied("Requested file hash does not match the manifest")
        try:
            return content.decode("utf-8")
        except UnicodeDecodeError:
            raise ReadAccessDenied("Requested file is not UTF-8 text") from None


def _open_directory(path: Path) -> int:
    absolute = _absolute_path(path)
    descriptor = os.open(absolute.anchor, _DIRECTORY_FLAGS)
    try:
        for part in _path_parts(absolute):
            child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            if not stat.S_ISDIR(os.fstat(child).st_mode):
                os.close(child)
                raise NotADirectoryError(part)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _open_regular_file(root_descriptor: int, parts: tuple[str, ...]) -> int:
    descriptor = root_descriptor
    owns_descriptor = False
    try:
        for part in parts[:-1]:
            child = os.open(part, _DIRECTORY_FLAGS, dir_fd=descriptor)
            if not stat.S_ISDIR(os.fstat(child).st_mode):
                os.close(child)
                raise NotADirectoryError(part)
            if owns_descriptor:
                os.close(descriptor)
            descriptor = child
            owns_descriptor = True
        return os.open(parts[-1], _FILE_FLAGS, dir_fd=descriptor)
    finally:
        if owns_descriptor:
            os.close(descriptor)


def _read_bounded(descriptor: int, max_bytes: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = os.read(descriptor, min(_READ_CHUNK_BYTES, max_bytes - size + 1))
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > max_bytes:
            raise ReadAccessDenied("Requested file exceeds the configured size limit")
        chunks.append(chunk)


def _is_under_denied_root(root: Path, parts: tuple[str, ...], denied_roots: tuple[Path, ...]) -> bool:
    candidate = _absolute_path(root).joinpath(*parts)
    return any(_is_relative_to(candidate, _absolute_path(denied_root)) for denied_root in denied_roots)


def _absolute_path(path: Path) -> Path:
    return Path(os.path.abspath(path))


def _path_parts(path: Path) -> tuple[str, ...]:
    return tuple(part for part in path.parts if part not in {path.anchor, "."})


def _is_relative_to(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True
