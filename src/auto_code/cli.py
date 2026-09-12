from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Protocol

from .contracts import EvidenceRef, RunnerIdentity
from .state import RunStateStore, StateGeneration, StateStoreError


_LAUNCHER_RUNTIME_FD = 3
_MAX_RUNTIME_CONFIG_BYTES = 4096
_SHA256 = re.compile(r"[0-9A-Fa-f]{64}\Z")
_CANONICAL_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class RuntimeConfigurationError(RuntimeError):
    pass


class _ArgumentParseError(ValueError):
    pass


class _StatusError(ValueError):
    pass


class _PrepareCoordinator(Protocol):
    def probe(self, repository_path: Path) -> object: ...

    def activate_reservation(self, input_path: Path, input_hash: str, challenge: str) -> object: ...

    def advance(self, run_id: str, expected_revision: int, expected_hash: str) -> object: ...

    def consume_receipt(
        self,
        run_id: str,
        expected_revision: int,
        expected_hash: str,
        receipt_ref: EvidenceRef,
    ) -> object: ...


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    config: dict[str, object] = {}
    for key, value in pairs:
        if key in config:
            raise ValueError("duplicate JSON key")
        config[key] = value
    return config


class _ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise _ArgumentParseError(message)


@dataclass(frozen=True)
class TrustedRuntimeConfig:
    state_root: Path
    project_root: Path
    project_policy_path: Path
    project_policy_hash: str
    runner_identity: RunnerIdentity

    @classmethod
    def from_descriptor(cls, value: object) -> TrustedRuntimeConfig:
        if not isinstance(value, dict) or set(value) != {
            "state_root",
            "project_root",
            "project_policy_path",
            "project_policy_hash",
            "runner_identity",
        }:
            raise ValueError("runtime descriptor shape is invalid")
        return cls(
            state_root=Path(value["state_root"]),
            project_root=Path(value["project_root"]),
            project_policy_path=Path(value["project_policy_path"]),
            project_policy_hash=value["project_policy_hash"],
            runner_identity=RunnerIdentity.model_validate(value["runner_identity"]),
        )

    def __post_init__(self) -> None:
        roots = (
            ("state_root", "state root"),
            ("project_root", "project root"),
            ("project_policy_path", "project policy path"),
        )
        for attribute, description in roots:
            path = Path(getattr(self, attribute))
            if not path.is_absolute():
                raise ValueError(f"{description} must be absolute")
            if ".." in path.parts:
                raise ValueError(f"{description} must not contain '..'")
            object.__setattr__(self, attribute, path)
        if self.project_policy_path == self.project_root or not self.project_policy_path.is_relative_to(
            self.project_root
        ):
            raise ValueError("project policy path must be below project root")
        if not isinstance(self.project_policy_hash, str) or _SHA256.fullmatch(self.project_policy_hash) is None:
            raise ValueError("project policy hash is invalid")
        if not isinstance(self.runner_identity, RunnerIdentity):
            raise ValueError("runner identity is invalid")


def load_launcher_runtime_from_protected_fd() -> TrustedRuntimeConfig:
    """Load the launcher-provided JSON runtime descriptor from fixed FD 3."""
    try:
        descriptor = os.dup(_LAUNCHER_RUNTIME_FD)
    except OSError as error:
        raise RuntimeConfigurationError("launcher runtime descriptor is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        access_mode = fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
        if not stat.S_ISREG(metadata.st_mode) or access_mode != os.O_RDONLY:
            raise RuntimeConfigurationError("launcher runtime descriptor is invalid")
        payload = os.pread(descriptor, _MAX_RUNTIME_CONFIG_BYTES + 1, 0)
    except OSError as error:
        raise RuntimeConfigurationError("launcher runtime descriptor is invalid") from error
    finally:
        os.close(descriptor)

    if len(payload) > _MAX_RUNTIME_CONFIG_BYTES:
        raise RuntimeConfigurationError("launcher runtime descriptor is invalid")
    try:
        config = json.loads(payload.decode("ascii"), object_pairs_hook=_reject_duplicate_json_keys)
        return TrustedRuntimeConfig.from_descriptor(config)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise RuntimeConfigurationError("launcher runtime descriptor is invalid") from error


def build_parser() -> argparse.ArgumentParser:
    parser = _ArgumentParser(prog="auto-code")
    commands = parser.add_subparsers(dest="command", parser_class=_ArgumentParser)
    status = commands.add_parser("status")
    status.add_argument("--run")
    status.add_argument("--expected-revision")
    status.add_argument("--expected-hash")
    prepare = commands.add_parser("prepare")
    mode = prepare.add_mutually_exclusive_group(required=True)
    mode.add_argument("--repository")
    mode.add_argument("--input")
    mode.add_argument("--run")
    prepare.add_argument("--sha256")
    prepare.add_argument("--challenge")
    prepare.add_argument("--expected-revision")
    prepare.add_argument("--expected-hash")
    prepare.add_argument("--receipt-ref", action="append")
    return parser


def require_expected(generation: StateGeneration, expected_revision: int, expected_hash: str) -> None:
    if generation.revision != expected_revision or generation.state_hash != expected_hash.lower():
        raise _StatusError("expected state does not match")


def _prepare_bindings(args: argparse.Namespace) -> tuple[int | None, EvidenceRef | None] | None:
    receipt_values = args.receipt_ref
    if args.repository is not None:
        if (
            not args.repository
            or args.input is not None
            or args.run is not None
            or args.sha256 is not None
            or args.challenge is not None
            or args.expected_revision is not None
            or args.expected_hash is not None
            or receipt_values is not None
        ):
            return None
        return (None, None)
    if args.input is not None:
        if (
            not args.input
            or args.run is not None
            or args.sha256 is None
            or _CANONICAL_SHA256.fullmatch(args.sha256) is None
            or not args.challenge
            or args.expected_revision is not None
            or args.expected_hash is not None
            or receipt_values is not None
        ):
            return None
        return (None, None)
    if (
        not args.run
        or args.sha256 is not None
        or args.challenge is not None
        or args.expected_revision is None
        or args.expected_hash is None
        or _CANONICAL_SHA256.fullmatch(args.expected_hash) is None
    ):
        return None
    try:
        expected_revision = int(args.expected_revision)
        if expected_revision < 1:
            return None
    except ValueError:
        return None
    if receipt_values is None:
        return (expected_revision, None)
    if len(receipt_values) != 1:
        return None
    try:
        receipt_ref = EvidenceRef.model_validate_json(receipt_values[0])
    except (TypeError, ValueError):
        return None
    if receipt_ref.creator != "trusted-mcp-bridge" or receipt_ref.media_type != "application/json":
        return None
    return (expected_revision, receipt_ref)


def _run_prepare(
    args: argparse.Namespace,
    runtime: TrustedRuntimeConfig | None,
    prepare_coordinator_factory: Callable[[TrustedRuntimeConfig], _PrepareCoordinator] | None,
) -> int:
    bindings = _prepare_bindings(args)
    if bindings is None:
        print("prepare: invalid arguments", file=sys.stderr)
        return 2
    try:
        trusted_runtime = runtime if runtime is not None else load_launcher_runtime_from_protected_fd()
    except RuntimeConfigurationError:
        print("prepare: launcher runtime unavailable", file=sys.stderr)
        return 2
    if prepare_coordinator_factory is None:
        print("prepare: launcher composition unavailable", file=sys.stderr)
        return 2
    try:
        coordinator = prepare_coordinator_factory(trusted_runtime)
        expected_revision, receipt_ref = bindings
        if args.repository is not None:
            coordinator.probe(Path(args.repository))
        elif args.input is not None:
            coordinator.activate_reservation(Path(args.input), args.sha256, args.challenge)
        elif receipt_ref is not None:
            assert expected_revision is not None
            coordinator.consume_receipt(args.run, expected_revision, args.expected_hash, receipt_ref)
        else:
            assert expected_revision is not None
            coordinator.advance(args.run, expected_revision, args.expected_hash)
    except Exception:
        print("prepare: operation unavailable", file=sys.stderr)
        return 2
    return 0


def main(
    argv: Sequence[str] | None = None,
    runtime: TrustedRuntimeConfig | None = None,
    *,
    prepare_coordinator_factory: Callable[[TrustedRuntimeConfig], _PrepareCoordinator] | None = None,
) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    try:
        args = build_parser().parse_args(arguments)
    except _ArgumentParseError as error:
        if len(arguments) > 0 and arguments[0] == "prepare":
            print("prepare: invalid arguments", file=sys.stderr)
            return 2
        print(f"auto-code: {error}", file=sys.stderr)
        return 2
    except SystemExit as error:
        return int(error.code)

    if args.command == "prepare":
        return _run_prepare(args, runtime, prepare_coordinator_factory)
    if args.command != "status":
        print("auto-code: a command is required", file=sys.stderr)
        return 2
    for option in ("run", "expected_revision", "expected_hash"):
        if getattr(args, option) is None:
            print(f"status: missing required option --{option.replace('_', '-')}", file=sys.stderr)
            return 2
    try:
        expected_revision = int(args.expected_revision)
        if expected_revision < 1:
            raise ValueError
    except ValueError:
        print("status: invalid --expected-revision", file=sys.stderr)
        return 2
    if _SHA256.fullmatch(args.expected_hash) is None:
        print("status: invalid --expected-hash", file=sys.stderr)
        return 2

    try:
        trusted_runtime = runtime if runtime is not None else load_launcher_runtime_from_protected_fd()
        generation = RunStateStore.load_read_only(trusted_runtime.state_root, args.run)
        require_expected(generation, expected_revision, args.expected_hash)
    except RuntimeConfigurationError:
        print("status: launcher runtime unavailable", file=sys.stderr)
        return 2
    except _StatusError as error:
        print(f"status: {error}", file=sys.stderr)
        return 2
    except (OSError, StateStoreError, ValueError):
        print("status: state unavailable", file=sys.stderr)
        return 2

    state = generation.state
    print(
        f"{state.ticket_id} crew_iterations={state.crew_iteration_count}/{state.authorized_iteration_limit} "
        f"disposition={state.disposition.value} freshness=unknown"
    )
    return 0


def entrypoint() -> None:
    raise SystemExit(main())
