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
import uuid

from .contracts import EvidenceRef, ProductChangeManifest, RepairRunnerIdentity, RunnerIdentity, StepResult
from .hashing import canonical_json_bytes
from .state import RunStateStore, StateGeneration, StateStoreError
from .supervisor import SupervisorStateMismatch


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


class _Supervisor(Protocol):
    def step(self, run_id: str, expected_revision: int, expected_hash: str) -> StepResult: ...


class _Finalizer(Protocol):
    def advance(self, generation: StateGeneration) -> StepResult: ...


class _ReceiptHandler(Protocol):
    def __call__(
        self,
        runtime: TrustedRuntimeConfig,
        run_id: str,
        expected_revision: int,
        expected_hash: str,
        request_id: str,
    ) -> object: ...


class _RepairRequestCoordinator(Protocol):
    def create_request(
        self,
        run_id: str,
        expected_revision: int,
        expected_hash: str,
        workspace: Path,
        plan: Path,
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
    repair_registry_root: Path | None = None
    repair_runner_identity: RepairRunnerIdentity | None = None
    repair_repository_id: str | None = None

    @classmethod
    def from_descriptor(cls, value: object) -> TrustedRuntimeConfig:
        base = {
            "state_root",
            "project_root",
            "project_policy_path",
            "project_policy_hash",
            "runner_identity",
        }
        repair = {"repair_registry_root", "repair_runner_identity", "repair_repository_id"}
        if not isinstance(value, dict) or frozenset(value) not in {frozenset(base), frozenset(base | repair)}:
            raise ValueError("runtime descriptor shape is invalid")
        return cls(
            state_root=Path(value["state_root"]),
            project_root=Path(value["project_root"]),
            project_policy_path=Path(value["project_policy_path"]),
            project_policy_hash=value["project_policy_hash"],
            runner_identity=RunnerIdentity.model_validate(value["runner_identity"]),
            repair_registry_root=(Path(value["repair_registry_root"]) if "repair_registry_root" in value else None),
            repair_runner_identity=(
                RepairRunnerIdentity.model_validate(value["repair_runner_identity"])
                if "repair_runner_identity" in value
                else None
            ),
            repair_repository_id=value.get("repair_repository_id"),
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
        repair_values = (self.repair_registry_root, self.repair_runner_identity, self.repair_repository_id)
        if any(value is not None for value in repair_values):
            if not all(value is not None for value in repair_values):
                raise ValueError("repair runtime bindings are incomplete")
            assert self.repair_registry_root is not None
            repair_root = Path(self.repair_registry_root)
            if not repair_root.is_absolute() or ".." in repair_root.parts:
                raise ValueError("repair registry root is invalid")
            object.__setattr__(self, "repair_registry_root", repair_root)
            if not isinstance(self.repair_runner_identity, RepairRunnerIdentity):
                raise ValueError("repair runner identity is invalid")
            if (
                not isinstance(self.repair_repository_id, str)
                or not self.repair_repository_id
                or len(self.repair_repository_id) > 255
                or any(character in self.repair_repository_id for character in ("/", "\x00"))
            ):
                raise ValueError("repair repository ID is invalid")


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
    step = commands.add_parser("step")
    step.add_argument("--run")
    step.add_argument("--expected-revision")
    step.add_argument("--expected-hash")
    step.add_argument("--json", action="store_true")
    finalize = commands.add_parser("finalize")
    finalize.add_argument("--run")
    finalize.add_argument("--expected-revision")
    finalize.add_argument("--expected-hash")
    receipt = commands.add_parser("receipt")
    receipt.add_argument("--run")
    receipt.add_argument("--expected-revision")
    receipt.add_argument("--expected-hash")
    receipt.add_argument("--request-id")
    repair_request = commands.add_parser("repair-request")
    repair_request.add_argument("--run")
    repair_request.add_argument("--expected-revision")
    repair_request.add_argument("--expected-hash")
    repair_request.add_argument("--workspace")
    repair_request.add_argument("--plan")
    repair_request.add_argument("--json", action="store_true")
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


def _run_step(
    args: argparse.Namespace,
    runtime: TrustedRuntimeConfig | None,
    supervisor_factory: Callable[[TrustedRuntimeConfig], _Supervisor] | None,
) -> int:
    if not args.run or args.expected_revision is None or args.expected_hash is None or not args.json:
        print("step: invalid arguments", file=sys.stderr)
        return 2
    try:
        expected_revision = int(args.expected_revision)
        if expected_revision < 1 or _SHA256.fullmatch(args.expected_hash) is None:
            raise ValueError
    except ValueError:
        print("step: invalid arguments", file=sys.stderr)
        return 2
    try:
        trusted_runtime = runtime if runtime is not None else load_launcher_runtime_from_protected_fd()
    except RuntimeConfigurationError:
        print("step: launcher runtime unavailable", file=sys.stderr)
        return 2
    if supervisor_factory is None:
        print("step: launcher composition unavailable", file=sys.stderr)
        return 2
    try:
        result = supervisor_factory(trusted_runtime).step(args.run, expected_revision, args.expected_hash)
    except (SupervisorStateMismatch, ValueError, StateStoreError):
        print("step: expected state does not match", file=sys.stderr)
        return 2
    except Exception:
        print("step: operation unavailable", file=sys.stderr)
        return 2
    print(result.model_dump_json())
    return 0


def _run_finalize(
    args: argparse.Namespace,
    runtime: TrustedRuntimeConfig | None,
    finalizer_factory: Callable[[TrustedRuntimeConfig], _Finalizer] | None,
) -> int:
    if not args.run or args.expected_revision is None or args.expected_hash is None:
        print("finalize: invalid arguments", file=sys.stderr)
        return 2
    try:
        revision = int(args.expected_revision)
        if revision < 1 or _CANONICAL_SHA256.fullmatch(args.expected_hash) is None:
            raise ValueError
        trusted_runtime = runtime if runtime is not None else load_launcher_runtime_from_protected_fd()
        if finalizer_factory is None:
            raise RuntimeConfigurationError("finalizer composition is unavailable")
        store = RunStateStore(trusted_runtime.state_root, args.run)
        generation = store.load()
        require_expected(generation, revision, args.expected_hash)
        result = finalizer_factory(trusted_runtime).advance(generation)
    except (RuntimeConfigurationError, ValueError, StateStoreError, SupervisorStateMismatch):
        print("finalize: expected state does not match", file=sys.stderr)
        return 2
    except Exception:
        print("finalize: operation unavailable", file=sys.stderr)
        return 2
    print(result.model_dump_json())
    return 0


def _run_receipt(
    args: argparse.Namespace,
    runtime: TrustedRuntimeConfig | None,
    receipt_handler: _ReceiptHandler | None,
) -> int:
    if not args.run or args.expected_revision is None or args.expected_hash is None or not args.request_id:
        print("receipt: invalid arguments", file=sys.stderr)
        return 2
    try:
        revision = int(args.expected_revision)
        if revision < 1 or _CANONICAL_SHA256.fullmatch(args.expected_hash) is None:
            raise ValueError
        if str(uuid.UUID(args.request_id)) != args.request_id:
            raise ValueError
        trusted_runtime = runtime if runtime is not None else load_launcher_runtime_from_protected_fd()
        if receipt_handler is None:
            raise RuntimeConfigurationError("receipt handler is unavailable")
        receipt_handler(trusted_runtime, args.run, revision, args.expected_hash, args.request_id)
    except (RuntimeConfigurationError, ValueError, StateStoreError):
        print("receipt: operation unavailable", file=sys.stderr)
        return 2
    except Exception:
        print("receipt: operation unavailable", file=sys.stderr)
        return 2
    return 0


def _run_repair_request(
    args: argparse.Namespace,
    runtime: TrustedRuntimeConfig | None,
    coordinator_factory: Callable[[TrustedRuntimeConfig], _RepairRequestCoordinator] | None,
) -> int:
    if (
        not args.run
        or args.expected_revision is None
        or not args.expected_hash
        or _CANONICAL_SHA256.fullmatch(args.expected_hash) is None
        or not args.workspace
        or not args.plan
        or not args.json
    ):
        print("repair-request: invalid arguments", file=sys.stderr)
        return 2
    try:
        revision = int(args.expected_revision)
        if revision < 1:
            raise ValueError
        trusted_runtime = runtime if runtime is not None else load_launcher_runtime_from_protected_fd()
        coordinator = (
            coordinator_factory(trusted_runtime)
            if coordinator_factory is not None
            else _compose_repair_request_coordinator(trusted_runtime, args.run)
        )
        request = coordinator.create_request(
            args.run,
            revision,
            args.expected_hash,
            Path(args.workspace),
            Path(args.plan),
        )
        content_hash = getattr(request, "content_hash", None)
        if not isinstance(content_hash, str):
            raise ValueError
    except (RuntimeConfigurationError, ValueError, StateStoreError):
        print("repair-request: operation unavailable", file=sys.stderr)
        return 2
    print(json.dumps({"request_hash": content_hash}, sort_keys=True))
    return 0


def _compose_repair_request_coordinator(
    runtime: TrustedRuntimeConfig,
    run_id: str,
) -> _RepairRequestCoordinator:
    if (
        runtime.repair_registry_root is None
        or runtime.repair_runner_identity is None
        or runtime.repair_repository_id is None
    ):
        raise RuntimeConfigurationError("repair coordinator is unavailable")
    from .repair import RepairRequestCoordinator, _open_regular_no_follow
    from .runner import RunnerRegistry

    registry = RunnerRegistry(runtime.repair_registry_root, repair_runner_identity=runtime.repair_runner_identity)
    store = RunStateStore(runtime.state_root, run_id)

    def load_product_manifest(relative_path: str) -> ProductChangeManifest:
        if not isinstance(relative_path, str):
            raise ValueError("product manifest path is invalid")
        path = runtime.project_root / relative_path
        try:
            path.relative_to(runtime.project_root)
            descriptor = _open_regular_no_follow(path)
            with os.fdopen(descriptor, "rb") as stream:
                raw = stream.read(1_048_577)
            if len(raw) > 1_048_576:
                raise ValueError
            payload = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_json_keys)
            if raw != canonical_json_bytes(payload):
                raise ValueError
            return ProductChangeManifest.model_validate(payload)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise RuntimeConfigurationError("product manifest is unavailable") from None

    return RepairRequestCoordinator(
        store,
        load_workspace_handle=registry.load_workspace_handle,
        load_product_manifest=load_product_manifest,
        repair_repository_id=runtime.repair_repository_id,
    )


def main(
    argv: Sequence[str] | None = None,
    runtime: TrustedRuntimeConfig | None = None,
    *,
    prepare_coordinator_factory: Callable[[TrustedRuntimeConfig], _PrepareCoordinator] | None = None,
    supervisor_factory: Callable[[TrustedRuntimeConfig], _Supervisor] | None = None,
    finalizer_factory: Callable[[TrustedRuntimeConfig], _Finalizer] | None = None,
    receipt_handler: _ReceiptHandler | None = None,
    repair_request_coordinator_factory: Callable[[TrustedRuntimeConfig], _RepairRequestCoordinator] | None = None,
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
    if args.command == "step":
        return _run_step(args, runtime, supervisor_factory)
    if args.command == "finalize":
        return _run_finalize(args, runtime, finalizer_factory)
    if args.command == "receipt":
        return _run_receipt(args, runtime, receipt_handler)
    if args.command == "repair-request":
        return _run_repair_request(args, runtime, repair_request_coordinator_factory)
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
