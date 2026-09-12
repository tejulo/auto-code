from __future__ import annotations

import argparse
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import UTC, datetime
import fcntl
import json
import os
from pathlib import Path
import stat
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import RepairRunnerIdentity
from .hashing import canonical_json_bytes
from .repair import RepairError, RepairGuard
from .runner import RepairRunner, TrustedLauncher
from .state import RunStateStore, StateStoreError


_REPAIR_DESCRIPTOR_FD = 3
_MAX_REPAIR_DESCRIPTOR_BYTES = 16_384
# Public trust anchor only. The launcher-owned matching private key is not part of this source tree.
_REPAIR_DESCRIPTOR_VERIFICATION_KEY = bytes.fromhex(
    "d7d968f09d90b953ba08b8e2c4f31eab5c4a634aa412f13f613732b540d253af"
)
_SHA256 = frozenset("0123456789abcdef")


class RepairRuntimeConfigurationError(RuntimeError):
    pass


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _absolute_path(value: object, description: str) -> Path:
    if not isinstance(value, str):
        raise ValueError(f"{description} is invalid")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{description} is invalid")
    return path


def _hash(value: object, description: str) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(character not in _SHA256 for character in value):
        raise ValueError(f"{description} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class RepairRuntimeDescriptor:
    operation: str
    run_id: str
    expected_revision: int
    expected_state_hash: str
    failure_hash: str | None
    workspace_id: str | None
    workspace_path: Path | None
    request_hash: str | None
    repair_runner_identity: RepairRunnerIdentity
    registry_root: Path
    state_root: Path
    repair_repository_root: Path
    repair_workspace_root: Path
    git_executable: Path
    git_executable_hash: str
    regression_command: tuple[str, ...]
    regression_executable_hash: str
    regression_timeout: float
    environment: Mapping[str, str]
    sandbox_policy_hash: str
    expiry: datetime
    nonce: str

    @classmethod
    def from_payload(cls, value: object, *, now: datetime) -> RepairRuntimeDescriptor:
        common = {
            "operation", "run_id", "expected_revision", "expected_state_hash", "repair_runner_identity",
            "registry_root", "state_root", "repair_repository_root", "repair_workspace_root", "git_executable",
            "git_executable_hash", "regression_command", "regression_executable_hash", "regression_timeout",
            "environment", "sandbox_policy_hash", "expiry", "nonce",
        }
        if not isinstance(value, dict) or value.get("operation") not in {"prepare", "apply"}:
            raise ValueError("repair descriptor shape is invalid")
        operation = value["operation"]
        specific = {"failure_hash"} if operation == "prepare" else {"workspace_id", "workspace_path", "request_hash"}
        if set(value) != common | specific:
            raise ValueError("repair descriptor shape is invalid")
        command = value["regression_command"]
        environment = value["environment"]
        if (
            not isinstance(command, list)
            or not command
            or len(command) > 64
            or any(not isinstance(argument, str) or not argument or len(argument) > 4_096 or "\x00" in argument for argument in command)
            or not Path(command[0]).is_absolute()
        ):
            raise ValueError("repair regression command is invalid")
        if (
            not isinstance(environment, dict)
            or len(environment) > 16
            or any(not isinstance(key, str) or not isinstance(item, str) or len(key) > 128 or len(item) > 4_096 for key, item in environment.items())
            or "HOME" in environment
            or "PATH" in environment
        ):
            raise ValueError("repair environment is invalid")
        expiry = datetime.fromisoformat(value["expiry"])
        if expiry.tzinfo is None or expiry <= now:
            raise ValueError("repair descriptor is expired")
        revision = value["expected_revision"]
        timeout = value["regression_timeout"]
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise ValueError("repair expected revision is invalid")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout <= 0 or timeout > 3_600:
            raise ValueError("repair regression timeout is invalid")
        nonce = _hash(value["nonce"], "repair nonce")
        run_id = value["run_id"]
        if not isinstance(run_id, str) or not run_id or len(run_id) > 255:
            raise ValueError("repair run ID is invalid")
        workspace_id = value.get("workspace_id")
        if workspace_id is not None and (not isinstance(workspace_id, str) or not workspace_id or len(workspace_id) > 255):
            raise ValueError("repair workspace ID is invalid")
        return cls(
            operation=operation,
            run_id=run_id,
            expected_revision=revision,
            expected_state_hash=_hash(value["expected_state_hash"], "expected state hash"),
            failure_hash=_hash(value["failure_hash"], "failure hash") if operation == "prepare" else None,
            workspace_id=workspace_id,
            workspace_path=_absolute_path(value["workspace_path"], "repair workspace") if operation == "apply" else None,
            request_hash=_hash(value["request_hash"], "repair request hash") if operation == "apply" else None,
            repair_runner_identity=RepairRunnerIdentity.model_validate(value["repair_runner_identity"]),
            registry_root=_absolute_path(value["registry_root"], "registry root"),
            state_root=_absolute_path(value["state_root"], "state root"),
            repair_repository_root=_absolute_path(value["repair_repository_root"], "repair repository root"),
            repair_workspace_root=_absolute_path(value["repair_workspace_root"], "repair workspace root"),
            git_executable=_absolute_path(value["git_executable"], "git executable"),
            git_executable_hash=_hash(value["git_executable_hash"], "Git executable hash"),
            regression_command=tuple(command),
            regression_executable_hash=_hash(value["regression_executable_hash"], "regression executable hash"),
            regression_timeout=float(timeout),
            environment=dict(environment),
            sandbox_policy_hash=_hash(value["sandbox_policy_hash"], "sandbox policy hash"),
            expiry=expiry,
            nonce=nonce,
        )

    def authorizes(self, operation: str, **bindings: object) -> bool:
        expected: dict[str, object] = {
            "run_id": self.run_id,
            "expected_revision": self.expected_revision,
            "expected_state_hash": self.expected_state_hash,
        }
        if self.operation == "prepare":
            expected["failure_hash"] = self.failure_hash
        else:
            expected.update(
                {
                    "workspace_id": self.workspace_id,
                    "workspace_path": self.workspace_path,
                    "request_hash": self.request_hash,
                }
            )
        normalized = dict(bindings)
        if "workspace_path" in normalized:
            normalized["workspace_path"] = Path(normalized["workspace_path"])
        return operation == self.operation and normalized == expected


@dataclass(frozen=True, slots=True)
class ProtectedRepairRuntime:
    descriptor: RepairRuntimeDescriptor
    runner: RepairRunner | None = None
    launcher: TrustedLauncher | None = None

    def with_capabilities(self, *, runner: RepairRunner, launcher: TrustedLauncher | None = None) -> ProtectedRepairRuntime:
        if runner.repair_runner_identity != self.descriptor.repair_runner_identity:
            raise PermissionError("repair runner capability does not match descriptor")
        if runner.registry.root != self.descriptor.registry_root or runner.state_root != self.descriptor.state_root:
            raise PermissionError("repair runner capability roots do not match descriptor")
        if runner.repair_workspace_root != self.descriptor.repair_workspace_root:
            raise PermissionError("repair workspace capability root does not match descriptor")
        regression = runner.regression
        if (
            not hasattr(regression, "command")
            or tuple(regression.command) != self.descriptor.regression_command
            or regression.timeout != self.descriptor.regression_timeout
            or dict(regression.environment) != dict(self.descriptor.environment)
            or regression.executable_hash != self.descriptor.regression_executable_hash
            or regression.sandbox_policy_hash != self.descriptor.sandbox_policy_hash
        ):
            raise PermissionError("repair regression capability does not match descriptor")
        return replace(self, runner=runner, launcher=launcher)

    def prepare(self, run_id: str, expected_revision: int, expected_state_hash: str, failure_hash: str) -> object:
        if self.runner is None or not self.descriptor.authorizes(
            "prepare",
            run_id=run_id,
            expected_revision=expected_revision,
            expected_state_hash=expected_state_hash,
            failure_hash=failure_hash,
        ):
            raise PermissionError("repair prepare is not authorized")
        generation = RunStateStore.load_read_only(self.descriptor.state_root, run_id)
        if generation.revision != expected_revision or generation.state_hash != expected_state_hash:
            raise PermissionError("repair prepare generation is stale")
        return self.runner.prepare_workspace(generation, failure_hash)

    def apply(self, workspace: str, request_hash: str) -> object:
        if self.runner is None or self.launcher is None:
            raise PermissionError("repair apply capabilities are unavailable")
        workspace_path = _absolute_path(workspace, "repair workspace")
        if not self.descriptor.authorizes(
            "apply",
            run_id=self.descriptor.run_id,
            expected_revision=self.descriptor.expected_revision,
            expected_state_hash=self.descriptor.expected_state_hash,
            workspace_id=workspace_path.name,
            workspace_path=workspace_path,
            request_hash=request_hash,
        ):
            raise PermissionError("repair apply is not authorized")
        request = RepairGuard(workspace_path).load_request(request_hash)
        if (
            request.workspace.id != self.descriptor.workspace_id
            or request.expected_revision != self.descriptor.expected_revision
            or request.expected_state_hash != self.descriptor.expected_state_hash
        ):
            raise PermissionError("repair request does not match descriptor")
        self.runner.validate_regress_build(request)
        return self.launcher.reconcile_activation(request.run_id, request.content_hash)


def load_protected_runtime(*, verification_key: bytes | None = None) -> ProtectedRepairRuntime:
    """Authenticate a one-operation launcher descriptor from fixed read-only FD 3."""
    try:
        descriptor = os.dup(_REPAIR_DESCRIPTOR_FD)
    except OSError as error:
        raise RepairRuntimeConfigurationError("repair descriptor is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        access_mode = fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
        if not stat.S_ISREG(metadata.st_mode) or access_mode != os.O_RDONLY:
            raise RepairRuntimeConfigurationError("repair descriptor is invalid")
        raw = os.pread(descriptor, _MAX_REPAIR_DESCRIPTOR_BYTES + 1, 0)
    except OSError as error:
        raise RepairRuntimeConfigurationError("repair descriptor is invalid") from error
    finally:
        os.close(descriptor)
    if len(raw) > _MAX_REPAIR_DESCRIPTOR_BYTES:
        raise RepairRuntimeConfigurationError("repair descriptor is invalid")
    try:
        envelope = json.loads(raw.decode("ascii"), object_pairs_hook=_reject_duplicate_json_keys)
        if not isinstance(envelope, dict) or set(envelope) != {"payload", "signature"}:
            raise ValueError
        payload = envelope["payload"]
        signature = envelope["signature"]
        if not isinstance(signature, str) or len(signature) != 128:
            raise ValueError
        key = _REPAIR_DESCRIPTOR_VERIFICATION_KEY if verification_key is None else verification_key
        if not isinstance(key, bytes) or len(key) != 32:
            raise ValueError
        Ed25519PublicKey.from_public_bytes(key).verify(bytes.fromhex(signature), canonical_json_bytes(payload))
        return ProtectedRepairRuntime(RepairRuntimeDescriptor.from_payload(payload, now=datetime.now(UTC)))
    except (InvalidSignature, TypeError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise RepairRuntimeConfigurationError("repair descriptor is invalid") from error


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def build_parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="auto-code-repair")
    commands = parser.add_subparsers(dest="command", parser_class=_Parser)
    prepare = commands.add_parser("prepare")
    prepare.add_argument("--run", required=True)
    prepare.add_argument("--expected-revision", required=True)
    prepare.add_argument("--expected-hash", required=True)
    prepare.add_argument("--failure", required=True)
    apply = commands.add_parser("apply")
    apply.add_argument("--workspace", required=True)
    apply.add_argument("--request", required=True)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    runtime: ProtectedRepairRuntime | None = None,
    prepare: Callable[[str, int, str, str], object] | None = None,
    apply: Callable[[str, str], object] | None = None,
) -> int:
    try:
        args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
        protected = runtime if runtime is not None else (None if prepare is not None or apply is not None else load_protected_runtime())
        if args.command == "prepare":
            revision = int(args.expected_revision)
            (prepare if prepare is not None else protected.prepare)(args.run, revision, args.expected_hash, args.failure)
            return 0
        if args.command == "apply":
            (apply if apply is not None else protected.apply)(args.workspace, args.request)
            return 0
    except (RepairRuntimeConfigurationError, RepairError, StateStoreError, ValueError, PermissionError, OSError):
        pass
    print("auto-code-repair: operation unavailable", file=sys.stderr)
    return 2


def entrypoint() -> None:
    raise SystemExit(main())
