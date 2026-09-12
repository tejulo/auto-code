from __future__ import annotations

import argparse
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
import fcntl
import json
import os
from pathlib import Path
import stat
import sys

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .contracts import RepairRunnerIdentity, RunnerIdentity, Stage
from .hashing import canonical_json_bytes
from .repair import InjectedCrash, RepairRequest, UnauthorizedRepairError
from .runner import RepairGit, RepairProcess, RepairRunner, RepairWorktreeFactory, RunnerActivationReceipt, RunnerRegistry
from .state import _atomic_replace_json, _path_lstat, _write_new_json


_REPAIR_DESCRIPTOR_FD = 3
_MAX_REPAIR_DESCRIPTOR_BYTES = 4096
# The launcher retains the matching private key; the ticket runner cannot forge descriptors.
_REPAIR_DESCRIPTOR_VERIFICATION_KEY = bytes.fromhex("0a55062008f88995434a07485256644f2592b450393917b801158047b61b0bcd")


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
    path = Path(value)
    if not isinstance(value, str) or not path.is_absolute() or ".." in path.parts:
        raise ValueError(f"{description} is invalid")
    return path


@dataclass(frozen=True, slots=True)
class RepairRuntimeDescriptor:
    repair_runner_identity: RepairRunnerIdentity
    registry_root: Path
    state_root: Path
    repair_workspace_root: Path
    regression_command: tuple[str, ...]
    expiry: datetime
    nonce: str

    @classmethod
    def from_payload(cls, value: object, *, now: datetime) -> RepairRuntimeDescriptor:
        if not isinstance(value, dict) or set(value) != {
            "repair_runner_identity",
            "registry_root",
            "state_root",
            "repair_workspace_root",
            "regression_command",
            "expiry",
            "nonce",
        }:
            raise ValueError("repair descriptor shape is invalid")
        command = value["regression_command"]
        if not isinstance(command, list) or not command or any(
            not isinstance(argument, str) or not argument or "\x00" in argument for argument in command
        ):
            raise ValueError("repair regression command is invalid")
        nonce = value["nonce"]
        if not isinstance(nonce, str) or len(nonce) != 64 or any(character not in "0123456789abcdef" for character in nonce):
            raise ValueError("repair descriptor nonce is invalid")
        expiry = datetime.fromisoformat(value["expiry"])
        if expiry.tzinfo is None or expiry <= now:
            raise ValueError("repair descriptor is expired")
        return cls(
            repair_runner_identity=RepairRunnerIdentity.model_validate(value["repair_runner_identity"]),
            registry_root=_absolute_path(value["registry_root"], "registry root"),
            state_root=_absolute_path(value["state_root"], "state root"),
            repair_workspace_root=_absolute_path(value["repair_workspace_root"], "repair workspace root"),
            regression_command=tuple(command),
            expiry=expiry,
            nonce=nonce,
        )


@dataclass(frozen=True, slots=True)
class ProtectedRepairRuntime:
    """Runtime authority assembled only after descriptor verification at this executable boundary."""

    descriptor: RepairRuntimeDescriptor

    def compose_runner(
        self,
        *,
        worktree_factory: RepairWorktreeFactory,
        git: RepairGit,
        process: RepairProcess,
        now: Callable[[], datetime] | None = None,
    ) -> RepairRunner:
        """Build the sole repair runner that can receive the activation closure."""
        registry = RunnerRegistry(
            self.descriptor.registry_root,
            repair_runner_identity=self.descriptor.repair_runner_identity,
        )
        return RepairRunner(
            worktree_factory=worktree_factory,
            git=git,
            process=process,
            registry=registry,
            repair_runner_identity=self.descriptor.repair_runner_identity,
            activate=_compose_activation(registry),
            now=now,
        )

    def prepare(self, run_id: str, failure_hash: str) -> object:
        raise PermissionError("protected repair composition is unavailable")

    def apply(self, workspace: str, request_hash: str) -> object:
        raise PermissionError("protected repair composition is unavailable")


def _compose_activation(
    registry: RunnerRegistry,
) -> Callable[[RepairRequest, RunnerIdentity], RunnerActivationReceipt]:
    """Keep the registry writer reachable only from this protected executable module."""
    def activate(request: RepairRequest, new_runner_identity: RunnerIdentity) -> RunnerActivationReceipt:
        path = registry.activation_path(request.content_hash)
        if _path_lstat(path, "runner activation receipt") is not None:
            existing = registry.lookup_activation(request.content_hash)
            if existing.old_runner_identity != request.old_runner_identity or existing.new_runner_identity != new_runner_identity:
                raise UnauthorizedRepairError("activation replay does not match its request")
            return existing
        receipt = RunnerActivationReceipt(
            request_hash=request.content_hash,
            old_runner_identity=request.old_runner_identity,
            new_runner_identity=new_runner_identity,
            old_contract_bundle_hash=request.old_runner_identity.contract_bundle_hash,
            new_contract_bundle_hash=new_runner_identity.contract_bundle_hash,
            compatible_checkpoint_stages=(
                tuple(Stage)
                if request.old_runner_identity.contract_bundle_hash == new_runner_identity.contract_bundle_hash
                else ()
            ),
            contract_hashes=dict(request.contract_hashes),
        )
        if not _write_new_json(path, receipt.payload()):
            return registry.lookup_activation(request.content_hash)
        _atomic_replace_json(registry.pointer_path, {"request_hash": request.content_hash})
        if registry._crash_marker == "REGISTRY_POINTER_REPLACED":
            registry._crash_marker = None
            raise InjectedCrash("injected crash after registry pointer replacement")
        return receipt

    return activate


def load_protected_runtime() -> ProtectedRepairRuntime:
    """Read and authenticate the launcher descriptor from a fixed read-only FD."""
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
        Ed25519PublicKey.from_public_bytes(_REPAIR_DESCRIPTOR_VERIFICATION_KEY).verify(
            bytes.fromhex(signature), canonical_json_bytes(payload)
        )
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
    prepare.add_argument("--failure", required=True)
    apply = commands.add_parser("apply")
    apply.add_argument("--workspace", required=True)
    apply.add_argument("--request", required=True)
    return parser


def main(
    argv: Sequence[str] | None = None,
    *,
    prepare: Callable[[str, str], object] | None = None,
    apply: Callable[[str, str], object] | None = None,
) -> int:
    try:
        args = build_parser().parse_args(sys.argv[1:] if argv is None else argv)
        runtime = None if prepare is not None or apply is not None else load_protected_runtime()
        if args.command == "prepare":
            (prepare if prepare is not None else runtime.prepare)(args.run, args.failure)
            return 0
        if args.command == "apply":
            (apply if apply is not None else runtime.apply)(args.workspace, args.request)
            return 0
    except (RepairRuntimeConfigurationError, ValueError, PermissionError):
        pass
    print("auto-code-repair: operation unavailable", file=sys.stderr)
    return 2


def entrypoint() -> None:
    raise SystemExit(main())
