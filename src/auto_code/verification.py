from __future__ import annotations

from collections.abc import Mapping
import math
from pathlib import Path

from .contracts import BuildIdentity, EvidenceRef, VerificationCheck, VerificationResult
from .hashing import hash_json
from .process import EvidenceSink, ProcessRunner, SandboxPolicy
from .project_config import ProjectConfig


class EmptyVerificationPolicyError(ValueError):
    pass


class VerificationEvidenceError(ValueError):
    pass


class VerificationRunner:
    def __init__(
        self,
        config: ProjectConfig,
        process: ProcessRunner,
        evidence_sink: EvidenceSink,
        sandbox_policy: SandboxPolicy,
        environment: Mapping[str, str],
        cwd: Path,
        timeout: float,
    ) -> None:
        if not isinstance(config, ProjectConfig):
            raise ValueError("Verification requires a Project Policy")
        if not callable(getattr(process, "run", None)):
            raise ValueError("Verification requires a process runner")
        if not callable(getattr(evidence_sink, "write", None)):
            raise ValueError("Verification requires an evidence sink")
        if sandbox_policy is None:
            raise ValueError("Verification requires a sandbox policy")
        if (
            not isinstance(environment, Mapping)
            or any(not isinstance(name, str) or not isinstance(value, str) for name, value in environment.items())
        ):
            raise ValueError("Verification requires an explicit environment")
        if not isinstance(cwd, Path) or not cwd.is_absolute():
            raise ValueError("Verification requires an absolute working directory")
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("Verification requires a positive timeout")
        self._config = config
        self._process = process
        self._evidence_sink = evidence_sink
        self._sandbox_policy = sandbox_policy
        self._environment = dict(environment)
        self._cwd = cwd
        self._timeout = float(timeout)

    def run_all(self, build: BuildIdentity) -> VerificationResult:
        if not isinstance(build, BuildIdentity):
            raise TypeError("Verification requires a Build Identity")
        commands = self._config.verification.commands
        if not commands and not self._config.verification.allow_empty:
            raise EmptyVerificationPolicyError("Verification commands are required")
        if build.project_policy_hash != self._config.policy_hash:
            raise ValueError("Build Identity does not match the Project Policy")
        expected_commands = tuple(
            (f"check-{index}", hash_json(argv)) for index, argv in enumerate(commands, start=1)
        )
        if tuple(build.command_hashes.items()) != expected_commands:
            raise ValueError("Build Identity commands do not match configured verification commands")

        checks: list[VerificationCheck] = []
        for index, argv in enumerate(commands, start=1):
            result = self._process.run(
                argv,
                self._cwd,
                self._timeout,
                self._evidence_sink,
                self._environment,
                self._sandbox_policy,
            )
            if not isinstance(result.stdout_path, EvidenceRef) or not isinstance(result.stderr_path, EvidenceRef):
                raise VerificationEvidenceError("Verification command has no immutable evidence")
            checks.append(
                VerificationCheck(
                    command_id=f"check-{index}",
                    command_hash=hash_json(argv),
                    returncode=result.returncode,
                    failure_kind=None if result.failure_kind is None else result.failure_kind.value,
                    stdout_evidence=result.stdout_path,
                    stderr_evidence=result.stderr_path,
                )
            )

        return VerificationResult.model_validate(
            {
                "build_identity_hash": hash_json(build.model_dump(mode="json", round_trip=True)),
                "checks": tuple(checks),
                "passed": all(check.returncode == 0 for check in checks),
                "empty_authorized": not checks,
            },
            context={"build_identity": build},
        )
