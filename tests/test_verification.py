from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path

import pytest

from auto_code.contracts import BuildIdentity, EvidenceRef
from auto_code.hashing import hash_json
from auto_code.process import CommandFailureKind, CommandResult
from auto_code.project_config import (
    AutomationPolicy,
    BrowserPolicy,
    CatalogPreflightPolicy,
    FinalizationPolicy,
    GitPolicy,
    LinearPolicy,
    ProcessPolicy,
    ProjectConfig,
    ReviewPolicy,
    TransportPolicy,
    VerificationPolicy,
)
from auto_code.verification import EmptyVerificationPolicyError, VerificationEvidenceError, VerificationRunner


COMMANDS = (("/bin/check-one",), ("/bin/check-two",), ("/bin/check-three",), ("/bin/check-four",))


def evidence_ref(name: str) -> EvidenceRef:
    return EvidenceRef(
        relative_path=f"verification/{name}.txt",
        sha256=sha256(name.encode("ascii")).hexdigest(),
        media_type="text/plain",
        creator="verification",
    )


def command_result(returncode: int, failure_kind: CommandFailureKind | None = None) -> CommandResult:
    return CommandResult(
        argv=("/bin/check",),
        returncode=returncode,
        stdout_text="",
        stderr_text="",
        stdout_path=evidence_ref(f"stdout-{returncode}"),
        stderr_path=evidence_ref(f"stderr-{returncode}"),
        redacted=True,
        failure_kind=failure_kind,
    )


def failed_result() -> CommandResult:
    return command_result(1, CommandFailureKind.EXIT)


def timeout_result() -> CommandResult:
    return command_result(124, CommandFailureKind.TIMEOUT)


def spawn_result() -> CommandResult:
    return command_result(127, CommandFailureKind.SPAWN)


def passed_result() -> CommandResult:
    return command_result(0)


def config_with_commands(
    commands: tuple[tuple[str, ...], ...],
    *,
    allow_empty: bool = False,
    mutation_commands: tuple[tuple[str, ...], ...] = (),
) -> ProjectConfig:
    return ProjectConfig(
        git=GitPolicy(remote="origin", base_branch=None),
        verification=VerificationPolicy.model_construct(
            commands=commands,
            allow_empty=allow_empty,
            mutation_commands=mutation_commands,
        ),
        browser=BrowserPolicy(
            start_command=None,
            base_url=None,
            ready_timeout_seconds=1,
            command_timeout_seconds=1,
            playwright_command_prefix=("/bin/true",),
            allowed_operations=(),
        ),
        process=ProcessPolicy(command_timeout_seconds=1, termination_grace_seconds=1),
        transport=TransportPolicy(total_retry_wait_seconds=0),
        preflight=CatalogPreflightPolicy(
            catalog_timeout_seconds=1,
            max_catalog_response_bytes=1024,
            catalog_retry_budget=0,
            catalog_cache_validity_seconds=1,
        ),
        finalization=FinalizationPolicy(max_invocations_per_effect=1, total_retry_wait_seconds=0),
        automation=AutomationPolicy(regression_command=("/bin/true",)),
        protected_paths=(".env", ".auto-code", ".git"),
        commit_excluded_paths=(".superpowers",),
        writable_roots=("src",),
        environment_allowlist=(),
        linear=LinearPolicy(started_state_id=None, completed_state_id=None),
        review=ReviewPolicy(),
    )


@dataclass
class RecordingProcess:
    results: tuple[CommandResult, ...] = ()
    argvs: list[tuple[str, ...]] = field(default_factory=list)

    def run(
        self,
        argv: tuple[str, ...],
        cwd: Path,
        timeout: float,
        evidence_sink: object,
        environment: dict[str, str],
        sandbox_policy: object,
    ) -> CommandResult:
        del cwd, timeout, evidence_sink, environment, sandbox_policy
        self.argvs.append(argv)
        return self.results[len(self.argvs) - 1]


class RecordingEvidenceSink:
    def write(self, result: CommandResult) -> CommandResult:
        return result


@dataclass
class VerificationHarness:
    config: ProjectConfig
    process: RecordingProcess
    build: BuildIdentity
    runner: VerificationRunner


@pytest.fixture
def harness(tmp_path: Path) -> VerificationHarness:
    config = config_with_commands(COMMANDS, mutation_commands=(("/bin/mutate",),))
    build = BuildIdentity(
        baseline_sha="a" * 40,
        product_manifest_hash="b" * 64,
        project_policy_hash=config.policy_hash,
        command_hashes={f"check-{index}": hash_json(command) for index, command in enumerate(COMMANDS, start=1)},
        runtime_hash="d" * 64,
    )
    process = RecordingProcess(results=(passed_result(),) * len(COMMANDS))
    return VerificationHarness(
        config=config,
        process=process,
        build=build,
        runner=VerificationRunner(
            config,
            process,
            evidence_sink=RecordingEvidenceSink(),
            sandbox_policy=object(),
            environment={},
            cwd=tmp_path,
            timeout=1,
        ),
    )


def test_run_all_keeps_running_after_exit_timeout_and_spawn_failure(harness: VerificationHarness) -> None:
    harness.process.results = (failed_result(), timeout_result(), spawn_result(), passed_result())

    result = harness.runner.run_all(harness.build)

    assert [check.returncode for check in result.checks] == [1, 124, 127, 0]
    assert harness.process.argvs == list(harness.config.verification.commands)
    assert result.passed is False


def test_empty_verification_requires_explicit_policy_authorization(harness: VerificationHarness) -> None:
    config_values = harness.config.model_dump(round_trip=True)
    config_values["verification"] = VerificationPolicy.model_construct(
        commands=(), allow_empty=False, mutation_commands=()
    )
    harness.config = ProjectConfig.model_construct(**config_values)
    harness.runner = VerificationRunner(
        harness.config,
        harness.process,
        evidence_sink=RecordingEvidenceSink(),
        sandbox_policy=object(),
        environment={},
        cwd=Path.cwd(),
        timeout=1,
    )

    with pytest.raises(EmptyVerificationPolicyError):
        harness.runner.run_all(harness.build)

    harness.config = config_with_commands((), allow_empty=True)
    harness.runner = VerificationRunner(
        harness.config,
        harness.process,
        evidence_sink=RecordingEvidenceSink(),
        sandbox_policy=object(),
        environment={},
        cwd=Path.cwd(),
        timeout=1,
    )

    empty_build = harness.build.model_copy(
        update={"project_policy_hash": harness.config.policy_hash, "command_hashes": {}}
    )
    result = harness.runner.run_all(empty_build)

    assert result.checks == ()
    assert result.empty_authorized is True


def test_verification_result_binds_the_exact_build_identity(harness: VerificationHarness) -> None:
    result = harness.runner.run_all(harness.build)

    assert result.build_identity_hash == hash_json(harness.build.model_dump(mode="json", round_trip=True))


def test_run_all_rejects_missing_evidence_before_creating_a_check(harness: VerificationHarness) -> None:
    harness.process.results = (
        CommandResult(
            argv=("/bin/check",),
            returncode=0,
            stdout_text="",
            stderr_text="",
            stdout_path=None,
            stderr_path=evidence_ref("stderr-missing-stdout"),
            redacted=True,
        ),
    ) + (passed_result(),) * 3

    with pytest.raises(VerificationEvidenceError):
        harness.runner.run_all(harness.build)

    assert harness.process.argvs == [COMMANDS[0]]


def test_run_all_rejects_an_unbound_build_before_running_commands(harness: VerificationHarness) -> None:
    with pytest.raises(TypeError):
        harness.runner.run_all(object())  # type: ignore[arg-type]

    assert harness.process.argvs == []


def test_run_all_rejects_a_build_from_another_project_policy_before_running_commands(
    harness: VerificationHarness,
) -> None:
    mismatched_build = harness.build.model_copy(update={"project_policy_hash": "0" * 64})

    with pytest.raises(ValueError, match="Project Policy"):
        harness.runner.run_all(mismatched_build)

    assert harness.process.argvs == []


def test_run_all_rejects_a_build_with_an_incomplete_command_mapping_before_running_commands(
    harness: VerificationHarness,
) -> None:
    mismatched_build = harness.build.model_copy(
        update={"command_hashes": {"check-1": hash_json(COMMANDS[0])}}
    )

    with pytest.raises(ValueError, match="commands"):
        harness.runner.run_all(mismatched_build)

    assert harness.process.argvs == []
