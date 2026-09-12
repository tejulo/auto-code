from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
import re
from typing import Annotated, Protocol
from urllib.parse import urlsplit

from crewai.tools import ToolFailurePolicy
from crewai.tools.base_tool import BaseTool
from pydantic import BaseModel, ConfigDict, Field, StringConstraints, ValidationError, model_validator

from .contracts import (
    BrowserE2EDecision,
    BrowserResult,
    BrowserResultStatus,
    BuildIdentity,
    EvidenceRef,
    FailureClass,
    FailureRecord,
    FailureSource,
    FindingKind,
    InvalidUnitOutput,
    Stage,
)
from .crew import CrewRunner, UnitContext
from .hashing import hash_json
from .process import EvidenceSink, ManagedProcessRunner, ProcessRunner, SandboxPolicy
from .project_config import ProjectConfig
from .tool_broker import MAX_NATIVE_TOOL_CALLS, ToolAccessDenied, ToolManifest


_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z")
_OPERATION_ARGUMENTS = {
    "open": (),
    "goto": ("url",),
    "snapshot": (),
    "click": ("target",),
    "fill": ("target", "value"),
    "type": ("target", "value"),
    "press": ("target", "value"),
    "screenshot": (),
    "close": (),
}


class PlaywrightAccessError(PermissionError):
    """A model request exceeds the fixed local Playwright capability."""


class BrowserEvidenceCapability(Protocol):
    """Mint and verify the persisted skip evidence for one browser run."""

    def mint_skipped(self, run_id: str) -> EvidenceRef: ...

    def verify_skipped(self, run_id: str, evidence: EvidenceRef) -> bool: ...


@dataclass(frozen=True)
class _CleanupResult:
    failed: bool
    evidence: tuple[EvidenceRef, ...]


class PlaywrightOperation(BaseModel):
    """One bounded Playwright CLI operation with no caller-controlled session data."""

    model_config = ConfigDict(extra="forbid", strict=True)

    operation: Annotated[str, StringConstraints(min_length=1, max_length=32)]
    url: Annotated[str, StringConstraints(min_length=1, max_length=2_048)] | None = None
    target: Annotated[str, StringConstraints(min_length=1, max_length=1_024)] | None = None
    value: Annotated[str, StringConstraints(min_length=1, max_length=4_096)] | None = None

    @model_validator(mode="after")
    def validate_arguments(self) -> PlaywrightOperation:
        required = _OPERATION_ARGUMENTS.get(self.operation)
        if required is None:
            return self
        supplied = tuple(name for name in ("url", "target", "value") if getattr(self, name) is not None)
        if supplied != required:
            raise ValueError("Playwright operation arguments are not authorized")
        if any(argument is not None and argument.startswith("-") for argument in (self.target, self.value)):
            raise ValueError("Playwright operation arguments are not authorized")
        return self

    def arguments(self) -> tuple[str, ...]:
        return tuple(getattr(self, name) for name in _OPERATION_ARGUMENTS.get(self.operation, ()))


class _PlaywrightTool(BaseTool):
    model_config = ConfigDict(arbitrary_types_allowed=True, extra="forbid")

    name: str = "playwright"
    description: str = "Run one fixed Playwright CLI operation against the configured localhost application."
    args_schema: type[BaseModel] = PlaywrightOperation
    tools: LocalPlaywrightTools = Field(exclude=True)
    max_usage_count: int = MAX_NATIVE_TOOL_CALLS
    tool_failure_policy: ToolFailurePolicy = ToolFailurePolicy.RAISE

    def _run(
        self,
        operation: str,
        url: str | None = None,
        target: str | None = None,
        value: str | None = None,
    ) -> str:
        return self.tools._run_operation(operation, url, target, value)


class LocalPlaywrightTools:
    """Expose the single localhost-only Playwright tool for a trusted run."""

    def __init__(
        self,
        config: ProjectConfig,
        process: ProcessRunner,
        *,
        evidence_sink: EvidenceSink,
        sandbox_policy: SandboxPolicy,
        environment: Mapping[str, str],
        cwd: Path,
        run_id: str,
    ) -> None:
        if not isinstance(config, ProjectConfig):
            raise ValueError("Playwright tools require a Project Policy")
        if not callable(getattr(process, "run", None)):
            raise ValueError("Playwright tools require a process runner")
        if not isinstance(environment, Mapping) or any(
            not isinstance(name, str) or not isinstance(value, str) for name, value in environment.items()
        ):
            raise ValueError("Playwright tools require an explicit environment")
        if not isinstance(cwd, Path):
            raise ValueError("Playwright tools require a working directory")
        if not isinstance(run_id, str) or _RUN_ID.fullmatch(run_id) is None or run_id in {".", ".."}:
            raise ValueError("Playwright tools require a safe run ID")
        self._policy = config.browser
        self._process = process
        self._evidence_sink = evidence_sink
        self._sandbox_policy = sandbox_policy
        self._environment = dict(environment)
        self._cwd = cwd
        self._run_id = run_id
        self._session_name = f"run-{run_id}"
        self._timeout = float(config.browser.command_timeout_seconds)
        self._evidence: list[EvidenceRef] = []

    @property
    def run_id(self) -> str:
        return self._run_id

    @property
    def evidence_sink(self) -> EvidenceSink:
        return self._evidence_sink

    def begin_run(self, run_id: str) -> None:
        if run_id != self._run_id:
            raise PlaywrightAccessError("Playwright tools are bound to another run")
        self._evidence.clear()

    def evidence_for_run(self, run_id: str) -> tuple[EvidenceRef, ...]:
        if run_id != self._run_id:
            raise PlaywrightAccessError("Playwright tools are bound to another run")
        return tuple(self._evidence)

    def for_manifest(self, manifest: ToolManifest) -> tuple[BaseTool, ...]:
        if not isinstance(manifest, ToolManifest):
            raise ToolAccessDenied("Tool manifests must use the bounded manifest contract")
        return (_PlaywrightTool(tools=self),)

    def _run_operation(
        self,
        operation: str,
        url: str | None = None,
        target: str | None = None,
        value: str | None = None,
    ) -> str:
        try:
            request = PlaywrightOperation(operation=operation, url=url, target=target, value=value)
        except ValidationError as error:
            raise PlaywrightAccessError("Playwright operation arguments are not authorized") from error
        if request.operation not in self._policy.allowed_operations:
            raise PlaywrightAccessError("Playwright operation is not authorized")
        if request.url is not None and not _is_policy_local_url(request.url, self._policy.base_url):
            raise PlaywrightAccessError("Playwright URL is not authorized")
        argv = (
            *self._policy.playwright_command_prefix,
            request.operation,
            "--session",
            self._session_name,
            *request.arguments(),
        )
        try:
            result = self._process.run(
                argv,
                self._cwd,
                self._timeout,
                self._evidence_sink,
                self._environment,
                self._sandbox_policy,
            )
        except BaseException as error:
            self._capture_evidence(getattr(error, "result", None))
            raise
        self._capture_evidence(result)
        return result.require_success().stdout_text

    def _capture_evidence(self, result: object) -> None:
        for reference in (getattr(result, "stdout_path", None), getattr(result, "stderr_path", None)):
            if isinstance(reference, EvidenceRef) and reference not in self._evidence:
                self._evidence.append(reference)


class BrowserRunner:
    """Run the policy-bound localhost lifecycle around one Tester execution."""

    def __init__(
        self,
        config: ProjectConfig,
        process_runner: ManagedProcessRunner,
        playwright_tools: LocalPlaywrightTools,
        crew_runner: CrewRunner,
        *,
        evidence_sink: EvidenceSink,
        sandbox_policy: SandboxPolicy,
        environment: Mapping[str, str],
        cwd: Path,
        skip_evidence: BrowserEvidenceCapability,
    ) -> None:
        if not isinstance(config, ProjectConfig):
            raise ValueError("Browser runner requires a Project Policy")
        if not callable(getattr(process_runner, "start", None)):
            raise ValueError("Browser runner requires a managed process runner")
        if (
            not callable(getattr(playwright_tools, "_run_operation", None))
            or not callable(getattr(playwright_tools, "begin_run", None))
            or not callable(getattr(playwright_tools, "evidence_for_run", None))
            or not isinstance(getattr(playwright_tools, "run_id", None), str)
        ):
            raise ValueError("Browser runner requires restricted Playwright tools")
        if not callable(getattr(crew_runner, "run", None)):
            raise ValueError("Browser runner requires a Crew runner")
        if not isinstance(environment, Mapping) or any(
            not isinstance(name, str) or not isinstance(value, str) for name, value in environment.items()
        ):
            raise ValueError("Browser runner requires an explicit environment")
        if not isinstance(cwd, Path):
            raise ValueError("Browser runner requires a working directory")
        if not callable(getattr(skip_evidence, "mint_skipped", None)) or not callable(
            getattr(skip_evidence, "verify_skipped", None)
        ):
            raise ValueError("Browser runner requires a per-run skipped-result evidence capability")
        if getattr(playwright_tools, "evidence_sink", None) is not evidence_sink:
            raise ValueError("Browser runner and Playwright tools must share one evidence sink")
        self._config = config
        self._managed = process_runner
        self._playwright_tools = playwright_tools
        self._crew = crew_runner
        self._evidence_sink = evidence_sink
        self._sandbox_policy = sandbox_policy
        self._environment = dict(environment)
        self._cwd = cwd
        self._skip_evidence = skip_evidence
        self._timeout = float(config.browser.command_timeout_seconds)
        self._readiness_timeout = float(config.browser.ready_timeout_seconds)

    def run(
        self,
        decision: BrowserE2EDecision,
        build: BuildIdentity,
        run_id: str,
        ticket_id: str,
    ) -> BrowserResult | FailureRecord:
        if not isinstance(decision, BrowserE2EDecision) or not isinstance(build, BuildIdentity):
            raise ValueError("Browser runner requires a declared decision and Build Identity")
        if not isinstance(run_id, str) or not run_id:
            raise ValueError("Browser runner requires a run ID")
        if not isinstance(ticket_id, str) or not ticket_id:
            raise ValueError("Browser runner requires a ticket ID")
        if self._playwright_tools.run_id != run_id:
            return self._orchestration_failure(())
        if not decision.required:
            return self._skipped_result(decision, build, run_id)
        if self._config.browser.start_command is None or self._config.browser.base_url is None:
            return self._ambiguity_failure()

        process: object | None = None
        primary: BrowserResult | FailureRecord | None = None
        cleanup = _CleanupResult(failed=False, evidence=())
        try:
            self._playwright_tools.begin_run(run_id)
            process = self._managed.start(
                self._config.browser.start_command,
                self._cwd,
                self._timeout,
                self._evidence_sink,
                self._environment,
                self._sandbox_policy,
                readiness=self._ready,
                readiness_timeout=self._readiness_timeout,
            )
            primary = self._tester_result(decision, build, run_id)
        except BaseException as error:
            process = process or self._startup_process(error)
            primary = self._orchestration_failure(self._exception_evidence(error))
        finally:
            cleanup = self._cleanup(process)

        assert primary is not None
        evidence = self._unique_evidence(
            (*self._run_evidence(run_id), *self._failure_evidence(primary), *cleanup.evidence)
        )
        if cleanup.failed:
            return self._orchestration_failure(evidence)
        return self._bind_run_evidence(primary, evidence, decision, build)

    def _ready(self, process: object) -> bool:
        del process
        base_url = self._config.browser.base_url
        assert base_url is not None
        self._playwright_tools._run_operation("goto", base_url)
        return True

    def _tester_result(self, decision: BrowserE2EDecision, build: BuildIdentity, run_id: str) -> BrowserResult | FailureRecord:
        result = self._crew.run(
            Stage.TESTER,
            UnitContext.for_browser_tester(decision, build, run_id),
            tester_adapter=self._playwright_tools,
        )
        if isinstance(result, InvalidUnitOutput) or not isinstance(result, BrowserResult):
            return self._orchestration_failure(())
        try:
            validated = BrowserResult.model_validate(
                result.model_dump(mode="json", round_trip=True),
                context=self._context(decision, build),
            )
        except ValidationError:
            return self._orchestration_failure(())
        if validated.status is BrowserResultStatus.FAILED:
            return FailureRecord(
                failure_class=FailureClass.PRODUCT,
                failure_source=FailureSource.BROWSER,
                finding_kind=FindingKind.SCENARIO_MISMATCH,
                owner_stage=Stage.PROGRAMMER,
                cited_ids=tuple(
                    observation.scenario_id for observation in validated.scenario_observations if observation.status.value == "failed"
                ),
                evidence_refs=(),
            )
        return validated

    def _cleanup(self, process: object | None) -> _CleanupResult:
        errors: list[EvidenceRef] = []
        failed = False
        try:
            self._playwright_tools._run_operation("close")
        except BaseException as error:
            failed = True
            errors.extend(self._exception_evidence(error))
        if process is not None:
            try:
                stop_and_reap = getattr(process, "stop_and_reap", None)
                if not callable(stop_and_reap):
                    raise TypeError("Managed process lacks stop_and_reap")
                errors.extend(self._command_evidence(stop_and_reap()))
            except BaseException as error:
                failed = True
                errors.extend(self._exception_evidence(error))
        return _CleanupResult(failed=failed, evidence=self._unique_evidence(tuple(errors)))

    def _run_evidence(self, run_id: str) -> tuple[EvidenceRef, ...]:
        try:
            evidence = self._playwright_tools.evidence_for_run(run_id)
        except BaseException:
            return ()
        return tuple(reference for reference in evidence if isinstance(reference, EvidenceRef))

    def _bind_run_evidence(
        self,
        primary: BrowserResult | FailureRecord,
        evidence: tuple[EvidenceRef, ...],
        decision: BrowserE2EDecision,
        build: BuildIdentity,
    ) -> BrowserResult | FailureRecord:
        if not evidence:
            return self._orchestration_failure(())
        if isinstance(primary, FailureRecord):
            return primary.model_copy(update={"evidence_refs": evidence})
        payload = primary.model_dump(mode="json", round_trip=True)
        serialized_evidence = [reference.model_dump(mode="json") for reference in evidence]
        payload["evidence"] = serialized_evidence
        payload["scenario_observations"] = [
            {**observation, "evidence": serialized_evidence} for observation in payload["scenario_observations"]
        ]
        try:
            return BrowserResult.model_validate(payload, context=self._context(decision, build))
        except ValidationError:
            return self._orchestration_failure(evidence)

    @staticmethod
    def _startup_process(error: BaseException) -> object | None:
        current: BaseException | None = error
        visited: set[int] = set()
        while current is not None and id(current) not in visited:
            visited.add(id(current))
            for name in ("process", "managed_process", "resource", "handle"):
                process = getattr(current, name, None)
                if callable(getattr(process, "stop_and_reap", None)):
                    return process
            cause = current.__cause__ or current.__context__
            current = cause if isinstance(cause, BaseException) else None
        return None

    @staticmethod
    def _context(decision: BrowserE2EDecision, build: BuildIdentity) -> dict[str, object]:
        return {"browser_e2e_decision": decision, "build_identity": build}

    @staticmethod
    def _orchestration_failure(evidence: tuple[EvidenceRef, ...]) -> FailureRecord:
        return FailureRecord(
            failure_class=FailureClass.ORCHESTRATION,
            failure_source=FailureSource.BROWSER,
            finding_kind=FindingKind.INVALID_UNIT_OUTPUT,
            evidence_refs=evidence,
        )

    @staticmethod
    def _ambiguity_failure() -> FailureRecord:
        return FailureRecord(
            failure_class=FailureClass.AMBIGUITY,
            failure_source=FailureSource.BROWSER,
            finding_kind=FindingKind.REQUIREMENTS_MISMATCH,
        )

    @staticmethod
    def _exception_evidence(error: BaseException) -> tuple[EvidenceRef, ...]:
        return BrowserRunner._command_evidence(getattr(error, "result", None))

    @staticmethod
    def _command_evidence(result: object) -> tuple[EvidenceRef, ...]:
        refs = tuple(
            reference
            for reference in (getattr(result, "stdout_path", None), getattr(result, "stderr_path", None))
            if isinstance(reference, EvidenceRef)
        )
        return refs

    @staticmethod
    def _failure_evidence(result: BrowserResult | FailureRecord) -> tuple[EvidenceRef, ...]:
        return result.evidence_refs if isinstance(result, FailureRecord) else ()

    @staticmethod
    def _unique_evidence(evidence: tuple[EvidenceRef, ...]) -> tuple[EvidenceRef, ...]:
        return tuple(dict.fromkeys(evidence))

    def _skipped_result(
        self,
        decision: BrowserE2EDecision,
        build: BuildIdentity,
        run_id: str,
    ) -> BrowserResult | FailureRecord:
        try:
            evidence = self._skip_evidence.mint_skipped(run_id)
            if not isinstance(evidence, EvidenceRef) or self._skip_evidence.verify_skipped(run_id, evidence) is not True:
                return self._orchestration_failure(())
            return BrowserResult.model_validate(
                self._skipped_payload(decision, build, evidence), context=self._context(decision, build)
            )
        except BaseException as error:
            return self._orchestration_failure(self._exception_evidence(error))

    @staticmethod
    def _skipped_payload(
        decision: BrowserE2EDecision,
        build: BuildIdentity,
        evidence: EvidenceRef,
    ) -> dict[str, object]:
        decision_hash = hash_json(decision.model_dump(mode="json", round_trip=True))
        build_hash = hash_json(build.model_dump(mode="json", round_trip=True))
        return {
            "status": "skipped",
            "browser_e2e_decision_hash": decision_hash,
            "build_identity_hash": build_hash,
            "reason": decision.reason,
            "scenario_observations": (),
            "evidence": (evidence,),
        }


def _is_policy_local_url(url: str, base_url: str | None) -> bool:
    if base_url is None:
        return False
    try:
        candidate = urlsplit(url)
        policy = urlsplit(base_url)
        return (
            candidate.scheme == policy.scheme
            and candidate.hostname == policy.hostname
            and candidate.port == policy.port
            and candidate.username is None
            and candidate.password is None
            and not candidate.query
            and not candidate.fragment
        )
    except ValueError:
        return False
