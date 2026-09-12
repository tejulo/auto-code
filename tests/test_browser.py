from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from auto_code.browser import BrowserRunner, LocalPlaywrightTools, PlaywrightAccessError
from auto_code.contracts import (
    BrowserE2EDecision,
    BrowserResult,
    BrowserScenario,
    BuildIdentity,
    EvidenceRef,
    FailureClass,
    FailureRecord,
    FailureSource,
    FindingKind,
    Stage,
)
from auto_code.crew import CrewRunner
from auto_code.hashing import hash_json
from auto_code.process import CommandResult
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
from auto_code.tool_broker import ToolBroker, ToolManifest


@dataclass
class RecordingProcess:
    argvs: list[tuple[str, ...]] = field(default_factory=list)
    stdout_path: EvidenceRef | None = None
    stderr_path: EvidenceRef | None = None

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
        return CommandResult(
            argv=argv,
            returncode=0,
            stdout_text="browser output",
            stderr_text="",
            stdout_path=self.stdout_path,
            stderr_path=self.stderr_path,
            redacted=True,
        )


def browser_config() -> ProjectConfig:
    return ProjectConfig(
        git=GitPolicy(remote="origin", base_branch=None),
        verification=VerificationPolicy(commands=(("/bin/true",),)),
        browser=BrowserPolicy(
            start_command=("/bin/server",),
            base_url="http://localhost:4173",
            ready_timeout_seconds=1,
            command_timeout_seconds=1,
            playwright_command_prefix=("/bin/playwright",),
            allowed_operations=("goto", "close", "click", "fill"),
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
class PlaywrightHarness:
    config: ProjectConfig
    process: RecordingProcess
    tools: LocalPlaywrightTools


@dataclass
class RecordingManagedProcess:
    stopped: int = 0
    fail_stop: bool = False
    cleanup_result: CommandResult | None = None

    def stop_and_reap(self) -> CommandResult | None:
        self.stopped += 1
        if self.fail_stop:
            raise RuntimeError("process cleanup failed")
        return self.cleanup_result


@dataclass
class RecordingManagedRunner:
    starts: list[tuple[tuple[str, ...], Path]] = field(default_factory=list)
    process: RecordingManagedProcess = field(default_factory=RecordingManagedProcess)
    start_error: BaseException | None = None

    def start(
        self,
        argv: tuple[str, ...],
        cwd: Path,
        timeout: float,
        evidence_sink: object,
        environment: dict[str, str],
        sandbox_policy: object,
        *,
        readiness: object,
        readiness_timeout: float | None = None,
    ) -> RecordingManagedProcess:
        del timeout, evidence_sink, environment, sandbox_policy, readiness_timeout
        self.starts.append((argv, cwd))
        if self.start_error is not None:
            raise self.start_error
        assert callable(readiness)
        readiness(self.process)
        return self.process


@dataclass
class RecordingPlaywrightTools:
    calls: list[tuple[str, str | None]] = field(default_factory=list)
    run_id: str = "run-1"
    evidence_sink: object = field(default_factory=object)
    evidence: list[EvidenceRef] = field(default_factory=list)
    fail_close: bool = False

    def begin_run(self, run_id: str) -> None:
        if run_id != self.run_id:
            raise ValueError("wrong browser run")
        self.evidence.clear()

    def evidence_for_run(self, run_id: str) -> tuple[EvidenceRef, ...]:
        if run_id != self.run_id:
            raise ValueError("wrong browser run")
        return tuple(self.evidence)

    def _run_operation(self, operation: str, url: str | None = None) -> str:
        self.calls.append((operation, url))
        self.evidence.append(actual_browser_evidence(operation))
        if operation == "close" and self.fail_close:
            raise RuntimeError("session close failed")
        return "ok"


@dataclass
class RecordingCrew:
    result: object
    calls: list[tuple[Stage, object]] = field(default_factory=list)

    def run(self, stage: Stage, context: object, *, tester_adapter: object | None = None) -> object:
        del tester_adapter
        self.calls.append((stage, context))
        return self.result


@dataclass
class IntegrationModels:
    calls: list[tuple[object, str]] = field(default_factory=list)

    def for_role(self, role: object, session_id: str) -> object:
        self.calls.append((role, session_id))
        return object()


@dataclass
class IntegrationBroker:
    calls: list[tuple[Stage, object]] = field(default_factory=list)

    def for_stage(self, stage: Stage, manifest: object, **kwargs: object) -> tuple[object, ...]:
        del kwargs
        self.calls.append((stage, manifest))
        return ()


@dataclass(frozen=True)
class IntegrationAgentResult:
    raw: str


class IntegrationAgent:
    instances: list[IntegrationAgent] = []
    raw: str = ""

    def __init__(self, **kwargs: object) -> None:
        self.kwargs = kwargs
        self.prompts: list[str] = []
        type(self).instances.append(self)

    def kickoff(self, prompt: str) -> IntegrationAgentResult:
        self.prompts.append(prompt)
        return IntegrationAgentResult(type(self).raw)


@dataclass
class BrowserHarness:
    runner: BrowserRunner
    managed: RecordingManagedRunner
    playwright: RecordingPlaywrightTools
    crew: RecordingCrew
    build: BuildIdentity
    evidence_sink: object
    skip_evidence: RecordingSkipEvidence


def required_decision() -> BrowserE2EDecision:
    return BrowserE2EDecision(
        required=True,
        reason="The changed browser flow must be verified.",
        scenarios=(
            BrowserScenario(
                scenario_id="BROWSER-1",
                description="Open the changed browser flow.",
                expected_result="The requested result is visible.",
            ),
        ),
    )


def optional_decision() -> BrowserE2EDecision:
    return BrowserE2EDecision(required=False, reason="Browser validation is not required.", scenarios=())


def browser_build() -> BuildIdentity:
    return BuildIdentity(
        baseline_sha="a" * 40,
        product_manifest_hash="b" * 64,
        project_policy_hash="c" * 64,
        command_hashes={"pytest": "d" * 64},
        runtime_hash="e" * 64,
    )


def browser_evidence() -> EvidenceRef:
    return EvidenceRef(
        relative_path="evidence/browser/result.json",
        sha256="f" * 64,
        media_type="application/json",
        creator="tester",
    )


def actual_browser_evidence(operation: str) -> EvidenceRef:
    return EvidenceRef(
        relative_path=f"evidence/browser/{operation}.json",
        sha256=hash_json({"operation": operation}),
        media_type="application/json",
        creator="evidence-sink",
    )


def skipped_browser_evidence(run_id: str) -> EvidenceRef:
    return EvidenceRef(
        relative_path=f"evidence/browser/{run_id}-skipped.json",
        sha256=hash_json({"status": "skipped", "run_id": run_id}),
        media_type="application/json",
        creator="evidence-sink",
    )


@dataclass
class RecordingSkipEvidence:
    minted: dict[str, EvidenceRef] = field(default_factory=dict)
    mint_calls: list[str] = field(default_factory=list)
    verify_calls: list[tuple[str, EvidenceRef]] = field(default_factory=list)
    replay_previous: bool = False

    def mint_skipped(self, run_id: str) -> EvidenceRef:
        self.mint_calls.append(run_id)
        if self.replay_previous and self.minted:
            return next(iter(self.minted.values()))
        evidence = skipped_browser_evidence(run_id)
        self.minted[run_id] = evidence
        return evidence

    def verify_skipped(self, run_id: str, evidence: EvidenceRef) -> bool:
        self.verify_calls.append((run_id, evidence))
        return self.minted.get(run_id) == evidence


def browser_result(*, status: str = "passed") -> BrowserResult:
    decision = required_decision()
    build = browser_build()
    observation_status = "failed" if status == "failed" else "passed"
    return BrowserResult.model_validate(
        {
            "status": status,
            "browser_e2e_decision_hash": hash_json(decision.model_dump(mode="json", round_trip=True)),
            "build_identity_hash": hash_json(build.model_dump(mode="json", round_trip=True)),
            "reason": "The declared scenario completed.",
            "scenario_observations": [
                {
                    "scenario_id": "BROWSER-1",
                    "status": observation_status,
                    "observation": "The requested result was observed.",
                    "evidence": [browser_evidence().model_dump(mode="json")],
                }
            ],
            "evidence": [browser_evidence().model_dump(mode="json")],
        }
    )


@pytest.fixture
def browser_harness(tmp_path: Path) -> BrowserHarness:
    managed = RecordingManagedRunner()
    evidence_sink = object()
    skip_evidence = RecordingSkipEvidence()
    playwright = RecordingPlaywrightTools(evidence_sink=evidence_sink)
    crew = RecordingCrew(result=browser_result())
    runner = BrowserRunner(
        browser_config(),
        managed,
        playwright,
        crew,
        evidence_sink=evidence_sink,
        sandbox_policy=object(),
        environment={},
        cwd=tmp_path,
        skip_evidence=skip_evidence,
    )
    return BrowserHarness(runner, managed, playwright, crew, browser_build(), evidence_sink, skip_evidence)


@pytest.fixture
def harness(tmp_path: Path) -> PlaywrightHarness:
    config = browser_config()
    process = RecordingProcess()
    return PlaywrightHarness(
        config=config,
        process=process,
        tools=LocalPlaywrightTools(
            config,
            process,
            evidence_sink=object(),
            sandbox_policy=object(),
            environment={},
            cwd=tmp_path,
            run_id="run_1",
        ),
    )


def test_playwright_tool_uses_only_policy_prefix_session_and_local_url(harness: PlaywrightHarness) -> None:
    tool = harness.tools.for_manifest(ToolManifest())[0]

    assert tool._run(operation="goto", url="http://localhost:4173/page") == "browser output"
    assert harness.process.argvs == [
        (*harness.config.browser.playwright_command_prefix, "goto", "--session", "run-run_1", "http://localhost:4173/page"),
    ]


@pytest.mark.parametrize(
    ("operation", "url"),
    (
        ("install", None),
        ("goto", "https://example.test"),
        ("goto", "http://localhost:4173/?x=1"),
        ("goto", "http://user:pass@localhost:4173/page"),
        ("goto", "http://localhost:4173/page#section"),
    ),
)
def test_playwright_tool_rejects_unapproved_operation_or_url(
    harness: PlaywrightHarness, operation: str, url: str | None
) -> None:
    tool = harness.tools.for_manifest(ToolManifest())[0]

    with pytest.raises(PlaywrightAccessError):
        tool._run(operation=operation, url=url)

    assert harness.process.argvs == []


@pytest.mark.parametrize(
    ("operation", "target", "value"),
    (("click", "--session", None), ("fill", "#name", "--session=other")),
)
def test_playwright_tool_rejects_dash_prefixed_cli_arguments(
    harness: PlaywrightHarness, operation: str, target: str, value: str | None
) -> None:
    tool = harness.tools.for_manifest(ToolManifest())[0]

    with pytest.raises(PlaywrightAccessError):
        tool._run(operation=operation, target=target, value=value)

    assert harness.process.argvs == []


def test_playwright_tool_keeps_ordinary_selector_and_text_arguments(harness: PlaywrightHarness) -> None:
    tool = harness.tools.for_manifest(ToolManifest())[0]

    assert tool._run(operation="fill", target="#name", value="Ada Lovelace") == "browser output"
    assert harness.process.argvs == [
        (*harness.config.browser.playwright_command_prefix, "fill", "--session", "run-run_1", "#name", "Ada Lovelace"),
    ]


def test_optional_browser_decision_skips_without_starting_app(browser_harness: BrowserHarness) -> None:
    result = browser_harness.runner.run(optional_decision(), browser_harness.build, "run-1", "ENG-1")

    assert isinstance(result, BrowserResult)
    assert result.status == "skipped"
    assert result.evidence == (skipped_browser_evidence("run-1"),)
    assert browser_harness.skip_evidence.mint_calls == ["run-1"]
    assert browser_harness.skip_evidence.verify_calls == [("run-1", skipped_browser_evidence("run-1"))]
    assert browser_harness.managed.starts == []
    assert browser_harness.playwright.calls == []
    assert browser_harness.crew.calls == []


def test_required_missing_local_policy_returns_browser_ambiguity(tmp_path: Path) -> None:
    config = browser_config().model_copy(
        update={"browser": browser_config().browser.model_copy(update={"start_command": None, "base_url": None})}
    )
    managed = RecordingManagedRunner()
    evidence_sink = object()
    playwright = RecordingPlaywrightTools(evidence_sink=evidence_sink)
    crew = RecordingCrew(result=browser_result())
    runner = BrowserRunner(
        config,
        managed,
        playwright,
        crew,
        evidence_sink=evidence_sink,
        sandbox_policy=object(),
        environment={},
        cwd=tmp_path,
        skip_evidence=RecordingSkipEvidence(),
    )

    result = runner.run(required_decision(), browser_build(), "run-1", "ENG-1")

    assert isinstance(result, FailureRecord)
    assert result.failure_class is FailureClass.AMBIGUITY
    assert result.failure_source is FailureSource.BROWSER
    assert managed.starts == []
    assert playwright.calls == []
    assert crew.calls == []


def test_failed_scenario_is_product_failure_and_still_closes_session_and_process(browser_harness: BrowserHarness) -> None:
    browser_harness.crew.result = browser_result(status="failed")

    result = browser_harness.runner.run(required_decision(), browser_harness.build, "run-1", "ENG-1")

    assert isinstance(result, FailureRecord)
    assert result.failure_class is FailureClass.PRODUCT
    assert result.failure_source is FailureSource.BROWSER
    assert result.finding_kind is FindingKind.SCENARIO_MISMATCH
    assert result.owner_stage is Stage.PROGRAMMER
    assert result.cited_ids == ("BROWSER-1",)
    assert result.evidence_refs == (actual_browser_evidence("goto"), actual_browser_evidence("close"))
    assert browser_harness.playwright.calls == [("goto", "http://localhost:4173"), ("close", None)]
    assert browser_harness.managed.process.stopped == 1
    assert browser_harness.crew.calls[0][0] is Stage.TESTER
    context = browser_harness.crew.calls[0][1]
    assert context.browser_e2e_decision == required_decision()
    assert context.build_identity == browser_harness.build
    assert context.session_id == "run-1"
    assert context.tool_names == ("playwright",)


def test_cleanup_failure_overrides_primary_result_after_attempting_all_cleanup(browser_harness: BrowserHarness) -> None:
    browser_harness.playwright.fail_close = True
    browser_harness.managed.process.fail_stop = True

    result = browser_harness.runner.run(required_decision(), browser_harness.build, "run-1", "ENG-1")

    assert isinstance(result, FailureRecord)
    assert result.failure_class is FailureClass.ORCHESTRATION
    assert result.failure_source is FailureSource.BROWSER
    assert result.finding_kind is FindingKind.INVALID_UNIT_OUTPUT
    assert browser_harness.playwright.calls == [("goto", "http://localhost:4173"), ("close", None)]
    assert browser_harness.managed.process.stopped == 1


def test_tester_evidence_is_replaced_with_evidence_created_by_this_run(browser_harness: BrowserHarness) -> None:
    result = browser_harness.runner.run(required_decision(), browser_harness.build, "run-1", "ENG-1")

    assert isinstance(result, BrowserResult)
    assert result.evidence == (actual_browser_evidence("goto"), actual_browser_evidence("close"))
    assert result.scenario_observations[0].evidence == result.evidence
    assert browser_evidence() not in result.evidence


def test_managed_cleanup_evidence_is_retained_from_the_evidence_sink(browser_harness: BrowserHarness) -> None:
    browser_harness.managed.process.cleanup_result = CommandResult(
        argv=("/bin/server",),
        returncode=0,
        stdout_text="",
        stderr_text="",
        stdout_path=actual_browser_evidence("stop"),
        stderr_path=actual_browser_evidence("reap"),
        redacted=True,
    )

    result = browser_harness.runner.run(required_decision(), browser_harness.build, "run-1", "ENG-1")

    assert isinstance(result, BrowserResult)
    assert result.evidence == (
        actual_browser_evidence("goto"),
        actual_browser_evidence("close"),
        actual_browser_evidence("stop"),
        actual_browser_evidence("reap"),
    )


def test_mismatched_playwright_adapter_is_rejected_without_session_activity(browser_harness: BrowserHarness) -> None:
    browser_harness.playwright.run_id = "other-run"

    result = browser_harness.runner.run(required_decision(), browser_harness.build, "run-1", "ENG-1")

    assert isinstance(result, FailureRecord)
    assert result.failure_class is FailureClass.ORCHESTRATION
    assert browser_harness.managed.starts == []
    assert browser_harness.playwright.calls == []


def test_skipped_evidence_is_minted_and_verified_per_run_and_replay_is_rejected(
    browser_harness: BrowserHarness,
    tmp_path: Path,
) -> None:
    first = browser_harness.runner.run(optional_decision(), browser_harness.build, "run-1", "ENG-1")
    browser_harness.skip_evidence.replay_previous = True
    second = BrowserRunner(
        browser_config(),
        RecordingManagedRunner(),
        RecordingPlaywrightTools(run_id="run-2", evidence_sink=browser_harness.evidence_sink),
        RecordingCrew(result=browser_result()),
        evidence_sink=browser_harness.evidence_sink,
        sandbox_policy=object(),
        environment={},
        cwd=tmp_path,
        skip_evidence=browser_harness.skip_evidence,
    ).run(optional_decision(), browser_harness.build, "run-2", "ENG-1")

    assert isinstance(first, BrowserResult)
    assert first.evidence == (skipped_browser_evidence("run-1"),)
    assert isinstance(second, FailureRecord)
    assert second.failure_class is FailureClass.ORCHESTRATION
    assert browser_harness.skip_evidence.mint_calls == ["run-1", "run-2"]
    assert browser_harness.skip_evidence.verify_calls == [
        ("run-1", skipped_browser_evidence("run-1")),
        ("run-2", skipped_browser_evidence("run-1")),
    ]


def test_runner_rejects_local_playwright_tools_bound_to_another_run(tmp_path: Path) -> None:
    config = browser_config()
    process = RecordingProcess()
    evidence_sink = object()
    tools = LocalPlaywrightTools(
        config,
        process,
        evidence_sink=evidence_sink,
        sandbox_policy=object(),
        environment={},
        cwd=tmp_path,
        run_id="other-run",
    )
    managed = RecordingManagedRunner()
    runner = BrowserRunner(
        config,
        managed,
        tools,
        RecordingCrew(result=browser_result()),
        evidence_sink=evidence_sink,
        sandbox_policy=object(),
        environment={},
        cwd=tmp_path,
        skip_evidence=RecordingSkipEvidence(),
    )

    result = runner.run(required_decision(), browser_build(), "run-1", "ENG-1")

    assert isinstance(result, FailureRecord)
    assert result.failure_class is FailureClass.ORCHESTRATION
    assert process.argvs == []
    assert managed.starts == []


class StartupAbort(BaseException):
    def __init__(self, process: RecordingManagedProcess) -> None:
        self.process = process


def test_base_exception_during_startup_closes_the_owned_session_and_partial_process(browser_harness: BrowserHarness) -> None:
    browser_harness.managed.start_error = StartupAbort(browser_harness.managed.process)

    result = browser_harness.runner.run(required_decision(), browser_harness.build, "run-1", "ENG-1")

    assert isinstance(result, FailureRecord)
    assert result.failure_class is FailureClass.ORCHESTRATION
    assert browser_harness.playwright.calls == [("close", None)]
    assert browser_harness.managed.process.stopped == 1


def test_invalid_tester_output_is_an_orchestration_failure_after_cleanup(browser_harness: BrowserHarness) -> None:
    browser_harness.crew.result = object()

    result = browser_harness.runner.run(required_decision(), browser_harness.build, "run-1", "ENG-1")

    assert isinstance(result, FailureRecord)
    assert result.failure_class is FailureClass.ORCHESTRATION
    assert result.failure_source is FailureSource.BROWSER
    assert browser_harness.playwright.calls == [("goto", "http://localhost:4173"), ("close", None)]
    assert browser_harness.managed.process.stopped == 1


def test_browser_runner_rejects_a_distinct_real_broker_tester_adapter_for_the_same_run(tmp_path: Path) -> None:
    IntegrationAgent.instances.clear()
    IntegrationAgent.raw = browser_result().model_dump_json()
    repository = tmp_path / "repository"
    repository.mkdir()
    managed = RecordingManagedRunner()
    evidence_sink = object()
    runner_process = RecordingProcess()
    runner_playwright = LocalPlaywrightTools(
        browser_config(),
        runner_process,
        evidence_sink=evidence_sink,
        sandbox_policy=object(),
        environment={},
        cwd=tmp_path,
        run_id="run-1",
    )
    broker_process = RecordingProcess()
    broker_playwright = LocalPlaywrightTools(
        browser_config(),
        broker_process,
        evidence_sink=evidence_sink,
        sandbox_policy=object(),
        environment={},
        cwd=tmp_path,
        run_id="run-1",
    )
    models = IntegrationModels()
    broker = ToolBroker(repository_root=repository, playwright_tools=broker_playwright)
    crew = CrewRunner(models=models, tool_broker=broker, agent_factory=IntegrationAgent)
    runner = BrowserRunner(
        browser_config(),
        managed,
        runner_playwright,
        crew,
        evidence_sink=evidence_sink,
        sandbox_policy=object(),
        environment={},
        cwd=tmp_path,
        skip_evidence=RecordingSkipEvidence(),
    )

    result = runner.run(required_decision(), browser_build(), "run-1", "ENG-1")

    assert isinstance(result, FailureRecord)
    assert result.failure_class is FailureClass.ORCHESTRATION
    assert IntegrationAgent.instances == []
    assert models.calls == []
    assert broker_process.argvs == []
    assert runner_process.argvs == [
        (*browser_config().browser.playwright_command_prefix, "goto", "--session", "run-run-1", "http://localhost:4173"),
        (*browser_config().browser.playwright_command_prefix, "close", "--session", "run-run-1"),
    ]
