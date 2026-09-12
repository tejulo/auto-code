from __future__ import annotations

from dataclasses import dataclass, field
import json
from typing import Any

from crewai.tools import ToolFailurePolicy
from pydantic import BaseModel
import pytest

from auto_code.contracts import (
    BrowserE2EDecision,
    BrowserScenario,
    BuildIdentity,
    ImplementationResult,
    InvalidUnitOutput,
    RequirementsPackage,
    Stage,
)
from auto_code.crew import COGNITIVE_STAGES, OUTPUT_FOR_STAGE, CrewRunner, UnitContext
from auto_code.hashing import hash_json
from auto_code.model_config import RoleName
from auto_code.read_tools import HashedReadFile, HashedReadManifest
from auto_code.tool_broker import RoleCapabilityMatrix, ToolManifest


def requirements_json() -> str:
    return json.dumps(
        {
            "objective": "Deliver the approved change.",
            "in_scope": ["Implement the requested behavior."],
            "out_of_scope": ["Do not change deployment."],
            "requirements": [
                {
                    "requirement_id": "REQ-1",
                    "text": "The behavior is observable.",
                    "sources": [
                        {"source_id": "ticket-description", "locator": "line-1", "source_hash": "a" * 64}
                    ],
                }
            ],
            "acceptance_criteria": [
                {
                    "criterion_id": "AC-1",
                    "text": "The behavior is verified.",
                    "sources": [
                        {"source_id": "ticket-description", "locator": "line-2", "source_hash": "a" * 64}
                    ],
                }
            ],
            "constraints": [],
            "dependencies": [],
            "ambiguities": [],
        }
    )


def implementation_json(
    *,
    task_definition_hash: str = "a" * 64,
    task_status_hash: str = "b" * 64,
    completed_task_ids: tuple[str, ...] = ("1.1",),
) -> str:
    return json.dumps(
        {
            "task_definition_hash": task_definition_hash,
            "task_status_hash": task_status_hash,
            "completed_task_ids": completed_task_ids,
            "changed_paths": ["src/auto_code/crew.py"],
            "command_evidence": [
                {
                    "relative_path": "evidence/commands/pytest.json",
                    "sha256": "c" * 64,
                    "media_type": "application/json",
                    "creator": "programmer",
                }
            ],
            "latest_failure_resolution": "Implemented the approved correction.",
        }
    )


def manifest_for_paths(*paths: str, digest: str = "a" * 64) -> ToolManifest:
    return ToolManifest(
        read_manifest=HashedReadManifest(
            files=tuple(HashedReadFile(relative_path=path, sha256=digest) for path in paths),
        )
    )


def programmer_context() -> UnitContext:
    return UnitContext(
        requirements_path="requirements.json",
        dependency_paths=("proposal.md", "specs.md", "design.md", "tasks.md"),
        task_definition_path="task-definition.json",
        task_definition_hash="a" * 64,
        task_status_path="task-status.json",
        task_status_hash="b" * 64,
        known_task_ids=("1.1", "1.2"),
        session_id="run-ENG-1",
    )


def browser_tester_context() -> UnitContext:
    decision = BrowserE2EDecision(
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
    build = BuildIdentity(
        baseline_sha="a" * 40,
        product_manifest_hash="b" * 64,
        project_policy_hash="c" * 64,
        command_hashes={"pytest": "d" * 64},
        runtime_hash="e" * 64,
    )
    return UnitContext(
        dependency_paths=("browser-decision.json", "build-identity.json"),
        session_id="run-ENG-1",
        browser_e2e_decision=decision,
        build_identity=build,
    )


@dataclass
class FakeModels:
    calls: list[tuple[RoleName, str]] = field(default_factory=list)

    def for_role(self, role: RoleName, session_id: str) -> object:
        self.calls.append((role, session_id))
        return object()


@dataclass
class FakeBroker:
    calls: list[tuple[Stage, ToolManifest]] = field(default_factory=list)

    def for_stage(
        self,
        stage: Stage,
        manifest: ToolManifest,
        *,
        expected_read_paths: tuple[str, ...] | None = None,
    ) -> tuple[object, ...]:
        del expected_read_paths
        self.calls.append((stage, manifest))
        return ()


@dataclass(frozen=True)
class FakeAgentResult:
    raw: object


class RecordingAgent:
    instances: list[RecordingAgent] = []
    next_raw: object = requirements_json()

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.prompts: list[str] = []
        self.result = FakeAgentResult(type(self).next_raw)
        type(self).instances.append(self)

    def kickoff(self, prompt: str) -> FakeAgentResult:
        self.prompts.append(prompt)
        return self.result


class RaisingAgent:
    def __init__(self, **kwargs: Any) -> None:
        del kwargs

    def kickoff(self, prompt: str) -> FakeAgentResult:
        del prompt
        raise RuntimeError("adapter failed")


class MalformedResultAgent:
    next_result: object = object()

    def __init__(self, **kwargs: Any) -> None:
        del kwargs

    def kickoff(self, prompt: str) -> object:
        del prompt
        return type(self).next_result


class CrashingOutput(BaseModel):
    @classmethod
    def model_validate_json(cls, json_data: str, **kwargs: Any) -> CrashingOutput:
        del json_data, kwargs
        raise RuntimeError("validator crashed")


def reset_recording_agent() -> None:
    RecordingAgent.instances.clear()
    RecordingAgent.next_raw = requirements_json()


def test_runner_creates_one_memoryless_non_delegating_agent_and_kicks_it_off_once() -> None:
    reset_recording_agent()
    models = FakeModels()
    broker = FakeBroker()
    runner = CrewRunner(models=models, tool_broker=broker, agent_factory=RecordingAgent)
    context = UnitContext(ticket_snapshot="trusted ticket", session_id="run-ENG-1")

    output = runner.run(Stage.ANALYST, context)

    assert isinstance(output, RequirementsPackage)
    assert models.calls == [(RoleName.ANALYST, "run-ENG-1")]
    assert broker.calls == [(Stage.ANALYST, context.tool_manifest)]
    assert len(RecordingAgent.instances) == 1
    agent = RecordingAgent.instances[0]
    assert agent.kwargs["memory"] is False
    assert agent.kwargs["allow_delegation"] is False
    assert agent.kwargs["verbose"] is False
    assert agent.kwargs["max_retry_limit"] == 0
    assert agent.kwargs["max_iter"] == 2
    assert agent.kwargs["tool_failure_policy"] is ToolFailurePolicy.RAISE
    assert agent.kwargs["tools"] == ()
    assert len(agent.prompts) == 1


def test_runner_converts_only_model_authored_pydantic_validation_failures_to_invalid_unit_output() -> None:
    reset_recording_agent()
    runner = CrewRunner(models=FakeModels(), tool_broker=FakeBroker(), agent_factory=RecordingAgent)
    output = runner.run(Stage.ANALYST, UnitContext(ticket_snapshot="trusted ticket", session_id="run-ENG-1"))
    RecordingAgent.next_raw = "{}"

    invalid = runner.run(Stage.ANALYST, UnitContext(ticket_snapshot="trusted ticket", session_id="run-ENG-1"))

    assert isinstance(output, RequirementsPackage)
    assert isinstance(invalid, InvalidUnitOutput)
    assert invalid.stage is Stage.ANALYST
    assert len(RecordingAgent.instances) == 2
    assert all(len(agent.prompts) == 1 for agent in RecordingAgent.instances)


def test_runner_propagates_agent_and_validator_runtime_faults() -> None:
    runner = CrewRunner(models=FakeModels(), tool_broker=FakeBroker(), agent_factory=RaisingAgent)

    with pytest.raises(RuntimeError, match="adapter failed"):
        runner.run(Stage.ANALYST, UnitContext(ticket_snapshot="trusted ticket", session_id="run-ENG-1"))

    reset_recording_agent()
    runner = CrewRunner(
        models=FakeModels(),
        tool_broker=FakeBroker(),
        agent_factory=RecordingAgent,
        output_types={**OUTPUT_FOR_STAGE, Stage.ANALYST: CrashingOutput},
    )
    with pytest.raises(RuntimeError, match="validator crashed"):
        runner.run(Stage.ANALYST, UnitContext(ticket_snapshot="trusted ticket", session_id="run-ENG-1"))


@pytest.mark.parametrize("result", (object(), FakeAgentResult(123)))
def test_runner_propagates_missing_or_non_string_agent_raw_as_adapter_faults(result: object) -> None:
    MalformedResultAgent.next_result = result
    runner = CrewRunner(models=FakeModels(), tool_broker=FakeBroker(), agent_factory=MalformedResultAgent)

    with pytest.raises(TypeError, match="raw"):
        runner.run(Stage.ANALYST, UnitContext(ticket_snapshot="trusted ticket", session_id="run-ENG-1"))


def test_runner_validates_review_result_against_the_bound_review_manifest_hash() -> None:
    reset_recording_agent()
    expected_hash = "b" * 64
    runner = CrewRunner(models=FakeModels(), tool_broker=FakeBroker(), agent_factory=RecordingAgent)
    RecordingAgent.next_raw = json.dumps(
        {
            "approved": True,
            "review_manifest_hash": "c" * 64,
            "cited_ids": [],
            "blocking_findings": [],
            "evidence": [],
            "next_action": "Proceed to finalization.",
        }
    )

    output = runner.run(
        Stage.REVIEWER,
        UnitContext(
            session_id="run-ENG-1",
            review_manifest_hash=expected_hash,
            dependency_paths=("review-manifest.json",),
            tool_manifest=manifest_for_paths("review-manifest.json", digest=expected_hash),
        ),
    )

    assert isinstance(output, InvalidUnitOutput)
    assert output.stage is Stage.REVIEWER


@pytest.mark.parametrize(
    "manifest",
    (
        manifest_for_paths("review-manifest.json", digest="c" * 64),
        manifest_for_paths("review-manifest.json", "unrelated.json", digest="b" * 64),
        manifest_for_paths("other-manifest.json", digest="b" * 64),
    ),
)
def test_runner_rejects_nonexact_review_manifest_before_agent_creation(manifest: ToolManifest) -> None:
    reset_recording_agent()
    models = FakeModels()
    broker = FakeBroker()
    runner = CrewRunner(models=models, tool_broker=broker, agent_factory=RecordingAgent)

    with pytest.raises(ValueError, match="Review Manifest|read manifest"):
        runner.run(
            Stage.REVIEWER,
            UnitContext(
                session_id="run-ENG-1",
                review_manifest_hash="b" * 64,
                dependency_paths=("review-manifest.json",),
                tool_manifest=manifest,
            ),
        )

    assert models.calls == []
    assert broker.calls == []
    assert RecordingAgent.instances == []


def test_runner_rejects_unrelated_hashed_read_files_before_agent_creation() -> None:
    reset_recording_agent()
    models = FakeModels()
    broker = FakeBroker()
    runner = CrewRunner(models=models, tool_broker=broker, agent_factory=RecordingAgent)
    context = UnitContext(
        session_id="run-ENG-1",
        requirements_path="requirements.json",
        openspec_instructions_path="openspec.md",
        dependency_paths=("proposal.md",),
        tool_manifest=manifest_for_paths("requirements.json", "openspec.md", "proposal.md", "unrelated.json"),
    )

    with pytest.raises(ValueError, match="read manifest"):
        runner.run(Stage.ARCHITECT_DESIGN, context)

    assert models.calls == []
    assert broker.calls == []
    assert RecordingAgent.instances == []


def test_runner_validates_implementation_output_against_programmer_task_context() -> None:
    reset_recording_agent()
    RecordingAgent.next_raw = implementation_json(task_definition_hash="d" * 64)
    runner = CrewRunner(models=FakeModels(), tool_broker=FakeBroker(), agent_factory=RecordingAgent)

    output = runner.run(Stage.PROGRAMMER, programmer_context())

    assert isinstance(output, InvalidUnitOutput)
    assert output.stage is Stage.PROGRAMMER


def test_runner_validates_tester_output_against_declared_decision_and_build() -> None:
    reset_recording_agent()
    context = browser_tester_context()
    assert context.browser_e2e_decision is not None
    assert context.build_identity is not None
    RecordingAgent.next_raw = json.dumps(
        {
            "status": "passed",
            "browser_e2e_decision_hash": "f" * 64,
            "build_identity_hash": hash_json(context.build_identity.model_dump(mode="json", round_trip=True)),
            "reason": "The declared scenario passed.",
            "scenario_observations": [
                {
                    "scenario_id": "BROWSER-1",
                    "status": "passed",
                    "observation": "The requested result was visible.",
                    "evidence": [
                        {
                            "relative_path": "evidence/browser/result.json",
                            "sha256": "e" * 64,
                            "media_type": "application/json",
                            "creator": "tester",
                        }
                    ],
                }
            ],
            "evidence": [
                {
                    "relative_path": "evidence/browser/result.json",
                    "sha256": "e" * 64,
                    "media_type": "application/json",
                    "creator": "tester",
                }
            ],
        }
    )
    runner = CrewRunner(models=FakeModels(), tool_broker=FakeBroker(), agent_factory=RecordingAgent)

    output = runner.run(Stage.TESTER, context)

    assert isinstance(output, InvalidUnitOutput)
    assert output.stage is Stage.TESTER


def test_browser_tester_context_uses_the_exact_decision_build_run_and_playwright_tool() -> None:
    source = browser_tester_context()
    assert source.browser_e2e_decision is not None
    assert source.build_identity is not None

    context = UnitContext.for_browser_tester(
        source.browser_e2e_decision,
        source.build_identity,
        "run-ENG-1",
    )

    assert context.browser_e2e_decision == source.browser_e2e_decision
    assert context.build_identity == source.build_identity
    assert context.session_id == "run-ENG-1"
    assert context.tool_names == ("playwright",)
    assert context.dependency_paths == ("browser-decision.json", "build-identity.json")


def test_runner_loads_canonical_yaml_for_every_role_and_cognitive_stage() -> None:
    runner = CrewRunner(models=FakeModels(), tool_broker=FakeBroker(), agent_factory=RecordingAgent)

    assert set(runner.agents) == {role.value for role in RoleName}
    assert set(runner.tasks) == {stage.value for stage in COGNITIVE_STAGES}
    assert all(runner.tasks[stage.value]["output_contract"] == OUTPUT_FOR_STAGE[stage].__name__ for stage in COGNITIVE_STAGES)
    assert RoleCapabilityMatrix.required(Stage.ANALYST) == frozenset({"structured_output", "text"})
    assert RoleCapabilityMatrix.required(Stage.ARCHITECT_DESIGN) == frozenset(
        {"structured_output", "text", "tool_calling"}
    )
    assert all("text" in RoleCapabilityMatrix.required(stage) for stage in COGNITIVE_STAGES)
    assert RoleCapabilityMatrix.required(Stage.VERIFICATION) == frozenset()


def test_runner_rejects_the_deterministic_verification_stage_and_missing_run_identity() -> None:
    runner = CrewRunner(models=FakeModels(), tool_broker=FakeBroker(), agent_factory=RecordingAgent)

    with pytest.raises(ValueError, match="deterministic"):
        runner.run(Stage.VERIFICATION, UnitContext(session_id="run-ENG-1"))
    with pytest.raises(ValueError, match="run ID"):
        runner.run(Stage.ANALYST, UnitContext(ticket_snapshot="trusted ticket"))


def test_runner_rejects_unallowlisted_context_before_requesting_a_model_or_tools() -> None:
    models = FakeModels()
    broker = FakeBroker()
    runner = CrewRunner(models=models, tool_broker=broker, agent_factory=RecordingAgent)

    with pytest.raises(ValueError, match="tool"):
        runner.run(
            Stage.ANALYST,
            UnitContext(ticket_snapshot="trusted ticket", session_id="run-ENG-1", tool_names=("read_hashed",)),
        )

    assert models.calls == []
    assert broker.calls == []
