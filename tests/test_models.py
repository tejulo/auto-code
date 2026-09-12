from __future__ import annotations

from collections.abc import Mapping
import hashlib
from pathlib import Path
import threading
from typing import Any

from crewai import Agent
from crewai.tools import ToolExecutionFailedError, ToolFailurePolicy
from crewai.tools.base_tool import BaseTool
from pydantic import BaseModel, ConfigDict, Field, ValidationError
import pytest

from auto_code.model_catalog import ModelCatalog, ModelMetadata, ModelRef
from auto_code.model_compatibility import ModelCompatibilityProfile, ModelCompatibilityRegistry
from auto_code.model_config import RoleModelConfig, RoleName
from auto_code.contracts import Stage
from auto_code.crew import DEFAULT_MAX_AGENT_ITERATIONS
from auto_code.model_transport import LLMReply, LLMRequest, MalformedToolArguments, ModelTransport, RetryPolicy, ToolCall
from auto_code.models import CrewModel, ModelFactory, ToolRoundLimitExceeded, UnknownTool
from auto_code.read_tools import HashedReadFile, HashedReadManifest, HashedReadTool
from auto_code.tool_broker import ToolBroker, ToolManifest


class ScriptedTransport(ModelTransport):
    def __init__(self, replies: list[LLMReply]) -> None:
        super().__init__(opencode_key="", ollama_key="", retry_policy=RetryPolicy())
        self._replies = iter(replies)
        self.requests: list[LLMRequest] = []
        self.sessions: list[str] = []

    def complete(self, metadata: ModelMetadata, request: LLMRequest, session_id: str) -> LLMReply:
        self.requests.append(request)
        self.sessions.append(session_id)
        return next(self._replies)


class ThreeNativeToolRoundTransport(ScriptedTransport):
    def __init__(self) -> None:
        super().__init__(
            [
                LLMReply(text=None, tool_calls=(tool_call("call-1"),)),
                LLMReply(text=None, tool_calls=(tool_call("call-2"),)),
                LLMReply(text=None, tool_calls=(tool_call("call-3"),)),
            ]
        )

    def complete(self, metadata: ModelMetadata, request: LLMRequest, session_id: str) -> LLMReply:
        self.requests.append(request)
        self.sessions.append(session_id)
        if not request.tools:
            return LLMReply(text="forced complete", tool_calls=())
        return next(self._replies)


def model_metadata(*, capabilities: frozenset[str] = frozenset({"tool_calling"})) -> ModelMetadata:
    return ModelMetadata(
        provider="opencode-go",
        model_id="model-1",
        protocol="chat",
        capabilities=capabilities,
        context_limit=128_000,
    )


def tool_call(call_id: str, name: str = "read_hashed") -> ToolCall:
    return ToolCall(id=call_id, name=name, arguments={"path": f"{call_id}.json"})


def test_model_executes_exact_allowlisted_tools_across_multiple_rounds_before_terminal_followup() -> None:
    transport = ScriptedTransport(
        [
            LLMReply(text=None, tool_calls=(tool_call("call-1"),), usage=None, finish_reason="tool_calls"),
            LLMReply(text=None, tool_calls=(tool_call("call-2"),), usage=None, finish_reason="tool_calls"),
            LLMReply(text="complete", tool_calls=(), usage=None, finish_reason="stop"),
        ]
    )
    calls: list[str] = []

    def read_hashed(path: str) -> Mapping[str, str]:
        calls.append(path)
        return {"path": path}

    result = CrewModel(model_metadata(), transport, "run-ENG-1", max_tool_rounds=2).call(
        [{"role": "user", "content": "inspect"}], available_functions={"read_hashed": read_hashed}
    )

    assert result == "complete"
    assert calls == ["call-1.json", "call-2.json"]
    assert len(transport.requests) == 3
    assert transport.sessions == ["run-ENG-1", "run-ENG-1", "run-ENG-1"]
    assert transport.requests[1].messages[-1] == {
        "content": '{"path":"call-1.json"}',
        "name": "read_hashed",
        "role": "tool",
        "tool_call_id": "call-1",
    }
    assert transport.requests[2].messages[-1]["tool_call_id"] == "call-2"


def test_model_rejects_a_tool_name_that_is_not_exactly_allowlisted() -> None:
    transport = ScriptedTransport(
        [LLMReply(text=None, tool_calls=(tool_call("call-1", "read_hashed_extra"),), usage=None, finish_reason=None)]
    )

    with pytest.raises(UnknownTool):
        CrewModel(model_metadata(), transport, "run-ENG-1").call(
            [{"role": "user", "content": "inspect"}], available_functions={"read_hashed": lambda path: path}
        )

    assert len(transport.requests) == 1


def test_model_rejects_an_additional_tool_round_after_its_bound() -> None:
    transport = ScriptedTransport(
        [
            LLMReply(text=None, tool_calls=(tool_call("call-1"),), usage=None, finish_reason=None),
            LLMReply(text=None, tool_calls=(tool_call("call-2"),), usage=None, finish_reason=None),
        ]
    )

    with pytest.raises(ToolRoundLimitExceeded):
        CrewModel(model_metadata(), transport, "run-ENG-1", max_tool_rounds=1).call(
            [{"role": "user", "content": "inspect"}], available_functions={"read_hashed": lambda path: path}
        )

    assert len(transport.requests) == 2


class Answer(BaseModel):
    answer: str


def test_model_returns_validated_response_models_and_advertises_their_schema() -> None:
    transport = ScriptedTransport(
        [LLMReply(text='{"answer":"ok"}', tool_calls=(), usage=None, finish_reason="stop")]
    )

    result = CrewModel(model_metadata(capabilities=frozenset({"structured_output"})), transport, "run-ENG-1").call(
        "answer", response_model=Answer
    )

    assert result == Answer(answer="ok")
    assert transport.requests[0].response_schema == Answer.model_json_schema()


def test_model_leaves_invalid_model_authored_structured_data_as_a_validation_error() -> None:
    transport = ScriptedTransport(
        [LLMReply(text='{"answer":1}', tool_calls=(), usage=None, finish_reason="stop")]
    )

    with pytest.raises(ValidationError):
        CrewModel(model_metadata(capabilities=frozenset({"structured_output"})), transport, "run-ENG-1").call(
            "answer", response_model=Answer
        )


class CountingReadArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")

    path: str


class CountingReadTool(BaseTool):
    name: str = "read_hashed"
    description: str = "Read a test-only hash-bound file."
    args_schema: type[BaseModel] = CountingReadArguments
    calls: list[str] = Field(default_factory=list)

    def _run(self, path: str) -> str:
        self.calls.append(path)
        return path


def test_real_crewai_agent_limits_native_tool_execution_before_a_forced_terminal_request() -> None:
    transport = ThreeNativeToolRoundTransport()
    tool = CountingReadTool()
    agent = Agent(
        role="Reader",
        goal="Read the approved files.",
        backstory="A bounded test agent.",
        llm=CrewModel(model_metadata(), transport, "run-ENG-1"),
        tools=[tool],
        max_iter=DEFAULT_MAX_AGENT_ITERATIONS,
        tool_failure_policy=ToolFailurePolicy.RAISE,
        memory=False,
        allow_delegation=False,
        verbose=False,
    )

    result = agent.kickoff("Read the approved files.")

    assert tool.calls == ["call-1.json", "call-2.json"]
    assert result.raw == "forced complete"
    assert len(transport.requests) == 3
    assert all(request.tools for request in transport.requests[:2])
    assert transport.requests[2].tools == ()


def test_real_crewai_agent_executes_a_validated_native_hashed_read_and_correlated_followup(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    document = root / "docs" / "approved.md"
    document.parent.mkdir(parents=True)
    document.write_text("approved content\n", encoding="utf-8")
    tool = HashedReadTool(
        root=root,
        manifest=HashedReadManifest(
            files=(
                HashedReadFile(
                    relative_path="docs/approved.md",
                    sha256=hashlib.sha256(document.read_bytes()).hexdigest(),
                ),
            )
        ),
    )
    transport = ScriptedTransport(
        [
            LLMReply(
                text=None,
                tool_calls=(ToolCall(id="call-1", name="read_hashed", arguments={"path": "docs/approved.md"}),),
            ),
            LLMReply(text="complete", tool_calls=()),
        ]
    )
    agent = Agent(
        role="Reader",
        goal="Read the approved file.",
        backstory="A bounded test agent.",
        llm=CrewModel(model_metadata(), transport, "run-ENG-1"),
        tools=[tool],
        max_iter=3,
        tool_failure_policy=ToolFailurePolicy.RAISE,
        memory=False,
        allow_delegation=False,
        verbose=False,
    )

    result = agent.kickoff("Read the approved file.")

    assert result.raw == "complete"
    assert len(transport.requests) == 2
    assert any(
        message.get("role") == "tool" and message.get("tool_call_id") == "call-1"
        for message in transport.requests[1].messages
    )


def test_real_crewai_agent_executes_an_allowed_native_batch_serially_with_correlated_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "repository"
    first = root / "docs" / "first.md"
    second = root / "docs" / "second.md"
    first.parent.mkdir(parents=True)
    first.write_text("first content\n", encoding="utf-8")
    second.write_text("second content\n", encoding="utf-8")
    tool = ToolBroker(repository_root=root).for_stage(
        Stage.ARCHITECT_OUTLINE,
        ToolManifest(
            read_manifest=HashedReadManifest(
                files=(
                    HashedReadFile(relative_path="docs/first.md", sha256=hashlib.sha256(first.read_bytes()).hexdigest()),
                    HashedReadFile(relative_path="docs/second.md", sha256=hashlib.sha256(second.read_bytes()).hexdigest()),
                )
            )
        ),
        expected_read_paths=("docs/first.md", "docs/second.md"),
    )[0]
    transport = ScriptedTransport(
        [
            LLMReply(
                text=None,
                tool_calls=(
                    ToolCall(id="call-1", name="read_hashed", arguments={"path": "docs/first.md"}),
                    ToolCall(id="call-2", name="read_hashed", arguments={"path": "docs/second.md"}),
                ),
            ),
            LLMReply(text="complete", tool_calls=()),
        ]
    )
    active_calls = 0
    maximum_active_calls = 0
    first_call_started = False
    second_call_started = threading.Event()
    call_lock = threading.Lock()
    original_run = HashedReadTool._run

    def track_concurrent_runs(self: HashedReadTool, path: str) -> str:
        nonlocal active_calls, maximum_active_calls, first_call_started
        with call_lock:
            active_calls += 1
            maximum_active_calls = max(maximum_active_calls, active_calls)
            wait_for_second_call = not first_call_started
            first_call_started = True
            if not wait_for_second_call:
                second_call_started.set()
        if wait_for_second_call:
            second_call_started.wait(timeout=0.5)
        try:
            return original_run(self, path)
        finally:
            with call_lock:
                active_calls -= 1

    monkeypatch.setattr(HashedReadTool, "_run", track_concurrent_runs)
    agent = Agent(
        role="Reader",
        goal="Read the approved files.",
        backstory="A bounded test agent.",
        llm=CrewModel(model_metadata(), transport, "run-ENG-1"),
        tools=[tool],
        max_iter=DEFAULT_MAX_AGENT_ITERATIONS,
        tool_failure_policy=ToolFailurePolicy.RAISE,
        memory=False,
        allow_delegation=False,
        verbose=False,
    )

    result = agent.kickoff("Read the approved files.")

    assert maximum_active_calls == 1
    assert tool.max_usage_count == 2
    assert tool.current_usage_count == 2
    assert result.raw == "complete"
    assert len(transport.requests) == 2
    assert transport.requests[1].tools == ()
    assert [
        (message["tool_call_id"], message["content"])
        for message in transport.requests[1].messages
        if message.get("role") == "tool"
    ] == [("call-1", "first content\n"), ("call-2", "second content\n")]


def test_real_crewai_agent_rejects_an_excess_native_batch_before_any_tool_body_runs() -> None:
    tool = CountingReadTool()
    agent = Agent(
        role="Reader",
        goal="Read only approved files.",
        backstory="A bounded test agent.",
        llm=CrewModel(
            model_metadata(),
            ScriptedTransport(
                [
                    LLMReply(
                        text=None,
                        tool_calls=(tool_call("call-1"), tool_call("call-2"), tool_call("call-3")),
                    ),
                    LLMReply(text="unexpected completion", tool_calls=()),
                ]
            ),
            "run-ENG-1",
        ),
        tools=[tool],
        max_iter=DEFAULT_MAX_AGENT_ITERATIONS,
        tool_failure_policy=ToolFailurePolicy.RAISE,
        memory=False,
        allow_delegation=False,
        verbose=False,
    )

    with pytest.raises(ToolRoundLimitExceeded, match="native tool-call bound"):
        agent.kickoff("Read only approved files.")

    assert tool.calls == []


def test_real_crewai_agent_stops_after_a_default_policy_hashed_read_denial(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    tool = HashedReadTool(root=root, manifest=HashedReadManifest(files=()))
    transport = ScriptedTransport(
        [
            LLMReply(
                text=None,
                tool_calls=(ToolCall(id="call-1", name="read_hashed", arguments={"path": "docs/denied.md"}),),
            ),
            LLMReply(text="unexpected follow-up", tool_calls=()),
        ]
    )
    agent = Agent(
        role="Reader",
        goal="Read only approved files.",
        backstory="A bounded test agent.",
        llm=CrewModel(model_metadata(), transport, "run-ENG-1"),
        tools=[tool],
        max_iter=DEFAULT_MAX_AGENT_ITERATIONS,
        tool_failure_policy=ToolFailurePolicy.RAISE,
        memory=False,
        allow_delegation=False,
        verbose=False,
    )

    with pytest.raises(ToolExecutionFailedError, match="not allowlisted"):
        agent.kickoff("Read the approved file.")

    assert len(transport.requests) == 1


@pytest.mark.parametrize(
    ("reply", "error_type"),
    (
        (
            LLMReply(text=None, tool_calls=(ToolCall(id="call-1", name="untrusted", arguments={"path": "approved"}),)),
            UnknownTool,
        ),
        (
            LLMReply(
                text=None,
                tool_calls=(ToolCall(id="call-1", name="read_hashed", arguments={"path": "approved", "extra": True}),),
            ),
            MalformedToolArguments,
        ),
    ),
)
def test_real_crewai_native_calls_reject_unknown_or_malformed_tools_before_execution(
    reply: LLMReply,
    error_type: type[Exception],
) -> None:
    tool = CountingReadTool()
    agent = Agent(
        role="Reader",
        goal="Read only approved files.",
        backstory="A bounded test agent.",
        llm=CrewModel(model_metadata(), ScriptedTransport([reply]), "run-ENG-1"),
        tools=[tool],
        max_iter=3,
        tool_failure_policy=ToolFailurePolicy.RAISE,
        memory=False,
        allow_delegation=False,
        verbose=False,
    )

    with pytest.raises(error_type):
        agent.kickoff("Read the approved file.")

    assert tool.calls == []


def role_config() -> RoleModelConfig:
    return RoleModelConfig(
        models={
            RoleName.ANALYST: ModelRef(provider="opencode-go", model_id="analyst-model"),
            RoleName.ARCHITECT: ModelRef(provider="opencode-go", model_id="architect-model"),
            RoleName.PROGRAMMER: ModelRef(provider="ollama-cloud", model_id="programmer-model"),
            RoleName.TESTER: ModelRef(provider="opencode-go", model_id="tester-model"),
            RoleName.REVIEWER: ModelRef(provider="opencode-go", model_id="reviewer-model"),
        }
    )


def compatibility_profiles() -> list[ModelCompatibilityProfile]:
    return [
        ModelCompatibilityProfile(
            provider=model_ref.provider,
            model_id=model_ref.model_id,
            protocol="ollama" if model_ref.provider == "ollama-cloud" else "chat",
            capabilities=frozenset({"structured_output", "text", "tool_calling"}),
            context_limit=128_000,
        )
        for model_ref in role_config().models.values()
    ]


def live_catalogs() -> dict[str, ModelCatalog]:
    return {
        "opencode-go": ModelCatalog(["analyst-model", "architect-model", "tester-model", "reviewer-model"]),
        "ollama-cloud": ModelCatalog(["programmer-model"]),
    }


def test_factory_resolves_each_role_from_injected_registry_catalogs_and_capabilities() -> None:
    transport = ScriptedTransport([])
    factory = ModelFactory(
        config=role_config(),
        compatibility_registry=ModelCompatibilityRegistry(compatibility_profiles()),
        live_catalogs=live_catalogs(),
        transport=transport,
    )

    architect = factory.for_role(RoleName.ARCHITECT, "run-ENG-1")
    programmer = factory.for_role(RoleName.PROGRAMMER, "run-ENG-1")

    assert isinstance(architect, CrewModel)
    assert architect.model == "architect-model"
    assert architect.session_id == "run-ENG-1"
    assert architect.transport is transport
    assert architect.get_context_window_size() == 128_000
    assert programmer.metadata.provider == "ollama-cloud"
    assert programmer.metadata.protocol == "ollama"


def test_factory_resolves_all_roles_during_construction() -> None:
    registry = ModelCompatibilityRegistry(
        profile for profile in compatibility_profiles() if profile.model_id != "reviewer-model"
    )

    with pytest.raises(ValueError, match="compatibility profile"):
        ModelFactory(
            config=role_config(),
            compatibility_registry=registry,
            live_catalogs=live_catalogs(),
            transport=ScriptedTransport([]),
        )


def test_factory_requires_a_live_catalog_for_every_configured_provider() -> None:
    catalogs = live_catalogs()
    del catalogs["ollama-cloud"]

    with pytest.raises(ValueError, match="live catalog"):
        ModelFactory(
            config=role_config(),
            compatibility_registry=ModelCompatibilityRegistry(compatibility_profiles()),
            live_catalogs=catalogs,
            transport=ScriptedTransport([]),
        )


def test_factory_enforces_role_capability_matrix_before_models_are_used() -> None:
    profiles = compatibility_profiles()
    profiles[2] = ModelCompatibilityProfile(
        provider="ollama-cloud",
        model_id="programmer-model",
        protocol="ollama",
        capabilities=frozenset({"structured_output"}),
        context_limit=128_000,
    )

    with pytest.raises(ValueError, match="missing required capabilities"):
        ModelFactory(
            config=role_config(),
            compatibility_registry=ModelCompatibilityRegistry(profiles),
            live_catalogs=live_catalogs(),
            transport=ScriptedTransport([]),
        )


@pytest.mark.parametrize("role", tuple(RoleName))
def test_factory_preflight_rejects_every_role_profile_without_text_capability(role: RoleName) -> None:
    profiles = compatibility_profiles()
    model_ref = role_config().models[role]
    profile_index = next(
        index
        for index, profile in enumerate(profiles)
        if profile.provider == model_ref.provider and profile.model_id == model_ref.model_id
    )
    profile = profiles[profile_index]
    profiles[profile_index] = ModelCompatibilityProfile(
        provider=profile.provider,
        model_id=profile.model_id,
        protocol=profile.protocol,
        capabilities=profile.capabilities.difference({"text"}),
        context_limit=profile.context_limit,
        version=profile.version,
    )

    with pytest.raises(ValueError, match="text"):
        ModelFactory(
            config=role_config(),
            compatibility_registry=ModelCompatibilityRegistry(profiles),
            live_catalogs=live_catalogs(),
            transport=ScriptedTransport([]),
        )


def test_factory_does_not_accept_a_caller_capability_map() -> None:
    with pytest.raises(TypeError, match="required_capabilities"):
        ModelFactory(
            config=role_config(),
            compatibility_registry=ModelCompatibilityRegistry(compatibility_profiles()),
            live_catalogs=live_catalogs(),
            required_capabilities={role: frozenset() for role in RoleName},
            transport=ScriptedTransport([]),
        )
