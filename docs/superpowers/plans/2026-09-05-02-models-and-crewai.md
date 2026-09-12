# Models and CrewAI Units Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add dynamic OpenCode Go and Ollama Cloud model selection plus isolated, typed CrewAI role executions.

**Architecture:** A provider-neutral `ModelFactory` validates role URIs against live catalogs and builds CrewAI `BaseLLM` adapters. `CrewRunner` creates one memoryless, non-delegating agent for exactly one typed unit and supplies only allowlisted context.

**Tech Stack:** Python 3.12, CrewAI 1.15.20, Pydantic 2, httpx, python-dotenv, PyYAML, pytest, respx.

**Spec:** `docs/superpowers/specs/2026-09-05-automated-development-orchestration-design.md`

## Global Constraints

- Complete `docs/superpowers/plans/2026-09-05-01-state-and-contracts.md` first.
- Select models only through `ANALYST_MODEL`, `ARCHITECT_MODEL`, `PROGRAMMER_MODEL`, `TESTER_MODEL`, and `REVIEWER_MODEL`.
- Never persist or log `OPENCODE_API_KEY` or `OLLAMA_API_KEY`.
- Include a stable per-run `x-opencode-session` header for OpenCode Go.
- Disable CrewAI memory, delegation, verbose output, and generative retries.
- Reject unsupported capabilities during preflight, before a Crew Iteration.

## File Map

- `.env.example`: role URI and secret-key shapes.
- `src/auto_code/model_config.py`: environment parsing and redacted settings.
- `src/auto_code/model_catalog.py`: dynamic provider catalogs and protocol metadata.
- `src/auto_code/model_compatibility.py`: versioned tested protocol/capability profiles.
- `src/auto_code/model_transport.py`: normalized protocol requests and responses.
- `src/auto_code/models.py`: CrewAI `BaseLLM` adapter and `ModelFactory`.
- `src/auto_code/crew.py`: bounded context construction and single-unit execution.
- `src/auto_code/read_tools.py`: stage-specific hash-checking read-only tools.
- `src/auto_code/tool_broker.py`: exact stage-to-capability and stage-to-tool binding.
- `src/auto_code/config/agents.yaml`: approved role definitions.
- `src/auto_code/config/tasks.yaml`: one template per Artifact Unit and execution role.

### Task 1: Role Model Configuration and Catalog Validation

**Files:**
- Create: `.env.example`
- Modify: `pyproject.toml`
- Create: `src/auto_code/model_config.py`
- Create: `src/auto_code/model_catalog.py`
- Test: `tests/test_model_config.py`
- Test: `tests/test_model_catalog.py`

**Interfaces:**
- Produces: `RoleName`, `RoleModelConfig.from_env(environ: Mapping[str, str])`.
- Produces: `ModelRef.parse(value: str) -> ModelRef` with providers `opencode-go` and `ollama-cloud`.
- Produces: `ModelCompatibilityRegistry.resolve(ref, live_catalog, capabilities) -> ModelMetadata`.

- [ ] **Step 1: Write failing parsing and catalog tests**

```python
import pytest
from auto_code.model_config import RoleModelConfig
from auto_code.model_catalog import ModelCatalog, ModelMetadata, ModelRef
from auto_code.model_compatibility import ModelCompatibilityProfile, ModelCompatibilityRegistry


def test_every_role_requires_an_explicit_model() -> None:
    with pytest.raises(ValueError, match="REVIEWER_MODEL"):
        RoleModelConfig.from_env({
            "ANALYST_MODEL": "opencode-go/a",
            "ARCHITECT_MODEL": "opencode-go/a",
            "PROGRAMMER_MODEL": "ollama-cloud/b",
            "TESTER_MODEL": "opencode-go/a",
        })


def test_catalog_rejects_missing_tool_capability() -> None:
    catalog = ModelCatalog(["a"])
    registry = ModelCompatibilityRegistry([ModelCompatibilityProfile(provider="opencode-go", model_id="a", protocol="chat", capabilities=frozenset())])
    with pytest.raises(ValueError, match="tool_calling"):
        registry.resolve(ModelRef.parse("opencode-go/a"), catalog, frozenset({"tool_calling"}))
```

- [ ] **Step 2: Run tests and verify missing modules**

Run: `.venv/bin/python -m pytest tests/test_model_config.py tests/test_model_catalog.py -v`

Expected: FAIL during collection.

- [ ] **Step 3: Implement strict configuration and redaction**

Pin `crewai==1.15.20`; add `httpx`, `python-dotenv`, `PyYAML`, and test dependency `respx`. Parse exactly one `/` between provider and non-empty model ID. `RoleModelConfig.__repr__` may show role URIs but must replace both keys with `***`. Live catalogs contribute availability only. `model_compatibility.py` maps tested model IDs to protocol, context limits, structured-output support, and tool-calling support. Resolve only the intersection; a missing profile fails preflight.

Write `.env.example` with all five role variables, blank keys, and `AUTO_CODE_MAX_ATTEMPTS=3`.

```python
ROLE_KEYS = {
    RoleName.ANALYST: "ANALYST_MODEL",
    RoleName.ARCHITECT: "ARCHITECT_MODEL",
    RoleName.PROGRAMMER: "PROGRAMMER_MODEL",
    RoleName.TESTER: "TESTER_MODEL",
    RoleName.REVIEWER: "REVIEWER_MODEL",
}


@classmethod
def from_env(cls, environ: Mapping[str, str]) -> "RoleModelConfig":
    missing = [key for key in ROLE_KEYS.values() if not environ.get(key)]
    if missing:
        raise ValueError(f"Missing model settings: {', '.join(missing)}")
    return cls(models={role: ModelRef.parse(environ[key]) for role, key in ROLE_KEYS.items()})
```

- [ ] **Step 4: Run model configuration tests**

Run: `.venv/bin/python -m pytest tests/test_model_config.py tests/test_model_catalog.py -v`

Expected: PASS.

- [ ] **Step 5: Commit configuration and catalogs**

```bash
git add pyproject.toml .env.example src/auto_code/model_config.py src/auto_code/model_catalog.py src/auto_code/model_compatibility.py tests/test_model_config.py tests/test_model_catalog.py
git commit -m "feat: validate role model catalogs"
```

### Task 2: Protocol-Normalizing CrewAI LLM Adapter

**Files:**
- Create: `src/auto_code/model_transport.py`
- Create: `src/auto_code/models.py`
- Test: `tests/test_model_transport.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Produces: `LLMRequest(messages, tools, response_schema)`; `ToolCall(id, name, arguments)`; and `LLMReply(text, tool_calls, usage, finish_reason)`.
- Produces: `ModelTransport.complete(metadata, request, session_id) -> LLMReply`.
- Produces: `CrewModel(BaseLLM).call(...) -> str | BaseModel`.
- Produces: `ModelFactory.for_role(role: RoleName, session_id: str) -> CrewModel`.

- [ ] **Step 1: Write one failing contract test per wire protocol**

```python
import httpx
import respx
from auto_code.model_catalog import ModelMetadata
from auto_code.model_transport import LLMRequest, ModelTransport


@respx.mock
def test_chat_transport_sets_session_header() -> None:
    route = respx.post("https://opencode.ai/zen/go/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"choices": [{"message": {"content": "ok"}}]})
    )
    reply = ModelTransport(opencode_key="secret", ollama_key="other").complete(
        ModelMetadata(provider="opencode-go", model_id="m", protocol="chat", capabilities=frozenset()),
        LLMRequest(messages=[{"role": "user", "content": "x"}], tools=[], response_schema=None),
        "run-ENG-1",
    )
    assert reply.text == "ok"
    assert route.calls[0].request.headers["x-opencode-session"] == "run-ENG-1"
```

Add these concrete cases beside the chat test:

```python
def complete_for_protocol(protocol: str):
    provider = "ollama-cloud" if protocol == "ollama" else "opencode-go"
    metadata = ModelMetadata(provider=provider, model_id="m", protocol=protocol, capabilities=frozenset({"tool_calling"}))
    return ModelTransport(opencode_key="secret", ollama_key="other").complete(
        metadata,
        LLMRequest(messages=[{"role": "user", "content": "x"}], tools=[], response_schema=None),
        "run-ENG-1",
    )


@respx.mock
def test_responses_transport_extracts_output_text() -> None:
    respx.post("https://opencode.ai/zen/go/v1/responses").mock(return_value=httpx.Response(200, json={"output": [{"type": "message", "content": [{"type": "output_text", "text": "ok"}]}]}))
    assert complete_for_protocol("responses").text == "ok"


@respx.mock
def test_messages_transport_normalizes_tool_call() -> None:
    respx.post("https://opencode.ai/zen/go/v1/messages").mock(return_value=httpx.Response(200, json={"content": [{"type": "tool_use", "id": "call-1", "name": "read_file", "input": {"path": "README.md"}}]}))
    assert complete_for_protocol("messages").tool_calls[0].name == "read_file"
    assert complete_for_protocol("messages").tool_calls[0].id == "call-1"


@respx.mock
def test_ollama_transport_uses_bearer_auth() -> None:
    route = respx.post("https://ollama.com/api/chat").mock(return_value=httpx.Response(200, json={"message": {"content": "ok"}}))
    assert complete_for_protocol("ollama").text == "ok"
    assert route.calls[0].request.headers["authorization"] == "Bearer other"


def test_multiple_tool_rounds_preserve_call_ids_and_allow_terminal_followup(model_with_two_tool_rounds) -> None:
    result = model_with_two_tool_rounds.call([{"role": "user", "content": "inspect"}], available_functions={"read_hashed": fake_read})
    assert result == "complete"
    assert model_with_two_tool_rounds.transport.request_count == 3
    assert model_with_two_tool_rounds.transport.correlated_result_ids == ["call-1", "call-2"]
```

- [ ] **Step 2: Run transport tests and verify failure**

Run: `.venv/bin/python -m pytest tests/test_model_transport.py tests/test_models.py -v`

Expected: FAIL during collection.

- [ ] **Step 3: Implement normalized requests without transcript logging**

Map `chat` to OpenAI Chat Completions, `responses` to OpenAI Responses, `messages` to Anthropic Messages, and `ollama` to Ollama chat. Preserve every provider call ID and protocol-specific assistant/tool correlation, including multiple calls. In `CrewModel.call`, execute only exact names present in `available_functions`; unknown names or malformed JSON become Orchestration Defects. Append correlated results and continue until text or `response_model` validates. Parse `Retry-After` delta-seconds and HTTP-date for status `429`, `502`, `503`, and `504`; cap total waiting from Project Policy and retry the byte-identical body.

```python
ENDPOINTS = {
    "chat": "https://opencode.ai/zen/go/v1/chat/completions",
    "responses": "https://opencode.ai/zen/go/v1/responses",
    "messages": "https://opencode.ai/zen/go/v1/messages",
    "ollama": "https://ollama.com/api/chat",
}


class CrewModel(BaseLLM):
    transport: ModelTransport
    metadata: ModelMetadata
    session_id: str

    def __init__(self, metadata: ModelMetadata, transport: ModelTransport, session_id: str):
        super().__init__(model=metadata.model_id, temperature=0, metadata=metadata, transport=transport, session_id=session_id)

    def supports_function_calling(self) -> bool:
        return "tool_calling" in self.metadata.capabilities

    def get_context_window_size(self) -> int:
        return self.metadata.context_window

    def call(self, messages, tools=None, callbacks=None, available_functions=None, from_task=None, from_agent=None, response_model=None):
        request = LLMRequest(messages=normalize_messages(messages), tools=normalize_tools(tools), response_schema=schema_for(response_model))
        functions = available_functions or {}
        for tool_round in range(self.metadata.max_tool_rounds + 1):
            reply = self.transport.complete(self.metadata, request, self.session_id)
            if reply.is_terminal_text:
                return validate_terminal_reply(reply, response_model)
            if tool_round == self.metadata.max_tool_rounds:
                raise ToolRoundLimitExceeded(self.metadata.max_tool_rounds)
            calls = validate_correlated_calls(reply.tool_calls, functions)
            results = tuple(execute_correlated_call(call, functions[call.name]) for call in calls)
            request = request.append_assistant_calls_and_results(reply, results)
```

- [ ] **Step 4: Run protocol and regression tests**

Run: `.venv/bin/python -m pytest tests/test_model_transport.py tests/test_models.py tests/test_model_config.py tests/test_model_catalog.py -v`

Expected: PASS, with captured requests containing no key in URL or body.

- [ ] **Step 5: Commit model adapters**

```bash
git add src/auto_code/model_transport.py src/auto_code/models.py tests/test_model_transport.py tests/test_models.py
git commit -m "feat: adapt crew models across providers"
```

### Task 3: Approved Role Prompts and Single-Unit Runner

**Files:**
- Create: `src/auto_code/config/agents.yaml`
- Create: `src/auto_code/config/tasks.yaml`
- Create: `src/auto_code/crew.py`
- Create: `src/auto_code/read_tools.py`
- Create: `src/auto_code/tool_broker.py`
- Modify: `src/auto_code/contracts.py`
- Test: `tests/test_crew.py`
- Test: `tests/test_prompt_boundaries.py`

**Interfaces:**
- Consumes: `ModelFactory.for_role()` and `Stage`.
- Produces fully specified, schema-versioned `RequirementsPackage`, `BrowserE2EDecision`, `ChangeOutline`, `ArtifactFile`, `ArtifactEnvelope`, `ImplementationResult`, `BuildIdentity`, `BrowserResult`, `ReviewManifest`, and `ReviewResult` Pydantic models with the fields and invariants from the design.
- Produces: `RoleCapabilityMatrix.required(stage) -> frozenset[str]` and `ToolBroker.for_stage(stage, manifest) -> tuple[BaseTool, ...]`.
- Produces: `CrewRunner.run(stage: Stage, context: UnitContext) -> BaseModel | InvalidUnitOutput`, distinguishing model-generated invalid output from adapter/validator execution defects.

- [ ] **Step 1: Write failing isolation tests**

```python
from auto_code.contracts import Stage
from auto_code.crew import UnitContext, build_prompt


def test_architect_design_receives_only_direct_dependencies() -> None:
    context = UnitContext(
        ticket_snapshot="forbidden",
        requirements_path="requirements.json",
        outline_path="outline.json",
        dependency_paths=("proposal.md",),
        latest_failure_path=None,
    )
    prompt = build_prompt(Stage.ARCHITECT_DESIGN, context)
    assert "requirements.json" in prompt
    assert "proposal.md" in prompt
    assert "forbidden" not in prompt


def test_programmer_gets_only_latest_failure() -> None:
    context = UnitContext(requirements_path="requirements.json", outline_path=None, dependency_paths=("proposal.md", "specs", "design.md", "tasks.md"), latest_failure_path="failure-3.json")
    assert "failure-3.json" in build_prompt(Stage.PROGRAMMER, context)


def test_tool_broker_enforces_effective_role_access(tool_broker, manifests) -> None:
    assert tool_broker.for_stage(Stage.ANALYST, manifests.none) == ()
    assert tool_names(tool_broker.for_stage(Stage.ARCHITECT_DESIGN, manifests.architect)) == {"read_hashed"}
    assert tool_names(tool_broker.for_stage(Stage.PROGRAMMER, manifests.programmer)) == {"read_repo", "write_repo", "search_repo", "run_authorized"}
    assert tool_names(tool_broker.for_stage(Stage.TESTER, manifests.tester)) == {"playwright"}
    assert tool_names(tool_broker.for_stage(Stage.REVIEWER, manifests.reviewer)) == {"read_hashed"}
```

- [ ] **Step 2: Run runner tests and verify failure**

Run: `.venv/bin/python -m pytest tests/test_crew.py tests/test_prompt_boundaries.py -v`

Expected: FAIL because `auto_code.crew` and output contracts are absent.

- [ ] **Step 3: Implement one-agent/one-task execution**

Copy the approved descriptive role, goal, and behavior text from the design into `agents.yaml`, using canonical IDs as YAML keys. Define one task key for each cognitive stage; every task names its Pydantic output contract. Construct `Agent(llm=model, memory=False, allow_delegation=False, verbose=False, max_retry_limit=0)` and execute one task only. Use persisted random `run_id` in provider sessions. `build_prompt` rejects fields/tools not allowlisted for the stage. Architect and Reviewer receive `HashedReadTool`, which reads only explicit manifests, rejects symlinks/oversized files, and verifies hashes. Programmer command tools always delegate to plan 03's sandboxed ProcessRunner. No model tool receives Authoritative State Root, provider keys, launcher/repair configuration, or unrestricted native shell/file access. Tests assert denied operations, not only absent prompt strings.

`ARCHITECT_OUTLINE` owns the required BrowserE2EDecision and checkpoints it inside ChangeOutline. Analyst receives no tools; Architect stages and Reviewer receive hash-checking read tools; Programmer receives only `ProgrammerTools`; Tester receives only the Playwright wrapper. A correctly functioning parser/validator that rejects model output returns typed `InvalidUnitOutput`; transport, adapter, contract-definition, or validator crashes return Orchestration Defect. `ReviewResult` must repeat `review_manifest_hash`; a mismatch fails validation.

The schemas are exact: `RequirementsPackage` has objective, explicit in/out scope, source-cited requirements/criteria, constraints, dependencies, and ambiguities; `BrowserE2EDecision` has required, reason, and immutable scenarios; `ChangeOutline` has change ID, Artifact Unit manifest, direct dependency hashes, and Browser E2E Decision; `ArtifactEnvelope` has artifact ID and one or more `ArtifactFile(relative_path, content, sha256)` entries; `ImplementationResult` has input Task Definition/Status hashes, completed task IDs, changed-path claims, command evidence, and latest-failure resolution; `BuildIdentity` has baseline SHA, product-manifest hash, Project Policy hash, command hashes, and runtime hash; `BrowserResult` has status, exact Browser E2E Decision hash, Build Identity hash, reason, scenario observations, and evidence; `ReviewManifest` binds all planning/product/policy/verification hashes; `ReviewResult` has approval, manifest hash, class/source/finding/owner, cited IDs, blocking findings, evidence, and next action. Every collection has bounded size and every model forbids unknown fields.

```python
def run(self, stage: Stage, context: UnitContext) -> BaseModel | InvalidUnitOutput:
    role = ROLE_FOR_STAGE[stage]
    output_type = OUTPUT_FOR_STAGE[stage]
    agent = Agent(
        config=self.agents[role.value],
        llm=self.models.for_role(role, context.session_id),
        tools=self.tool_broker.for_stage(stage, context.tool_manifest),
        memory=False,
        allow_delegation=False,
        verbose=False,
        max_retry_limit=0,
    )
    result = agent.kickoff(build_prompt_with_schema(stage, context, output_type.model_json_schema()))
    try:
        return output_type.model_validate_json(result.raw)
    except ValidationError as error:
        return InvalidUnitOutput(stage=stage, output_hash=hash_invalid_output(error), validation_errors=sanitize_validation_errors(error))
```

Only Pydantic's explicit JSON/schema validation boundary is caught as Invalid Unit Output, including model-authored invalid JSON. Exceptions from CrewAI setup, tools, transport, contract construction, or validator execution propagate to Orchestration Defect classification.

- [ ] **Step 4: Run the full second-increment suite**

Run: `.venv/bin/python -m pytest tests/test_crew.py tests/test_prompt_boundaries.py tests/test_model_*.py tests/test_models.py -v`

Expected: PASS.

- [ ] **Step 5: Commit CrewAI units**

```bash
git add src/auto_code/config src/auto_code/crew.py src/auto_code/read_tools.py src/auto_code/tool_broker.py src/auto_code/contracts.py tests/test_crew.py tests/test_prompt_boundaries.py
git commit -m "feat: run isolated crew role units"
```
