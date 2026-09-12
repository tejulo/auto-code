from __future__ import annotations

from collections.abc import Mapping, Sequence
import json
from typing import Any

from crewai.llms.base_llm import BaseLLM
from pydantic import BaseModel, PrivateAttr, ValidationError

from .model_catalog import ModelCatalog, ModelMetadata
from .model_compatibility import ModelCompatibilityRegistry
from .model_config import RoleModelConfig, RoleName
from .model_transport import (
    LLMReply,
    LLMRequest,
    MalformedToolArguments,
    ModelTransport,
    OrchestrationDefect,
    ToolCall,
    ToolResult,
    normalize_tools,
)
from .tool_broker import MAX_NATIVE_TOOL_CALLS, RoleCapabilityMatrix


DEFAULT_MAX_TOOL_ROUNDS = MAX_NATIVE_TOOL_CALLS


class UnknownTool(OrchestrationDefect):
    pass


class ToolRoundLimitExceeded(OrchestrationDefect):
    pass


class ToolExecutionFailed(OrchestrationDefect):
    pass


class InvalidResponseModel(OrchestrationDefect):
    pass


class CrewModel(BaseLLM):
    """CrewAI adapter that keeps provider tool loops inside one bounded call."""

    llm_type: str = "auto_code"
    metadata: ModelMetadata
    transport: ModelTransport
    session_id: str
    max_tool_rounds: int = DEFAULT_MAX_TOOL_ROUNDS
    _native_tool_call_count: int = PrivateAttr(default=0)
    _pending_native_tool_calls: list[dict[str, Any]] = PrivateAttr(default_factory=list)

    def __init__(
        self,
        metadata: ModelMetadata,
        transport: ModelTransport,
        session_id: str,
        *,
        max_tool_rounds: int = DEFAULT_MAX_TOOL_ROUNDS,
    ) -> None:
        if not isinstance(metadata, ModelMetadata):
            raise ValueError("Crew models require validated metadata")
        if not isinstance(transport, ModelTransport):
            raise ValueError("Crew models require a model transport")
        _validate_session_id(session_id)
        _validate_tool_rounds(max_tool_rounds)
        super().__init__(
            model=metadata.model_id,
            provider=metadata.provider,
            temperature=0,
            metadata=metadata,
            transport=transport,
            session_id=session_id,
            max_tool_rounds=max_tool_rounds,
        )

    def supports_function_calling(self) -> bool:
        return "tool_calling" in self.metadata.capabilities

    def get_context_window_size(self) -> int:
        return self.metadata.context_limit or super().get_context_window_size()

    def call(
        self,
        messages: str | list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        callbacks: list[Any] | None = None,
        available_functions: dict[str, Any] | None = None,
        from_task: Any | None = None,
        from_agent: Any | None = None,
        response_model: type[BaseModel] | None = None,
    ) -> str | BaseModel | list[dict[str, Any]]:
        del callbacks, from_task
        request = LLMRequest(
            messages=self._format_messages(messages),
            tools=normalize_tools(tools),
            response_schema=_response_schema(response_model),
        )
        if available_functions is None:
            if self._pending_native_tool_calls:
                if not request.tools:
                    raise ToolRoundLimitExceeded("Model exceeded the configured native tool-call bound")
                return [self._pending_native_tool_calls.pop(0)]
            reply = self.transport.complete(self.metadata, request, self.session_id)
            if not isinstance(reply, LLMReply):
                raise OrchestrationDefect("Model transport returned an invalid reply")
            if reply.is_terminal_text:
                return _validate_terminal_reply(reply.text, response_model)
            native_calls = _native_tool_calls(reply.tool_calls, request.tools, from_agent)
            if self._native_tool_call_count + len(native_calls) > MAX_NATIVE_TOOL_CALLS:
                raise ToolRoundLimitExceeded("Model exceeded the configured native tool-call bound")
            self._native_tool_call_count += len(native_calls)
            self._pending_native_tool_calls.extend(native_calls[1:])
            return native_calls[:1]

        functions = _allowlisted_functions(available_functions)

        for tool_round in range(self.max_tool_rounds + 1):
            reply = self.transport.complete(self.metadata, request, self.session_id)
            if not isinstance(reply, LLMReply):
                raise OrchestrationDefect("Model transport returned an invalid reply")
            if reply.is_terminal_text:
                return _validate_terminal_reply(reply.text, response_model)
            if tool_round == self.max_tool_rounds:
                raise ToolRoundLimitExceeded("Model exceeded the configured tool-call bound")
            results = tuple(_execute_call(call, functions) for call in _validate_calls(reply.tool_calls, functions))
            request = request.append_assistant_calls_and_results(reply, results)

        raise ToolRoundLimitExceeded("Model exceeded the configured tool-call bound")


class ModelFactory:
    """Build role models exclusively from preflight-validated settings."""

    def __init__(
        self,
        config: RoleModelConfig,
        compatibility_registry: ModelCompatibilityRegistry,
        live_catalogs: Mapping[str, ModelCatalog],
        transport: ModelTransport,
        *,
        max_tool_rounds: int = DEFAULT_MAX_TOOL_ROUNDS,
    ) -> None:
        if not isinstance(config, RoleModelConfig):
            raise ValueError("Model factories require validated role configuration")
        if not isinstance(compatibility_registry, ModelCompatibilityRegistry):
            raise ValueError("Model factories require a compatibility registry")
        if not isinstance(live_catalogs, Mapping) or any(
            not isinstance(provider, str) or not isinstance(catalog, ModelCatalog)
            for provider, catalog in live_catalogs.items()
        ):
            raise ValueError("Model factories require provider-keyed live catalogs")
        if not isinstance(transport, ModelTransport):
            raise ValueError("Model factories require a model transport")
        _validate_tool_rounds(max_tool_rounds)
        validated: dict[RoleName, ModelMetadata] = {}
        for role in RoleName:
            model_ref = config.models[role]
            catalog = live_catalogs.get(model_ref.provider)
            if not isinstance(catalog, ModelCatalog):
                raise ValueError("Model factories require a live catalog for each configured provider")
            validated[role] = compatibility_registry.resolve(
                model_ref,
                catalog,
                RoleCapabilityMatrix.required_for_role(role),
            )
        self._metadata = validated
        self._transport = transport
        self._max_tool_rounds = max_tool_rounds

    def for_role(self, role: RoleName, session_id: str) -> CrewModel:
        if not isinstance(role, RoleName):
            raise ValueError("Role must be a validated role name")
        return CrewModel(
            self._metadata[role],
            self._transport,
            session_id,
            max_tool_rounds=self._max_tool_rounds,
        )


def _response_schema(response_model: type[BaseModel] | None) -> Mapping[str, Any] | None:
    if response_model is None:
        return None
    if not isinstance(response_model, type) or not issubclass(response_model, BaseModel):
        raise InvalidResponseModel("Response models must be Pydantic models")
    try:
        schema = response_model.model_json_schema()
    except Exception:
        raise InvalidResponseModel("Response model schema generation failed") from None
    if not isinstance(schema, Mapping):
        raise InvalidResponseModel("Response model schema must be a JSON object")
    return schema


def _allowlisted_functions(available_functions: dict[str, Any] | None) -> dict[str, Any]:
    if available_functions is None:
        return {}
    if not isinstance(available_functions, Mapping):
        raise OrchestrationDefect("Available functions must be a mapping")
    functions = dict(available_functions)
    if any(not isinstance(name, str) or not callable(function) for name, function in functions.items()):
        raise OrchestrationDefect("Available functions must be named callables")
    return functions


def _validate_calls(calls: tuple[ToolCall, ...], functions: Mapping[str, Any]) -> tuple[ToolCall, ...]:
    if not calls:
        raise OrchestrationDefect("Provider reply contained neither text nor tool calls")
    if len({call.id for call in calls}) != len(calls):
        raise OrchestrationDefect("Provider returned duplicate tool-call IDs")
    for call in calls:
        if call.name not in functions:
            raise UnknownTool("Provider requested a tool that is not allowlisted")
    return calls


def _native_tool_calls(
    calls: tuple[ToolCall, ...],
    tools: tuple[Mapping[str, Any], ...],
    from_agent: Any | None,
) -> list[dict[str, Any]]:
    if not calls:
        raise OrchestrationDefect("Provider reply contained neither text nor tool calls")
    if len({call.id for call in calls}) != len(calls):
        raise OrchestrationDefect("Provider returned duplicate tool-call IDs")
    declared = {tool["name"]: tool for tool in tools}
    if len(declared) != len(tools):
        raise OrchestrationDefect("Native tool schemas must have unique names")
    agent_tools = getattr(from_agent, "tools", None)
    if isinstance(agent_tools, (str, bytes)) or not isinstance(agent_tools, Sequence):
        raise OrchestrationDefect("Native tool calls require trusted CrewAI tool schemas")
    schemas: dict[str, type[BaseModel]] = {}
    for tool in agent_tools:
        name = getattr(tool, "name", None)
        args_schema = getattr(tool, "args_schema", None)
        if name not in declared:
            continue
        if name in schemas or not isinstance(args_schema, type) or not issubclass(args_schema, BaseModel):
            raise OrchestrationDefect("Native tool calls require trusted CrewAI tool schemas")
        schemas[name] = args_schema
    if set(schemas) != set(declared):
        raise OrchestrationDefect("Native tool calls require trusted CrewAI tool schemas")

    native_calls: list[dict[str, Any]] = []
    for call in calls:
        schema = schemas.get(call.name)
        if schema is None:
            raise UnknownTool("Provider requested a tool that is not allowlisted")
        try:
            arguments = schema.model_validate(dict(call.arguments)).model_dump(mode="json")
        except ValidationError:
            raise MalformedToolArguments("Provider tool arguments do not match the trusted tool schema") from None
        native_calls.append(
            {
                "id": call.id,
                "type": "function",
                "function": {
                    "name": call.name,
                    "arguments": json.dumps(arguments, allow_nan=False, separators=(",", ":"), sort_keys=True),
                },
            }
        )
    return native_calls


def _execute_call(call: ToolCall, functions: Mapping[str, Any]) -> ToolResult:
    try:
        result = functions[call.name](**dict(call.arguments))
    except Exception:
        raise ToolExecutionFailed("Allowlisted tool execution failed") from None
    return ToolResult(call_id=call.id, name=call.name, content=_tool_result_content(result))


def _tool_result_content(result: Any) -> str:
    if isinstance(result, str):
        return result
    if isinstance(result, BaseModel):
        result = result.model_dump(mode="json")
    try:
        return json.dumps(result, allow_nan=False, separators=(",", ":"), sort_keys=True)
    except (TypeError, ValueError, OverflowError):
        raise ToolExecutionFailed("Allowlisted tool returned non-JSON data") from None


def _validate_terminal_reply(text: str | None, response_model: type[BaseModel] | None) -> str | BaseModel:
    if not isinstance(text, str):
        raise OrchestrationDefect("Provider reply contained no terminal text")
    if response_model is None:
        return text
    if not isinstance(response_model, type) or not issubclass(response_model, BaseModel):
        raise InvalidResponseModel("Response models must be Pydantic models")
    return response_model.model_validate_json(text)


def _validate_session_id(session_id: str) -> None:
    if not isinstance(session_id, str) or not session_id.strip() or "\r" in session_id or "\n" in session_id:
        raise ValueError("Session IDs must be safe non-empty text")


def _validate_tool_rounds(max_tool_rounds: int) -> None:
    if isinstance(max_tool_rounds, bool) or not isinstance(max_tool_rounds, int) or max_tool_rounds < 0:
        raise ValueError("Maximum tool rounds must be a non-negative integer")
