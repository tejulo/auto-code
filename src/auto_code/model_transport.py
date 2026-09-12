from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import json
import math
import re
import time
from types import MappingProxyType
from typing import Any

import httpx

from .model_catalog import ModelMetadata


ENDPOINTS: Mapping[str, str] = MappingProxyType(
    {
        "chat": "https://opencode.ai/zen/go/v1/chat/completions",
        "responses": "https://opencode.ai/zen/go/v1/responses",
        "messages": "https://opencode.ai/zen/go/v1/messages",
        "ollama": "https://ollama.com/api/chat",
    }
)
_RETRYABLE_STATUSES = frozenset({429, 502, 503, 504})
_RETRYABLE_HTTP_ERRORS = (httpx.TimeoutException, httpx.NetworkError, httpx.RemoteProtocolError)
_DELTA_SECONDS = re.compile(r"[0-9]+$")
_MAX_RETRY_AFTER_LENGTH = 128


class OrchestrationDefect(RuntimeError):
    """A provider or adapter failure that must not be treated as model output."""


class InvalidModelRequest(OrchestrationDefect):
    pass


class UnsupportedModelProtocol(OrchestrationDefect):
    pass


class MalformedProviderReply(OrchestrationDefect):
    pass


class MalformedToolArguments(MalformedProviderReply):
    pass


class ModelTransportFailure(OrchestrationDefect):
    pass


class ProviderStatusError(ModelTransportFailure):
    pass


class RetryExhausted(ModelTransportFailure):
    pass


class RetryWaitLimitExceeded(ModelTransportFailure):
    pass


@dataclass(frozen=True)
class ToolCall:
    id: str
    name: str
    arguments: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not _is_nonempty_string(self.id) or not _is_nonempty_string(self.name):
            raise MalformedProviderReply("Provider tool calls require an ID and name")
        object.__setattr__(self, "arguments", _json_object(self.arguments, MalformedToolArguments))


@dataclass(frozen=True)
class ToolResult:
    call_id: str
    name: str
    content: str

    def __post_init__(self) -> None:
        if not _is_nonempty_string(self.call_id) or not _is_nonempty_string(self.name):
            raise InvalidModelRequest("Tool results require a call ID and name")
        if not isinstance(self.content, str):
            raise InvalidModelRequest("Tool result content must be text")


@dataclass(frozen=True)
class LLMReply:
    text: str | None
    tool_calls: Sequence[ToolCall] = ()
    usage: Mapping[str, Any] | None = None
    finish_reason: str | None = None

    def __post_init__(self) -> None:
        if self.text is not None and not isinstance(self.text, str):
            raise MalformedProviderReply("Provider reply text must be text")
        if isinstance(self.tool_calls, (str, bytes)) or not isinstance(self.tool_calls, Sequence):
            raise MalformedProviderReply("Provider reply tool calls are invalid")
        calls = tuple(self.tool_calls)
        if not all(isinstance(call, ToolCall) for call in calls):
            raise MalformedProviderReply("Provider reply tool calls are invalid")
        if len({call.id for call in calls}) != len(calls):
            raise MalformedProviderReply("Provider reply tool call IDs must be unique")
        object.__setattr__(self, "tool_calls", calls)
        if self.usage is not None:
            object.__setattr__(self, "usage", _json_object(self.usage, MalformedProviderReply))
        if self.finish_reason is not None and not isinstance(self.finish_reason, str):
            raise MalformedProviderReply("Provider finish reason must be text")

    @property
    def is_terminal_text(self) -> bool:
        return not self.tool_calls and self.text is not None


@dataclass(frozen=True)
class LLMRequest:
    messages: tuple[Mapping[str, Any], ...]
    tools: tuple[Mapping[str, Any], ...]
    response_schema: Mapping[str, Any] | None

    def __post_init__(self) -> None:
        object.__setattr__(self, "messages", _json_mapping_sequence(self.messages, "Messages"))
        object.__setattr__(self, "tools", _json_mapping_sequence(self.tools, "Tools"))
        if self.response_schema is not None:
            object.__setattr__(self, "response_schema", _json_object(self.response_schema, InvalidModelRequest))

    def append_assistant_calls_and_results(
        self,
        reply: LLMReply,
        results: Sequence[ToolResult],
    ) -> LLMRequest:
        if not reply.tool_calls or len(results) != len(reply.tool_calls):
            raise InvalidModelRequest("Tool results must match provider tool calls")
        expected = [(call.id, call.name) for call in reply.tool_calls]
        actual = [(result.call_id, result.name) for result in results]
        if actual != expected:
            raise InvalidModelRequest("Tool results must preserve provider correlation")

        assistant = {
            "role": "assistant",
            "content": reply.text or "",
            "tool_calls": [
                {"id": call.id, "name": call.name, "arguments": dict(call.arguments)} for call in reply.tool_calls
            ],
        }
        tool_results = [
            {
                "role": "tool",
                "tool_call_id": result.call_id,
                "name": result.name,
                "content": result.content,
            }
            for result in results
        ]
        return LLMRequest(
            messages=(*self.messages, assistant, *tool_results),
            tools=self.tools,
            response_schema=self.response_schema,
        )


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 3
    total_retry_wait_seconds: float = 30
    initial_backoff_seconds: float = 1

    def __post_init__(self) -> None:
        if isinstance(self.max_attempts, bool) or not isinstance(self.max_attempts, int) or self.max_attempts <= 0:
            raise ValueError("Retry attempts must be a positive integer")
        if not _is_nonnegative_finite_number(self.total_retry_wait_seconds):
            raise ValueError("Total retry wait must be a non-negative finite number")
        if not _is_nonnegative_finite_number(self.initial_backoff_seconds):
            raise ValueError("Initial retry backoff must be a non-negative finite number")


def parse_retry_after(value: str | None, now: datetime) -> float | None:
    """Return a valid Retry-After delay or None when the header is malformed."""
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if not candidate or len(candidate) > _MAX_RETRY_AFTER_LENGTH:
        return None
    try:
        if _DELTA_SECONDS.fullmatch(candidate):
            delay = float(int(candidate))
            return delay if math.isfinite(delay) else None
        retry_at = parsedate_to_datetime(candidate)
        if not isinstance(retry_at, datetime) or retry_at.tzinfo is None:
            return None
        current = now if now.tzinfo is not None else now.replace(tzinfo=timezone.utc)
        return max(0.0, (retry_at.astimezone(timezone.utc) - current.astimezone(timezone.utc)).total_seconds())
    except (TypeError, ValueError, IndexError, OverflowError, OSError):
        return None


class ModelTransport:
    """Serialize fixed provider protocols without retaining request transcripts."""

    def __init__(
        self,
        *,
        opencode_key: str,
        ollama_key: str,
        retry_policy: RetryPolicy,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], datetime] | None = None,
        timeout: float = 30,
    ) -> None:
        if not isinstance(opencode_key, str) or not isinstance(ollama_key, str):
            raise ValueError("Provider keys must be text")
        if not isinstance(retry_policy, RetryPolicy):
            raise ValueError("Transport retry policy must be a RetryPolicy")
        if not callable(sleep):
            raise ValueError("Sleep must be callable")
        if now is not None and not callable(now):
            raise ValueError("Clock must be callable")
        if not _is_nonnegative_finite_number(timeout) or timeout == 0:
            raise ValueError("Transport timeout must be a positive finite number")
        self._opencode_key = opencode_key
        self._ollama_key = ollama_key
        self._retry_policy = retry_policy
        self._sleep = sleep
        self._now = now or (lambda: datetime.now(timezone.utc))
        self._timeout = timeout

    def __repr__(self) -> str:
        return (
            "ModelTransport(opencode_key='***', ollama_key='***', "
            f"retry_policy={self._retry_policy!r})"
        )

    def complete(self, metadata: ModelMetadata, request: LLMRequest, session_id: str) -> LLMReply:
        protocol = _validate_protocol(metadata)
        if not isinstance(request, LLMRequest):
            raise InvalidModelRequest("LLM requests must use the normalized request type")
        _validate_session_id(session_id)
        body = _encode_body(_request_payload(protocol, metadata, request))
        headers = self._headers_for(metadata, session_id)
        waited = 0.0

        for attempt in range(self._retry_policy.max_attempts):
            try:
                response = httpx.post(
                    ENDPOINTS[protocol],
                    content=body,
                    headers=headers,
                    timeout=self._timeout,
                    trust_env=False,
                )
            except _RETRYABLE_HTTP_ERRORS:
                if attempt + 1 == self._retry_policy.max_attempts:
                    raise RetryExhausted("Provider retry budget was exhausted") from None
                delay = self._retry_delay(None, attempt)
                if waited + delay > self._retry_policy.total_retry_wait_seconds:
                    raise RetryWaitLimitExceeded("Provider retry wait exceeds the policy cap") from None
                self._sleep(delay)
                waited += delay
                continue
            except httpx.HTTPError:
                raise ModelTransportFailure("Provider request failed") from None

            if response.status_code in _RETRYABLE_STATUSES:
                if attempt + 1 == self._retry_policy.max_attempts:
                    raise RetryExhausted("Provider retry budget was exhausted")
                delay = self._retry_delay(response, attempt)
                if waited + delay > self._retry_policy.total_retry_wait_seconds:
                    raise RetryWaitLimitExceeded("Provider retry wait exceeds the policy cap")
                self._sleep(delay)
                waited += delay
                continue
            if not 200 <= response.status_code < 300:
                raise ProviderStatusError(f"Provider returned HTTP {response.status_code}")
            return _parse_reply(protocol, _response_json(response))

        raise RetryExhausted("Provider retry budget was exhausted")

    def _headers_for(self, metadata: ModelMetadata, session_id: str) -> dict[str, str]:
        headers = {"accept": "application/json", "content-type": "application/json"}
        if metadata.provider == "opencode-go":
            headers["x-opencode-session"] = session_id
            if self._opencode_key:
                headers["authorization"] = f"Bearer {self._opencode_key}"
        elif self._ollama_key:
            headers["authorization"] = f"Bearer {self._ollama_key}"
        return headers

    def _retry_delay(self, response: httpx.Response | None, attempt: int) -> float:
        retry_after = parse_retry_after(response.headers.get("retry-after") if response is not None else None, self._now())
        if retry_after is not None:
            return retry_after
        try:
            return min(
                math.ldexp(float(self._retry_policy.initial_backoff_seconds), attempt),
                float(self._retry_policy.total_retry_wait_seconds),
            )
        except OverflowError:
            return float(self._retry_policy.total_retry_wait_seconds)


def normalize_tools(tools: object) -> tuple[Mapping[str, Any], ...]:
    if tools is None:
        return ()
    if isinstance(tools, (str, bytes)) or not isinstance(tools, Sequence):
        raise InvalidModelRequest("Tools must be a sequence")

    normalized: list[Mapping[str, Any]] = []
    for tool in tools:
        if not isinstance(tool, Mapping):
            raise InvalidModelRequest("Each tool must be a mapping")
        function = tool.get("function", tool)
        if not isinstance(function, Mapping):
            raise InvalidModelRequest("Tool functions must be mappings")
        name = function.get("name")
        if not _is_nonempty_string(name):
            raise InvalidModelRequest("Tool names must be non-empty text")
        description = function.get("description", "")
        if not isinstance(description, str):
            raise InvalidModelRequest("Tool descriptions must be text")
        parameters = function.get("parameters", function.get("input_schema", {"type": "object", "properties": {}}))
        normalized.append(
            {
                "name": name,
                "description": description,
                "parameters": _json_object(parameters, InvalidModelRequest),
            }
        )
    return tuple(normalized)


def _validate_protocol(metadata: ModelMetadata) -> str:
    if not isinstance(metadata, ModelMetadata):
        raise InvalidModelRequest("Model metadata must be validated")
    if metadata.provider == "opencode-go" and metadata.protocol in {"chat", "responses", "messages"}:
        return metadata.protocol
    if metadata.provider == "ollama-cloud" and metadata.protocol == "ollama":
        return metadata.protocol
    raise UnsupportedModelProtocol("Model provider and protocol are incompatible")


def _validate_session_id(session_id: str) -> None:
    if not _is_nonempty_string(session_id) or "\r" in session_id or "\n" in session_id:
        raise InvalidModelRequest("Provider session IDs must be safe non-empty text")


def _request_payload(protocol: str, metadata: ModelMetadata, request: LLMRequest) -> dict[str, Any]:
    tools = normalize_tools(request.tools)
    if protocol == "chat":
        payload: dict[str, Any] = {"model": metadata.model_id, "messages": _chat_messages(request.messages)}
        if tools:
            payload["tools"] = [{"type": "function", "function": dict(tool)} for tool in tools]
        if request.response_schema is not None:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {"name": "response", "schema": _strict_schema(request.response_schema), "strict": True},
            }
        return payload
    if protocol == "responses":
        payload = {"model": metadata.model_id, "input": _responses_input(request.messages)}
        if tools:
            payload["tools"] = [
                {"type": "function", "name": tool["name"], "description": tool["description"], "parameters": tool["parameters"]}
                for tool in tools
            ]
        if request.response_schema is not None:
            payload["text"] = {
                "format": {
                    "type": "json_schema",
                    "name": "response",
                    "schema": _strict_schema(request.response_schema),
                    "strict": True,
                }
            }
        return payload
    if protocol == "messages":
        payload = {"model": metadata.model_id, "messages": _anthropic_messages(request.messages), "max_tokens": 4096}
        system = _anthropic_system(request.messages)
        if system is not None:
            payload["system"] = system
        if tools:
            payload["tools"] = [
                {"name": tool["name"], "description": tool["description"], "input_schema": tool["parameters"]}
                for tool in tools
            ]
        if request.response_schema is not None:
            payload["output_config"] = {"format": {"type": "json_schema", "schema": dict(request.response_schema)}}
        return payload
    payload = {"model": metadata.model_id, "messages": _ollama_messages(request.messages), "stream": False}
    if tools:
        payload["tools"] = [{"type": "function", "function": dict(tool)} for tool in tools]
    if request.response_schema is not None:
        payload["format"] = dict(request.response_schema)
    return payload


def _chat_messages(messages: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    serialized: list[dict[str, Any]] = []
    for message in messages:
        role = _message_role(message)
        if role == "tool":
            serialized.append(
                {
                    "role": "tool",
                    "tool_call_id": _tool_result_id(message),
                    "content": _text_content(message),
                }
            )
            continue
        content = message.get("content")
        if role == "assistant" and "tool_calls" in message:
            serialized.append(
                {
                    "role": "assistant",
                    "content": content if content != "" else None,
                    "tool_calls": [_chat_tool_call(call) for call in _message_tool_calls(message)],
                }
            )
            continue
        serialized.append({"role": role, "content": content})
    return serialized


def _responses_input(messages: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    serialized: list[dict[str, Any]] = []
    for message in messages:
        role = _message_role(message)
        if role == "tool":
            serialized.append(
                {
                    "type": "function_call_output",
                    "call_id": _tool_result_id(message),
                    "output": _text_content(message),
                }
            )
            continue
        if role == "assistant" and "tool_calls" in message:
            content = message.get("content")
            if content not in (None, ""):
                serialized.append({"role": "assistant", "content": content})
            serialized.extend(
                {
                    "type": "function_call",
                    "call_id": call.id,
                    "name": call.name,
                    "arguments": _encode_body(call.arguments).decode("utf-8"),
                }
                for call in _message_tool_calls(message)
            )
            continue
        serialized.append({"role": role, "content": message.get("content")})
    return serialized


def _anthropic_system(messages: Sequence[Mapping[str, Any]]) -> str | None:
    parts = [_text_content(message) for message in messages if _message_role(message) == "system"]
    return "\n\n".join(parts) if parts else None


def _anthropic_messages(messages: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    serialized: list[dict[str, Any]] = []
    pending_results: list[dict[str, Any]] = []

    def flush_results() -> None:
        if pending_results:
            serialized.append({"role": "user", "content": list(pending_results)})
            pending_results.clear()

    for message in messages:
        role = _message_role(message)
        if role == "system":
            continue
        if role == "tool":
            pending_results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": _tool_result_id(message),
                    "content": _text_content(message),
                }
            )
            continue
        flush_results()
        if role == "assistant" and "tool_calls" in message:
            blocks: list[dict[str, Any]] = []
            content = message.get("content")
            if isinstance(content, str) and content:
                blocks.append({"type": "text", "text": content})
            elif content not in (None, ""):
                raise InvalidModelRequest("Anthropic assistant content must be text")
            blocks.extend(
                {"type": "tool_use", "id": call.id, "name": call.name, "input": dict(call.arguments)}
                for call in _message_tool_calls(message)
            )
            serialized.append({"role": "assistant", "content": blocks})
            continue
        if role not in {"user", "assistant"}:
            raise InvalidModelRequest("Anthropic messages support user and assistant roles")
        serialized.append({"role": role, "content": message.get("content")})
    flush_results()
    return serialized


def _ollama_messages(messages: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    serialized: list[dict[str, Any]] = []
    for message in messages:
        role = _message_role(message)
        if role == "tool":
            serialized.append({"role": "tool", "tool_name": _tool_name(message), "content": _text_content(message)})
            continue
        if role == "assistant" and "tool_calls" in message:
            serialized.append(
                {
                    "role": "assistant",
                    "content": _text_content(message),
                    "tool_calls": [
                        {
                            "id": call.id,
                            "type": "function",
                            "function": {"name": call.name, "arguments": dict(call.arguments)},
                        }
                        for call in _message_tool_calls(message)
                    ],
                }
            )
            continue
        serialized.append({"role": role, "content": message.get("content")})
    return serialized


def _message_role(message: Mapping[str, Any]) -> str:
    role = message.get("role")
    if not _is_nonempty_string(role):
        raise InvalidModelRequest("Messages require a role")
    return role


def _text_content(message: Mapping[str, Any]) -> str:
    content = message.get("content")
    if not isinstance(content, str):
        raise InvalidModelRequest("Tool and system message content must be text")
    return content


def _tool_result_id(message: Mapping[str, Any]) -> str:
    call_id = message.get("tool_call_id")
    if not _is_nonempty_string(call_id):
        raise InvalidModelRequest("Tool results require a call ID")
    return call_id


def _tool_name(message: Mapping[str, Any]) -> str:
    name = message.get("name")
    if not _is_nonempty_string(name):
        raise InvalidModelRequest("Tool results require a tool name")
    return name


def _message_tool_calls(message: Mapping[str, Any]) -> tuple[ToolCall, ...]:
    calls = message.get("tool_calls")
    if not isinstance(calls, list):
        raise InvalidModelRequest("Assistant tool calls must be a list")
    normalized: list[ToolCall] = []
    for raw in calls:
        if not isinstance(raw, Mapping):
            raise InvalidModelRequest("Assistant tool calls must be mappings")
        function = raw.get("function", raw)
        if not isinstance(function, Mapping):
            raise InvalidModelRequest("Assistant tool call functions must be mappings")
        call_id = raw.get("id")
        name = raw.get("name", function.get("name"))
        arguments = raw.get("arguments", function.get("arguments"))
        normalized.append(
            ToolCall(
                id=call_id if isinstance(call_id, str) else "",
                name=name if isinstance(name, str) else "",
                arguments=_parse_arguments(arguments),
            )
        )
    return tuple(normalized)


def _chat_tool_call(call: ToolCall) -> dict[str, Any]:
    return {
        "id": call.id,
        "type": "function",
        "function": {"name": call.name, "arguments": _encode_body(call.arguments).decode("utf-8")},
    }


def _response_json(response: httpx.Response) -> Mapping[str, Any]:
    try:
        payload = response.json()
    except (ValueError, json.JSONDecodeError):
        raise MalformedProviderReply("Provider response was not JSON") from None
    if not isinstance(payload, Mapping):
        raise MalformedProviderReply("Provider response must be a JSON object")
    return payload


def _parse_reply(protocol: str, payload: Mapping[str, Any]) -> LLMReply:
    if protocol == "chat":
        return _parse_chat_reply(payload)
    if protocol == "responses":
        return _parse_responses_reply(payload)
    if protocol == "messages":
        return _parse_messages_reply(payload)
    return _parse_ollama_reply(payload)


def _parse_chat_reply(payload: Mapping[str, Any]) -> LLMReply:
    choices = payload.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], Mapping):
        raise MalformedProviderReply("Chat responses require a choice")
    choice = choices[0]
    message = choice.get("message")
    if not isinstance(message, Mapping):
        raise MalformedProviderReply("Chat responses require an assistant message")
    if message.get("role") != "assistant":
        raise MalformedProviderReply("Chat responses require an assistant message")
    content = message.get("content")
    if content is not None and not isinstance(content, str):
        raise MalformedProviderReply("Chat response content must be text")
    calls = _parse_openai_tool_calls(message.get("tool_calls"))
    return _terminal_or_tools(content, calls, _usage(payload), _optional_text(choice.get("finish_reason")))


def _parse_responses_reply(payload: Mapping[str, Any]) -> LLMReply:
    output = payload.get("output")
    if not isinstance(output, list):
        raise MalformedProviderReply("Responses replies require output items")
    text: list[str] = []
    calls: list[ToolCall] = []
    for item in output:
        if not isinstance(item, Mapping):
            raise MalformedProviderReply("Responses output items must be objects")
        item_type = item.get("type")
        if item_type == "message":
            if item.get("role") != "assistant":
                raise MalformedProviderReply("Responses replies require assistant messages")
            content = item.get("content")
            if not isinstance(content, list):
                raise MalformedProviderReply("Responses message content must be a list")
            for block in content:
                if not isinstance(block, Mapping):
                    raise MalformedProviderReply("Responses content blocks must be objects")
                if block.get("type") == "output_text":
                    value = block.get("text")
                    if not isinstance(value, str):
                        raise MalformedProviderReply("Responses text blocks must contain text")
                    text.append(value)
        elif item_type == "function_call":
            calls.append(_parse_responses_tool_call(item))
    return _terminal_or_tools(
        "".join(text) if text else None,
        tuple(calls),
        _usage(payload),
        _optional_text(payload.get("status")),
    )


def _parse_messages_reply(payload: Mapping[str, Any]) -> LLMReply:
    if payload.get("role") != "assistant":
        raise MalformedProviderReply("Messages replies require an assistant role")
    content = payload.get("content")
    if not isinstance(content, list):
        raise MalformedProviderReply("Messages replies require content blocks")
    text: list[str] = []
    calls: list[ToolCall] = []
    for block in content:
        if not isinstance(block, Mapping):
            raise MalformedProviderReply("Messages content blocks must be objects")
        if block.get("type") == "text":
            value = block.get("text")
            if not isinstance(value, str):
                raise MalformedProviderReply("Messages text blocks must contain text")
            text.append(value)
        elif block.get("type") == "tool_use":
            calls.append(_parse_messages_tool_call(block))
    return _terminal_or_tools(
        "".join(text) if text else None,
        tuple(calls),
        _usage(payload),
        _optional_text(payload.get("stop_reason")),
    )


def _parse_ollama_reply(payload: Mapping[str, Any]) -> LLMReply:
    message = payload.get("message")
    if not isinstance(message, Mapping):
        raise MalformedProviderReply("Ollama replies require an assistant message")
    if message.get("role") != "assistant":
        raise MalformedProviderReply("Ollama replies require an assistant message")
    content = message.get("content")
    if not isinstance(content, str):
        raise MalformedProviderReply("Ollama response content must be text")
    raw_calls = message.get("tool_calls", [])
    if not isinstance(raw_calls, list):
        raise MalformedProviderReply("Ollama tool calls must be a list")
    calls = tuple(_parse_ollama_tool_call(call, index) for index, call in enumerate(raw_calls))
    usage = {
        key: payload[key]
        for key in ("prompt_eval_count", "eval_count")
        if isinstance(payload.get(key), int) and not isinstance(payload.get(key), bool)
    }
    return _terminal_or_tools(content if content else None, calls, usage or None, _optional_text(payload.get("done_reason")))


def _parse_openai_tool_calls(value: object) -> tuple[ToolCall, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise MalformedProviderReply("Chat tool calls must be a list")
    calls: list[ToolCall] = []
    for raw in value:
        if not isinstance(raw, Mapping):
            raise MalformedProviderReply("Chat tool calls must be objects")
        if raw.get("type") != "function":
            raise MalformedProviderReply("Chat tool calls must be functions")
        function = raw.get("function")
        if not isinstance(function, Mapping):
            raise MalformedProviderReply("Chat tool calls require functions")
        calls.append(
            ToolCall(
                id=_required_text(raw.get("id"), "Chat tool calls require IDs"),
                name=_required_text(function.get("name"), "Chat tool calls require names"),
                arguments=_parse_arguments(function.get("arguments")),
            )
        )
    return tuple(calls)


def _parse_responses_tool_call(raw: Mapping[str, Any]) -> ToolCall:
    return ToolCall(
        id=_required_text(raw.get("call_id"), "Responses tool calls require call IDs"),
        name=_required_text(raw.get("name"), "Responses tool calls require names"),
        arguments=_parse_arguments(raw.get("arguments")),
    )


def _parse_messages_tool_call(raw: Mapping[str, Any]) -> ToolCall:
    return ToolCall(
        id=_required_text(raw.get("id"), "Messages tool calls require IDs"),
        name=_required_text(raw.get("name"), "Messages tool calls require names"),
        arguments=_parse_arguments(raw.get("input")),
    )


def _parse_ollama_tool_call(raw: object, index: int) -> ToolCall:
    if not isinstance(raw, Mapping):
        raise MalformedProviderReply("Ollama tool calls must be objects")
    function = raw.get("function")
    if not isinstance(function, Mapping):
        raise MalformedProviderReply("Ollama tool calls require functions")
    provider_id = raw.get("id")
    # Native Ollama has no call IDs; its tool-result protocol correlates by ordered tool name.
    call_id = provider_id if _is_nonempty_string(provider_id) else f"ollama-{index}"
    return ToolCall(
        id=call_id,
        name=_required_text(function.get("name"), "Ollama tool calls require names"),
        arguments=_parse_arguments(function.get("arguments", {})),
    )


def _terminal_or_tools(
    text: str | None,
    calls: tuple[ToolCall, ...],
    usage: Mapping[str, Any] | None,
    finish_reason: str | None,
) -> LLMReply:
    if (text is None or not text.strip()) and not calls:
        raise MalformedProviderReply("Provider reply contained neither text nor tool calls")
    return LLMReply(text=text, tool_calls=calls, usage=usage, finish_reason=finish_reason)


def _usage(payload: Mapping[str, Any]) -> Mapping[str, Any] | None:
    usage = payload.get("usage")
    if usage is None:
        return None
    return _json_object(usage, MalformedProviderReply)


def _parse_arguments(value: object) -> Mapping[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            raise MalformedToolArguments("Provider tool arguments were not valid JSON") from None
    if not isinstance(value, Mapping):
        raise MalformedToolArguments("Provider tool arguments must be a JSON object")
    return _json_object(value, MalformedToolArguments)


def _required_text(value: object, message: str) -> str:
    if not _is_nonempty_string(value):
        raise MalformedProviderReply(message)
    return value


def _optional_text(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise MalformedProviderReply("Provider reply metadata must be text")
    return value


def _json_mapping_sequence(value: object, name: str) -> tuple[Mapping[str, Any], ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        raise InvalidModelRequest(f"{name} must be a sequence")
    copied: list[Mapping[str, Any]] = []
    for item in value:
        copied.append(_json_object(item, InvalidModelRequest))
    return tuple(copied)


def _json_object(value: object, error_type: type[OrchestrationDefect]) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise error_type("Expected a JSON object")
    try:
        encoded = json.dumps(value, allow_nan=False, separators=(",", ":"), sort_keys=True)
        copied = json.loads(encoded)
    except (TypeError, ValueError, OverflowError):
        raise error_type("Expected JSON-compatible data") from None
    if not isinstance(copied, dict):
        raise error_type("Expected a JSON object")
    return copied


def _strict_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
    copied = dict(_json_object(schema, InvalidModelRequest))

    def close_objects(value: object) -> None:
        if isinstance(value, dict):
            schema_type = value.get("type")
            if schema_type == "object" or (isinstance(schema_type, list) and "object" in schema_type) or "properties" in value:
                value["additionalProperties"] = False
            for child in value.values():
                close_objects(child)
        elif isinstance(value, list):
            for child in value:
                close_objects(child)

    close_objects(copied)
    return copied


def _encode_body(value: object) -> bytes:
    try:
        return json.dumps(value, allow_nan=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    except (TypeError, ValueError, OverflowError):
        raise InvalidModelRequest("Model requests must contain JSON-compatible data") from None


def _is_nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_nonnegative_finite_number(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        return False
    try:
        return math.isfinite(float(value))
    except OverflowError:
        return False
