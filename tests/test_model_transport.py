from __future__ import annotations

from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
import json

import httpx
from pydantic import BaseModel
import pytest
import respx

from auto_code.model_catalog import ModelMetadata
from auto_code.model_transport import (
    LLMReply,
    LLMRequest,
    MalformedProviderReply,
    MalformedToolArguments,
    ModelTransport,
    RetryPolicy,
    RetryExhausted,
    RetryWaitLimitExceeded,
    ToolCall,
    ToolResult,
    ModelTransportFailure,
    ProviderStatusError,
    parse_retry_after,
)


DEFAULT_RETRY_POLICY = RetryPolicy()


class FlatStructuredReply(BaseModel):
    answer: str


class NestedStructuredReply(BaseModel):
    detail: FlatStructuredReply


def metadata(protocol: str) -> ModelMetadata:
    return ModelMetadata(
        provider="ollama-cloud" if protocol == "ollama" else "opencode-go",
        model_id="model-1",
        protocol=protocol,
        capabilities=frozenset({"structured_output", "tool_calling"}),
    )


def request(schema: dict[str, object] | None = None) -> LLMRequest:
    return LLMRequest(
        messages=[{"role": "user", "content": "inspect this"}],
        tools=[],
        response_schema=schema,
    )


def request_json(call: respx.models.Call) -> dict[str, object]:
    return json.loads(call.request.content)


def tool_followup_request() -> LLMRequest:
    return LLMRequest(
        messages=[{"role": "user", "content": "inspect this"}],
        tools=[],
        response_schema=None,
    ).append_assistant_calls_and_results(
        LLMReply(
            text="checking",
            tool_calls=(ToolCall(id="call-1", name="read_file", arguments={"path": "README.md"}),),
        ),
        (ToolResult(call_id="call-1", name="read_file", content="file contents"),),
    )


def assert_opencode_auth_isolated(call: respx.models.Call) -> None:
    sent = call.request
    assert sent.headers["authorization"] == "Bearer opencode-secret"
    assert sent.headers["x-opencode-session"] == "run-ENG-1"
    assert "ollama-secret" not in str(sent.headers)
    assert "opencode-secret" not in str(sent.url)
    assert "ollama-secret" not in str(sent.url)
    assert "opencode-secret" not in sent.content.decode("utf-8")
    assert "ollama-secret" not in sent.content.decode("utf-8")


def assert_ollama_auth_isolated(call: respx.models.Call) -> None:
    sent = call.request
    assert sent.headers["authorization"] == "Bearer ollama-secret"
    assert "x-opencode-session" not in sent.headers
    assert "opencode-secret" not in str(sent.headers)
    assert "opencode-secret" not in str(sent.url)
    assert "ollama-secret" not in str(sent.url)
    assert "opencode-secret" not in sent.content.decode("utf-8")
    assert "ollama-secret" not in sent.content.decode("utf-8")


def test_transport_requires_an_injected_retry_policy() -> None:
    with pytest.raises(TypeError):
        ModelTransport(opencode_key="secret", ollama_key="other")


@pytest.mark.parametrize("retry_policy", (None, object()))
def test_transport_rejects_a_non_policy_retry_configuration(retry_policy: object) -> None:
    with pytest.raises(ValueError, match="retry policy"):
        ModelTransport(opencode_key="secret", ollama_key="other", retry_policy=retry_policy)  # type: ignore[arg-type]


def test_retry_policy_rejects_a_giant_total_wait_with_value_error() -> None:
    with pytest.raises(ValueError, match="Total retry wait"):
        RetryPolicy(total_retry_wait_seconds=10**500)


def test_retry_policy_rejects_a_giant_initial_backoff_with_value_error() -> None:
    with pytest.raises(ValueError, match="Initial retry backoff"):
        RetryPolicy(initial_backoff_seconds=10**500)


def test_transport_rejects_a_giant_timeout_with_value_error() -> None:
    with pytest.raises(ValueError, match="Transport timeout"):
        ModelTransport(opencode_key="secret", ollama_key="other", retry_policy=DEFAULT_RETRY_POLICY, timeout=10**500)


def test_numeric_settings_accept_ordinary_ints_and_floats() -> None:
    policy = RetryPolicy(total_retry_wait_seconds=2, initial_backoff_seconds=0.5)

    assert policy.total_retry_wait_seconds == 2
    assert policy.initial_backoff_seconds == 0.5
    assert isinstance(
        ModelTransport(opencode_key="secret", ollama_key="other", retry_policy=policy, timeout=2.5), ModelTransport
    )


def test_transport_disables_httpx_environment_configuration(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[dict[str, object]] = []

    def post(url: str, **kwargs: object) -> httpx.Response:
        del url
        calls.append(kwargs)
        return httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "ok"}}]})

    monkeypatch.setattr(httpx, "post", post)

    reply = ModelTransport(opencode_key="secret", ollama_key="other", retry_policy=DEFAULT_RETRY_POLICY).complete(
        metadata("chat"), request(), "run-ENG-1"
    )

    assert reply.text == "ok"
    assert calls[0]["trust_env"] is False


def test_reply_normalizes_a_list_of_tool_calls() -> None:
    reply = LLMReply(text=None, tool_calls=[ToolCall(id="call-1", name="read_file", arguments={"path": "README.md"})])

    assert reply.tool_calls == (ToolCall(id="call-1", name="read_file", arguments={"path": "README.md"}),)


@respx.mock
def test_chat_transport_sets_session_and_keeps_key_out_of_request_content() -> None:
    route = respx.post("https://opencode.ai/zen/go/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "ok"}}]})
    )

    reply = ModelTransport(
        opencode_key="opencode-secret", ollama_key="ollama-secret", retry_policy=DEFAULT_RETRY_POLICY
    ).complete(
        metadata("chat"), request(), "run-ENG-1"
    )

    assert reply.text == "ok"
    sent = route.calls[0].request
    assert sent.headers["x-opencode-session"] == "run-ENG-1"
    assert sent.headers["authorization"] == "Bearer opencode-secret"
    assert "opencode-secret" not in str(sent.url)
    assert "opencode-secret" not in sent.content.decode("utf-8")
    assert request_json(route.calls[0]) == {
        "messages": [{"content": "inspect this", "role": "user"}],
        "model": "model-1",
    }


@respx.mock
def test_responses_transport_extracts_text_and_sends_structured_schema() -> None:
    route = respx.post("https://opencode.ai/zen/go/v1/responses").mock(
        return_value=httpx.Response(
            200,
            json={
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "ok"}],
                    }
                ]
            },
        )
    )

    reply = ModelTransport(opencode_key="secret", ollama_key="other", retry_policy=DEFAULT_RETRY_POLICY).complete(
        metadata("responses"), request({"type": "object", "properties": {"answer": {"type": "string"}}}), "run-ENG-1"
    )

    assert reply.text == "ok"
    assert request_json(route.calls[0]) == {
        "input": [{"content": "inspect this", "role": "user"}],
        "model": "model-1",
        "text": {
            "format": {
                "name": "response",
                "schema": {
                    "additionalProperties": False,
                    "properties": {"answer": {"type": "string"}},
                    "type": "object",
                },
                "strict": True,
                "type": "json_schema",
            }
        },
    }


@respx.mock
def test_chat_transport_closes_a_pydantic_object_schema_for_strict_output() -> None:
    route = respx.post("https://opencode.ai/zen/go/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "ok"}}]})
    )

    ModelTransport(opencode_key="secret", ollama_key="other", retry_policy=DEFAULT_RETRY_POLICY).complete(
        metadata("chat"), request(FlatStructuredReply.model_json_schema()), "run-ENG-1"
    )

    response_format = request_json(route.calls[0])["response_format"]
    assert isinstance(response_format, dict)
    json_schema = response_format["json_schema"]
    assert isinstance(json_schema, dict)
    schema = json_schema["schema"]
    assert isinstance(schema, dict)
    assert schema.get("additionalProperties") is False


@respx.mock
def test_responses_transport_closes_nested_pydantic_object_schemas_for_strict_output() -> None:
    route = respx.post("https://opencode.ai/zen/go/v1/responses").mock(
        return_value=httpx.Response(
            200,
            json={
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "ok"}],
                    }
                ]
            },
        )
    )

    ModelTransport(opencode_key="secret", ollama_key="other", retry_policy=DEFAULT_RETRY_POLICY).complete(
        metadata("responses"), request(NestedStructuredReply.model_json_schema()), "run-ENG-1"
    )

    text = request_json(route.calls[0])["text"]
    assert isinstance(text, dict)
    response_format = text["format"]
    assert isinstance(response_format, dict)
    schema = response_format["schema"]
    assert isinstance(schema, dict)
    definitions = schema["$defs"]
    assert isinstance(definitions, dict)
    nested = definitions["FlatStructuredReply"]
    assert isinstance(nested, dict)
    assert schema.get("additionalProperties") is False
    assert nested.get("additionalProperties") is False


@respx.mock
def test_messages_transport_normalizes_tool_call_and_schema() -> None:
    route = respx.post("https://opencode.ai/zen/go/v1/messages").mock(
        return_value=httpx.Response(
            200,
            json={
                "role": "assistant",
                "content": [
                    {
                        "type": "tool_use",
                        "id": "call-1",
                        "name": "read_file",
                        "input": {"path": "README.md"},
                    }
                ]
            },
        )
    )

    reply = ModelTransport(opencode_key="secret", ollama_key="other", retry_policy=DEFAULT_RETRY_POLICY).complete(
        metadata("messages"), request({"type": "object"}), "run-ENG-1"
    )

    assert reply.tool_calls[0].name == "read_file"
    assert reply.tool_calls[0].id == "call-1"
    assert reply.tool_calls[0].arguments == {"path": "README.md"}
    assert request_json(route.calls[0]) == {
        "max_tokens": 4096,
        "messages": [{"content": "inspect this", "role": "user"}],
        "model": "model-1",
        "output_config": {"format": {"schema": {"type": "object"}, "type": "json_schema"}},
    }


@respx.mock
def test_ollama_transport_uses_bearer_auth_and_native_schema() -> None:
    route = respx.post("https://ollama.com/api/chat").mock(
        return_value=httpx.Response(200, json={"message": {"role": "assistant", "content": "ok"}, "done_reason": "stop"})
    )

    reply = ModelTransport(
        opencode_key="secret", ollama_key="ollama-secret", retry_policy=DEFAULT_RETRY_POLICY
    ).complete(
        metadata("ollama"), request({"type": "object"}), "run-ENG-1"
    )

    assert reply.text == "ok"
    sent = route.calls[0].request
    assert sent.headers["authorization"] == "Bearer ollama-secret"
    assert "x-opencode-session" not in sent.headers
    assert "ollama-secret" not in str(sent.url)
    assert "ollama-secret" not in sent.content.decode("utf-8")
    assert request_json(route.calls[0]) == {
        "format": {"type": "object"},
        "messages": [{"content": "inspect this", "role": "user"}],
        "model": "model-1",
        "stream": False,
    }


@respx.mock
def test_chat_transport_captures_correlated_tool_followup_and_isolates_provider_auth() -> None:
    route = respx.post("https://opencode.ai/zen/go/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "done"}}]})
    )

    ModelTransport(
        opencode_key="opencode-secret", ollama_key="ollama-secret", retry_policy=DEFAULT_RETRY_POLICY
    ).complete(metadata("chat"), tool_followup_request(), "run-ENG-1")

    assert_opencode_auth_isolated(route.calls[0])
    assert request_json(route.calls[0]) == {
        "messages": [
            {"content": "inspect this", "role": "user"},
            {
                "content": "checking",
                "role": "assistant",
                "tool_calls": [
                    {
                        "function": {"arguments": '{"path":"README.md"}', "name": "read_file"},
                        "id": "call-1",
                        "type": "function",
                    }
                ],
            },
            {"content": "file contents", "role": "tool", "tool_call_id": "call-1"},
        ],
        "model": "model-1",
    }


@respx.mock
def test_responses_transport_captures_correlated_tool_followup_and_isolates_provider_auth() -> None:
    route = respx.post("https://opencode.ai/zen/go/v1/responses").mock(
        return_value=httpx.Response(
            200,
            json={
                "output": [
                    {
                        "type": "message",
                        "role": "assistant",
                        "content": [{"type": "output_text", "text": "done"}],
                    }
                ]
            },
        )
    )

    ModelTransport(
        opencode_key="opencode-secret", ollama_key="ollama-secret", retry_policy=DEFAULT_RETRY_POLICY
    ).complete(metadata("responses"), tool_followup_request(), "run-ENG-1")

    assert_opencode_auth_isolated(route.calls[0])
    assert request_json(route.calls[0]) == {
        "input": [
            {"content": "inspect this", "role": "user"},
            {"content": "checking", "role": "assistant"},
            {
                "arguments": '{"path":"README.md"}',
                "call_id": "call-1",
                "name": "read_file",
                "type": "function_call",
            },
            {"call_id": "call-1", "output": "file contents", "type": "function_call_output"},
        ],
        "model": "model-1",
    }


@respx.mock
def test_messages_transport_captures_correlated_tool_followup_and_isolates_provider_auth() -> None:
    route = respx.post("https://opencode.ai/zen/go/v1/messages").mock(
        return_value=httpx.Response(
            200,
            json={"role": "assistant", "content": [{"type": "text", "text": "done"}]},
        )
    )

    ModelTransport(
        opencode_key="opencode-secret", ollama_key="ollama-secret", retry_policy=DEFAULT_RETRY_POLICY
    ).complete(metadata("messages"), tool_followup_request(), "run-ENG-1")

    assert_opencode_auth_isolated(route.calls[0])
    assert request_json(route.calls[0]) == {
        "max_tokens": 4096,
        "messages": [
            {"content": "inspect this", "role": "user"},
            {
                "content": [
                    {"text": "checking", "type": "text"},
                    {"id": "call-1", "input": {"path": "README.md"}, "name": "read_file", "type": "tool_use"},
                ],
                "role": "assistant",
            },
            {
                "content": [{"content": "file contents", "tool_use_id": "call-1", "type": "tool_result"}],
                "role": "user",
            },
        ],
        "model": "model-1",
    }


@respx.mock
def test_ollama_transport_captures_correlated_tool_followup_and_isolates_provider_auth() -> None:
    route = respx.post("https://ollama.com/api/chat").mock(
        return_value=httpx.Response(200, json={"message": {"role": "assistant", "content": "done"}})
    )

    ModelTransport(
        opencode_key="opencode-secret", ollama_key="ollama-secret", retry_policy=DEFAULT_RETRY_POLICY
    ).complete(metadata("ollama"), tool_followup_request(), "run-ENG-1")

    assert_ollama_auth_isolated(route.calls[0])
    assert request_json(route.calls[0]) == {
        "messages": [
            {"content": "inspect this", "role": "user"},
            {
                "content": "checking",
                "role": "assistant",
                "tool_calls": [
                    {
                        "function": {"arguments": {"path": "README.md"}, "name": "read_file"},
                        "id": "call-1",
                        "type": "function",
                    }
                ],
            },
            {"content": "file contents", "role": "tool", "tool_name": "read_file"},
        ],
        "model": "model-1",
        "stream": False,
    }


@respx.mock
def test_chat_transport_rejects_a_success_reply_with_a_non_assistant_role() -> None:
    respx.post("https://opencode.ai/zen/go/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"choices": [{"message": {"role": "user", "content": "ok"}}]})
    )

    with pytest.raises(MalformedProviderReply):
        ModelTransport(opencode_key="secret", ollama_key="other", retry_policy=DEFAULT_RETRY_POLICY).complete(
            metadata("chat"), request(), "run-ENG-1"
        )


@respx.mock
def test_responses_transport_rejects_a_success_reply_with_a_non_assistant_role() -> None:
    respx.post("https://opencode.ai/zen/go/v1/responses").mock(
        return_value=httpx.Response(
            200,
            json={
                "output": [
                    {
                        "type": "message",
                        "role": "user",
                        "content": [{"type": "output_text", "text": "ok"}],
                    }
                ]
            },
        )
    )

    with pytest.raises(MalformedProviderReply):
        ModelTransport(opencode_key="secret", ollama_key="other", retry_policy=DEFAULT_RETRY_POLICY).complete(
            metadata("responses"), request(), "run-ENG-1"
        )


@respx.mock
def test_messages_transport_rejects_a_success_reply_with_a_non_assistant_role() -> None:
    respx.post("https://opencode.ai/zen/go/v1/messages").mock(
        return_value=httpx.Response(
            200,
            json={"role": "user", "content": [{"type": "text", "text": "ok"}]},
        )
    )

    with pytest.raises(MalformedProviderReply):
        ModelTransport(opencode_key="secret", ollama_key="other", retry_policy=DEFAULT_RETRY_POLICY).complete(
            metadata("messages"), request(), "run-ENG-1"
        )


@respx.mock
def test_ollama_transport_rejects_a_success_reply_with_a_non_assistant_role() -> None:
    respx.post("https://ollama.com/api/chat").mock(
        return_value=httpx.Response(200, json={"message": {"role": "user", "content": "ok"}})
    )

    with pytest.raises(MalformedProviderReply):
        ModelTransport(opencode_key="secret", ollama_key="other", retry_policy=DEFAULT_RETRY_POLICY).complete(
            metadata("ollama"), request(), "run-ENG-1"
        )


@respx.mock
def test_chat_transport_rejects_a_success_reply_without_a_message() -> None:
    respx.post("https://opencode.ai/zen/go/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"choices": []})
    )

    with pytest.raises(MalformedProviderReply):
        ModelTransport(opencode_key="secret", ollama_key="other", retry_policy=DEFAULT_RETRY_POLICY).complete(
            metadata("chat"), request(), "run-ENG-1"
        )


@respx.mock
def test_chat_transport_rejects_an_empty_terminal_message() -> None:
    respx.post("https://opencode.ai/zen/go/v1/chat/completions").mock(
        return_value=httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": ""}}]})
    )

    with pytest.raises(MalformedProviderReply):
        ModelTransport(opencode_key="secret", ollama_key="other", retry_policy=DEFAULT_RETRY_POLICY).complete(
            metadata("chat"), request(), "run-ENG-1"
        )


@respx.mock
def test_chat_transport_rejects_a_non_function_tool_call() -> None:
    respx.post("https://opencode.ai/zen/go/v1/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call-1",
                                    "type": "computer_use_preview",
                                    "function": {"name": "read_file", "arguments": "{}"},
                                }
                            ],
                        }
                    }
                ]
            },
        )
    )

    with pytest.raises(MalformedProviderReply):
        ModelTransport(opencode_key="secret", ollama_key="other", retry_policy=DEFAULT_RETRY_POLICY).complete(
            metadata("chat"), request(), "run-ENG-1"
        )


@respx.mock
def test_chat_transport_rejects_malformed_tool_arguments() -> None:
    respx.post("https://opencode.ai/zen/go/v1/chat/completions").mock(
        return_value=httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": None,
                            "tool_calls": [
                                {
                                    "id": "call-1",
                                    "type": "function",
                                    "function": {"name": "read_file", "arguments": "{not-json"},
                                }
                            ],
                        }
                    }
                ]
            },
        )
    )

    with pytest.raises(MalformedToolArguments):
        ModelTransport(opencode_key="secret", ollama_key="other", retry_policy=DEFAULT_RETRY_POLICY).complete(
            metadata("chat"), request(), "run-ENG-1"
        )


@pytest.mark.parametrize("status", (429, 502, 503, 504))
@respx.mock
def test_retryable_status_reuses_the_identical_serialized_body(status: int) -> None:
    route = respx.post("https://opencode.ai/zen/go/v1/chat/completions").mock(
        side_effect=[
            httpx.Response(status, headers={"Retry-After": "2"}),
            httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "ok"}}]}),
        ]
    )
    waits: list[float] = []

    reply = ModelTransport(
        opencode_key="secret",
        ollama_key="other",
        retry_policy=RetryPolicy(max_attempts=2, total_retry_wait_seconds=2),
        sleep=waits.append,
    ).complete(metadata("chat"), request(), "run-ENG-1")

    assert reply.text == "ok"
    assert waits == [2]
    assert len(route.calls) == 2
    assert route.calls[0].request.content == route.calls[1].request.content


@pytest.mark.parametrize(
    "error_type",
    (httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError),
)
@respx.mock
def test_transient_httpx_failures_retry_with_the_identical_serialized_body(error_type: type[httpx.HTTPError]) -> None:
    route = respx.post("https://opencode.ai/zen/go/v1/chat/completions").mock(
        side_effect=[
            error_type("temporarily unavailable"),
            httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "ok"}}]}),
        ]
    )
    waits: list[float] = []

    reply = ModelTransport(
        opencode_key="secret",
        ollama_key="other",
        retry_policy=RetryPolicy(max_attempts=2, total_retry_wait_seconds=1, initial_backoff_seconds=1),
        sleep=waits.append,
    ).complete(metadata("chat"), request(), "run-ENG-1")

    assert reply.text == "ok"
    assert waits == [1]
    assert len(route.calls) == 2
    assert route.calls[0].request.content == route.calls[1].request.content


def test_retry_after_accepts_delta_seconds_and_http_dates() -> None:
    now = datetime(2026, 9, 6, 12, tzinfo=timezone.utc)

    assert parse_retry_after("3", now) == 3
    assert parse_retry_after(format_datetime(now + timedelta(seconds=5), usegmt=True), now) == 5


@pytest.mark.parametrize("value", ("not-a-date", "Sun, 32 Sep 2026 12:00:00 GMT"))
def test_retry_after_ignores_malformed_dates(value: str) -> None:
    assert parse_retry_after(value, datetime(2026, 9, 6, 12, tzinfo=timezone.utc)) is None


def test_retry_after_ignores_an_oversized_delta_without_raising() -> None:
    try:
        delay = parse_retry_after("9" * 5_000, datetime(2026, 9, 6, 12, tzinfo=timezone.utc))
    except Exception as error:
        pytest.fail(f"oversized Retry-After raised {type(error).__name__}")

    assert delay is None


@respx.mock
def test_malformed_retry_after_falls_back_to_the_injected_backoff() -> None:
    route = respx.post("https://opencode.ai/zen/go/v1/chat/completions").mock(
        side_effect=[
            httpx.Response(429, headers={"Retry-After": "not-a-date"}),
            httpx.Response(200, json={"choices": [{"message": {"role": "assistant", "content": "ok"}}]}),
        ]
    )
    waits: list[float] = []

    reply = ModelTransport(
        opencode_key="secret",
        ollama_key="other",
        retry_policy=RetryPolicy(max_attempts=2, total_retry_wait_seconds=2, initial_backoff_seconds=1),
        sleep=waits.append,
    ).complete(metadata("chat"), request(), "run-ENG-1")

    assert reply.text == "ok"
    assert waits == [1]
    assert len(route.calls) == 2


@respx.mock
def test_nonretryable_status_raises_a_typed_provider_error_without_retrying() -> None:
    route = respx.post("https://opencode.ai/zen/go/v1/chat/completions").mock(
        return_value=httpx.Response(400)
    )

    with pytest.raises(ProviderStatusError, match="HTTP 400"):
        ModelTransport(opencode_key="secret", ollama_key="other", retry_policy=DEFAULT_RETRY_POLICY).complete(
            metadata("chat"), request(), "run-ENG-1"
        )

    assert len(route.calls) == 1


@respx.mock
def test_local_protocol_errors_become_typed_transport_failures_without_retrying() -> None:
    route = respx.post("https://opencode.ai/zen/go/v1/chat/completions").mock(
        side_effect=httpx.LocalProtocolError("invalid local request")
    )

    with pytest.raises(ModelTransportFailure, match="Provider request failed"):
        ModelTransport(opencode_key="secret", ollama_key="other", retry_policy=DEFAULT_RETRY_POLICY).complete(
            metadata("chat"), request(), "run-ENG-1"
        )

    assert len(route.calls) == 1


@respx.mock
def test_retryable_failures_raise_retry_exhausted_after_the_injected_attempt_budget() -> None:
    route = respx.post("https://opencode.ai/zen/go/v1/chat/completions").mock(
        return_value=httpx.Response(503)
    )
    waits: list[float] = []

    with pytest.raises(RetryExhausted):
        ModelTransport(
            opencode_key="secret",
            ollama_key="other",
            retry_policy=RetryPolicy(max_attempts=2, total_retry_wait_seconds=0, initial_backoff_seconds=0),
            sleep=waits.append,
        ).complete(metadata("chat"), request(), "run-ENG-1")

    assert waits == [0]
    assert len(route.calls) == 2


@respx.mock
def test_retry_wait_cannot_exceed_the_injected_policy_cap() -> None:
    route = respx.post("https://opencode.ai/zen/go/v1/chat/completions").mock(
        return_value=httpx.Response(429, headers={"Retry-After": "3"})
    )
    waits: list[float] = []

    with pytest.raises(RetryWaitLimitExceeded):
        ModelTransport(
            opencode_key="secret",
            ollama_key="other",
            retry_policy=RetryPolicy(max_attempts=2, total_retry_wait_seconds=2),
            sleep=waits.append,
        ).complete(metadata("chat"), request(), "run-ENG-1")

    assert waits == []
    assert len(route.calls) == 1
