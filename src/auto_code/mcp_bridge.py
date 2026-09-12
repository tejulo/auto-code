from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
import hashlib
import hmac
from pathlib import Path
from typing import Protocol
import uuid

from .contracts import (
    EffectOutcome,
    McpActionRequest,
    PendingExternalRequest,
    PreparationBridgeAttestation,
    PreparationInput,
    TrustedMcpReceipt,
    TrustedPreparationInputRef,
    preparation_input_envelope_hash,
    sanitize_untrusted_text,
    sanitize_untrusted_value,
)
from .hashing import canonical_json_bytes, hash_json
from .state import (
    BridgeReceiptAuthority,
    RunStateStore,
    _ensure_directory,
    _normalize_state_root,
    _read_canonical_json,
    _require_sha256,
    _write_new_json,
)


class McpBridgeError(RuntimeError):
    pass


class UnpersistedMcpRequestError(McpBridgeError):
    pass


class McpOperationNotAllowedError(McpBridgeError):
    pass


@dataclass(frozen=True)
class McpToolResult:
    tool_call_id: str
    result: object
    external_revision: str | None = None
    outcome: EffectOutcome = EffectOutcome.SUCCESS
    observations: tuple[str, ...] = ()


class LinearMcpClient(Protocol):
    def call(self, server_identity: str, tool_name: str, arguments: object) -> McpToolResult: ...


_ALLOWED_LINEAR_OPERATIONS = frozenset(
    {
        "query_ticket_projection",
        "query_ticket_state",
        "compare_and_start_ticket",
        "compare_and_complete_ticket",
        "restore_ticket_state",
        "query_preparation",
    }
)


class TrustedLinearBridge:
    """Launcher-owned boundary for allowlisted Linear MCP calls and trusted evidence."""

    def __init__(
        self,
        *,
        state_root: Path,
        bridge_identity: str,
        mcp_server_identity: str,
        receipt_signing_key: bytes,
        client: LinearMcpClient,
    ) -> None:
        if not isinstance(bridge_identity, str) or not bridge_identity:
            raise ValueError("Bridge identity is required")
        if not isinstance(mcp_server_identity, str) or not mcp_server_identity:
            raise ValueError("MCP server identity is required")
        if not isinstance(receipt_signing_key, bytes) or len(receipt_signing_key) < 16:
            raise ValueError("Launcher receipt signing key is invalid")
        if not hasattr(client, "call") or not callable(client.call):
            raise ValueError("Trusted bridge requires an MCP client")
        self.state_root = _normalize_state_root(state_root)
        self.bridge_identity = bridge_identity
        self.mcp_server_identity = mcp_server_identity
        self._signing_key = bytes(receipt_signing_key)
        self.client = client
        self.receipts_dir = _ensure_directory(self.state_root, self.state_root / "trusted-mcp" / "receipts")
        self.preparation_dir = _ensure_directory(self.state_root, self.state_root / "trusted-mcp" / "preparation")
        self._receipt_authority = BridgeReceiptAuthority(
            self.state_root,
            bridge_identity,
            mcp_server_identity,
            self._signing_key,
        )

    @property
    def receipt_authority(self) -> BridgeReceiptAuthority:
        return self._receipt_authority

    def execute(self, request: McpActionRequest) -> TrustedMcpReceipt:
        try:
            snapshot = McpActionRequest.snapshot(request)
        except (TypeError, ValueError) as error:
            if str(error) == "MCP ticket target is invalid":
                raise McpBridgeError("MCP ticket target is invalid") from None
            raise McpBridgeError("MCP request is invalid") from None
        if snapshot.operation not in _ALLOWED_LINEAR_OPERATIONS or snapshot.operation == "query_preparation":
            raise McpOperationNotAllowedError("MCP operation is not allowlisted")
        try:
            ticket_target = snapshot.validated_ticket_target()
        except ValueError:
            raise McpBridgeError("MCP ticket target is invalid") from None
        try:
            snapshot.validate_request_hashes()
        except ValueError:
            raise McpBridgeError("MCP request is invalid") from None
        if not self._request_is_persisted(snapshot):
            raise UnpersistedMcpRequestError("MCP request was not persisted before bridge execution")
        result = self._call(snapshot.operation, snapshot.arguments)
        return self._write_signed_receipt(snapshot, result, target=ticket_target or snapshot.target)

    def _write_signed_receipt(
        self,
        request: McpActionRequest,
        result: McpToolResult,
        *,
        target: str,
    ) -> TrustedMcpReceipt:
        receipt_id = str(uuid.uuid4())
        relative_path = f"trusted-mcp/receipts/{receipt_id}.json"
        provisional = TrustedMcpReceipt(
            receipt_id=receipt_id,
            request_id=request.request_id,
            effect_id=request.effect_id,
            effect_hash=request.effect_hash,
            request_hash=request.request_hash,
            operation=request.operation,
            target=target,
            run_id=request.run_id,
            expected_revision=request.expected_revision,
            expected_state_hash=request.expected_state_hash,
            expected_external_revision=request.expected_external_revision,
            payload_hash=request.payload_hash,
            result_hash=_hash_external_result(result.result),
            outcome=result.outcome,
            external_revision=_safe_external_revision(result.external_revision),
            bridge_identity=self.bridge_identity,
            mcp_server_identity=self.mcp_server_identity,
            tool_call_id=result.tool_call_id,
            observed_at=datetime.now(UTC),
            observations=_safe_observations(result.observations),
            relative_path=relative_path,
        )
        receipt = provisional.model_copy(update={"bridge_signature": _sign(self._signing_key, provisional.signed_payload())})
        self._write_once(self.state_root / receipt.relative_path, receipt.model_dump(mode="json", round_trip=True))
        return receipt

    def query_preparation(
        self,
        challenge_id: str,
        query: object,
        *,
        repository_id: str,
        reservation_id: str,
    ) -> TrustedPreparationInputRef:
        if not isinstance(challenge_id, str) or not challenge_id:
            raise McpBridgeError("Preparation challenge is invalid")
        sanitized_query = sanitize_untrusted_value(query)
        if not isinstance(sanitized_query, Mapping):
            raise McpBridgeError("Preparation query is invalid")
        result = self._call("query_preparation", sanitized_query)
        if not isinstance(result.result, Mapping):
            raise McpBridgeError("Preparation response is malformed")
        sanitized_result = _redact_preparation_challenge(sanitize_untrusted_value(result.result), challenge_id)
        if not isinstance(sanitized_result, Mapping):
            raise McpBridgeError("Preparation response is malformed")
        pages = sanitized_result.get("pages")
        complete = sanitized_result.get("pagination_complete")
        max_crew_iterations = sanitized_result.get("max_crew_iterations")
        if (
            not isinstance(pages, (list, tuple))
            or not isinstance(complete, bool)
            or type(max_crew_iterations) is not int
        ):
            raise McpBridgeError("Preparation response is malformed")
        page_hashes = {f"page-{index}": hash_json(page) for index, page in enumerate(pages, start=1)}
        input_id = str(uuid.uuid4())
        relative_path = f"trusted-mcp/preparation/{input_id}.json"
        captured_at = datetime.now(UTC)
        tool_call_id = _safe_preparation_tool_call_id(result.tool_call_id, challenge_id)
        try:
            preparation_input = PreparationInput(
                repository_id=repository_id,
                max_crew_iterations=max_crew_iterations,
                assignee_resolution=sanitized_result.get("assignee_resolution"),
                milestone_resolution=sanitized_result.get("milestone_resolution"),
                pages=pages,
                page_hashes=page_hashes,
                workflow_states=sanitized_result.get("workflow_states"),
                bridge_attestation=PreparationBridgeAttestation(
                    bridge_identity=self.bridge_identity,
                    mcp_server_identity=self.mcp_server_identity,
                    tool_call_id=tool_call_id,
                    captured_at=captured_at,
                ),
            )
            provisional = TrustedPreparationInputRef(
                input_id=input_id,
                relative_path=relative_path,
                repository_id=repository_id,
                reservation_id=reservation_id,
                challenge_hash=hash_json(challenge_id),
                input_hash="0" * 64,
                query_hash=hash_json(sanitized_query),
                payload_hash=hash_json(sanitized_query),
                result_hash=_hash_external_result(result.result),
                source_page_hashes=page_hashes,
                pagination_complete=complete,
                max_crew_iterations=max_crew_iterations,
                bridge_identity=self.bridge_identity,
                mcp_server_identity=self.mcp_server_identity,
                tool_call_id=tool_call_id,
                captured_at=captured_at,
                observations=_safe_observations(result.observations, forbidden_text=challenge_id),
            )
        except (TypeError, ValueError):
            raise McpBridgeError("Preparation response is malformed") from None
        provisional = provisional.model_copy(
            update={"input_hash": preparation_input_envelope_hash(provisional, preparation_input)}
        )
        reference = provisional.model_copy(update={"bridge_signature": _sign(self._signing_key, provisional.signed_payload())})
        self._write_once(
            self.state_root / reference.relative_path,
            {
                "reference": reference.model_dump(mode="json", round_trip=True),
                "input": preparation_input.model_dump(mode="json", round_trip=True),
            },
        )
        return reference

    def verify_preparation_input(self, reference: TrustedPreparationInputRef) -> bool:
        """Compatibility predicate backed by the opaque bridge-owned input loader."""
        try:
            self.verify_and_load_preparation_input(reference)
            return True
        except Exception:
            return False

    def verify_and_load_preparation_input(
        self,
        reference: TrustedPreparationInputRef,
    ) -> tuple[TrustedPreparationInputRef, PreparationInput]:
        """Verify that a reference resolves to this bridge's immutable typed envelope."""

        if not isinstance(reference, TrustedPreparationInputRef):
            raise McpBridgeError("Trusted preparation input is invalid")
        loaded_reference, preparation_input = self.load_verified_preparation_input(
            self.state_root / reference.relative_path,
            reference.input_hash,
        )
        if loaded_reference != reference:
            raise McpBridgeError("Trusted preparation input is invalid")
        return loaded_reference, preparation_input

    def load_verified_preparation_input(
        self,
        input_path: Path | str,
        input_hash: str,
    ) -> tuple[TrustedPreparationInputRef, PreparationInput]:
        """Load only a signed envelope beneath this bridge's authoritative state root."""

        try:
            path = self._preparation_envelope_path(input_path)
            expected_hash = _require_sha256(input_hash, "preparation input hash")
            envelope = _read_canonical_json(path, "trusted preparation input")
            if not isinstance(envelope, Mapping) or set(envelope) != {"reference", "input"}:
                raise ValueError("invalid preparation envelope")
            reference = TrustedPreparationInputRef.model_validate(envelope["reference"])
            preparation_input = PreparationInput.model_validate(envelope["input"])
            relative_path = path.relative_to(self.state_root).as_posix()
            if (
                reference.relative_path != relative_path
                or Path(reference.relative_path).name != f"{reference.input_id}.json"
                or reference.bridge_identity != self.bridge_identity
                or reference.mcp_server_identity != self.mcp_server_identity
                or reference.bridge_signature is None
                or not hmac.compare_digest(reference.bridge_signature, _sign(self._signing_key, reference.signed_payload()))
                or not hmac.compare_digest(reference.input_hash, expected_hash)
                or not hmac.compare_digest(
                    reference.input_hash,
                    preparation_input_envelope_hash(reference, preparation_input),
                )
                or preparation_input.repository_id != reference.repository_id
                or preparation_input.max_crew_iterations != reference.max_crew_iterations
                or dict(preparation_input.page_hashes) != dict(reference.source_page_hashes)
                or preparation_input.bridge_attestation.bridge_identity != reference.bridge_identity
                or preparation_input.bridge_attestation.mcp_server_identity != reference.mcp_server_identity
                or preparation_input.bridge_attestation.tool_call_id != reference.tool_call_id
                or preparation_input.bridge_attestation.captured_at != reference.captured_at
                or not reference.pagination_complete
                or preparation_input.max_crew_iterations <= 0
            ):
                raise ValueError("preparation envelope does not match its trusted reference")
            return reference, preparation_input
        except Exception:
            raise McpBridgeError("Trusted preparation input is invalid") from None

    def _preparation_envelope_path(self, input_path: Path | str) -> Path:
        if not isinstance(input_path, (str, Path)):
            raise ValueError("Preparation input path is invalid")
        requested = Path(input_path)
        if requested.is_absolute():
            relative = requested.relative_to(self.state_root)
        else:
            relative = requested
        if (
            len(relative.parts) != 3
            or relative.parts[:2] != ("trusted-mcp", "preparation")
            or relative.suffix != ".json"
            or any(part in {"", ".", ".."} for part in relative.parts)
        ):
            raise ValueError("Preparation input path is invalid")
        return self.state_root.joinpath(*relative.parts)

    def _call(self, operation: str, arguments: object) -> McpToolResult:
        if operation not in _ALLOWED_LINEAR_OPERATIONS:
            raise McpOperationNotAllowedError("MCP operation is not allowlisted")
        try:
            result = self.client.call(self.mcp_server_identity, operation, arguments)
        except Exception as error:
            raise McpBridgeError("Trusted Linear MCP invocation failed") from error
        if not isinstance(result, McpToolResult):
            raise McpBridgeError("Trusted Linear MCP returned an invalid result")
        return result

    def _request_is_persisted(self, request: McpActionRequest) -> bool:
        try:
            generation = RunStateStore.load_read_only(self.state_root, request.run_id)
            pending = generation.state.pending_external_request
            return pending is not None and _pending_matches_request(pending, request)
        except Exception:
            return False

    def _write_once(self, path: Path, value: object) -> None:
        if _write_new_json(path, value):
            return
        try:
            existing = _read_canonical_json(path, "trusted bridge evidence")
        except Exception as error:
            raise McpBridgeError("Trusted bridge evidence cannot be reconciled") from error
        if existing != value:
            raise McpBridgeError("Trusted bridge evidence conflicts with an existing receipt")


def _sign(signing_key: bytes, payload: object) -> str:
    return hmac.new(signing_key, canonical_json_bytes(payload), hashlib.sha256).hexdigest()


def _hash_external_result(value: object) -> str:
    try:
        return hash_json(value)
    except (TypeError, ValueError) as error:
        raise McpBridgeError("Trusted Linear MCP returned a non-JSON result") from error


def _safe_external_revision(value: str | None) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > 256:
        return None
    sanitized = sanitize_untrusted_text(value)
    return None if sanitized == "[REDACTED]" else sanitized


def _safe_observations(observations: tuple[str, ...], *, forbidden_text: str | None = None) -> tuple[str, ...]:
    if not isinstance(observations, tuple) or any(not isinstance(item, str) for item in observations):
        raise McpBridgeError("Trusted Linear MCP observations are invalid")
    normalized = tuple(sanitize_untrusted_text(item)[:1_024] for item in observations)
    if forbidden_text is not None:
        normalized = tuple(item.replace(forbidden_text, "[REDACTED]") for item in normalized)
    return normalized or ("Trusted Linear MCP call completed.",)


def _safe_preparation_tool_call_id(value: object, challenge_id: str) -> str:
    if not isinstance(value, str) or not value or challenge_id in value:
        raise McpBridgeError("Preparation response contains an unsafe tool-call ID")
    return value


def _redact_preparation_challenge(value: object, challenge_id: str) -> object:
    if isinstance(value, str):
        return value.replace(challenge_id, "[REDACTED]")
    if isinstance(value, Mapping):
        redacted: dict[str, object] = {}
        for key, item in value.items():
            clean_key = _redact_preparation_challenge(key, challenge_id)
            if not isinstance(clean_key, str) or clean_key in redacted:
                raise McpBridgeError("Preparation response has conflicting redacted keys")
            redacted[clean_key] = _redact_preparation_challenge(item, challenge_id)
        return redacted
    if isinstance(value, (list, tuple)):
        return [_redact_preparation_challenge(item, challenge_id) for item in value]
    return value


def _pending_matches_request(pending: PendingExternalRequest, request: McpActionRequest) -> bool:
    return (
        pending.request_id == request.request_id
        and pending.effect_id == request.effect_id
        and hmac.compare_digest(pending.request_hash.lower(), request.request_hash.lower())
        and pending.operation == request.operation
        and pending.effect_hash == request.effect_hash
        and pending.expected_revision == request.expected_revision
        and pending.expected_state_hash == request.expected_state_hash
        and pending.expected_external_revision == request.expected_external_revision
        and pending.payload_hash == request.payload_hash
    )
