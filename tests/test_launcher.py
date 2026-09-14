from __future__ import annotations

import socket
import threading
import time

import pytest

from auto_code.hashing import canonical_json_bytes
from auto_code.launcher import _ProtectedBridgeClient


def test_protected_bridge_client_timeout_applies_one_deadline_to_the_response() -> None:
    """Resetting bridge socket timeouts would let a stalled response outlive the request deadline."""

    client_transport, bridge_transport = socket.socketpair()
    request_received = threading.Event()

    def stall_response() -> None:
        with bridge_transport:
            bridge_transport.recv(65_536)
            request_received.set()
            threading.Event().wait(0.2)

    worker = threading.Thread(target=stall_response, daemon=True)
    worker.start()
    try:
        client = _ProtectedBridgeClient(client_transport, "linear-mcp")
        started = time.monotonic()
        with pytest.raises(RuntimeError, match="bridge response is unavailable"):
            client.call("linear-mcp", "query_ticket_state", {"id": "ENG-1"}, deadline=started + 0.05)
        assert request_received.is_set()
        assert time.monotonic() - started < 0.15
    finally:
        client_transport.close()
        worker.join(timeout=1)


def test_protected_bridge_client_uses_the_finalization_deadline_by_default() -> None:
    """Requiring every legacy bridge caller to supply a deadline would reject valid finalization work."""

    client_transport, bridge_transport = socket.socketpair()

    def return_response() -> None:
        with bridge_transport:
            bridge_transport.recv(65_536)
            try:
                bridge_transport.sendall(
                    canonical_json_bytes(
                        {
                            "tool_call_id": "tool-call-1",
                            "result": {"id": "ENG-1"},
                            "external_revision": "4",
                            "observed_state_id": "state-4",
                            "outcome": "success",
                            "observations": ["Ticket is in progress."],
                        }
                    )
                    + b"\n"
                )
            except BrokenPipeError:
                pass

    worker = threading.Thread(target=return_response, daemon=True)
    worker.start()
    try:
        client = _ProtectedBridgeClient(client_transport, "linear-mcp")

        response = client.call("linear-mcp", "query_ticket_state", {"id": "ENG-1"})

        assert response.tool_call_id == "tool-call-1"
    finally:
        client_transport.close()
        worker.join(timeout=1)
