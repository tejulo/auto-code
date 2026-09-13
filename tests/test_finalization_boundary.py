from __future__ import annotations

import importlib


def test_ticket_package_exposes_no_private_finalization_authority() -> None:
    """A ticket process must not import the signing, listener, or launcher-composition authority."""

    service = importlib.import_module("auto_code.finalization_service")

    assert not hasattr(service, "FinalizationKeyAuthority")
    assert not hasattr(service, "_LauncherFinalizationService")
    assert not hasattr(service, "_FinalizationHandlers")
    assert importlib.util.find_spec("auto_code.finalization_launcher") is None
