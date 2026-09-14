from __future__ import annotations

import importlib
import os
from pathlib import Path
import subprocess
import sys

import pytest

from auto_code.finalization_service import FinalizationTrustMaterial


def test_ticket_package_exposes_no_private_finalization_authority() -> None:
    """A ticket process must not import the signing, listener, or launcher-composition authority."""

    service = importlib.import_module("auto_code.finalization_service")

    assert not hasattr(service, "FinalizationKeyAuthority")
    assert not hasattr(service, "_LauncherFinalizationService")
    assert not hasattr(service, "_FinalizationHandlers")
    assert importlib.util.find_spec("auto_code.finalization_launcher") is None


def test_ticket_process_cannot_import_a_finalization_private_key_loader() -> None:
    """Restoring a state-backed key authority would let ticket code recover launcher signing power."""

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from auto_code.finalization_service import _FinalizationKeyAuthority",
        ],
        capture_output=True,
        check=False,
        env={**os.environ, "PYTHONPATH": str(Path(__file__).parents[1] / "src")},
        text=True,
    )

    assert result.returncode != 0


def test_ticket_trust_envelope_cannot_disclose_the_authoritative_state_root(tmp_path: Path) -> None:
    """Adding a state-root field would remount launcher authority into the ticket process."""

    with pytest.raises(TypeError):
        FinalizationTrustMaterial(public_key="a" * 64, state_root=tmp_path)  # type: ignore[call-arg]


def test_launcher_module_is_importable_separately_from_the_ticket_cli() -> None:
    """Keeping launcher ownership in an uninstalled top-level module bypasses package deployment."""

    assert importlib.util.find_spec("auto_code.launcher") is not None
