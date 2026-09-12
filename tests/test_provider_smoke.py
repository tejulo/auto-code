from __future__ import annotations

import importlib
import os
from pathlib import Path
import subprocess
import sys
import types
from typing import Protocol, cast

import pytest

from auto_code.cli import TrustedRuntimeConfig
from auto_code.compatibility import PreflightVersionVerifier
from auto_code.model_config import RoleModelConfig, RoleName


class ProviderSmokeHarness(Protocol):
    verifier: PreflightVersionVerifier
    runtime_config: TrustedRuntimeConfig
    role_config: RoleModelConfig


def load_launcher_smoke_harness() -> ProviderSmokeHarness:
    module_path = os.getenv("AUTO_CODE_PROVIDER_SMOKE_HARNESS")
    if not module_path or not all(part.isidentifier() for part in module_path.split(".")):
        pytest.skip("provider smoke harness is unavailable")
    try:
        module = importlib.import_module(module_path)
        builder = getattr(module, "build_provider_smoke_harness")
        if not callable(builder):
            raise TypeError
        harness = builder()
        if any(not hasattr(harness, attribute) for attribute in ("verifier", "runtime_config", "role_config")):
            raise TypeError
    # The launcher-owned boundary must not expose harness-controlled outcomes.
    except BaseException:
        pytest.skip("provider smoke harness is unavailable")
    return cast(ProviderSmokeHarness, harness)


def test_launcher_smoke_loader_validates_a_fake_harness(monkeypatch: pytest.MonkeyPatch) -> None:
    harness = types.SimpleNamespace(
        verifier=object(),
        runtime_config=object(),
        role_config=object(),
    )
    fake = types.SimpleNamespace(build_provider_smoke_harness=lambda: harness)
    monkeypatch.setenv("AUTO_CODE_PROVIDER_SMOKE_HARNESS", "fake_launcher_harness")
    monkeypatch.setattr(importlib, "import_module", lambda _: fake)

    assert load_launcher_smoke_harness() is harness


def test_launcher_smoke_loader_hides_harness_outcome_exceptions(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_untrusted_skip() -> object:
        raise pytest.skip.Exception("untrusted harness outcome")

    fake = types.SimpleNamespace(build_provider_smoke_harness=raise_untrusted_skip)
    monkeypatch.setenv("AUTO_CODE_PROVIDER_SMOKE_HARNESS", "fake_launcher_harness")
    monkeypatch.setattr(importlib, "import_module", lambda _: fake)

    with pytest.raises(pytest.skip.Exception, match="^provider smoke harness is unavailable$"):
        load_launcher_smoke_harness()


def test_default_pytest_deselects_launcher_harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    sentinel = tmp_path / "harness-imported"
    module = tmp_path / "external_smoke_harness.py"
    module.write_text(
        "from pathlib import Path\n"
        f"Path({str(sentinel)!r}).write_text('imported', encoding='ascii')\n"
        "\n"
        "def build_provider_smoke_harness():\n"
        "    raise AssertionError('the default test suite must not call the smoke harness')\n",
        encoding="ascii",
    )
    monkeypatch.setenv("AUTO_CODE_PROVIDER_SMOKE_HARNESS", "external_smoke_harness")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-k",
            "not test_default_pytest_deselects_launcher_harness",
            "tests/test_provider_smoke.py",
            "-q",
        ],
        cwd=Path(__file__).parents[1],
        capture_output=True,
        check=False,
        text=True,
    )

    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert not sentinel.exists()
    assert "PytestUnknownMarkWarning" not in completed.stdout + completed.stderr


@pytest.mark.provider_smoke
def test_launcher_composed_provider_smoke_contract() -> None:
    harness = load_launcher_smoke_harness()
    result = harness.verifier.verify(harness.runtime_config, harness.role_config)

    assert result.receipt_ref.sha256 == result.receipt.content_hash
    assert set(result.catalogs) == {ref.provider for ref in harness.role_config.models.values()}
    assert set(result.resolved_models) == set(RoleName)
