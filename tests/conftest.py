from __future__ import annotations

import pytest


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--provider-smoke", action="store_true", default=False)


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if config.getoption("--provider-smoke"):
        return
    items[:] = [item for item in items if "provider_smoke" not in item.keywords]
