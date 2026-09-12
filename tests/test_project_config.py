from __future__ import annotations

from copy import deepcopy
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from auto_code import project_config
from auto_code.project_config import (
    LauncherRoots,
    ProjectConfig,
    ProjectConfigError,
    expand_launcher_tokens,
)


ROOT = Path(__file__).resolve().parents[1]


def policy_data() -> dict[str, object]:
    return {
        "git": {"remote": "origin", "base_branch": None},
        "verification": {
            "allow_empty": False,
            "commands": [["${PROJECT}/.venv/bin/python", "-m", "pytest", "-q"]],
            "mutation_commands": [],
        },
        "browser": {
            "start_command": None,
            "base_url": None,
            "ready_timeout_seconds": 30,
            "command_timeout_seconds": 120,
            "playwright_command_prefix": ["${RUNNER}/bin/playwright-cli"],
            "allowed_operations": [
                "open",
                "goto",
                "snapshot",
                "click",
                "fill",
                "type",
                "press",
                "screenshot",
                "close",
            ],
        },
        "process": {"command_timeout_seconds": 120, "termination_grace_seconds": 5},
        "transport": {"total_retry_wait_seconds": 30},
        "preflight": {
            "catalog_timeout_seconds": 30,
            "max_catalog_response_bytes": 1_048_576,
            "catalog_retry_budget": 2,
            "catalog_cache_validity_seconds": 300,
        },
        "finalization": {"max_invocations_per_effect": 3, "total_retry_wait_seconds": 60},
        "automation": {
            "regression_command": ["${REPAIR_WORKTREE}/.venv/bin/python", "-m", "pytest", "-q"]
        },
        "protected_paths": [".env", ".auto-code", ".git", ".venv", "auto-code.yaml"],
        "evidence_readable_paths": [],
        "commit_excluded_paths": [".auto-code"],
        "writable_roots": [],
        "environment_allowlist": ["LANG", "LC_ALL", "TZ"],
        "linear": {"started_state_id": None, "completed_state_id": None},
        "review": {"require_distinct_model": False},
    }


def write_policy(tmp_path: Path, data: dict[str, object], name: str = "auto-code.yaml") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(data), encoding="ascii")
    return path


def test_example_policy_loads_with_immutable_hash_and_separate_safe_command_lists() -> None:
    config = ProjectConfig.load(ROOT / "auto-code.example.yaml")

    assert config.git.remote == "origin"
    assert config.verification.commands == (("${PROJECT}/.venv/bin/python", "-m", "pytest", "-q"),)
    assert config.verification.mutation_commands == ()
    assert config.evidence_readable_paths == ()
    assert config.writable_roots == ()
    assert config.preflight.catalog_timeout_seconds == 30
    assert len(config.policy_hash) == 64
    with pytest.raises(ValidationError):
        config.verification.commands += (("${PROJECT}/bin/false",),)


def test_policy_hash_is_canonical_and_token_expansion_is_literal_not_shell(tmp_path: Path) -> None:
    first_data = policy_data()
    second_data = {key: first_data[key] for key in reversed(tuple(first_data))}
    first = ProjectConfig.load(write_policy(tmp_path, first_data, "first.yaml"))
    second = ProjectConfig.load(write_policy(tmp_path, second_data, "second.yaml"))
    roots = LauncherRoots(
        project_root=tmp_path / "project",
        runner_root=tmp_path / "runner",
        repair_worktree=tmp_path / "repair",
    )

    assert first.policy_hash == second.policy_hash
    assert expand_launcher_tokens(
        ("${PROJECT}/bin/tool", "--runner=${RUNNER}", "${REPAIR_WORKTREE}/input"),
        roots,
    ) == (
        f"{tmp_path}/project/bin/tool",
        f"--runner={tmp_path}/runner",
        f"{tmp_path}/repair/input",
    )


def test_project_policy_requires_catalog_preflight_controls(tmp_path: Path) -> None:
    data = policy_data()
    del data["preflight"]

    with pytest.raises(ProjectConfigError):
        ProjectConfig.load(write_policy(tmp_path, data))


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("catalog_timeout_seconds", 0),
        ("catalog_timeout_seconds", 301),
        ("max_catalog_response_bytes", 1_023),
        ("max_catalog_response_bytes", 8_388_609),
        ("catalog_retry_budget", -1),
        ("catalog_retry_budget", 4),
        ("catalog_cache_validity_seconds", 0),
        ("catalog_cache_validity_seconds", 3_601),
    ),
)
def test_catalog_preflight_policy_rejects_out_of_bounds_controls(field: str, value: int) -> None:
    controls = {
        "catalog_timeout_seconds": 30,
        "max_catalog_response_bytes": 1_048_576,
        "catalog_retry_budget": 2,
        "catalog_cache_validity_seconds": 300,
    }
    controls[field] = value

    with pytest.raises(ValidationError):
        project_config.CatalogPreflightPolicy.model_validate(controls)


def test_catalog_preflight_policy_rejects_unrecognized_controls() -> None:
    controls = {
        "catalog_timeout_seconds": 30,
        "max_catalog_response_bytes": 1_048_576,
        "catalog_retry_budget": 2,
        "catalog_cache_validity_seconds": 300,
        "provider_endpoint": "https://catalog.example.test",
    }

    with pytest.raises(ValidationError):
        project_config.CatalogPreflightPolicy.model_validate(controls)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("catalog_timeout_seconds", 31),
        ("max_catalog_response_bytes", 1_048_577),
        ("catalog_retry_budget", 1),
        ("catalog_cache_validity_seconds", 301),
    ),
)
def test_policy_hash_changes_when_catalog_preflight_limits_change(
    tmp_path: Path,
    field: str,
    replacement: int,
) -> None:
    data = policy_data()
    first = ProjectConfig.load(write_policy(tmp_path, data, "first.yaml"))
    data["preflight"][field] = replacement  # type: ignore[index]
    second = ProjectConfig.load(write_policy(tmp_path, data, "second.yaml"))

    assert first.policy_hash != second.policy_hash


def test_policy_rejects_duplicate_unknown_and_launcher_owned_configuration(tmp_path: Path) -> None:
    duplicate = write_policy(tmp_path, policy_data()).read_text(encoding="ascii") + "\ngit:\n  remote: other\n"
    duplicate_path = tmp_path / "duplicate.yaml"
    duplicate_path.write_text(duplicate, encoding="ascii")

    with pytest.raises(ProjectConfigError):
        ProjectConfig.load(duplicate_path)

    for forbidden_field in ("state_root", "authorization_keys", "receipt_trust_root", "repair_runner_identity"):
        data = deepcopy(policy_data())
        data[forbidden_field] = "launcher-only"
        with pytest.raises(ProjectConfigError):
            ProjectConfig.load(write_policy(tmp_path, data, f"{forbidden_field}.yaml"))


def test_policy_rejects_shell_syntax_unknown_tokens_and_unapproved_empty_verification(tmp_path: Path) -> None:
    shell = deepcopy(policy_data())
    shell["verification"]["commands"] = [["${PROJECT}/bin/tool", ";", "whoami"]]  # type: ignore[index]
    with pytest.raises(ProjectConfigError):
        ProjectConfig.load(write_policy(tmp_path, shell, "shell.yaml"))

    shell_binary = deepcopy(policy_data())
    shell_binary["verification"]["commands"] = [["/bin/sh", "-c", "run"]]  # type: ignore[index]
    with pytest.raises(ProjectConfigError):
        ProjectConfig.load(write_policy(tmp_path, shell_binary, "shell-binary.yaml"))

    token = deepcopy(policy_data())
    token["automation"]["regression_command"] = ["${HOME}/bin/test"]  # type: ignore[index]
    with pytest.raises(ProjectConfigError):
        ProjectConfig.load(write_policy(tmp_path, token, "token.yaml"))

    environment = deepcopy(policy_data())
    environment["environment_allowlist"] = ["PATH"]
    with pytest.raises(ProjectConfigError):
        ProjectConfig.load(write_policy(tmp_path, environment, "environment.yaml"))

    empty = deepcopy(policy_data())
    empty["verification"]["commands"] = []  # type: ignore[index]
    with pytest.raises(ProjectConfigError):
        ProjectConfig.load(write_policy(tmp_path, empty, "empty.yaml"))


def test_policy_rejects_secret_bearing_values_in_every_command_role(tmp_path: Path) -> None:
    secret_argument = "--api-key=policy-value-with-no-marker"
    verification = deepcopy(policy_data())
    verification["verification"]["commands"] = [["${PROJECT}/bin/check", secret_argument]]  # type: ignore[index]

    mutation = deepcopy(policy_data())
    mutation["verification"]["mutation_commands"] = [["${PROJECT}/bin/mutate", secret_argument]]  # type: ignore[index]

    browser_start = deepcopy(policy_data())
    browser_start["browser"]["start_command"] = ["${PROJECT}/bin/server", secret_argument]  # type: ignore[index]
    browser_start["browser"]["base_url"] = "http://localhost:3000"  # type: ignore[index]

    browser_prefix = deepcopy(policy_data())
    browser_prefix["browser"]["playwright_command_prefix"] = ["${RUNNER}/bin/playwright-cli", secret_argument]  # type: ignore[index]

    regression = deepcopy(policy_data())
    regression["automation"]["regression_command"] = ["${REPAIR_WORKTREE}/bin/test", secret_argument]  # type: ignore[index]

    for name, data in (
        ("verification", verification),
        ("mutation", mutation),
        ("browser-start", browser_start),
        ("browser-prefix", browser_prefix),
        ("regression", regression),
    ):
        with pytest.raises(ProjectConfigError):
            ProjectConfig.load(write_policy(tmp_path, data, f"{name}.yaml"))


@pytest.mark.parametrize(
    "secret_argument",
    ("--clientSecret=plain-secret-value", "--clientSecret=plain-value"),
)
def test_policy_rejects_camel_case_secret_argument_keys_without_rejecting_safe_launcher_token_paths(
    tmp_path: Path,
    secret_argument: str,
) -> None:
    safe = deepcopy(policy_data())
    safe["verification"]["commands"] = [["${PROJECT}/bin/clientSecret-tool"]]  # type: ignore[index]
    ProjectConfig.load(write_policy(tmp_path, safe, "safe.yaml"))

    verification = deepcopy(policy_data())
    verification["verification"]["commands"] = [["${PROJECT}/bin/check", secret_argument]]  # type: ignore[index]

    mutation = deepcopy(policy_data())
    mutation["verification"]["mutation_commands"] = [["${PROJECT}/bin/mutate", secret_argument]]  # type: ignore[index]

    browser_start = deepcopy(policy_data())
    browser_start["browser"]["start_command"] = ["${PROJECT}/bin/server", secret_argument]  # type: ignore[index]
    browser_start["browser"]["base_url"] = "http://localhost:3000"  # type: ignore[index]

    browser_prefix = deepcopy(policy_data())
    browser_prefix["browser"]["playwright_command_prefix"] = ["${RUNNER}/bin/playwright-cli", secret_argument]  # type: ignore[index]

    regression = deepcopy(policy_data())
    regression["automation"]["regression_command"] = ["${REPAIR_WORKTREE}/bin/test", secret_argument]  # type: ignore[index]

    for name, data in (
        ("verification", verification),
        ("mutation", mutation),
        ("browser-start", browser_start),
        ("browser-prefix", browser_prefix),
        ("regression", regression),
    ):
        with pytest.raises(ProjectConfigError):
            ProjectConfig.load(write_policy(tmp_path, data, f"{name}.yaml"))
