from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from auto_code import cli
from auto_code.cli import RuntimeConfigurationError, TrustedRuntimeConfig, main
from auto_code.contracts import EvidenceRef, RunState, RunnerIdentity
from auto_code.state import EMPTY_STATE_HASH, RunStateStore


def runner_identity() -> RunnerIdentity:
    return RunnerIdentity(
        content_hash="a" * 64,
        source_sha="b" * 64,
        dependency_lock_hash="c" * 64,
        contract_bundle_hash="d" * 64,
        built_at=datetime(2026, 9, 7, tzinfo=UTC),
    )


def runtime_payload(tmp_path: Path) -> dict[str, object]:
    project_root = tmp_path / "project"
    project_root.mkdir(exist_ok=True)
    policy_path = project_root / "auto-code.yaml"
    return {
        "state_root": str(tmp_path / "state"),
        "project_root": str(project_root),
        "project_policy_path": str(policy_path),
        "project_policy_hash": "0" * 64,
        "runner_identity": runner_identity().model_dump(mode="json"),
    }


@pytest.fixture
def trusted_runtime_factory() -> Callable[..., TrustedRuntimeConfig]:
    def factory(*, state_root: Path) -> TrustedRuntimeConfig:
        project_root = state_root.parent
        return TrustedRuntimeConfig(
            state_root=state_root,
            project_root=project_root,
            project_policy_path=project_root / "auto-code.yaml",
            project_policy_hash="0" * 64,
            runner_identity=runner_identity(),
        )

    return factory


class PrepareCliHarness:
    def __init__(self, runtime: TrustedRuntimeConfig, repository: Path) -> None:
        self.runtime = runtime
        self.repository = repository
        self.probe_calls: list[Path] = []
        self.activation_calls: list[tuple[Path, str, str]] = []
        self.advance_calls: list[tuple[str, int, str]] = []
        self.receipt_calls: list[tuple[str, int, str, EvidenceRef]] = []
        self.factory_calls: list[TrustedRuntimeConfig] = []

    @property
    def calls(self) -> list[object]:
        return [*self.probe_calls, *self.activation_calls, *self.advance_calls, *self.receipt_calls]

    def factory(self, runtime: TrustedRuntimeConfig) -> PrepareCliHarness:
        self.factory_calls.append(runtime)
        return self

    def probe(self, repository: Path) -> object:
        self.probe_calls.append(repository)
        return object()

    def activate_reservation(self, input_path: Path, input_hash: str, challenge: str) -> object:
        self.activation_calls.append((input_path, input_hash, challenge))
        return object()

    def advance(self, run_id: str, expected_revision: int, expected_hash: str) -> object:
        self.advance_calls.append((run_id, expected_revision, expected_hash))
        return object()

    def consume_receipt(
        self,
        run_id: str,
        expected_revision: int,
        expected_hash: str,
        receipt_ref: EvidenceRef,
    ) -> object:
        self.receipt_calls.append((run_id, expected_revision, expected_hash, receipt_ref))
        return object()


@pytest.fixture
def prepare_cli_harness(tmp_path: Path, trusted_runtime_factory: Callable[..., TrustedRuntimeConfig]) -> PrepareCliHarness:
    repository = tmp_path / "repository"
    repository.mkdir()
    return PrepareCliHarness(trusted_runtime_factory(state_root=tmp_path / "state"), repository)


def test_prepare_probe_requires_only_a_repository(prepare_cli_harness: PrepareCliHarness) -> None:
    """Adding coordinator work before a valid probe dispatch must fail this boundary."""
    assert (
        main(
            ["prepare", "--repository", str(prepare_cli_harness.repository)],
            runtime=prepare_cli_harness.runtime,
            prepare_coordinator_factory=prepare_cli_harness.factory,
        )
        == 0
    )

    assert prepare_cli_harness.probe_calls == [prepare_cli_harness.repository]


def test_prepare_rejects_mixed_probe_activation_and_advance_arguments(
    prepare_cli_harness: PrepareCliHarness,
) -> None:
    """Removing mode exclusion would construct a coordinator for ambiguous work."""
    assert (
        main(
            ["prepare", "--repository", "repo", "--run", "run-1"],
            runtime=prepare_cli_harness.runtime,
            prepare_coordinator_factory=prepare_cli_harness.factory,
        )
        == 2
    )

    assert prepare_cli_harness.factory_calls == []
    assert prepare_cli_harness.calls == []


def test_prepare_parse_errors_use_a_fixed_message_when_reading_process_arguments(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Classifying only injected argv would leak argparse details for process arguments."""
    monkeypatch.setattr(cli.sys, "argv", ["auto-code", "prepare", "--repository", "repo", "--run", "run-1"])

    assert main() == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "prepare: invalid arguments\n"


def test_prepare_uses_trusted_runtime_before_dispatch(
    monkeypatch: pytest.MonkeyPatch,
    prepare_cli_harness: PrepareCliHarness,
) -> None:
    """Moving dispatch before protected runtime loading would invoke unbound capabilities."""
    def unavailable_runtime() -> TrustedRuntimeConfig:
        raise RuntimeConfigurationError("unavailable")

    monkeypatch.setattr(cli, "load_launcher_runtime_from_protected_fd", unavailable_runtime)

    assert (
        main(
            ["prepare", "--repository", str(prepare_cli_harness.repository)],
            prepare_coordinator_factory=prepare_cli_harness.factory,
        )
        == 2
    )

    assert prepare_cli_harness.factory_calls == []
    assert prepare_cli_harness.calls == []


def test_prepare_activation_dispatches_only_after_the_complete_local_binding(
    prepare_cli_harness: PrepareCliHarness,
) -> None:
    """Dropping activation binding validation would pass incomplete trusted-input work to the coordinator."""
    input_path = prepare_cli_harness.repository / "input.json"

    assert (
        main(
            [
                "prepare",
                "--input",
                str(input_path),
                "--sha256",
                "a" * 64,
                "--challenge",
                "reservation-challenge",
            ],
            runtime=prepare_cli_harness.runtime,
            prepare_coordinator_factory=prepare_cli_harness.factory,
        )
        == 0
    )

    assert prepare_cli_harness.activation_calls == [(input_path, "a" * 64, "reservation-challenge")]


@pytest.mark.parametrize(
    "argv",
    (
        ["prepare", "--input", "input.json", "--sha256", "a" * 64],
        ["prepare", "--input", "input.json", "--sha256", "A" * 64, "--challenge", "challenge"],
        ["prepare", "--run", "run-1", "--expected-revision", "0", "--expected-hash", "a" * 64],
        ["prepare", "--run", "run-1", "--expected-revision", "1", "--expected-hash", "A" * 64],
    ),
)
def test_prepare_rejects_incomplete_or_noncanonical_local_bindings(
    prepare_cli_harness: PrepareCliHarness,
    argv: list[str],
) -> None:
    """Weakening local validation would construct protected capabilities for malformed bindings."""
    assert main(argv, runtime=prepare_cli_harness.runtime, prepare_coordinator_factory=prepare_cli_harness.factory) == 2

    assert prepare_cli_harness.factory_calls == []
    assert prepare_cli_harness.calls == []


def test_prepare_advance_dispatches_a_valid_expected_state(prepare_cli_harness: PrepareCliHarness) -> None:
    """Changing advance argument normalization would send the wrong CAS binding to the coordinator."""
    assert (
        main(
            ["prepare", "--run", "run-1", "--expected-revision", "2", "--expected-hash", "b" * 64],
            runtime=prepare_cli_harness.runtime,
            prepare_coordinator_factory=prepare_cli_harness.factory,
        )
        == 0
    )

    assert prepare_cli_harness.advance_calls == [("run-1", 2, "b" * 64)]


def test_prepare_consumes_a_single_structured_receipt_reference(prepare_cli_harness: PrepareCliHarness) -> None:
    """Passing receipt payloads or duplicate references would bypass the coordinator's bridge authority."""
    receipt_ref = EvidenceRef(
        relative_path="trusted-mcp/receipts/11111111-1111-4111-8111-111111111111.json",
        sha256="c" * 64,
        media_type="application/json",
        creator="trusted-mcp-bridge",
    )

    assert (
        main(
            [
                "prepare",
                "--run",
                "run-1",
                "--expected-revision",
                "3",
                "--expected-hash",
                "d" * 64,
                "--receipt-ref",
                receipt_ref.model_dump_json(),
            ],
            runtime=prepare_cli_harness.runtime,
            prepare_coordinator_factory=prepare_cli_harness.factory,
        )
        == 0
    )

    assert prepare_cli_harness.receipt_calls == [("run-1", 3, "d" * 64, receipt_ref)]


def test_prepare_rejects_multiple_receipt_references_before_composition(
    prepare_cli_harness: PrepareCliHarness,
) -> None:
    """Removing the single-reference guard would let an ambiguous receipt reach the coordinator."""
    receipt_ref = EvidenceRef(
        relative_path="trusted-mcp/receipts/11111111-1111-4111-8111-111111111111.json",
        sha256="c" * 64,
        media_type="application/json",
        creator="trusted-mcp-bridge",
    ).model_dump_json()

    assert (
        main(
            [
                "prepare",
                "--run",
                "run-1",
                "--expected-revision",
                "3",
                "--expected-hash",
                "d" * 64,
                "--receipt-ref",
                receipt_ref,
                "--receipt-ref",
                receipt_ref,
            ],
            runtime=prepare_cli_harness.runtime,
            prepare_coordinator_factory=prepare_cli_harness.factory,
        )
        == 2
    )

    assert prepare_cli_harness.factory_calls == []
    assert prepare_cli_harness.calls == []


def test_status_reports_exact_read_only_summary(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    trusted_runtime_factory: Callable[..., TrustedRuntimeConfig],
) -> None:
    persisted = RunStateStore(tmp_path, "run-1").compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo", max_crew_iterations=3),
    )
    runtime = trusted_runtime_factory(state_root=tmp_path)

    assert (
        main(
            [
                "status",
                "--run",
                "run-1",
                "--expected-revision",
                "1",
                "--expected-hash",
                persisted.state_hash,
            ],
            runtime=runtime,
        )
        == 0
    )

    captured = capsys.readouterr()
    assert captured.out.strip() == "ENG-1 crew_iterations=0/3 disposition=active freshness=unknown"
    assert captured.err == ""


def test_status_does_not_create_missing_state_paths(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    trusted_runtime_factory: Callable[..., TrustedRuntimeConfig],
) -> None:
    state_root = tmp_path / "missing-state-root"

    assert (
        main(
            [
                "status",
                "--run",
                "run-1",
                "--expected-revision",
                "1",
                "--expected-hash",
                EMPTY_STATE_HASH,
            ],
            runtime=trusted_runtime_factory(state_root=state_root),
        )
        == 2
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.strip() == "status: state unavailable"
    assert not state_root.exists()


def test_status_does_not_create_paths_for_a_missing_run(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    trusted_runtime_factory: Callable[..., TrustedRuntimeConfig],
) -> None:
    state_root = tmp_path / "state-root"
    state_root.mkdir()

    assert (
        main(
            [
                "status",
                "--run",
                "run-1",
                "--expected-revision",
                "1",
                "--expected-hash",
                EMPTY_STATE_HASH,
            ],
            runtime=trusted_runtime_factory(state_root=state_root),
        )
        == 2
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.strip() == "status: state unavailable"
    assert list(state_root.iterdir()) == []


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["status", "--expected-revision", "1", "--expected-hash", EMPTY_STATE_HASH], "--run"),
        (["status", "--run", "run-1", "--expected-hash", EMPTY_STATE_HASH], "--expected-revision"),
        (["status", "--run", "run-1", "--expected-revision", "1"], "--expected-hash"),
    ],
)
def test_status_requires_each_expected_state_binding(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    trusted_runtime_factory: Callable[..., TrustedRuntimeConfig],
    argv: list[str],
    message: str,
) -> None:
    assert main(argv, runtime=trusted_runtime_factory(state_root=tmp_path)) == 2

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.strip() == f"status: missing required option {message}"


def test_status_rejects_a_stale_expected_state(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    trusted_runtime_factory: Callable[..., TrustedRuntimeConfig],
) -> None:
    persisted = RunStateStore(tmp_path, "run-1").compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo", max_crew_iterations=3),
    )

    assert (
        main(
            [
                "status",
                "--run",
                "run-1",
                "--expected-revision",
                "2",
                "--expected-hash",
                persisted.state_hash,
            ],
            runtime=trusted_runtime_factory(state_root=tmp_path),
        )
        == 2
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.strip() == "status: expected state does not match"


def test_status_rejects_matching_revision_with_wrong_valid_hash(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    trusted_runtime_factory: Callable[..., TrustedRuntimeConfig],
) -> None:
    persisted = RunStateStore(tmp_path, "run-1").compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo", max_crew_iterations=3),
    )

    assert (
        main(
            [
                "status",
                "--run",
                "run-1",
                "--expected-revision",
                str(persisted.revision),
                "--expected-hash",
                EMPTY_STATE_HASH,
            ],
            runtime=trusted_runtime_factory(state_root=tmp_path),
        )
        == 2
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.strip() == "status: expected state does not match"


@pytest.mark.parametrize("corrupt", [False, True])
def test_status_returns_a_concise_error_for_unavailable_state(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    trusted_runtime_factory: Callable[..., TrustedRuntimeConfig],
    corrupt: bool,
) -> None:
    if corrupt:
        store = RunStateStore(tmp_path, "run-1")
        persisted = store.compare_and_swap(
            0,
            EMPTY_STATE_HASH,
            RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo", max_crew_iterations=3),
        )
        store.current_path.write_text("{corrupt", encoding="ascii")
        expected_hash = persisted.state_hash
    else:
        expected_hash = EMPTY_STATE_HASH

    assert (
        main(
            [
                "status",
                "--run",
                "run-1",
                "--expected-revision",
                "1",
                "--expected-hash",
                expected_hash,
            ],
            runtime=trusted_runtime_factory(state_root=tmp_path),
        )
        == 2
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.strip() == "status: state unavailable"


def test_status_does_not_accept_a_state_root_argument(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    trusted_runtime_factory: Callable[..., TrustedRuntimeConfig],
) -> None:
    assert (
        main(
            [
                "status",
                "--run",
                "run-1",
                "--expected-revision",
                "1",
                "--expected-hash",
                EMPTY_STATE_HASH,
                "--state-root",
                str(tmp_path),
            ],
            runtime=trusted_runtime_factory(state_root=tmp_path),
        )
        == 2
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert "--state-root" in captured.err


def test_runtime_descriptor_builds_all_trusted_bindings(tmp_path: Path) -> None:
    payload = runtime_payload(tmp_path)

    assert TrustedRuntimeConfig.from_descriptor(payload) == TrustedRuntimeConfig(
        state_root=tmp_path / "state",
        project_root=tmp_path / "project",
        project_policy_path=tmp_path / "project" / "auto-code.yaml",
        project_policy_hash="0" * 64,
        runner_identity=runner_identity(),
    )


def test_trusted_runtime_config_direct_constructor_requires_exact_bindings(tmp_path: Path) -> None:
    bindings = {
        "state_root": tmp_path / "state",
        "project_root": tmp_path / "project",
        "project_policy_path": tmp_path / "project" / "auto-code.yaml",
        "project_policy_hash": "0" * 64,
        "runner_identity": runner_identity(),
    }

    with pytest.raises(TypeError):
        TrustedRuntimeConfig(state_root=tmp_path / "state")
    with pytest.raises(TypeError):
        TrustedRuntimeConfig(**bindings, unexpected="value")  # type: ignore[call-arg]


@pytest.mark.parametrize(
    ("missing", "extra"),
    (("runner_identity", None), (None, "unexpected")),
)
def test_runtime_descriptor_rejects_missing_or_extra_keys(
    tmp_path: Path,
    missing: str | None,
    extra: str | None,
) -> None:
    payload = runtime_payload(tmp_path)
    if missing is not None:
        del payload[missing]
    if extra is not None:
        payload[extra] = "value"

    with pytest.raises(ValueError, match="runtime descriptor shape is invalid"):
        TrustedRuntimeConfig.from_descriptor(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("state_root", "relative-state"),
        ("project_root", "relative-project"),
        ("project_policy_path", "relative-policy.yaml"),
    ),
)
def test_runtime_descriptor_rejects_relative_paths(tmp_path: Path, field: str, value: str) -> None:
    payload = runtime_payload(tmp_path)
    payload[field] = value

    with pytest.raises(ValueError):
        TrustedRuntimeConfig.from_descriptor(payload)


@pytest.mark.parametrize("field", ("state_root", "project_root", "project_policy_path"))
def test_runtime_descriptor_rejects_parent_path_components(tmp_path: Path, field: str) -> None:
    payload = runtime_payload(tmp_path)
    paths = {
        "state_root": tmp_path / "state" / ".." / "state",
        "project_root": tmp_path / "project" / ".." / "project",
        "project_policy_path": tmp_path / "project" / "policy" / ".." / "auto-code.yaml",
    }
    payload[field] = str(paths[field])

    with pytest.raises(ValueError):
        TrustedRuntimeConfig.from_descriptor(payload)


def test_runtime_descriptor_rejects_policy_path_equal_to_project_root(tmp_path: Path) -> None:
    payload = runtime_payload(tmp_path)
    payload["project_policy_path"] = payload["project_root"]

    with pytest.raises(ValueError, match="project policy path"):
        TrustedRuntimeConfig.from_descriptor(payload)


def test_runtime_descriptor_rejects_policy_outside_project_root(tmp_path: Path) -> None:
    payload = runtime_payload(tmp_path)
    payload["project_policy_path"] = str(tmp_path / "outside.yaml")

    with pytest.raises(ValueError, match="project policy path"):
        TrustedRuntimeConfig.from_descriptor(payload)


@pytest.mark.parametrize("project_policy_hash", ("0" * 63, "g" * 64))
def test_runtime_descriptor_rejects_malformed_policy_hash(tmp_path: Path, project_policy_hash: str) -> None:
    payload = runtime_payload(tmp_path)
    payload["project_policy_hash"] = project_policy_hash

    with pytest.raises(ValueError):
        TrustedRuntimeConfig.from_descriptor(payload)


def test_runtime_descriptor_rejects_malformed_runner_identity(tmp_path: Path) -> None:
    payload = runtime_payload(tmp_path)
    payload["runner_identity"] = {"content_hash": "invalid"}

    with pytest.raises(ValueError):
        TrustedRuntimeConfig.from_descriptor(payload)


def test_trusted_runtime_config_rejects_non_runner_identity(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        TrustedRuntimeConfig(
            state_root=tmp_path / "state",
            project_root=tmp_path / "project",
            project_policy_path=tmp_path / "project" / "auto-code.yaml",
            project_policy_hash="0" * 64,
            runner_identity=object(),  # type: ignore[arg-type]
        )


def test_protected_runtime_descriptor_must_be_read_only(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor_path = tmp_path / "runtime.json"
    descriptor_path.write_text(json.dumps(runtime_payload(tmp_path)), encoding="ascii")
    descriptor = os.open(descriptor_path, os.O_RDWR)
    try:
        monkeypatch.setattr(cli, "_LAUNCHER_RUNTIME_FD", descriptor)

        with pytest.raises(RuntimeConfigurationError, match="descriptor is invalid"):
            cli.load_launcher_runtime_from_protected_fd()
    finally:
        os.close(descriptor)


def test_protected_runtime_descriptor_must_be_a_regular_file(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor, writer = os.pipe()
    try:
        monkeypatch.setattr(cli, "_LAUNCHER_RUNTIME_FD", descriptor)

        with pytest.raises(RuntimeConfigurationError, match="descriptor is invalid"):
            cli.load_launcher_runtime_from_protected_fd()
    finally:
        os.close(descriptor)
        os.close(writer)


def test_protected_runtime_descriptor_loads_read_only_launcher_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor_path = tmp_path / "runtime.json"
    descriptor_path.write_text(json.dumps(runtime_payload(tmp_path)), encoding="ascii")
    descriptor = os.open(descriptor_path, os.O_RDONLY)
    try:
        monkeypatch.setattr(cli, "_LAUNCHER_RUNTIME_FD", descriptor)

        assert cli.load_launcher_runtime_from_protected_fd() == TrustedRuntimeConfig(
            state_root=tmp_path / "state",
            project_root=tmp_path / "project",
            project_policy_path=tmp_path / "project" / "auto-code.yaml",
            project_policy_hash="0" * 64,
            runner_identity=runner_identity(),
        )
    finally:
        os.close(descriptor)


def test_protected_runtime_descriptor_rejects_duplicate_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor_path = tmp_path / "runtime.json"
    payload = json.dumps(runtime_payload(tmp_path))
    descriptor_path.write_text(
        f'{payload[:-1]},"state_root":{json.dumps(str(tmp_path / "other"))}}}',
        encoding="ascii",
    )
    descriptor = os.open(descriptor_path, os.O_RDONLY)
    try:
        monkeypatch.setattr(cli, "_LAUNCHER_RUNTIME_FD", descriptor)

        with pytest.raises(RuntimeConfigurationError, match="descriptor is invalid"):
            cli.load_launcher_runtime_from_protected_fd()
    finally:
        os.close(descriptor)


def test_protected_runtime_descriptor_rejects_extra_keys(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    payload = runtime_payload(tmp_path)
    payload["unexpected"] = "value"
    descriptor_path = tmp_path / "runtime.json"
    descriptor_path.write_text(json.dumps(payload), encoding="ascii")
    descriptor = os.open(descriptor_path, os.O_RDONLY)
    try:
        monkeypatch.setattr(cli, "_LAUNCHER_RUNTIME_FD", descriptor)

        with pytest.raises(RuntimeConfigurationError, match="descriptor is invalid"):
            cli.load_launcher_runtime_from_protected_fd()
    finally:
        os.close(descriptor)


def test_protected_runtime_descriptor_rejects_oversized_payload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    descriptor_path = tmp_path / "runtime.json"
    descriptor_path.write_bytes(b" " * (cli._MAX_RUNTIME_CONFIG_BYTES + 1))
    descriptor = os.open(descriptor_path, os.O_RDONLY)
    try:
        monkeypatch.setattr(cli, "_LAUNCHER_RUNTIME_FD", descriptor)

        with pytest.raises(RuntimeConfigurationError, match="descriptor is invalid"):
            cli.load_launcher_runtime_from_protected_fd()
    finally:
        os.close(descriptor)


@pytest.mark.parametrize("payload", [b"{", b'{"state_root":1}', b"\xff"])
def test_status_returns_concise_error_for_malformed_runtime_descriptor(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
) -> None:
    descriptor_path = tmp_path / "runtime.json"
    descriptor_path.write_bytes(payload)
    descriptor = os.open(descriptor_path, os.O_RDONLY)
    try:
        monkeypatch.setattr(cli, "_LAUNCHER_RUNTIME_FD", descriptor)

        assert (
            main(
                [
                    "status",
                    "--run",
                    "run-1",
                    "--expected-revision",
                    "1",
                    "--expected-hash",
                    EMPTY_STATE_HASH,
                ]
            )
            == 2
        )
    finally:
        os.close(descriptor)

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.strip() == "status: launcher runtime unavailable"


def test_status_returns_concise_error_for_inaccessible_runtime_descriptor(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def deny_descriptor(_: int) -> int:
        raise PermissionError("denied")

    monkeypatch.setattr(cli.os, "dup", deny_descriptor)

    assert (
        main(
            [
                "status",
                "--run",
                "run-1",
                "--expected-revision",
                "1",
                "--expected-hash",
                EMPTY_STATE_HASH,
            ]
        )
        == 2
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.strip() == "status: launcher runtime unavailable"


def test_status_converts_permission_error_from_read_only_state_load(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    trusted_runtime_factory: Callable[..., TrustedRuntimeConfig],
) -> None:
    persisted = RunStateStore(tmp_path, "run-1").compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo", max_crew_iterations=3),
    )

    def deny_state_load(_: type[RunStateStore], __: Path, ___: str) -> object:
        raise PermissionError("denied")

    monkeypatch.setattr(RunStateStore, "load_read_only", classmethod(deny_state_load), raising=False)

    assert (
        main(
            [
                "status",
                "--run",
                "run-1",
                "--expected-revision",
                str(persisted.revision),
                "--expected-hash",
                persisted.state_hash,
            ],
            runtime=trusted_runtime_factory(state_root=tmp_path),
        )
        == 2
    )

    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err.strip() == "status: state unavailable"


def test_module_entrypoint_reads_the_protected_runtime_descriptor(tmp_path: Path) -> None:
    persisted = RunStateStore(tmp_path, "run-1").compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo", max_crew_iterations=3),
    )
    descriptor_path = tmp_path / "runtime.json"
    payload = runtime_payload(tmp_path)
    payload["state_root"] = str(tmp_path)
    descriptor_path.write_text(json.dumps(payload), encoding="ascii")
    descriptor = os.open(descriptor_path, os.O_RDONLY)
    try:
        environment = dict(os.environ)
        source_root = Path(__file__).parents[1] / "src"
        environment["PYTHONPATH"] = str(source_root)
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                (
                    "import os, sys; "
                    "os.dup2(int(sys.argv[1]), 3, inheritable=True); "
                    "os.execv(sys.executable, [sys.executable, '-m', 'auto_code', *sys.argv[2:]])"
                ),
                str(descriptor),
                "status",
                "--run",
                "run-1",
                "--expected-revision",
                str(persisted.revision),
                "--expected-hash",
                persisted.state_hash,
            ],
            capture_output=True,
            check=False,
            env=environment,
            pass_fds=(descriptor,),
            text=True,
        )
    finally:
        os.close(descriptor)

    assert result.returncode == 0
    assert result.stdout == "ENG-1 crew_iterations=0/3 disposition=active freshness=unknown\n"
    assert result.stderr == ""
