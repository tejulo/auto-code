from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path

from pydantic import ValidationError
import pytest

from auto_code.catalog_preflight import CatalogPreflightResult
from auto_code.cli import TrustedRuntimeConfig
from auto_code.compatibility import (
    CompatibilityPreflightError,
    CompatibilityPreflightResult,
    CompatibilityReceiptAuthority,
    CompatibilityReceiptError,
    CompatibilityRuntime,
    PreflightVersionVerifier,
    RunnerPackageManifest,
    TrustedVersionObservation,
    build_compatibility_receipt,
    verify_browser_if_configured,
)
from auto_code.contracts import (
    BrowserPreflightStatus,
    CatalogObservation,
    CompatibilityComponentObservation,
    CompatibilityReceipt,
    EvidenceRef,
    RunnerIdentity,
)
from auto_code.hashing import canonical_json_bytes, hash_json
from auto_code.model_catalog import ModelCatalog, ModelMetadata, ModelRef
from auto_code.model_compatibility import ModelCompatibilityProfile, ModelCompatibilityRegistry
from auto_code.model_config import RoleModelConfig, RoleName
from auto_code.project_config import BrowserPolicy, ProjectConfig
from auto_code.tool_broker import RoleCapabilityMatrix


NOW = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)
RECEIPT_ID = "123e4567-e89b-12d3-a456-426614174000"
OTHER_RECEIPT_ID = "123e4567-e89b-12d3-a456-426614174001"
LAUNCHER_IDENTITY = "trusted-launcher"
PROFILE_BUNDLE_HASH = "0" * 64
_COMPONENT_VERSIONS = {
    "python": ("3.12.x", "3.12.13"),
    "crewai": ("1.15.20", "1.15.20"),
    "openspec": ("1.12.0", "1.12.0"),
    "node": (">=20.19.0", "20.19.0"),
    "ralph": ("1.0.10", "1.0.10"),
    "playwright": ("0.1.19", "0.1.19"),
}


def runner_identity(content_hash: str = "a" * 64) -> RunnerIdentity:
    return RunnerIdentity(
        content_hash=content_hash,
        source_sha="b" * 64,
        dependency_lock_hash="c" * 64,
        contract_bundle_hash="d" * 64,
        built_at=NOW,
    )


def catalog_observation(provider: str) -> CatalogObservation:
    values = {
        "opencode-go": ("a" * 64, "b" * 64, "d" * 64),
        "ollama-cloud": ("e" * 64, "f" * 64, "1" * 64),
    }
    credential_scope_hash, model_set_hash, response_evidence_hash = values[provider]
    return CatalogObservation(
        provider=provider,
        endpoint_identity="catalog-one",
        credential_scope_hash=credential_scope_hash,
        fetched_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        model_set_hash=model_set_hash,
        profile_bundle_hash=PROFILE_BUNDLE_HASH,
        response_evidence_hash=response_evidence_hash,
    )


def component_observation(component: str, *, hash_character: str = "a") -> CompatibilityComponentObservation:
    expected_constraint, observed_version = _COMPONENT_VERSIONS[component]
    return CompatibilityComponentObservation(
        component=component,
        expected_constraint=expected_constraint,
        observed_version=observed_version,
        verified_identity_hash=hash_character * 64,
        evidence_hashes=("b" * 64,),
    )


def component_observations(*, browser_verified: bool = False) -> tuple[CompatibilityComponentObservation, ...]:
    components = ["crewai", "node", "openspec", "python", "ralph"]
    if browser_verified:
        components.append("playwright")
    return tuple(component_observation(component) for component in sorted(components))


def receipt_data(
    *,
    receipt_id: str = RECEIPT_ID,
    launcher_identity: str = LAUNCHER_IDENTITY,
    runner: RunnerIdentity | None = None,
    browser_status: BrowserPreflightStatus = BrowserPreflightStatus.NOT_CONFIGURED,
    observations: tuple[CatalogObservation, ...] | None = None,
    components: tuple[CompatibilityComponentObservation, ...] | None = None,
) -> dict[str, object]:
    resolved_runner = runner or runner_identity()
    resolved_observations = observations or tuple(
        catalog_observation(provider) for provider in ("ollama-cloud", "opencode-go")
    )
    browser_verified = browser_status is BrowserPreflightStatus.VERIFIED
    return {
        "receipt_id": receipt_id,
        "issued_at": NOW,
        "launcher_identity": launcher_identity,
        "runner_identity": resolved_runner,
        "runner_content_hash": resolved_runner.content_hash,
        "project_policy_hash": "e" * 64,
        "selected_role_models_hash": "f" * 64,
        "profile_bundle_hash": PROFILE_BUNDLE_HASH,
        "catalog_receipt_hashes": {
            observation.provider: observation.content_hash for observation in resolved_observations
        },
        "catalog_observations": resolved_observations,
        "browser_preflight_status": browser_status,
        "component_observations": components or component_observations(browser_verified=browser_verified),
        "relative_path": f"trusted-launcher/compatibility/{receipt_id}.json",
    }


def compatibility_receipt(
    authority: CompatibilityReceiptAuthority | None = None,
    *,
    receipt_id: str = RECEIPT_ID,
    **changes: object,
) -> CompatibilityReceipt:
    values = receipt_data(
        receipt_id=receipt_id,
        launcher_identity=authority.launcher_identity if authority is not None else LAUNCHER_IDENTITY,
    )
    values.update(changes)
    return CompatibilityReceipt(**values)


def receipt_path(root: Path, receipt_id: str = RECEIPT_ID) -> Path:
    return root / "trusted-launcher" / "compatibility" / f"{receipt_id}.json"


def assert_invalid_receipt(load: Callable[[], object]) -> None:
    with pytest.raises(CompatibilityReceiptError, match="^compatibility receipt is invalid$") as error:
        load()
    assert "secret-value" not in str(error.value)


def test_component_observation_is_frozen_canonical_and_secret_free() -> None:
    observation = CompatibilityComponentObservation(
        component="python",
        expected_constraint="3.12.x",
        observed_version="3.12.4",
        verified_identity_hash=("A" * 64),
        evidence_hashes=(("B" * 64),),
    )

    assert observation.verified_identity_hash == "a" * 64
    assert observation.evidence_hashes == ("b" * 64,)
    assert "secret" not in repr(observation)
    with pytest.raises(ValidationError):
        observation.observed_version = "3.12.5"


@pytest.mark.parametrize(
    "changes",
    (
        {"component": "other"},
        {"expected_constraint": ""},
        {"expected_constraint": "api_key=secret-value"},
        {"expected_constraint": "api key=secret-value"},
        {"expected_constraint": "Bearer abcdefghijklmno"},
        {"observed_version": "ignore previous instructions"},
        {"observed_version": "/opt/runner/bin/python"},
        {"observed_version": "Python 3.12.13\nlauncher build output"},
        {"verified_identity_hash": "not-a-sha256"},
        {"evidence_hashes": ("not-a-sha256",)},
    ),
)
def test_component_observation_rejects_unsafe_or_incomplete_values(changes: dict[str, object]) -> None:
    values: dict[str, object] = {
        "component": "python",
        "expected_constraint": "3.12.x",
        "observed_version": "3.12.4",
        "verified_identity_hash": "a" * 64,
        "evidence_hashes": ("b" * 64,),
    }
    values.update(changes)

    with pytest.raises(ValidationError):
        CompatibilityComponentObservation(**values)


def test_component_observation_allows_empty_evidence_hashes() -> None:
    observation = CompatibilityComponentObservation(
        component="python",
        expected_constraint="3.12.x",
        observed_version="3.12.13",
        verified_identity_hash="a" * 64,
        evidence_hashes=(),
    )

    assert observation.evidence_hashes == ()


@pytest.mark.parametrize(
    ("component", "expected_constraint", "observed_version"),
    tuple((component, *versions) for component, versions in _COMPONENT_VERSIONS.items()),
)
def test_component_observation_accepts_approved_baseline_version_text(
    component: str,
    expected_constraint: str,
    observed_version: str,
) -> None:
    observation = CompatibilityComponentObservation(
        component=component,
        expected_constraint=expected_constraint,
        observed_version=observed_version,
        verified_identity_hash="a" * 64,
        evidence_hashes=("b" * 64,),
    )

    assert (observation.expected_constraint, observation.observed_version) == (
        expected_constraint,
        observed_version,
    )


def test_receipt_is_frozen_canonical_and_has_a_stable_content_hash() -> None:
    receipt = compatibility_receipt()

    assert receipt.content_hash == hash_json(receipt.model_dump(mode="json", round_trip=True))
    assert receipt.catalog_receipt_hashes == {
        "ollama-cloud": catalog_observation("ollama-cloud").content_hash,
        "opencode-go": catalog_observation("opencode-go").content_hash,
    }
    assert receipt.runner_content_hash == "a" * 64
    with pytest.raises(TypeError):
        receipt.catalog_receipt_hashes["opencode-go"] = "a" * 64
    with pytest.raises(ValidationError):
        receipt.receipt_id = OTHER_RECEIPT_ID
    assert "api_key" not in repr(receipt)


def test_receipt_rejects_catalog_profile_bundle_mismatch() -> None:
    observations = tuple(catalog_observation(provider) for provider in ("ollama-cloud", "opencode-go"))
    mismatched = observations[1].model_copy(update={"profile_bundle_hash": "1" * 64})
    values = receipt_data(observations=(observations[0], mismatched))
    values["catalog_receipt_hashes"] = {
        observation.provider: observation.content_hash
        for observation in (observations[0], mismatched)
    }

    with pytest.raises(ValidationError):
        CompatibilityReceipt(**values)


def test_receipt_requires_timezone_aware_issue_and_runner_times() -> None:
    with pytest.raises(ValidationError):
        RunnerIdentity(
            content_hash="a" * 64,
            source_sha="b" * 64,
            dependency_lock_hash="c" * 64,
            contract_bundle_hash="d" * 64,
            built_at=datetime(2026, 9, 7, 12, 0),
        )

    values = receipt_data()
    values["issued_at"] = datetime(2026, 9, 7, 12, 0)
    with pytest.raises(ValidationError):
        CompatibilityReceipt(**values)


@pytest.mark.parametrize("forged_contract", ("runner", "catalog", "component"))
def test_receipt_revalidates_constructed_nested_contracts(forged_contract: str) -> None:
    values = receipt_data()
    if forged_contract == "runner":
        values["runner_identity"] = RunnerIdentity.model_construct(
            content_hash="a" * 64,
            source_sha="b" * 64,
            dependency_lock_hash="c" * 64,
            contract_bundle_hash="d" * 64,
            built_at=datetime(2026, 9, 7, 12, 0),
        )
    elif forged_contract == "catalog":
        observations = values["catalog_observations"]
        assert isinstance(observations, tuple)
        first, second = observations
        data = first.model_dump(round_trip=True)
        data["fetched_at"] = datetime(2026, 9, 7, 12, 0)
        forged = CatalogObservation.model_construct(**data)
        values["catalog_observations"] = (forged, second)
        hashes = dict(values["catalog_receipt_hashes"])
        hashes[forged.provider] = forged.content_hash
        values["catalog_receipt_hashes"] = hashes
    else:
        observations = values["component_observations"]
        assert isinstance(observations, tuple)
        first, *remaining = observations
        data = first.model_dump(round_trip=True)
        data["observed_version"] = "api_key=secret-value"
        values["component_observations"] = (
            CompatibilityComponentObservation.model_construct(**data),
            *remaining,
        )

    with pytest.raises(ValidationError):
        CompatibilityReceipt(**values)


@pytest.mark.parametrize(
    "mutate",
    (
        lambda values: values.update(receipt_id=RECEIPT_ID.upper()),
        lambda values: values.update(launcher_identity="api_key=secret-value"),
        lambda values: values.update(relative_path="trusted-launcher/compatibility/other.json"),
        lambda values: values.update(runner_content_hash="b" * 64),
        lambda values: values.update(catalog_observations=tuple(reversed(values["catalog_observations"]))),
        lambda values: values.update(
            catalog_observations=(values["catalog_observations"][0], values["catalog_observations"][0])
        ),
        lambda values: values.update(catalog_receipt_hashes={"opencode-go": "a" * 64}),
        lambda values: values.update(component_observations=tuple(reversed(values["component_observations"]))),
        lambda values: values.update(component_observations=values["component_observations"][:-1]),
        lambda values: values.update(
            component_observations=(*values["component_observations"], component_observation("playwright"))
        ),
    ),
)
def test_receipt_rejects_invalid_provenance_catalog_or_component_bindings(
    mutate: Callable[[dict[str, object]], None],
) -> None:
    values = receipt_data()
    mutate(values)

    with pytest.raises(ValidationError):
        CompatibilityReceipt(**values)


def test_receipt_requires_playwright_only_for_verified_browser_status() -> None:
    verified = CompatibilityReceipt(
        **receipt_data(
            browser_status=BrowserPreflightStatus.VERIFIED,
            components=component_observations(browser_verified=True),
        )
    )

    assert verified.browser_preflight_status is BrowserPreflightStatus.VERIFIED
    values = receipt_data(
        browser_status=BrowserPreflightStatus.VERIFIED,
        components=component_observations(browser_verified=False),
    )
    with pytest.raises(ValidationError):
        CompatibilityReceipt(**values)


def test_receipt_authority_rejects_invalid_construction_inputs(
    tmp_path: Path,
) -> None:
    for state_root, launcher, runner in (
        (Path("relative-state-root"), LAUNCHER_IDENTITY, runner_identity()),
        (tmp_path / "state", "api_key=secret-value", runner_identity()),
        (tmp_path / "state", LAUNCHER_IDENTITY, object()),
    ):
        with pytest.raises((TypeError, ValueError, ValidationError)):
            CompatibilityReceiptAuthority(state_root, launcher, runner)  # type: ignore[arg-type]


def test_receipt_authority_publishes_once_and_reloads_matching_evidence(tmp_path: Path) -> None:
    authority = CompatibilityReceiptAuthority(tmp_path, LAUNCHER_IDENTITY, runner_identity())
    receipt = compatibility_receipt(authority)

    evidence = authority.publish(receipt)

    assert evidence == EvidenceRef(
        relative_path="trusted-launcher/compatibility/123e4567-e89b-12d3-a456-426614174000.json",
        sha256=receipt.content_hash,
        media_type="application/json",
        creator="trusted-launcher",
    )
    original_bytes = receipt_path(tmp_path).read_bytes()
    assert authority.publish(receipt) == evidence
    assert receipt_path(tmp_path).read_bytes() == original_bytes
    assert authority.load_verified_receipt(evidence) == receipt


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("project_policy_hash", "E" * 64),
        ("issued_at", "2026-09-07T12:00:00+00:00"),
    ),
)
def test_receipt_authority_rejects_contract_normalized_existing_receipt_on_load(
    tmp_path: Path,
    field: str,
    replacement: str,
) -> None:
    authority = CompatibilityReceiptAuthority(tmp_path, LAUNCHER_IDENTITY, runner_identity())
    receipt = compatibility_receipt(authority)
    evidence = authority.publish(receipt)
    payload = receipt.model_dump(mode="json", round_trip=True)
    payload[field] = replacement
    receipt_path(tmp_path).write_bytes(canonical_json_bytes(payload))

    assert_invalid_receipt(lambda: authority.load_verified_receipt(evidence))


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("project_policy_hash", "E" * 64),
        ("issued_at", "2026-09-07T12:00:00+00:00"),
    ),
)
def test_receipt_authority_rejects_contract_normalized_existing_receipt_on_publication(
    tmp_path: Path,
    field: str,
    replacement: str,
) -> None:
    authority = CompatibilityReceiptAuthority(tmp_path, LAUNCHER_IDENTITY, runner_identity())
    receipt = compatibility_receipt(authority)
    authority.publish(receipt)
    payload = receipt.model_dump(mode="json", round_trip=True)
    payload[field] = replacement
    expected_bytes = canonical_json_bytes(payload)
    path = receipt_path(tmp_path)
    path.write_bytes(expected_bytes)

    with pytest.raises(CompatibilityReceiptError, match="^compatibility receipt cannot be published$"):
        authority.publish(receipt)

    assert path.read_bytes() == expected_bytes


def test_receipt_authority_rejects_conflicting_publication_without_replacing_bytes(tmp_path: Path) -> None:
    authority = CompatibilityReceiptAuthority(tmp_path, LAUNCHER_IDENTITY, runner_identity())
    receipt = compatibility_receipt(authority)
    authority.publish(receipt)
    original_bytes = receipt_path(tmp_path).read_bytes()
    conflicting = compatibility_receipt(authority, project_policy_hash="1" * 64)

    with pytest.raises(CompatibilityReceiptError, match="^compatibility receipt cannot be published$"):
        authority.publish(conflicting)

    assert receipt_path(tmp_path).read_bytes() == original_bytes


def test_receipt_authority_rejects_authority_mismatch_before_creating_a_receipt(tmp_path: Path) -> None:
    authority = CompatibilityReceiptAuthority(tmp_path, LAUNCHER_IDENTITY, runner_identity())
    receipt = compatibility_receipt(authority, launcher_identity="other-launcher")

    with pytest.raises(CompatibilityReceiptError, match="^compatibility receipt cannot be published$"):
        authority.publish(receipt)

    assert not receipt_path(tmp_path).exists()


@pytest.mark.parametrize("tamper", ("path", "hash", "launcher", "runner", "shape"))
def test_receipt_authority_rejects_tampered_evidence_without_leaking_input(tmp_path: Path, tamper: str) -> None:
    authority = CompatibilityReceiptAuthority(tmp_path, LAUNCHER_IDENTITY, runner_identity())
    receipt = compatibility_receipt(authority)
    evidence = authority.publish(receipt)

    if tamper == "path":
        evidence = evidence.model_copy(
            update={
                "relative_path": "trusted-launcher/compatibility/123e4567-e89b-12d3-a456-426614174001.json"
            }
        )
    elif tamper == "hash":
        evidence = evidence.model_copy(update={"sha256": "0" * 64})
    elif tamper == "launcher":
        payload = receipt.model_dump(mode="json", round_trip=True)
        payload["launcher_identity"] = "api_key=secret-value"
        receipt_path(tmp_path).write_bytes(canonical_json_bytes(payload))
    elif tamper == "runner":
        other_runner = runner_identity().model_copy(update={"source_sha": "1" * 64})
        replacement = compatibility_receipt(authority, runner_identity=other_runner, runner_content_hash=other_runner.content_hash)
        receipt_path(tmp_path).write_bytes(canonical_json_bytes(replacement.model_dump(mode="json", round_trip=True)))
        evidence = evidence.model_copy(update={"sha256": replacement.content_hash})
    else:
        receipt_path(tmp_path).write_bytes(canonical_json_bytes({"api_key": "secret-value"}))

    assert_invalid_receipt(lambda: authority.load_verified_receipt(evidence))


def test_receipt_authority_rejects_noncanonical_and_nonregular_receipts(tmp_path: Path) -> None:
    authority = CompatibilityReceiptAuthority(tmp_path, LAUNCHER_IDENTITY, runner_identity())
    evidence = authority.publish(compatibility_receipt(authority))
    path = receipt_path(tmp_path)

    path.write_bytes(path.read_bytes() + b"\n")
    assert_invalid_receipt(lambda: authority.load_verified_receipt(evidence))

    authority = CompatibilityReceiptAuthority(tmp_path / "symlink-root", LAUNCHER_IDENTITY, runner_identity())
    evidence = authority.publish(compatibility_receipt(authority))
    path = receipt_path(tmp_path / "symlink-root")
    preserved = path.with_name("preserved.json")
    path.rename(preserved)
    path.symlink_to(preserved)
    assert_invalid_receipt(lambda: authority.load_verified_receipt(evidence))


def test_receipt_authority_refuses_foreign_or_caller_authored_paths_and_metadata(tmp_path: Path) -> None:
    authority = CompatibilityReceiptAuthority(tmp_path, LAUNCHER_IDENTITY, runner_identity())
    evidence = authority.publish(compatibility_receipt(authority))
    arbitrary = tmp_path / "arbitrary.json"
    arbitrary.write_bytes(receipt_path(tmp_path).read_bytes())

    arbitrary_evidence = evidence.model_copy(update={"relative_path": "arbitrary.json"})
    wrong_creator = evidence.model_copy(update={"creator": "other-launcher"})
    wrong_media_type = evidence.model_copy(update={"media_type": "text/plain"})
    foreign = CompatibilityReceiptAuthority(tmp_path / "foreign-root", LAUNCHER_IDENTITY, runner_identity())

    assert_invalid_receipt(lambda: authority.load_verified_receipt(arbitrary_evidence))
    assert_invalid_receipt(lambda: authority.load_verified_receipt(wrong_creator))
    assert_invalid_receipt(lambda: authority.load_verified_receipt(wrong_media_type))
    assert_invalid_receipt(lambda: foreign.load_verified_receipt(evidence))


def test_receipt_authority_requires_matching_launcher_and_full_runner_identity(tmp_path: Path) -> None:
    authority = CompatibilityReceiptAuthority(tmp_path, LAUNCHER_IDENTITY, runner_identity())
    evidence = authority.publish(compatibility_receipt(authority))
    other_launcher = CompatibilityReceiptAuthority(tmp_path, "other-launcher", runner_identity())
    other_runner = CompatibilityReceiptAuthority(
        tmp_path,
        LAUNCHER_IDENTITY,
        runner_identity().model_copy(update={"source_sha": "1" * 64}),
    )

    assert_invalid_receipt(lambda: other_launcher.load_verified_receipt(evidence))
    assert_invalid_receipt(lambda: other_runner.load_verified_receipt(evidence))


class OpaquePreflightFailure(RuntimeError):
    def __str__(self) -> str:
        raise AssertionError("Preflight failures must not be converted to text")


class FakeInterpreter:
    def __init__(self, runner: RunnerIdentity, events: list[str]) -> None:
        self.events = events
        self.calls: list[str] = []
        self.python = TrustedVersionObservation("3.12.13", "1" * 64, ("2" * 64,))
        self.distributions = {
            "crewai": TrustedVersionObservation("1.15.20", runner.dependency_lock_hash, ("3" * 64,))
        }

    def python_observation(self) -> TrustedVersionObservation:
        self.calls.append("python")
        self.events.append("python")
        return self.python

    def distribution_observation(self, distribution: str) -> TrustedVersionObservation:
        self.calls.append(f"distribution:{distribution}")
        self.events.append(f"distribution:{distribution}")
        return self.distributions[distribution]


class FakeTools:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.calls: list[str] = []
        self.observations = {
            "openspec": TrustedVersionObservation("1.12.0", "4" * 64, ("5" * 64,)),
            "node": TrustedVersionObservation("v20.19.0", "6" * 64, ("7" * 64,)),
            "playwright": TrustedVersionObservation("0.1.19", "8" * 64, ("9" * 64,)),
        }

    def version_observation(self, component: str) -> TrustedVersionObservation:
        self.calls.append(component)
        self.events.append(f"tool:{component}")
        return self.observations[component]


class FakeCatalogPreflight:
    def __init__(
        self,
        result: CatalogPreflightResult,
        profiles: ModelCompatibilityRegistry,
        runner_identity: RunnerIdentity,
        events: list[str],
    ) -> None:
        self.profiles = profiles
        self.runner_identity = runner_identity
        self.result = result
        self.events = events
        self.calls: list[str] = []
        self.failure: Exception | None = None

    def resolve(
        self,
        role_models: Mapping[RoleName, ModelRef],
        policy: object,
        *,
        operation_id: str,
    ) -> CatalogPreflightResult:
        assert set(role_models) == set(RoleName)
        assert policy is not None
        self.calls.append(operation_id)
        self.events.append("catalog")
        if self.failure is not None:
            raise self.failure
        return self.result


class FakeReceiptAuthority:
    def __init__(self, events: list[str]) -> None:
        self.events = events
        self.calls = 0
        self.published: list[CompatibilityReceipt] = []
        self.failure: Exception | None = None

    def publish(self, receipt: CompatibilityReceipt) -> EvidenceRef:
        self.calls += 1
        self.events.append("publish")
        if self.failure is not None:
            raise self.failure
        self.published.append(receipt)
        return EvidenceRef(
            relative_path=receipt.relative_path,
            sha256=receipt.content_hash,
            media_type="application/json",
            creator="trusted-launcher",
        )


class FakeOperationIds:
    def __init__(self, events: list[str], value: str = RECEIPT_ID) -> None:
        self.events = events
        self.value = value
        self.calls = 0

    def __call__(self) -> str:
        self.calls += 1
        self.events.append("operation")
        return self.value


class ProhibitedEffects:
    def __init__(self) -> None:
        self.calls: list[str] = []


@dataclass
class PreflightHarness:
    runtime_config: TrustedRuntimeConfig
    role_config: RoleModelConfig
    runtime: CompatibilityRuntime
    interpreter: FakeInterpreter
    tools: FakeTools
    catalog: FakeCatalogPreflight
    authority: FakeReceiptAuthority
    operation_ids: FakeOperationIds
    effects: ProhibitedEffects
    events: list[str]

    def verify(self) -> CompatibilityPreflightResult:
        return PreflightVersionVerifier(self.runtime).verify(self.runtime_config, self.role_config)

    def replace_manifest(self, **changes: object) -> None:
        manifest = replace(self.runtime.runner_manifest, **changes)
        self.runtime = replace(self.runtime, runner_manifest=manifest)


def task_four_policy_data(*, browser_configured: bool) -> dict[str, object]:
    return {
        "git": {"remote": "origin", "base_branch": None},
        "verification": {
            "allow_empty": False,
            "commands": [["${PROJECT}/.venv/bin/python", "-m", "pytest", "-q"]],
            "mutation_commands": [],
        },
        "browser": {
            "start_command": ["${PROJECT}/bin/server"] if browser_configured else None,
            "base_url": "http://localhost:3000" if browser_configured else None,
            "ready_timeout_seconds": 30,
            "command_timeout_seconds": 120,
            "playwright_command_prefix": ["${RUNNER}/bin/playwright-cli"],
            "allowed_operations": ["open", "goto", "snapshot", "click", "fill", "type", "press", "screenshot", "close"],
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


def write_task_four_policy(path: Path, *, browser_configured: bool) -> ProjectConfig:
    path.write_text(json.dumps(task_four_policy_data(browser_configured=browser_configured)), encoding="ascii")
    return ProjectConfig.load(path)


def task_four_role_models() -> dict[RoleName, ModelRef]:
    return {
        role: ModelRef(
            provider="ollama-cloud" if role is RoleName.PROGRAMMER else "opencode-go",
            model_id=f"{role.value}-model",
        )
        for role in RoleName
    }


def task_four_profiles(role_models: Mapping[RoleName, ModelRef]) -> ModelCompatibilityRegistry:
    return ModelCompatibilityRegistry(
        ModelCompatibilityProfile(
            provider=ref.provider,
            model_id=ref.model_id,
            protocol="ollama" if ref.provider == "ollama-cloud" else "chat",
            capabilities=frozenset({"structured_output", "text", "tool_calling"}),
            context_limit=128_000,
            version="2026-09",
        )
        for ref in role_models.values()
    )


def task_four_catalog_result(
    role_models: Mapping[RoleName, ModelRef],
    profiles: ModelCompatibilityRegistry,
) -> CatalogPreflightResult:
    providers = sorted({ref.provider for ref in role_models.values()})
    catalogs = {
        provider: ModelCatalog(ref.model_id for ref in role_models.values() if ref.provider == provider)
        for provider in providers
    }
    metadata = {
        role: profiles.resolve(ref, catalogs[ref.provider], RoleCapabilityMatrix.required_for_role(role))
        for role, ref in role_models.items()
    }
    observations = {
        provider: catalog_observation(provider).model_copy(
            update={
                "model_set_hash": hash_json(sorted(catalogs[provider].model_ids)),
                "profile_bundle_hash": profiles.profile_bundle_hash,
            }
        )
        for provider in providers
    }
    return CatalogPreflightResult(catalogs=catalogs, resolved_models=metadata, catalog_observations=observations)


def valid_preflight_harness(tmp_path: Path, *, browser_configured: bool = False) -> PreflightHarness:
    project_root = tmp_path / "project"
    project_root.mkdir()
    policy_path = project_root / "auto-code.yaml"
    policy = write_task_four_policy(policy_path, browser_configured=browser_configured)
    runner = runner_identity()
    role_models = task_four_role_models()
    profiles = task_four_profiles(role_models)
    events: list[str] = []
    interpreter = FakeInterpreter(runner, events)
    tools = FakeTools(events)
    catalog = FakeCatalogPreflight(task_four_catalog_result(role_models, profiles), profiles, runner, events)
    authority = FakeReceiptAuthority(events)
    operation_ids = FakeOperationIds(events)
    runtime = CompatibilityRuntime(
        launcher_identity=LAUNCHER_IDENTITY,
        interpreter=interpreter,
        tools=tools,
        runner_manifest=RunnerPackageManifest(
            runner_identity=runner,
            openspec_schema_name="spec-driven",
            openspec_schema_hash="5" * 64,
            ralph_upstream_name="opencode-ralph-loop",
            ralph_upstream_version="1.0.10",
            node_package_versions={
                "@playwright/cli": "0.1.19",
                "playwright": "1.63.0-alpha-2026-08-31",
                "playwright-core": "1.63.0-alpha-2026-08-31",
            },
        ),
        catalog_preflight=catalog,  # type: ignore[arg-type]
        receipt_authority=authority,  # type: ignore[arg-type]
        now=lambda: NOW,
        new_operation_id=operation_ids,
    )
    return PreflightHarness(
        runtime_config=TrustedRuntimeConfig(
            state_root=tmp_path / "state",
            project_root=project_root,
            project_policy_path=policy_path,
            project_policy_hash=policy.policy_hash,
            runner_identity=runner,
        ),
        role_config=RoleModelConfig(models=role_models),
        runtime=runtime,
        interpreter=interpreter,
        tools=tools,
        catalog=catalog,
        authority=authority,
        operation_ids=operation_ids,
        effects=ProhibitedEffects(),
        events=events,
    )


def assert_preflight_failure(operation: Callable[[], object], message: str) -> None:
    with pytest.raises(CompatibilityPreflightError, match=f"^{message}$") as error:
        operation()
    assert str(error.value) == message
    assert error.value.__cause__ is None
    assert error.value.__suppress_context__


def forged_runtime_config(config: TrustedRuntimeConfig, **changes: object) -> TrustedRuntimeConfig:
    forged = object.__new__(TrustedRuntimeConfig)
    for name in ("state_root", "project_root", "project_policy_path", "project_policy_hash", "runner_identity"):
        object.__setattr__(forged, name, changes.get(name, getattr(config, name)))
    return forged


def test_preflight_composes_one_bound_receipt_with_browser_disabled(tmp_path: Path) -> None:
    harness = valid_preflight_harness(tmp_path)

    result = harness.verify()

    expected_role_hash = hash_json(
        {
            role.value: f"{ref.provider}/{ref.model_id}"
            for role, ref in sorted(harness.role_config.models.items(), key=lambda item: item[0].value)
        }
    )
    expected_components = {
        "python": ("3.12.x", "3.12.13", "1" * 64, ("2" * 64,)),
        "crewai": ("1.15.20", "1.15.20", "c" * 64, ("3" * 64,)),
        "openspec": ("1.12.0", "1.12.0", "4" * 64, ("5" * 64,)),
        "node": (">=20.19.0", "v20.19.0", "6" * 64, ("7" * 64,)),
        "ralph": ("1.0.10", "1.0.10", "a" * 64, ()),
    }

    assert harness.events == ["python", "distribution:crewai", "tool:openspec", "tool:node", "operation", "catalog", "publish"]
    assert harness.operation_ids.calls == 1
    assert harness.catalog.calls == [RECEIPT_ID]
    assert harness.authority.published == [result.receipt]
    assert harness.tools.calls == ["openspec", "node"]
    assert harness.effects.calls == []
    assert result.receipt.receipt_id == RECEIPT_ID
    assert result.receipt.issued_at == NOW
    assert result.receipt.launcher_identity == LAUNCHER_IDENTITY
    assert result.receipt.runner_identity == harness.runtime_config.runner_identity
    assert result.receipt.runner_content_hash == harness.runtime_config.runner_identity.content_hash
    assert result.receipt.project_policy_hash == harness.runtime_config.project_policy_hash
    assert result.receipt.selected_role_models_hash == expected_role_hash
    assert result.receipt.profile_bundle_hash == harness.catalog.profiles.profile_bundle_hash
    assert result.receipt.browser_preflight_status is BrowserPreflightStatus.NOT_CONFIGURED
    assert result.receipt.content_hash == result.receipt_ref.sha256
    assert result.receipt_ref.relative_path == f"trusted-launcher/compatibility/{RECEIPT_ID}.json"
    assert set(result.catalogs) == {"opencode-go", "ollama-cloud"}
    assert set(result.resolved_models) == set(RoleName)
    assert {
        observation.component: (
            observation.expected_constraint,
            observation.observed_version,
            observation.verified_identity_hash,
            observation.evidence_hashes,
        )
        for observation in result.receipt.component_observations
    } == expected_components
    with pytest.raises(TypeError):
        result.catalogs["opencode-go"] = ModelCatalog(())  # type: ignore[index]
    with pytest.raises(TypeError):
        result.resolved_models[RoleName.ANALYST] = result.resolved_models[RoleName.ANALYST]  # type: ignore[index]
    with pytest.raises(TypeError):
        harness.runtime.runner_manifest.node_package_versions["playwright"] = "other"  # type: ignore[index]


@pytest.mark.parametrize(
    ("component", "mutate"),
    (
        ("python", lambda harness: setattr(harness.interpreter, "python", TrustedVersionObservation("3.11.9", "1" * 64, ("2" * 64,)))),
        (
            "crewai",
            lambda harness: harness.interpreter.distributions.__setitem__(
                "crewai", TrustedVersionObservation("1.15.19", "c" * 64, ("3" * 64,))
            ),
        ),
        (
            "openspec",
            lambda harness: harness.tools.observations.__setitem__(
                "openspec", TrustedVersionObservation("1.11.0", "4" * 64, ("5" * 64,))
            ),
        ),
        (
            "node",
            lambda harness: harness.tools.observations.__setitem__(
                "node", TrustedVersionObservation("v20.19.0-rc.1", "6" * 64, ("7" * 64,))
            ),
        ),
        ("ralph", lambda harness: harness.replace_manifest(ralph_upstream_version="1.0.9")),
    ),
)
def test_baseline_component_mismatches_stop_before_catalog_or_publication(
    tmp_path: Path,
    component: str,
    mutate: Callable[[PreflightHarness], None],
) -> None:
    harness = valid_preflight_harness(tmp_path)
    mutate(harness)

    assert_preflight_failure(harness.verify, "compatibility baseline is invalid")

    assert component
    assert harness.catalog.calls == []
    assert harness.authority.calls == 0
    assert harness.operation_ids.calls == 0
    assert harness.effects.calls == []


@pytest.mark.parametrize(
    "mutate",
    (
        lambda harness: harness.replace_manifest(openspec_schema_name="other-schema"),
        lambda harness: harness.replace_manifest(openspec_schema_hash="not-a-sha256"),
        lambda harness: harness.replace_manifest(ralph_upstream_name="other-ralph"),
        lambda harness: harness.replace_manifest(ralph_upstream_version="1.0.9"),
        lambda harness: harness.replace_manifest(
            runner_identity=harness.runtime.runner_manifest.runner_identity.model_copy(update={"source_sha": "1" * 64})
        ),
        lambda harness: harness.replace_manifest(
            runner_identity=harness.runtime.runner_manifest.runner_identity.model_copy(
                update={"dependency_lock_hash": "2" * 64}
            )
        ),
        lambda harness: harness.replace_manifest(
            runner_identity=harness.runtime.runner_manifest.runner_identity.model_copy(update={"content_hash": "3" * 64})
        ),
        lambda harness: harness.replace_manifest(
            runner_identity=harness.runtime.runner_manifest.runner_identity.model_copy(
                update={"contract_bundle_hash": "4" * 64}
            )
        ),
    ),
    ids=("schema-name", "schema-hash", "ralph-name", "ralph-version", "source", "dependency", "content", "contract"),
)
def test_manifest_provenance_mismatches_stop_before_catalog_or_publication(
    tmp_path: Path,
    mutate: Callable[[PreflightHarness], None],
) -> None:
    harness = valid_preflight_harness(tmp_path)
    mutate(harness)

    assert_preflight_failure(harness.verify, "compatibility baseline is invalid")

    assert harness.catalog.calls == []
    assert harness.authority.calls == 0
    assert harness.operation_ids.calls == 0
    assert harness.effects.calls == []


def test_manifest_schema_hash_must_occur_in_trusted_openspec_evidence_before_catalog_resolution(
    tmp_path: Path,
) -> None:
    harness = valid_preflight_harness(tmp_path)
    harness.replace_manifest(openspec_schema_hash="a" * 64)

    assert_preflight_failure(harness.verify, "compatibility baseline is invalid")

    assert harness.tools.calls == ["openspec"]
    assert harness.catalog.calls == []
    assert harness.authority.calls == 0
    assert harness.operation_ids.calls == 0
    assert harness.effects.calls == []


def test_policy_hash_drift_stops_before_any_runtime_capability(tmp_path: Path) -> None:
    harness = valid_preflight_harness(tmp_path)
    changed = task_four_policy_data(browser_configured=False)
    changed["preflight"] = {
        "catalog_timeout_seconds": 31,
        "max_catalog_response_bytes": 1_048_576,
        "catalog_retry_budget": 2,
        "catalog_cache_validity_seconds": 300,
    }
    harness.runtime_config.project_policy_path.write_text(json.dumps(changed), encoding="ascii")

    assert_preflight_failure(harness.verify, "compatibility policy is invalid")

    assert harness.interpreter.calls == []
    assert harness.tools.calls == []
    assert harness.catalog.calls == []
    assert harness.authority.calls == 0
    assert harness.operation_ids.calls == 0
    assert harness.effects.calls == []


def test_policy_path_escape_stops_before_any_runtime_capability(tmp_path: Path) -> None:
    harness = valid_preflight_harness(tmp_path)
    harness.runtime_config = forged_runtime_config(
        harness.runtime_config,
        project_policy_path=tmp_path / "outside.yaml",
    )

    assert_preflight_failure(harness.verify, "compatibility policy is invalid")

    assert harness.interpreter.calls == []
    assert harness.tools.calls == []
    assert harness.catalog.calls == []
    assert harness.authority.calls == 0
    assert harness.operation_ids.calls == 0
    assert harness.effects.calls == []


def test_configured_browser_adds_only_a_verified_playwright_observation(tmp_path: Path) -> None:
    harness = valid_preflight_harness(tmp_path, browser_configured=True)

    result = harness.verify()

    assert result.receipt.browser_preflight_status is BrowserPreflightStatus.VERIFIED
    assert [observation.component for observation in result.receipt.component_observations] == [
        "crewai",
        "node",
        "openspec",
        "playwright",
        "python",
        "ralph",
    ]
    playwright = next(
        observation for observation in result.receipt.component_observations if observation.component == "playwright"
    )
    assert (playwright.expected_constraint, playwright.observed_version, playwright.verified_identity_hash) == (
        "0.1.19",
        "0.1.19",
        "8" * 64,
    )
    assert playwright.evidence_hashes == ("9" * 64,)
    assert harness.tools.calls == ["openspec", "node", "playwright"]
    assert harness.effects.calls == []


@pytest.mark.parametrize(
    ("package", "version"),
    (
        ("@playwright/cli", "0.1.18"),
        ("playwright", "1.63.0-alpha-2026-08-30"),
        ("playwright-core", "1.63.0-alpha-2026-08-30"),
    ),
)
def test_configured_browser_requires_exact_playwright_package_tree(
    tmp_path: Path,
    package: str,
    version: str,
) -> None:
    harness = valid_preflight_harness(tmp_path, browser_configured=True)
    packages = dict(harness.runtime.runner_manifest.node_package_versions)
    packages[package] = version
    harness.replace_manifest(node_package_versions=packages)

    assert_preflight_failure(harness.verify, "compatibility baseline is invalid")

    assert harness.catalog.calls == []
    assert harness.authority.calls == 0
    assert harness.effects.calls == []


def test_configured_browser_requires_exact_playwright_cli_version_without_starting_a_browser(tmp_path: Path) -> None:
    harness = valid_preflight_harness(tmp_path, browser_configured=True)
    harness.tools.observations["playwright"] = TrustedVersionObservation("0.1.18", "8" * 64, ("9" * 64,))

    assert_preflight_failure(harness.verify, "compatibility baseline is invalid")

    assert harness.catalog.calls == []
    assert harness.authority.calls == 0
    assert harness.effects.calls == []


def test_inconsistent_browser_pair_is_a_baseline_failure_without_a_playwright_probe(tmp_path: Path) -> None:
    harness = valid_preflight_harness(tmp_path)
    invalid_browser = BrowserPolicy.model_construct(
        start_command=None,
        base_url="http://localhost:3000",
        ready_timeout_seconds=30,
        command_timeout_seconds=120,
        playwright_command_prefix=("${RUNNER}/bin/playwright-cli",),
        allowed_operations=("open",),
    )

    assert_preflight_failure(
        lambda: verify_browser_if_configured(harness.runtime, invalid_browser),
        "compatibility baseline is invalid",
    )

    assert harness.tools.calls == []
    assert harness.effects.calls == []


def test_catalog_failure_is_fixed_and_never_publishes_a_receipt(tmp_path: Path) -> None:
    harness = valid_preflight_harness(tmp_path)
    harness.catalog.failure = OpaquePreflightFailure()

    assert_preflight_failure(harness.verify, "compatibility catalog is invalid")

    assert harness.catalog.calls == [RECEIPT_ID]
    assert harness.authority.calls == 0
    assert harness.effects.calls == []


def test_receipt_authority_failure_is_fixed_and_leaves_no_published_receipt(tmp_path: Path) -> None:
    harness = valid_preflight_harness(tmp_path)
    harness.authority.failure = OpaquePreflightFailure()

    assert_preflight_failure(harness.verify, "compatibility receipt is invalid")

    assert harness.catalog.calls == [RECEIPT_ID]
    assert harness.authority.calls == 1
    assert harness.authority.published == []
    assert harness.effects.calls == []


def test_operation_id_is_one_canonical_uuid_shared_by_catalog_and_receipt(tmp_path: Path) -> None:
    harness = valid_preflight_harness(tmp_path)
    harness.operation_ids.value = RECEIPT_ID.upper()

    assert_preflight_failure(harness.verify, "compatibility baseline is invalid")

    assert harness.operation_ids.calls == 1
    assert harness.catalog.calls == []
    assert harness.authority.calls == 0
    assert harness.effects.calls == []


def test_preflight_rejects_preconstructed_forged_catalog_observations_before_publication(tmp_path: Path) -> None:
    harness = valid_preflight_harness(tmp_path)
    observations = dict(harness.catalog.result.catalog_observations)
    forged = CatalogObservation.model_construct(
        **observations["opencode-go"].model_dump(mode="python", round_trip=True)
    )
    object.__setattr__(forged, "profile_bundle_hash", "not-a-sha256")
    observations["opencode-go"] = forged
    harness.catalog.result = CatalogPreflightResult(
        catalogs=harness.catalog.result.catalogs,
        resolved_models=harness.catalog.result.resolved_models,
        catalog_observations=observations,
    )

    assert_preflight_failure(harness.verify, "compatibility catalog is invalid")

    assert harness.authority.calls == 0
    assert harness.effects.calls == []


def test_preflight_rejects_a_forged_catalog_model_set_before_publication(tmp_path: Path) -> None:
    harness = valid_preflight_harness(tmp_path)
    catalogs = dict(harness.catalog.result.catalogs)
    catalogs["opencode-go"] = ModelCatalog((*catalogs["opencode-go"].model_ids, "extra-model"))
    harness.catalog.result = CatalogPreflightResult(
        catalogs=catalogs,
        resolved_models=harness.catalog.result.resolved_models,
        catalog_observations=harness.catalog.result.catalog_observations,
    )

    assert_preflight_failure(harness.verify, "compatibility catalog is invalid")

    assert harness.authority.calls == 0
    assert harness.effects.calls == []


def test_preflight_rejects_preconstructed_forged_descriptor_identity_before_probes(tmp_path: Path) -> None:
    harness = valid_preflight_harness(tmp_path)
    forged_runner = RunnerIdentity.model_construct(
        **harness.runtime_config.runner_identity.model_dump(mode="python", round_trip=True)
    )
    object.__setattr__(forged_runner, "source_sha", "not-a-sha256")
    harness.runtime_config = forged_runtime_config(harness.runtime_config, runner_identity=forged_runner)

    assert_preflight_failure(harness.verify, "compatibility baseline is invalid")

    assert harness.interpreter.calls == []
    assert harness.tools.calls == []
    assert harness.catalog.calls == []
    assert harness.authority.calls == 0
    assert harness.effects.calls == []


def test_receipt_builder_rejects_preconstructed_role_mappings_with_plain_string_keys(tmp_path: Path) -> None:
    harness = valid_preflight_harness(tmp_path)
    forged_role_models = {role.value: model for role, model in harness.role_config.models.items()}

    assert_preflight_failure(
        lambda: build_compatibility_receipt(
            harness.runtime,
            harness.runtime_config,
            forged_role_models,  # type: ignore[arg-type]
            harness.catalog.result,
            component_observations(),
            BrowserPreflightStatus.NOT_CONFIGURED,
            receipt_id=RECEIPT_ID,
        ),
        "compatibility receipt is invalid",
    )

    assert harness.authority.calls == 0
    assert harness.effects.calls == []


@pytest.mark.parametrize("substitution", ("catalog", "selected-model"))
def test_preflight_result_rejects_maps_not_attested_by_its_receipt(
    tmp_path: Path,
    substitution: str,
) -> None:
    harness = valid_preflight_harness(tmp_path)
    result = harness.verify()
    catalogs = dict(result.catalogs)
    resolved_models = dict(result.resolved_models)
    if substitution == "catalog":
        catalogs["opencode-go"] = ModelCatalog((*catalogs["opencode-go"].model_ids, "extra-model"))
    else:
        resolved_models[RoleName.ANALYST] = resolved_models[RoleName.ARCHITECT]

    with pytest.raises(ValueError, match="^compatibility preflight result is invalid$"):
        CompatibilityPreflightResult(
            receipt=result.receipt,
            receipt_ref=result.receipt_ref,
            catalogs=catalogs,
            resolved_models=resolved_models,
            profiles=harness.catalog.profiles,
        )


@pytest.mark.parametrize(
    ("field", "forged_value"),
    (
        ("protocol", "messages"),
        ("capabilities", frozenset({"structured_output", "text"})),
        ("context_limit", 64_000),
        ("compatibility_version", "2026-10"),
    ),
)
def test_preflight_result_rejects_metadata_forged_away_from_its_profile(
    tmp_path: Path,
    field: str,
    forged_value: object,
) -> None:
    harness = valid_preflight_harness(tmp_path)
    result = harness.verify()
    resolved_models = dict(result.resolved_models)
    resolved_models[RoleName.ANALYST] = replace(
        resolved_models[RoleName.ANALYST],
        **{field: forged_value},
    )

    with pytest.raises(ValueError, match="^compatibility preflight result is invalid$"):
        CompatibilityPreflightResult(
            receipt=result.receipt,
            receipt_ref=result.receipt_ref,
            catalogs=result.catalogs,
            resolved_models=resolved_models,
            profiles=harness.catalog.profiles,
        )


def test_preflight_result_rejects_a_registry_subclass_with_overridden_resolution(tmp_path: Path) -> None:
    harness = valid_preflight_harness(tmp_path)
    result = harness.verify()

    class OverridingRegistry(ModelCompatibilityRegistry):
        def resolve(self, ref: ModelRef, live_catalog: ModelCatalog, capabilities: object) -> ModelMetadata:
            metadata = super().resolve(ref, live_catalog, capabilities)
            if ref == ModelRef(provider="opencode-go", model_id="analyst-model"):
                return replace(metadata, protocol="messages")
            return metadata

    profiles = OverridingRegistry(
        ModelCompatibilityProfile(
            provider=ref.provider,
            model_id=ref.model_id,
            protocol="ollama" if ref.provider == "ollama-cloud" else "chat",
            capabilities=frozenset({"structured_output", "text", "tool_calling"}),
            context_limit=128_000,
            version="2026-09",
        )
        for ref in harness.role_config.models.values()
    )
    resolved_models = dict(result.resolved_models)
    resolved_models[RoleName.ANALYST] = replace(resolved_models[RoleName.ANALYST], protocol="messages")

    assert profiles.profile_bundle_hash == result.receipt.profile_bundle_hash
    with pytest.raises(ValueError, match="^compatibility preflight result is invalid$"):
        CompatibilityPreflightResult(
            receipt=result.receipt,
            receipt_ref=result.receipt_ref,
            catalogs=result.catalogs,
            resolved_models=resolved_models,
            profiles=profiles,
        )


def test_preflight_rejects_a_registry_subclass_before_probes_or_publication(tmp_path: Path) -> None:
    harness = valid_preflight_harness(tmp_path)

    class OverridingRegistry(ModelCompatibilityRegistry):
        def resolve(self, ref: ModelRef, live_catalog: ModelCatalog, capabilities: object) -> ModelMetadata:
            return super().resolve(ref, live_catalog, capabilities)

    harness.catalog.profiles = OverridingRegistry(
        ModelCompatibilityProfile(
            provider=ref.provider,
            model_id=ref.model_id,
            protocol="ollama" if ref.provider == "ollama-cloud" else "chat",
            capabilities=frozenset({"structured_output", "text", "tool_calling"}),
            context_limit=128_000,
            version="2026-09",
        )
        for ref in harness.role_config.models.values()
    )

    assert_preflight_failure(harness.verify, "compatibility baseline is invalid")

    assert harness.interpreter.calls == []
    assert harness.tools.calls == []
    assert harness.catalog.calls == []
    assert harness.authority.calls == 0
    assert harness.operation_ids.calls == 0
    assert harness.effects.calls == []


def test_catalog_sanitization_rejects_selected_live_metadata_not_resolved_from_profiles(tmp_path: Path) -> None:
    harness = valid_preflight_harness(tmp_path)
    metadata = dict(harness.catalog.result.resolved_models)
    selected = metadata[RoleName.ANALYST]
    metadata[RoleName.ANALYST] = ModelMetadata(
        provider=selected.provider,
        model_id=selected.model_id,
        protocol="messages",
        capabilities=frozenset({"text"}),
        context_limit=64_000,
        compatibility_version="2026-10",
    )
    harness.catalog.result = CatalogPreflightResult(
        catalogs=harness.catalog.result.catalogs,
        resolved_models=metadata,
        catalog_observations=harness.catalog.result.catalog_observations,
    )

    assert_preflight_failure(harness.verify, "compatibility catalog is invalid")

    assert harness.catalog.calls == [RECEIPT_ID]
    assert harness.authority.calls == 0
    assert harness.effects.calls == []


def test_catalog_runner_identity_mismatch_is_baseline_invalid_before_probes(tmp_path: Path) -> None:
    harness = valid_preflight_harness(tmp_path)
    harness.catalog.runner_identity = runner_identity("e" * 64)

    assert_preflight_failure(harness.verify, "compatibility baseline is invalid")

    assert harness.interpreter.calls == []
    assert harness.tools.calls == []
    assert harness.catalog.calls == []
    assert harness.authority.calls == 0
    assert harness.operation_ids.calls == 0
    assert harness.effects.calls == []
