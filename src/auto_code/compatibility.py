from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import InitVar, dataclass
from datetime import datetime
import hmac
from pathlib import Path
import re
from types import MappingProxyType
from typing import Final, Literal, Protocol

from .catalog_preflight import CatalogPreflightResult, LiveCatalogPreflight
from .cli import TrustedRuntimeConfig
from .contracts import (
    BrowserPreflightStatus,
    CatalogObservation,
    CompatibilityComponentObservation,
    CompatibilityReceipt,
    EvidenceRef,
    RunnerIdentity,
    reject_unsafe_persisted_value,
)
from .hashing import hash_json
from .model_catalog import ModelCatalog, ModelMetadata, ModelRef, SUPPORTED_PROVIDERS, canonical_text, is_secret_like_identifier
from .model_compatibility import ModelCompatibilityRegistry
from .model_config import RoleModelConfig, RoleName
from .project_config import BrowserPolicy, ProjectConfig
from .state import _ensure_directory, _normalize_state_root, _read_canonical_json, _write_new_json
from .tool_broker import RoleCapabilityMatrix


_SAFE_REFERENCE_SEGMENT: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,254}\Z")
_CANONICAL_RECEIPT_ID: Final = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z"
)
_RECEIPT_DIRECTORY: Final = ("trusted-launcher", "compatibility")
_SHA256: Final = re.compile(r"[0-9A-Fa-f]{64}\Z")
_SAFE_VERSION: Final = re.compile(
    r"v?(?:0|[1-9][0-9]{0,8})(?:\.(?:0|[1-9][0-9]{0,8})){0,3}"
    r"(?:-[0-9A-Za-z.-]{1,64})?(?:\+[0-9A-Za-z.-]{1,64})?\Z"
)
_PYTHON_312_VERSION: Final = re.compile(r"3\.12\.(?:0|[1-9][0-9]{0,8})\Z")
_FINAL_SEMVER: Final = re.compile(
    r"v?(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\Z"
)
_SAFE_MANIFEST_TEXT: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}\Z")
_SAFE_PACKAGE_NAME: Final = re.compile(r"@?[A-Za-z0-9][A-Za-z0-9@._/-]{0,255}\Z")
_SAFE_PACKAGE_VERSION: Final = re.compile(r"[0-9A-Za-z.+-]{1,128}\Z")
_PLAYWRIGHT_PACKAGE_VERSIONS: Final = MappingProxyType(
    {
        "@playwright/cli": "0.1.19",
        "playwright": "1.63.0-alpha-2026-08-31",
        "playwright-core": "1.63.0-alpha-2026-08-31",
    }
)


class CompatibilityReceiptError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True, init=False)
class CompatibilityReceiptAuthority:
    """Root-owned, write-once authority for immutable compatibility receipts."""

    state_root: Path
    launcher_identity: str
    runner_identity: RunnerIdentity

    def __init__(self, state_root: Path, launcher_identity: str, runner_identity: RunnerIdentity) -> None:
        object.__setattr__(self, "state_root", _normalize_state_root(state_root))
        object.__setattr__(self, "launcher_identity", _validate_launcher_identity(launcher_identity))
        object.__setattr__(self, "runner_identity", _validate_runner_identity(runner_identity))

    def publish(self, receipt: CompatibilityReceipt) -> EvidenceRef:
        try:
            validated = _validate_receipt(receipt)
            if not self._matches_authority(validated):
                raise ValueError("receipt authority does not match")
            path = self._receipt_path(validated.relative_path)
            self._receipt_directory()
            payload = validated.model_dump(mode="json", round_trip=True)
            if not _write_new_json(path, payload):
                stored = _read_contract_canonical_receipt(path)
                if stored.model_dump(mode="json", round_trip=True) != payload:
                    raise ValueError("receipt publication conflicts")
            return self._evidence_for(validated)
        except Exception:
            raise CompatibilityReceiptError("compatibility receipt cannot be published") from None

    def load_verified_receipt(self, evidence: EvidenceRef) -> CompatibilityReceipt:
        try:
            validated_evidence = _validate_evidence(evidence)
            if (
                validated_evidence.creator != "trusted-launcher"
                or validated_evidence.media_type != "application/json"
            ):
                raise ValueError("receipt evidence is invalid")
            path = self._receipt_path(validated_evidence.relative_path)
            receipt = _read_contract_canonical_receipt(path)
            if (
                receipt.relative_path != validated_evidence.relative_path
                or path.name != f"{receipt.receipt_id}.json"
                or not hmac.compare_digest(receipt.content_hash, validated_evidence.sha256)
                or not self._matches_authority(receipt)
            ):
                raise ValueError("receipt evidence is invalid")
            return receipt
        except Exception:
            raise CompatibilityReceiptError("compatibility receipt is invalid") from None

    def _receipt_directory(self) -> Path:
        return _ensure_directory(self.state_root, self.state_root.joinpath(*_RECEIPT_DIRECTORY))

    def _receipt_path(self, relative_path: object) -> Path:
        if not isinstance(relative_path, str):
            raise ValueError("receipt path is invalid")
        path = str.__str__(relative_path)
        parts = path.split("/")
        if len(parts) != 3 or tuple(parts[:2]) != _RECEIPT_DIRECTORY:
            raise ValueError("receipt path is invalid")
        name = parts[2]
        if not name.endswith(".json"):
            raise ValueError("receipt path is invalid")
        receipt_id = name.removesuffix(".json")
        if _CANONICAL_RECEIPT_ID.fullmatch(receipt_id) is None or name != f"{receipt_id}.json":
            raise ValueError("receipt path is invalid")
        return self.state_root.joinpath(*_RECEIPT_DIRECTORY, name)

    def _matches_authority(self, receipt: CompatibilityReceipt) -> bool:
        return receipt.launcher_identity == self.launcher_identity and receipt.runner_identity == self.runner_identity

    @staticmethod
    def _evidence_for(receipt: CompatibilityReceipt) -> EvidenceRef:
        return EvidenceRef(
            relative_path=receipt.relative_path,
            sha256=receipt.content_hash,
            media_type="application/json",
            creator="trusted-launcher",
        )


def _validate_launcher_identity(value: object) -> str:
    identity = canonical_text(value, "Compatibility launcher identity")
    parts = identity.split("/")
    if (
        len(identity) > 256
        or not parts
        or any(_SAFE_REFERENCE_SEGMENT.fullmatch(part) is None for part in parts)
        or is_secret_like_identifier(identity)
    ):
        raise ValueError("Compatibility launcher identity is invalid")
    return reject_unsafe_persisted_value(identity)


def _validate_runner_identity(value: object) -> RunnerIdentity:
    if not isinstance(value, RunnerIdentity):
        raise ValueError("Compatibility runner identity is invalid")
    return RunnerIdentity.model_validate(value.model_dump(mode="json", round_trip=True))


def _validate_receipt(value: object) -> CompatibilityReceipt:
    if not isinstance(value, CompatibilityReceipt):
        raise ValueError("Compatibility receipt is invalid")
    return CompatibilityReceipt.model_validate(value.model_dump(mode="json", round_trip=True))


def _validate_evidence(value: object) -> EvidenceRef:
    if not isinstance(value, EvidenceRef):
        raise ValueError("Compatibility receipt evidence is invalid")
    return EvidenceRef.model_validate(value.model_dump(mode="json", round_trip=True))


def _read_contract_canonical_receipt(path: Path) -> CompatibilityReceipt:
    raw = _read_canonical_json(path, "compatibility receipt")
    receipt = CompatibilityReceipt.model_validate(raw)
    if raw != receipt.model_dump(mode="json", round_trip=True):
        raise ValueError("compatibility receipt is not contract canonical")
    return receipt


class TrustedInterpreterProbe(Protocol):
    def python_observation(self) -> TrustedVersionObservation: ...

    def distribution_observation(self, distribution: str) -> TrustedVersionObservation: ...


class TrustedToolProbe(Protocol):
    def version_observation(
        self,
        component: Literal["openspec", "node", "playwright"],
    ) -> TrustedVersionObservation: ...


@dataclass(frozen=True)
class TrustedVersionObservation:
    observed_version: str
    verified_identity_hash: str
    evidence_hashes: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "observed_version", _safe_version_text(self.observed_version))
        object.__setattr__(self, "verified_identity_hash", _canonical_sha256(self.verified_identity_hash))
        object.__setattr__(self, "evidence_hashes", _canonical_evidence_hashes(self.evidence_hashes))


@dataclass(frozen=True)
class RunnerPackageManifest:
    runner_identity: RunnerIdentity
    openspec_schema_name: str
    openspec_schema_hash: str
    ralph_upstream_name: str
    ralph_upstream_version: str
    node_package_versions: Mapping[str, str]

    def __post_init__(self) -> None:
        object.__setattr__(self, "node_package_versions", MappingProxyType(_copy_package_versions(self.node_package_versions)))


@dataclass(frozen=True)
class CompatibilityPreflightResult:
    receipt: CompatibilityReceipt
    receipt_ref: EvidenceRef
    catalogs: Mapping[str, ModelCatalog]
    resolved_models: Mapping[RoleName, ModelMetadata]
    profiles: InitVar[ModelCompatibilityRegistry]

    def __post_init__(self, profiles: ModelCompatibilityRegistry) -> None:
        try:
            receipt = _validate_receipt(self.receipt)
            receipt_ref = _validate_evidence(self.receipt_ref)
            catalogs = _copy_catalogs(self.catalogs)
            resolved_models = _copy_resolved_models(self.resolved_models)
            if (
                not hmac.compare_digest(receipt.content_hash, receipt_ref.sha256)
                or receipt.relative_path != receipt_ref.relative_path
                or receipt_ref.media_type != "application/json"
                or receipt_ref.creator != "trusted-launcher"
            ):
                raise ValueError("compatibility preflight result is invalid")
            _validate_result_receipt_bindings(receipt, catalogs, resolved_models, profiles)
        except Exception:
            raise ValueError("compatibility preflight result is invalid") from None
        object.__setattr__(self, "receipt", receipt)
        object.__setattr__(self, "receipt_ref", receipt_ref)
        object.__setattr__(self, "catalogs", MappingProxyType(catalogs))
        object.__setattr__(self, "resolved_models", MappingProxyType(resolved_models))


class CompatibilityPreflightError(RuntimeError):
    pass


@dataclass(frozen=True)
class CompatibilityRuntime:
    launcher_identity: str
    interpreter: TrustedInterpreterProbe
    tools: TrustedToolProbe
    runner_manifest: RunnerPackageManifest
    catalog_preflight: LiveCatalogPreflight
    receipt_authority: CompatibilityReceiptAuthority
    now: Callable[[], datetime]
    new_operation_id: Callable[[], str]


@dataclass(frozen=True)
class _ValidatedManifest:
    runner_identity: RunnerIdentity
    openspec_schema_hash: str
    node_package_versions: Mapping[str, str]


@dataclass(frozen=True)
class _ValidatedRuntime:
    launcher_identity: str
    manifest: _ValidatedManifest
    profiles: ModelCompatibilityRegistry
    profile_bundle_hash: str


class PreflightVersionVerifier:
    def __init__(self, runtime: CompatibilityRuntime) -> None:
        self._runtime = runtime

    def verify(
        self,
        runtime_config: TrustedRuntimeConfig,
        role_config: RoleModelConfig,
    ) -> CompatibilityPreflightResult:
        policy = load_descriptor_bound_policy(runtime_config)
        try:
            descriptor_runner_identity = _descriptor_runner_identity(runtime_config)
            bindings = _validated_runtime(self._runtime, descriptor_runner_identity)
            observations = verify_python_crewai_openspec_node_and_ralph(
                self._runtime,
                descriptor_runner_identity,
                policy,
            )
            browser_status, browser_observations = verify_browser_if_configured(self._runtime, policy.browser)
        except CompatibilityPreflightError:
            raise
        except Exception:
            raise CompatibilityPreflightError("compatibility baseline is invalid") from None

        try:
            operation_id = _canonical_receipt_id(self._runtime.new_operation_id())
        except Exception:
            raise CompatibilityPreflightError("compatibility baseline is invalid") from None

        try:
            role_models = _role_models_from_config(role_config)
            catalog_result = self._runtime.catalog_preflight.resolve(
                role_models,
                policy.preflight,
                operation_id=operation_id,
            )
            sanitized_catalog_result = _sanitize_catalog_result(
                catalog_result,
                role_models,
                bindings.profiles,
            )
        except Exception:
            raise CompatibilityPreflightError("compatibility catalog is invalid") from None

        try:
            receipt = build_compatibility_receipt(
                self._runtime,
                runtime_config,
                role_models,
                sanitized_catalog_result,
                (*observations, *browser_observations),
                browser_status,
                receipt_id=operation_id,
            )
            receipt_ref = self._runtime.receipt_authority.publish(receipt)
            return CompatibilityPreflightResult(
                receipt=receipt,
                receipt_ref=receipt_ref,
                catalogs=sanitized_catalog_result.catalogs,
                resolved_models=sanitized_catalog_result.resolved_models,
                profiles=bindings.profiles,
            )
        except Exception:
            raise CompatibilityPreflightError("compatibility receipt is invalid") from None


def load_descriptor_bound_policy(runtime_config: TrustedRuntimeConfig) -> ProjectConfig:
    try:
        policy_path, descriptor_hash = _descriptor_policy_binding(runtime_config)
        policy = ProjectConfig.load(policy_path)
        if not hmac.compare_digest(_canonical_sha256(policy.policy_hash), descriptor_hash):
            raise ValueError("policy hash does not match descriptor")
        return policy
    except Exception:
        raise CompatibilityPreflightError("compatibility policy is invalid") from None


def verify_python_crewai_openspec_node_and_ralph(
    runtime: CompatibilityRuntime,
    descriptor_runner_identity: RunnerIdentity,
    policy: ProjectConfig,
) -> tuple[CompatibilityComponentObservation, ...]:
    try:
        if not isinstance(policy, ProjectConfig):
            raise ValueError("policy is invalid")
        descriptor_runner_identity = _validated_runner_identity(descriptor_runner_identity)
        bindings = _validated_runtime(runtime, descriptor_runner_identity)

        python = _validated_version_observation(runtime.interpreter.python_observation())
        if _PYTHON_312_VERSION.fullmatch(python.observed_version) is None:
            raise ValueError("python version is invalid")

        crewai = _validated_version_observation(runtime.interpreter.distribution_observation("crewai"))
        if crewai.observed_version != "1.15.20" or not hmac.compare_digest(
            crewai.verified_identity_hash,
            descriptor_runner_identity.dependency_lock_hash,
        ):
            raise ValueError("CrewAI version is invalid")

        openspec = _validated_version_observation(runtime.tools.version_observation("openspec"))
        if (
            openspec.observed_version != "1.12.0"
            or bindings.manifest.openspec_schema_hash not in openspec.evidence_hashes
        ):
            raise ValueError("OpenSpec version is invalid")

        node = _validated_version_observation(runtime.tools.version_observation("node"))
        node_version = _final_semver(node.observed_version)
        if node_version < (20, 19, 0):
            raise ValueError("Node version is invalid")

        observations = (
            CompatibilityComponentObservation(
                component="python",
                expected_constraint="3.12.x",
                observed_version=python.observed_version,
                verified_identity_hash=python.verified_identity_hash,
                evidence_hashes=python.evidence_hashes,
            ),
            CompatibilityComponentObservation(
                component="crewai",
                expected_constraint="1.15.20",
                observed_version=crewai.observed_version,
                verified_identity_hash=descriptor_runner_identity.dependency_lock_hash,
                evidence_hashes=crewai.evidence_hashes,
            ),
            CompatibilityComponentObservation(
                component="openspec",
                expected_constraint="1.12.0",
                observed_version=openspec.observed_version,
                verified_identity_hash=openspec.verified_identity_hash,
                evidence_hashes=openspec.evidence_hashes,
            ),
            CompatibilityComponentObservation(
                component="node",
                expected_constraint=">=20.19.0",
                observed_version=node.observed_version,
                verified_identity_hash=node.verified_identity_hash,
                evidence_hashes=node.evidence_hashes,
            ),
            CompatibilityComponentObservation(
                component="ralph",
                expected_constraint="1.0.10",
                observed_version="1.0.10",
                verified_identity_hash=bindings.manifest.runner_identity.content_hash,
                evidence_hashes=(),
            ),
        )
        return tuple(sorted(observations, key=lambda observation: observation.component))
    except CompatibilityPreflightError:
        raise
    except Exception:
        raise CompatibilityPreflightError("compatibility baseline is invalid") from None


def verify_browser_if_configured(
    runtime: CompatibilityRuntime,
    browser_policy: BrowserPolicy,
) -> tuple[BrowserPreflightStatus, tuple[CompatibilityComponentObservation, ...]]:
    try:
        bindings = _validated_runtime(runtime)
        if not isinstance(browser_policy, BrowserPolicy):
            raise ValueError("browser policy is invalid")
        start_command = browser_policy.start_command
        base_url = browser_policy.base_url
        if start_command is None and base_url is None:
            return BrowserPreflightStatus.NOT_CONFIGURED, ()
        if (
            start_command is None
            or base_url is None
            or not isinstance(start_command, tuple)
            or not start_command
            or any(type(argument) is not str or not argument for argument in start_command)
            or type(base_url) is not str
            or not base_url
        ):
            raise ValueError("browser policy is invalid")
        if any(
            bindings.manifest.node_package_versions.get(package) != version
            for package, version in _PLAYWRIGHT_PACKAGE_VERSIONS.items()
        ):
            raise ValueError("Playwright package tree is invalid")
        playwright = _validated_version_observation(runtime.tools.version_observation("playwright"))
        if playwright.observed_version != "0.1.19":
            raise ValueError("Playwright version is invalid")
        return (
            BrowserPreflightStatus.VERIFIED,
            (
                CompatibilityComponentObservation(
                    component="playwright",
                    expected_constraint="0.1.19",
                    observed_version=playwright.observed_version,
                    verified_identity_hash=playwright.verified_identity_hash,
                    evidence_hashes=playwright.evidence_hashes,
                ),
            ),
        )
    except CompatibilityPreflightError:
        raise
    except Exception:
        raise CompatibilityPreflightError("compatibility baseline is invalid") from None


def build_compatibility_receipt(
    runtime: CompatibilityRuntime,
    runtime_config: TrustedRuntimeConfig,
    role_models: Mapping[RoleName, ModelRef],
    catalog_result: CatalogPreflightResult,
    observations: tuple[CompatibilityComponentObservation, ...],
    browser_status: BrowserPreflightStatus,
    *,
    receipt_id: str,
) -> CompatibilityReceipt:
    try:
        descriptor_runner_identity = _descriptor_runner_identity(runtime_config)
        descriptor_policy_hash = _descriptor_policy_hash(runtime_config)
        bindings = _validated_runtime(runtime, descriptor_runner_identity)
        selected_roles = _validated_role_models(role_models)
        sanitized_catalog_result = _sanitize_catalog_result(
            catalog_result,
            selected_roles,
            bindings.profiles,
        )
        components = _copy_component_observations(observations)
        if not isinstance(browser_status, BrowserPreflightStatus):
            raise ValueError("browser status is invalid")
        issued_at = _validated_datetime(runtime.now())
        receipt_id = _canonical_receipt_id(receipt_id)
        catalog_observations = tuple(
            sanitized_catalog_result.catalog_observations[provider]
            for provider in sorted(sanitized_catalog_result.catalog_observations)
        )
        return CompatibilityReceipt(
            receipt_id=receipt_id,
            issued_at=issued_at,
            launcher_identity=bindings.launcher_identity,
            runner_identity=descriptor_runner_identity,
            runner_content_hash=descriptor_runner_identity.content_hash,
            project_policy_hash=descriptor_policy_hash,
            selected_role_models_hash=hash_json(
                {
                    role.value: f"{ref.provider}/{ref.model_id}"
                    for role, ref in sorted(selected_roles.items(), key=lambda item: item[0].value)
                }
            ),
            profile_bundle_hash=bindings.profile_bundle_hash,
            catalog_receipt_hashes={
                observation.provider: observation.content_hash for observation in catalog_observations
            },
            catalog_observations=catalog_observations,
            browser_preflight_status=browser_status,
            component_observations=tuple(sorted(components, key=lambda observation: observation.component)),
            relative_path=f"trusted-launcher/compatibility/{receipt_id}.json",
        )
    except CompatibilityPreflightError:
        raise
    except Exception:
        raise CompatibilityPreflightError("compatibility receipt is invalid") from None


def _descriptor_policy_binding(runtime_config: TrustedRuntimeConfig) -> tuple[Path, str]:
    if not isinstance(runtime_config, TrustedRuntimeConfig):
        raise ValueError("runtime descriptor is invalid")
    state_root = _lexical_absolute_path(runtime_config.state_root)
    project_root = _lexical_absolute_path(runtime_config.project_root)
    policy_path = _lexical_absolute_path(runtime_config.project_policy_path)
    if policy_path == project_root or not policy_path.is_relative_to(project_root):
        raise ValueError("policy path is outside project root")
    del state_root
    return policy_path, _descriptor_policy_hash(runtime_config)


def _descriptor_policy_hash(runtime_config: TrustedRuntimeConfig) -> str:
    if not isinstance(runtime_config, TrustedRuntimeConfig):
        raise ValueError("runtime descriptor is invalid")
    return _canonical_sha256(runtime_config.project_policy_hash)


def _descriptor_runner_identity(runtime_config: TrustedRuntimeConfig) -> RunnerIdentity:
    if not isinstance(runtime_config, TrustedRuntimeConfig):
        raise ValueError("runtime descriptor is invalid")
    return _validated_runner_identity(runtime_config.runner_identity)


def _lexical_absolute_path(value: object) -> Path:
    if not isinstance(value, Path) or not value.is_absolute() or ".." in value.parts:
        raise ValueError("runtime path is invalid")
    return value


def _validated_runtime(
    runtime: CompatibilityRuntime,
    descriptor_runner_identity: RunnerIdentity | None = None,
) -> _ValidatedRuntime:
    if not isinstance(runtime, CompatibilityRuntime):
        raise ValueError("compatibility runtime is invalid")
    launcher_identity = _validate_launcher_identity(runtime.launcher_identity)
    if not all(
        callable(getattr(runtime.interpreter, method, None))
        for method in ("python_observation", "distribution_observation")
    ):
        raise ValueError("interpreter probe is invalid")
    if not callable(getattr(runtime.tools, "version_observation", None)):
        raise ValueError("tool probe is invalid")
    manifest = _validated_manifest(runtime.runner_manifest, descriptor_runner_identity)
    if not callable(getattr(runtime.catalog_preflight, "resolve", None)):
        raise ValueError("catalog preflight is invalid")
    profiles = getattr(runtime.catalog_preflight, "profiles", None)
    if type(profiles) is not ModelCompatibilityRegistry:
        raise ValueError("catalog profiles are invalid")
    profile_bundle_hash = _canonical_sha256(getattr(profiles, "profile_bundle_hash", None))
    catalog_runner_identity = _validated_runner_identity(getattr(runtime.catalog_preflight, "runner_identity", None))
    if descriptor_runner_identity is not None and catalog_runner_identity != descriptor_runner_identity:
        raise ValueError("catalog runner identity is invalid")
    if not callable(getattr(runtime.receipt_authority, "publish", None)):
        raise ValueError("receipt authority is invalid")
    if not callable(runtime.now) or not callable(runtime.new_operation_id):
        raise ValueError("runtime capability is invalid")
    return _ValidatedRuntime(
        launcher_identity=launcher_identity,
        manifest=manifest,
        profiles=profiles,
        profile_bundle_hash=profile_bundle_hash,
    )


def _validated_manifest(
    value: object,
    descriptor_runner_identity: RunnerIdentity | None,
) -> _ValidatedManifest:
    if not isinstance(value, RunnerPackageManifest):
        raise ValueError("runner manifest is invalid")
    runner_identity = _validated_runner_identity(value.runner_identity)
    if descriptor_runner_identity is not None and runner_identity != descriptor_runner_identity:
        raise ValueError("runner manifest identity is invalid")
    if _safe_manifest_text(value.openspec_schema_name) != "spec-driven":
        raise ValueError("OpenSpec schema is invalid")
    openspec_schema_hash = _canonical_sha256(value.openspec_schema_hash)
    if _safe_manifest_text(value.ralph_upstream_name) != "opencode-ralph-loop":
        raise ValueError("Ralph upstream is invalid")
    if _safe_version_text(value.ralph_upstream_version) != "1.0.10":
        raise ValueError("Ralph version is invalid")
    return _ValidatedManifest(
        runner_identity=runner_identity,
        openspec_schema_hash=openspec_schema_hash,
        node_package_versions=MappingProxyType(_copy_package_versions(value.node_package_versions)),
    )


def _validated_version_observation(value: object) -> TrustedVersionObservation:
    if not isinstance(value, TrustedVersionObservation):
        raise ValueError("trusted version observation is invalid")
    return TrustedVersionObservation(
        observed_version=value.observed_version,
        verified_identity_hash=value.verified_identity_hash,
        evidence_hashes=value.evidence_hashes,
    )


def _validated_runner_identity(value: object) -> RunnerIdentity:
    if not isinstance(value, RunnerIdentity):
        raise ValueError("runner identity is invalid")
    return RunnerIdentity.model_validate(value.model_dump(mode="json", round_trip=True))


def _safe_version_text(value: object) -> str:
    version = canonical_text(value, "Compatibility version")
    if _SAFE_VERSION.fullmatch(version) is None:
        raise ValueError("Compatibility version is invalid")
    return version


def _safe_manifest_text(value: object) -> str:
    text = canonical_text(value, "Runner manifest text")
    if _SAFE_MANIFEST_TEXT.fullmatch(text) is None or is_secret_like_identifier(text):
        raise ValueError("Runner manifest text is invalid")
    return text


def _canonical_sha256(value: object) -> str:
    candidate = canonical_text(value, "Compatibility hash")
    if _SHA256.fullmatch(candidate) is None:
        raise ValueError("Compatibility hash is invalid")
    return candidate.lower()


def _canonical_evidence_hashes(value: object) -> tuple[str, ...]:
    if not isinstance(value, tuple) or len(value) > 64:
        raise ValueError("Compatibility evidence hashes are invalid")
    return tuple(_canonical_sha256(item) for item in value)


def _copy_package_versions(value: object) -> dict[str, str]:
    if not isinstance(value, Mapping):
        raise ValueError("Runner package versions are invalid")
    copied: dict[str, str] = {}
    for source_name, source_version in value.items():
        name = canonical_text(source_name, "Runner package name")
        version = canonical_text(source_version, "Runner package version")
        if (
            _SAFE_PACKAGE_NAME.fullmatch(name) is None
            or _SAFE_PACKAGE_VERSION.fullmatch(version) is None
            or is_secret_like_identifier(name)
            or is_secret_like_identifier(version)
            or name in copied
        ):
            raise ValueError("Runner package versions are invalid")
        copied[name] = version
    return copied


def _final_semver(value: str) -> tuple[int, int, int]:
    match = _FINAL_SEMVER.fullmatch(value)
    if match is None:
        raise ValueError("SemVer is invalid")
    return int(match.group(1)), int(match.group(2)), int(match.group(3))


def _canonical_receipt_id(value: object) -> str:
    receipt_id = canonical_text(value, "Compatibility receipt ID")
    if _CANONICAL_RECEIPT_ID.fullmatch(receipt_id) is None:
        raise ValueError("Compatibility receipt ID is invalid")
    return receipt_id


def _validated_datetime(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("compatibility time is invalid")
    return value


def _role_models_from_config(value: object) -> Mapping[RoleName, ModelRef]:
    if not isinstance(value, RoleModelConfig):
        raise ValueError("role model config is invalid")
    return _validated_role_models(value.models)


def _validated_role_models(value: object) -> Mapping[RoleName, ModelRef]:
    if (
        not isinstance(value, Mapping)
        or set(value) != set(RoleName)
        or any(not isinstance(role, RoleName) for role in value)
    ):
        raise ValueError("role models are invalid")
    copied: dict[RoleName, ModelRef] = {}
    for role in RoleName:
        model = value.get(role)
        if not isinstance(role, RoleName) or not isinstance(model, ModelRef):
            raise ValueError("role models are invalid")
        copied[role] = ModelRef(provider=model.provider, model_id=model.model_id)
    return MappingProxyType(copied)


def _validate_result_receipt_bindings(
    receipt: CompatibilityReceipt,
    catalogs: Mapping[str, ModelCatalog],
    resolved_models: Mapping[RoleName, ModelMetadata],
    profiles: ModelCompatibilityRegistry,
) -> None:
    if type(profiles) is not ModelCompatibilityRegistry:
        raise ValueError("compatibility preflight result is invalid")
    profile_bundle_hash = _canonical_sha256(profiles.profile_bundle_hash)
    if not hmac.compare_digest(receipt.profile_bundle_hash, profile_bundle_hash):
        raise ValueError("compatibility preflight result is invalid")
    observations = {observation.provider: observation for observation in receipt.catalog_observations}
    if set(catalogs) != set(observations):
        raise ValueError("compatibility preflight result is invalid")
    for provider, catalog in catalogs.items():
        if not hmac.compare_digest(
            observations[provider].model_set_hash,
            hash_json(sorted(catalog.model_ids)),
        ):
            raise ValueError("compatibility preflight result is invalid")
    selected_role_models_hash = hash_json(
        {
            role.value: f"{metadata.provider}/{metadata.model_id}"
            for role, metadata in sorted(resolved_models.items(), key=lambda item: item[0].value)
        }
    )
    if not hmac.compare_digest(receipt.selected_role_models_hash, selected_role_models_hash):
        raise ValueError("compatibility preflight result is invalid")
    for role, metadata in resolved_models.items():
        catalog = catalogs.get(metadata.provider)
        if catalog is None or not catalog.is_available(metadata.model_id):
            raise ValueError("compatibility preflight result is invalid")
        expected_metadata = ModelCompatibilityRegistry.resolve(
            profiles,
            ModelRef(provider=metadata.provider, model_id=metadata.model_id),
            catalog,
            RoleCapabilityMatrix.required_for_role(role),
        )
        if not isinstance(expected_metadata, ModelMetadata):
            raise ValueError("compatibility preflight result is invalid")
        expected_metadata = ModelMetadata(
            provider=expected_metadata.provider,
            model_id=expected_metadata.model_id,
            protocol=expected_metadata.protocol,
            capabilities=expected_metadata.capabilities,
            context_limit=expected_metadata.context_limit,
            compatibility_version=expected_metadata.compatibility_version,
        )
        if metadata != expected_metadata:
            raise ValueError("compatibility preflight result is invalid")


def _sanitize_catalog_result(
    value: object,
    role_models: Mapping[RoleName, ModelRef],
    profiles: ModelCompatibilityRegistry,
) -> CatalogPreflightResult:
    if not isinstance(value, CatalogPreflightResult) or not isinstance(profiles, ModelCompatibilityRegistry):
        raise ValueError("catalog preflight result is invalid")
    profile_bundle_hash = _canonical_sha256(profiles.profile_bundle_hash)
    catalogs = _copy_catalogs(value.catalogs)
    resolved_models = _copy_resolved_models(value.resolved_models)
    observations = _copy_catalog_observations(value.catalog_observations)
    selected_providers = {model.provider for model in role_models.values()}
    if set(catalogs) != selected_providers or set(observations) != selected_providers:
        raise ValueError("catalog providers are invalid")
    for provider, observation in observations.items():
        if (
            observation.provider != provider
            or not hmac.compare_digest(observation.profile_bundle_hash, profile_bundle_hash)
            or not hmac.compare_digest(observation.model_set_hash, hash_json(sorted(catalogs[provider].model_ids)))
        ):
            raise ValueError("catalog observation is invalid")
    for role, model in role_models.items():
        metadata = resolved_models[role]
        expected_metadata = profiles.resolve(
            model,
            catalogs[model.provider],
            RoleCapabilityMatrix.required_for_role(role),
        )
        if not isinstance(expected_metadata, ModelMetadata):
            raise ValueError("catalog model resolution is invalid")
        expected_metadata = ModelMetadata(
            provider=expected_metadata.provider,
            model_id=expected_metadata.model_id,
            protocol=expected_metadata.protocol,
            capabilities=expected_metadata.capabilities,
            context_limit=expected_metadata.context_limit,
            compatibility_version=expected_metadata.compatibility_version,
        )
        if (
            metadata.provider != model.provider
            or metadata.model_id != model.model_id
            or not catalogs[model.provider].is_available(model.model_id)
            or metadata != expected_metadata
        ):
            raise ValueError("catalog model resolution is invalid")
    return CatalogPreflightResult(
        catalogs=catalogs,
        resolved_models=resolved_models,
        catalog_observations=observations,
    )


def _copy_catalogs(value: object) -> dict[str, ModelCatalog]:
    if not isinstance(value, Mapping):
        raise ValueError("catalog mappings are invalid")
    copied: dict[str, ModelCatalog] = {}
    for source_provider, source_catalog in value.items():
        provider = _canonical_provider(source_provider)
        if provider in copied or not isinstance(source_catalog, ModelCatalog):
            raise ValueError("catalog mappings are invalid")
        copied[provider] = ModelCatalog(source_catalog.model_ids)
    return copied


def _copy_resolved_models(value: object) -> dict[RoleName, ModelMetadata]:
    if (
        not isinstance(value, Mapping)
        or set(value) != set(RoleName)
        or any(not isinstance(role, RoleName) for role in value)
    ):
        raise ValueError("resolved model mappings are invalid")
    copied: dict[RoleName, ModelMetadata] = {}
    for role in RoleName:
        source_metadata = value.get(role)
        if not isinstance(source_metadata, ModelMetadata):
            raise ValueError("resolved model mappings are invalid")
        copied[role] = ModelMetadata(
            provider=source_metadata.provider,
            model_id=source_metadata.model_id,
            protocol=source_metadata.protocol,
            capabilities=source_metadata.capabilities,
            context_limit=source_metadata.context_limit,
            compatibility_version=source_metadata.compatibility_version,
        )
    return copied


def _copy_catalog_observations(value: object) -> dict[str, CatalogObservation]:
    if not isinstance(value, Mapping):
        raise ValueError("catalog observations are invalid")
    copied: dict[str, CatalogObservation] = {}
    for source_provider, source_observation in value.items():
        provider = _canonical_provider(source_provider)
        if provider in copied or not isinstance(source_observation, CatalogObservation):
            raise ValueError("catalog observations are invalid")
        copied[provider] = CatalogObservation.model_validate(source_observation.model_dump(mode="json", round_trip=True))
    return copied


def _copy_component_observations(value: object) -> tuple[CompatibilityComponentObservation, ...]:
    if not isinstance(value, tuple):
        raise ValueError("component observations are invalid")
    copied: list[CompatibilityComponentObservation] = []
    for source_observation in value:
        if not isinstance(source_observation, CompatibilityComponentObservation):
            raise ValueError("component observations are invalid")
        copied.append(
            CompatibilityComponentObservation.model_validate(source_observation.model_dump(mode="json", round_trip=True))
        )
    return tuple(copied)


def _canonical_provider(value: object) -> str:
    provider = canonical_text(value, "Catalog provider")
    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError("Catalog provider is invalid")
    return provider
