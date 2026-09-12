from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
import re
from types import MappingProxyType
from typing import Protocol

from .contracts import CatalogObservation, RunnerIdentity, reject_unsafe_persisted_value
from .model_catalog import (
    ModelCatalog,
    ModelMetadata,
    ModelRef,
    SUPPORTED_PROVIDERS,
    canonical_text,
    is_secret_like_identifier,
)
from .model_compatibility import ModelCompatibilityRegistry
from .model_config import RoleName
from .project_config import CatalogPreflightPolicy
from .tool_broker import RoleCapabilityMatrix


_SAFE_OPERATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,255}")
_SAFE_ENDPOINT_IDENTITY = re.compile(r"[a-z][a-z0-9_-]{0,63}")
_SHA256 = re.compile(r"[0-9A-Fa-f]{64}")


class ProviderCredentialSource(Protocol):
    def require(self, provider: str) -> object: ...

    def optional(self, provider: str) -> object | None: ...

    def credential_scope_hash(self, provider: str, credential: object | None) -> str: ...


class CatalogPreflightError(RuntimeError):
    pass


@dataclass(frozen=True, repr=False)
class CatalogFetch:
    model_ids: tuple[object, ...]
    response_evidence_hash: str
    fetched_at: datetime
    response_bytes: int


class ProviderCatalogClient(Protocol):
    provider: str
    endpoint_identity: str

    def fetch(
        self,
        credential: object | None,
        *,
        timeout_seconds: int,
        max_response_bytes: int,
        retry_budget: int,
    ) -> CatalogFetch: ...


@dataclass(frozen=True)
class CatalogCacheKey:
    operation_id: str
    provider: str
    endpoint_identity: str
    credential_scope_hash: str
    runner_content_hash: str
    profile_bundle_hash: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation_id", _validate_operation_id(self.operation_id))
        object.__setattr__(self, "provider", _validate_provider(self.provider))
        object.__setattr__(self, "endpoint_identity", _validate_endpoint_identity(self.endpoint_identity))
        object.__setattr__(self, "credential_scope_hash", _validate_sha256(self.credential_scope_hash))
        object.__setattr__(self, "runner_content_hash", _validate_sha256(self.runner_content_hash))
        object.__setattr__(self, "profile_bundle_hash", _validate_sha256(self.profile_bundle_hash))


class CatalogPreflightCache(Protocol):
    def get(self, key: CatalogCacheKey, *, now: datetime) -> CatalogFetch | None: ...

    def put(self, key: CatalogCacheKey, fetch: CatalogFetch, *, expires_at: datetime) -> None: ...


@dataclass(frozen=True)
class CatalogPreflightResult:
    catalogs: Mapping[str, ModelCatalog]
    resolved_models: Mapping[RoleName, ModelMetadata]
    catalog_observations: Mapping[str, CatalogObservation]

    def __post_init__(self) -> None:
        if not all(
            isinstance(value, Mapping)
            for value in (self.catalogs, self.resolved_models, self.catalog_observations)
        ):
            raise ValueError("Catalog preflight result mappings are invalid")
        catalogs: dict[str, ModelCatalog] = {}
        for source_provider, catalog in self.catalogs.items():
            try:
                provider = _validate_provider(source_provider)
            except ValueError:
                raise ValueError("Catalog preflight result catalogs are invalid") from None
            if provider in catalogs:
                raise ValueError("Catalog preflight result catalogs are invalid")
            catalogs[provider] = catalog
        resolved_models = dict(self.resolved_models)
        observations: dict[str, CatalogObservation] = {}
        for source_provider, observation in self.catalog_observations.items():
            try:
                provider = _validate_provider(source_provider)
            except ValueError:
                raise ValueError("Catalog preflight result observations are invalid") from None
            if provider in observations:
                raise ValueError("Catalog preflight result observations are invalid")
            observations[provider] = observation
        if any(not isinstance(catalog, ModelCatalog) for catalog in catalogs.values()):
            raise ValueError("Catalog preflight result catalogs are invalid")
        if set(resolved_models) != set(RoleName) or any(
            not isinstance(role, RoleName) or not isinstance(metadata, ModelMetadata)
            for role, metadata in resolved_models.items()
        ):
            raise ValueError("Catalog preflight result models are invalid")
        if set(catalogs) != set(observations) or any(
            not isinstance(observation, CatalogObservation) or observation.provider != provider
            for provider, observation in observations.items()
        ):
            raise ValueError("Catalog preflight result observations are invalid")
        object.__setattr__(self, "catalogs", MappingProxyType(catalogs))
        object.__setattr__(self, "resolved_models", MappingProxyType(resolved_models))
        object.__setattr__(self, "catalog_observations", MappingProxyType(observations))


class LiveCatalogPreflight:
    def __init__(
        self,
        *,
        clients: Mapping[str, ProviderCatalogClient],
        credentials: ProviderCredentialSource,
        profiles: ModelCompatibilityRegistry,
        runner_identity: RunnerIdentity,
        cache: CatalogPreflightCache,
        now: Callable[[], datetime],
    ) -> None:
        self.clients = clients
        self.credentials = credentials
        self.profiles = profiles
        self.runner_identity = runner_identity
        self.cache = cache
        self.now = now

    def resolve(
        self,
        role_models: Mapping[RoleName, ModelRef],
        policy: CatalogPreflightPolicy,
        *,
        operation_id: str,
    ) -> CatalogPreflightResult:
        try:
            selected_roles = _validate_role_models(role_models)
            if not isinstance(policy, CatalogPreflightPolicy):
                raise ValueError("Catalog preflight policy is invalid")
            operation_id = _validate_operation_id(operation_id)
            clients = self._validate_dependencies()
            current_time = _validate_datetime(self.now())
            runner_content_hash = _validate_sha256(self.runner_identity.content_hash)
            profile_bundle_hash = _validate_sha256(self.profiles.profile_bundle_hash)
            selected_providers = tuple(sorted({ref.provider for ref in selected_roles.values()}))
            if any(provider not in clients for provider in selected_providers):
                raise ValueError("Selected provider client is missing")

            catalogs: dict[str, ModelCatalog] = {}
            observations: dict[str, CatalogObservation] = {}
            for provider in selected_providers:
                client, endpoint_identity = clients[provider]
                catalog, observation = self._resolve_provider(
                    provider=provider,
                    client=client,
                    endpoint_identity=endpoint_identity,
                    policy=policy,
                    operation_id=operation_id,
                    now=current_time,
                    runner_content_hash=runner_content_hash,
                    profile_bundle_hash=profile_bundle_hash,
                )
                catalogs[provider] = catalog
                observations[provider] = observation

            resolved_models = {
                role: self.profiles.resolve(
                    ref,
                    catalogs[ref.provider],
                    RoleCapabilityMatrix.required_for_role(role),
                )
                for role, ref in selected_roles.items()
            }
            return CatalogPreflightResult(
                catalogs=catalogs,
                resolved_models=resolved_models,
                catalog_observations=observations,
            )
        except Exception:
            raise CatalogPreflightError("catalog preflight failed") from None

    def _validate_dependencies(self) -> dict[str, tuple[ProviderCatalogClient, str]]:
        if not isinstance(self.clients, Mapping):
            raise ValueError("Catalog clients are invalid")
        if not isinstance(self.profiles, ModelCompatibilityRegistry):
            raise ValueError("Compatibility profiles are invalid")
        if not isinstance(self.runner_identity, RunnerIdentity):
            raise ValueError("Runner identity is invalid")
        if not callable(self.now):
            raise ValueError("Catalog clock is invalid")
        if not all(
            callable(getattr(self.credentials, method, None))
            for method in ("require", "optional", "credential_scope_hash")
        ):
            raise ValueError("Catalog credentials are invalid")
        if not all(callable(getattr(self.cache, method, None)) for method in ("get", "put")):
            raise ValueError("Catalog cache is invalid")

        clients: dict[str, tuple[ProviderCatalogClient, str]] = {}
        for source_provider, client in self.clients.items():
            provider = _validate_provider(source_provider)
            client_provider = _validate_provider(getattr(client, "provider", None))
            if client_provider != provider or not callable(getattr(client, "fetch", None)):
                raise ValueError("Catalog client is invalid")
            endpoint_identity = _validate_endpoint_identity(getattr(client, "endpoint_identity", None))
            if provider in clients:
                raise ValueError("Catalog client is invalid")
            clients[provider] = (client, endpoint_identity)
        return clients

    def _resolve_provider(
        self,
        *,
        provider: str,
        client: ProviderCatalogClient,
        endpoint_identity: str,
        policy: CatalogPreflightPolicy,
        operation_id: str,
        now: datetime,
        runner_content_hash: str,
        profile_bundle_hash: str,
    ) -> tuple[ModelCatalog, CatalogObservation]:
        credential = self._credential_for(provider)
        try:
            credential_scope_hash = _validate_sha256(self.credentials.credential_scope_hash(provider, credential))
            key = CatalogCacheKey(
                operation_id=operation_id,
                provider=provider,
                endpoint_identity=endpoint_identity,
                credential_scope_hash=credential_scope_hash,
                runner_content_hash=runner_content_hash,
                profile_bundle_hash=profile_bundle_hash,
            )
            cached_fetch = self.cache.get(key, now=now)
            normalized = (
                self._normalize_fetch(cached_fetch, policy, now, cache_entry=True)
                if cached_fetch is not None
                else None
            )
            if normalized is None:
                try:
                    raw_fetch = client.fetch(
                        credential,
                        timeout_seconds=policy.catalog_timeout_seconds,
                        max_response_bytes=policy.max_catalog_response_bytes,
                        retry_budget=policy.catalog_retry_budget,
                    )
                finally:
                    credential = None
                fetch_observed_at = _validate_datetime(self.now())
                normalized = self._normalize_fetch(raw_fetch, policy, fetch_observed_at, cache_entry=False)
                assert normalized is not None
                fetch, catalog, expires_at = normalized
                self.cache.put(key, fetch, expires_at=expires_at)
            else:
                credential = None
                fetch, catalog, expires_at = normalized

            observation = CatalogObservation(
                provider=provider,
                endpoint_identity=endpoint_identity,
                credential_scope_hash=credential_scope_hash,
                fetched_at=fetch.fetched_at,
                expires_at=expires_at,
                model_set_hash=_validate_sha256(_model_set_hash(catalog)),
                profile_bundle_hash=profile_bundle_hash,
                response_evidence_hash=fetch.response_evidence_hash,
            )
            return catalog, observation
        finally:
            credential = None

    def _credential_for(self, provider: str) -> object | None:
        if provider == "ollama-cloud":
            credential = self.credentials.require(provider)
            if credential is None:
                raise ValueError("Ollama credential is missing")
            return credential
        if provider == "opencode-go":
            return self.credentials.optional(provider)
        raise ValueError("Catalog provider is invalid")

    @staticmethod
    def _normalize_fetch(
        fetch: object,
        policy: CatalogPreflightPolicy,
        now: datetime,
        *,
        cache_entry: bool,
    ) -> tuple[CatalogFetch, ModelCatalog, datetime] | None:
        if not isinstance(fetch, CatalogFetch):
            raise ValueError("Catalog fetch is invalid")
        fetched_at = _validate_datetime(fetch.fetched_at)
        if fetched_at > now:
            raise ValueError("Catalog fetch timestamp is invalid")
        expires_at = fetched_at + timedelta(seconds=policy.catalog_cache_validity_seconds)
        if expires_at <= now:
            if cache_entry:
                return None
            raise ValueError("Catalog fetch is expired")
        if isinstance(fetch.response_bytes, bool) or not isinstance(fetch.response_bytes, int):
            raise ValueError("Catalog response bytes are invalid")
        if not 0 <= fetch.response_bytes <= policy.max_catalog_response_bytes:
            raise ValueError("Catalog response bytes are invalid")
        if not isinstance(fetch.model_ids, tuple):
            raise ValueError("Catalog model IDs are invalid")
        catalog = ModelCatalog(fetch.model_ids)
        normalized_fetch = CatalogFetch(
            model_ids=tuple(sorted(catalog.model_ids)),
            response_evidence_hash=_validate_sha256(fetch.response_evidence_hash),
            fetched_at=fetched_at,
            response_bytes=fetch.response_bytes,
        )
        return normalized_fetch, catalog, expires_at


def _validate_role_models(value: object) -> dict[RoleName, ModelRef]:
    if not isinstance(value, Mapping) or set(value) != set(RoleName):
        raise ValueError("Role models are invalid")
    resolved = dict(value)
    if any(not isinstance(role, RoleName) or not isinstance(ref, ModelRef) for role, ref in resolved.items()):
        raise ValueError("Role models are invalid")
    return {role: resolved[role] for role in RoleName}


def _validate_provider(value: object) -> str:
    provider = canonical_text(value, "Catalog provider")
    if provider not in SUPPORTED_PROVIDERS:
        raise ValueError("Catalog provider is invalid")
    return provider


def _validate_operation_id(value: object) -> str:
    operation_id = canonical_text(value, "Catalog operation")
    if _SAFE_OPERATION_ID.fullmatch(operation_id) is None or is_secret_like_identifier(operation_id):
        raise ValueError("Catalog operation is invalid")
    reject_unsafe_persisted_value(operation_id)
    return operation_id


def _validate_endpoint_identity(value: object) -> str:
    endpoint_identity = canonical_text(value, "Catalog endpoint identity")
    if _SAFE_ENDPOINT_IDENTITY.fullmatch(endpoint_identity) is None or is_secret_like_identifier(endpoint_identity):
        raise ValueError("Catalog endpoint identity is invalid")
    reject_unsafe_persisted_value(endpoint_identity)
    return endpoint_identity


def _validate_sha256(value: object) -> str:
    sha256 = canonical_text(value, "Catalog hash")
    if _SHA256.fullmatch(sha256) is None:
        raise ValueError("Catalog hash is invalid")
    return sha256.lower()


def _validate_datetime(value: object) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("Catalog timestamp is invalid")
    return value


def _model_set_hash(catalog: ModelCatalog) -> str:
    from .hashing import hash_json

    return hash_json(sorted(catalog.model_ids))
