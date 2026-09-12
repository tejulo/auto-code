from __future__ import annotations

from collections.abc import Callable, Mapping
from datetime import UTC, datetime, timedelta
import importlib
from typing import Any

from pydantic import ValidationError
import pytest

from auto_code.contracts import RunnerIdentity
from auto_code.hashing import hash_json
from auto_code.model_catalog import ModelCatalog, ModelRef
from auto_code.model_compatibility import ModelCompatibilityProfile, ModelCompatibilityRegistry
from auto_code.model_config import RoleModelConfig, RoleName
from auto_code.model_transport import ModelTransport, RetryPolicy
from auto_code.models import ModelFactory
from auto_code.project_config import CatalogPreflightPolicy


NOW = datetime(2026, 9, 7, 12, 0, tzinfo=UTC)
CAPABILITIES = frozenset({"structured_output", "text", "tool_calling"})
_DEFAULT_CREDENTIAL = object()


def catalog_preflight() -> Any:
    return importlib.import_module("auto_code.catalog_preflight")


def catalog_observation_type() -> type[Any]:
    return getattr(importlib.import_module("auto_code.contracts"), "CatalogObservation")


class OpaqueCredential:
    def __repr__(self) -> str:
        raise AssertionError("Opaque credentials must not be represented")


class OpaqueProviderFailure(RuntimeError):
    def __str__(self) -> str:
        raise AssertionError("Provider failure text must not be represented")


class OpaqueCacheFailure(RuntimeError):
    def __str__(self) -> str:
        raise AssertionError("Cache failure text must not be represented")


class HostileText(str):
    def __repr__(self) -> str:
        return "hostile-text-marker"

    def lower(self) -> str:
        return self


class HostileKeyText(HostileText):
    def __hash__(self) -> int:
        return 0


class HostileCollisionText(HostileText):
    def __new__(cls, value: str) -> HostileCollisionText:
        instance = super().__new__(cls, value)
        instance.use_standard_hash = False
        return instance

    def __hash__(self) -> int:
        return str.__hash__(self) if self.use_standard_hash else 0


class FakeCredentials:
    def __init__(
        self,
        *,
        opencode: object | None = _DEFAULT_CREDENTIAL,
        ollama: object | None = _DEFAULT_CREDENTIAL,
        scope_hashes: Mapping[str, object] | None = None,
        events: list[str] | None = None,
    ) -> None:
        self.opencode = OpaqueCredential() if opencode is _DEFAULT_CREDENTIAL else opencode
        self.ollama = OpaqueCredential() if ollama is _DEFAULT_CREDENTIAL else ollama
        self.scope_hashes = dict(scope_hashes or {})
        self.events = events if events is not None else []
        self.require_calls: list[str] = []
        self.optional_calls: list[str] = []
        self.scope_calls: list[str] = []

    def require(self, provider: str) -> object | None:
        self.require_calls.append(provider)
        self.events.append(f"credential:require:{provider}")
        if provider != "ollama-cloud":
            raise AssertionError("Unexpected required credential provider")
        return self.ollama

    def optional(self, provider: str) -> object | None:
        self.optional_calls.append(provider)
        self.events.append(f"credential:optional:{provider}")
        if provider != "opencode-go":
            raise AssertionError("Unexpected optional credential provider")
        return self.opencode

    def credential_scope_hash(self, provider: str, credential: object | None) -> object:
        del credential
        self.scope_calls.append(provider)
        self.events.append(f"credential:scope:{provider}")
        return self.scope_hashes.get(provider, "c" * 64)


class RecordingCatalogClient:
    def __init__(
        self,
        provider: str,
        model_ids: list[object],
        *,
        endpoint_identity: str | None = None,
        fetched_at: datetime = NOW,
        response_evidence_hash: str = "d" * 64,
        response_bytes: int = 128,
    ) -> None:
        self.provider = provider
        self.endpoint_identity = endpoint_identity or f"{provider}-catalog"
        self.model_ids = list(model_ids)
        self.fetched_at = fetched_at
        self.response_evidence_hash = response_evidence_hash
        self.response_bytes = response_bytes
        self.failure: Exception | None = None
        self.calls = 0
        self.fetch_arguments: list[tuple[int, int, int]] = []

    def fetch(
        self,
        credential: object | None,
        *,
        timeout_seconds: int,
        max_response_bytes: int,
        retry_budget: int,
    ) -> object:
        del credential
        self.calls += 1
        self.fetch_arguments.append((timeout_seconds, max_response_bytes, retry_budget))
        if self.failure is not None:
            raise self.failure
        return catalog_preflight().CatalogFetch(
            model_ids=tuple(self.model_ids),
            response_evidence_hash=self.response_evidence_hash,
            fetched_at=self.fetched_at,
            response_bytes=self.response_bytes,
        )


class InMemoryCatalogCache:
    def __init__(self, events: list[str] | None = None) -> None:
        self.entries: dict[object, tuple[object, datetime]] = {}
        self.events = events if events is not None else []
        self.get_keys: list[object] = []
        self.put_keys: list[object] = []

    def get(self, key: object, *, now: datetime) -> object | None:
        self.events.append("cache:get")
        self.get_keys.append(key)
        entry = self.entries.get(key)
        if entry is None:
            return None
        fetch, expires_at = entry
        return fetch if now < expires_at else None

    def put(self, key: object, fetch: object, *, expires_at: datetime) -> None:
        self.events.append("cache:put")
        self.put_keys.append(key)
        self.entries[key] = (fetch, expires_at)


class ReturningCatalogCache(InMemoryCatalogCache):
    def __init__(self, fetch: object) -> None:
        super().__init__()
        self.fetch = fetch

    def get(self, key: object, *, now: datetime) -> object | None:
        del now
        self.events.append("cache:get")
        self.get_keys.append(key)
        return self.fetch


class FailingCatalogCache:
    def __init__(self, failure_point: str) -> None:
        self.failure_point = failure_point
        self.get_calls = 0
        self.put_calls = 0

    def get(self, key: object, *, now: datetime) -> object | None:
        del key, now
        self.get_calls += 1
        if self.failure_point == "get":
            raise OpaqueCacheFailure()
        return None

    def put(self, key: object, fetch: object, *, expires_at: datetime) -> None:
        del key, fetch, expires_at
        self.put_calls += 1
        if self.failure_point == "put":
            raise OpaqueCacheFailure()


class MutableClock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


class AdvancingClock:
    def __init__(self, values: list[datetime]) -> None:
        self.values = list(values)
        self.calls: list[datetime] = []

    def __call__(self) -> datetime:
        if not self.values:
            raise AssertionError("Unexpected clock observation")
        value = self.values.pop(0)
        self.calls.append(value)
        return value


def runner_identity(content_hash: str = "a" * 64) -> RunnerIdentity:
    return RunnerIdentity(
        content_hash=content_hash,
        source_sha="b" * 64,
        dependency_lock_hash="c" * 64,
        contract_bundle_hash="d" * 64,
        built_at=NOW,
    )


def preflight_policy(**changes: int) -> CatalogPreflightPolicy:
    values = {
        "catalog_timeout_seconds": 30,
        "max_catalog_response_bytes": 1_024,
        "catalog_retry_budget": 2,
        "catalog_cache_validity_seconds": 300,
    }
    values.update(changes)
    return CatalogPreflightPolicy.model_validate(values)


def all_opencode_roles() -> dict[RoleName, ModelRef]:
    return {role: ModelRef(provider="opencode-go", model_id=role.value) for role in RoleName}


def mixed_provider_roles() -> dict[RoleName, ModelRef]:
    roles = all_opencode_roles()
    roles[RoleName.PROGRAMMER] = ModelRef(provider="ollama-cloud", model_id="programmer")
    return roles


def all_ollama_roles() -> dict[RoleName, ModelRef]:
    return {role: ModelRef(provider="ollama-cloud", model_id=role.value) for role in RoleName}


def profiles_for_roles(
    role_models: Mapping[RoleName, ModelRef],
    *,
    capabilities: frozenset[str] = CAPABILITIES,
    version: str = "2026-09",
) -> ModelCompatibilityRegistry:
    return ModelCompatibilityRegistry(
        ModelCompatibilityProfile(
            provider=ref.provider,
            model_id=ref.model_id,
            protocol="ollama" if ref.provider == "ollama-cloud" else "chat",
            capabilities=capabilities,
            context_limit=128_000,
            version=version,
        )
        for ref in role_models.values()
    )


def catalog_service(
    *,
    clients: Mapping[str, object] | None = None,
    credentials: FakeCredentials | None = None,
    profiles: ModelCompatibilityRegistry | None = None,
    runner: RunnerIdentity | None = None,
    cache: object | None = None,
    now: Callable[[], datetime] = lambda: NOW,
) -> object:
    roles = all_opencode_roles()
    return catalog_preflight().LiveCatalogPreflight(
        clients=clients
        or {"opencode-go": RecordingCatalogClient("opencode-go", [ref.model_id for ref in roles.values()])},
        credentials=credentials or FakeCredentials(),
        profiles=profiles or profiles_for_roles(roles),
        runner_identity=runner or runner_identity(),
        cache=cache or InMemoryCatalogCache(),
        now=now,
    )


def resolve_opencode_roles(service: object, operation_id: str = "operation-a") -> object:
    return service.resolve(all_opencode_roles(), preflight_policy(), operation_id=operation_id)  # type: ignore[union-attr]


def test_catalog_fetch_repr_does_not_expose_untrusted_model_ids() -> None:
    fetch = catalog_preflight().CatalogFetch(
        model_ids=("raw-provider-model",),
        response_evidence_hash="raw-provider-evidence",
        fetched_at=NOW,
        response_bytes=128,
    )

    assert "raw-provider-model" not in repr(fetch)
    assert "raw-provider-evidence" not in repr(fetch)


def test_cache_key_and_observation_canonicalize_hostile_text_subclasses() -> None:
    api = catalog_preflight()
    key = api.CatalogCacheKey(
        operation_id=HostileKeyText("operation-a"),
        provider=HostileText("opencode-go"),
        endpoint_identity=HostileKeyText("catalog-one"),
        credential_scope_hash=HostileKeyText("a" * 64),
        runner_content_hash=HostileKeyText("b" * 64),
        profile_bundle_hash=HostileKeyText("c" * 64),
    )
    expected_key = api.CatalogCacheKey(
        operation_id="operation-a",
        provider="opencode-go",
        endpoint_identity="catalog-one",
        credential_scope_hash="a" * 64,
        runner_content_hash="b" * 64,
        profile_bundle_hash="c" * 64,
    )
    CatalogObservation = catalog_observation_type()
    observation = CatalogObservation(
        provider=HostileText("opencode-go"),
        endpoint_identity=HostileKeyText("catalog-one"),
        credential_scope_hash=HostileKeyText("a" * 64),
        fetched_at=NOW,
        expires_at=NOW + timedelta(seconds=300),
        model_set_hash=HostileKeyText("b" * 64),
        profile_bundle_hash=HostileKeyText("c" * 64),
        response_evidence_hash=HostileKeyText("d" * 64),
    )

    assert all(
        type(value) is str
        for value in (
            key.operation_id,
            key.provider,
            key.endpoint_identity,
            key.credential_scope_hash,
            key.runner_content_hash,
            key.profile_bundle_hash,
            observation.provider,
            observation.endpoint_identity,
            observation.credential_scope_hash,
            observation.model_set_hash,
            observation.profile_bundle_hash,
            observation.response_evidence_hash,
        )
    )
    assert key == expected_key
    assert hash(key) == hash(expected_key)
    assert "hostile-text-marker" not in repr((key, observation))


def test_preflight_canonicalizes_hostile_text_before_cache_and_result_boundaries() -> None:
    client = RecordingCatalogClient(
        HostileText("opencode-go"),
        [HostileText(role.value) for role in RoleName],
        endpoint_identity=HostileText("catalog-one"),
    )
    cache = InMemoryCatalogCache()
    service = catalog_service(
        clients={HostileText("opencode-go"): client},
        credentials=FakeCredentials(scope_hashes={"opencode-go": HostileKeyText("c" * 64)}),
        cache=cache,
    )

    result = resolve_opencode_roles(service, operation_id=HostileKeyText("operation-a"))
    key = cache.get_keys[0]

    assert all(
        type(value) is str
        for value in (
            key.operation_id,
            key.provider,
            key.endpoint_identity,
            key.credential_scope_hash,
            key.runner_content_hash,
            key.profile_bundle_hash,
        )
    )
    assert all(type(value) is str for value in result.catalogs["opencode-go"].model_ids)
    assert type(result.catalog_observations["opencode-go"].endpoint_identity) is str
    assert "hostile-text-marker" not in repr((key, result.catalogs, result.catalog_observations))


def test_preflight_result_canonicalizes_hostile_provider_mapping_keys() -> None:
    api = catalog_preflight()
    base_result = resolve_opencode_roles(catalog_service())

    result = api.CatalogPreflightResult(
        catalogs={HostileText("opencode-go"): base_result.catalogs["opencode-go"]},
        resolved_models=base_result.resolved_models,
        catalog_observations={HostileText("opencode-go"): base_result.catalog_observations["opencode-go"]},
    )

    assert tuple(result.catalogs) == ("opencode-go",)
    assert tuple(result.catalog_observations) == ("opencode-go",)
    assert all(type(provider) is str for provider in (*result.catalogs, *result.catalog_observations))
    assert "hostile-text-marker" not in repr(result)


def test_preflight_result_rejects_canonical_provider_key_collisions() -> None:
    api = catalog_preflight()
    base_result = resolve_opencode_roles(catalog_service())
    collision = HostileCollisionText("opencode-go")
    catalogs = {
        "opencode-go": base_result.catalogs["opencode-go"],
        collision: base_result.catalogs["opencode-go"],
    }
    observations = {
        "opencode-go": base_result.catalog_observations["opencode-go"],
        collision: base_result.catalog_observations["opencode-go"],
    }
    collision.use_standard_hash = True

    with pytest.raises(ValueError, match="^Catalog preflight result catalogs are invalid$"):
        api.CatalogPreflightResult(
            catalogs=catalogs,
            resolved_models=base_result.resolved_models,
            catalog_observations=observations,
        )


def test_preflight_fetches_each_selected_provider_once_and_resolves_every_role() -> None:
    events: list[str] = []
    client = RecordingCatalogClient("opencode-go", [role.value for role in RoleName])
    unselected = RecordingCatalogClient("ollama-cloud", ["programmer"])
    credentials = FakeCredentials(events=events)
    cache = InMemoryCatalogCache(events)
    service = catalog_service(
        clients={"opencode-go": client, "ollama-cloud": unselected},
        credentials=credentials,
        cache=cache,
    )

    result = resolve_opencode_roles(service)

    assert client.calls == 1
    assert unselected.calls == 0
    assert client.fetch_arguments == [(30, 1_024, 2)]
    assert set(result.catalogs) == {"opencode-go"}
    assert set(result.resolved_models) == set(RoleName)
    assert result.catalog_observations["opencode-go"].model_set_hash == hash_json(sorted(client.model_ids))
    assert credentials.optional_calls == ["opencode-go"]
    assert credentials.require_calls == []
    assert events.index("credential:scope:opencode-go") < events.index("cache:get")
    assert "OpaqueCredential" not in repr(result)


def test_preflight_fetches_each_distinct_selected_provider_once() -> None:
    roles = mixed_provider_roles()
    opencode = RecordingCatalogClient("opencode-go", [role.value for role in RoleName if role is not RoleName.PROGRAMMER])
    ollama = RecordingCatalogClient("ollama-cloud", ["programmer"])
    service = catalog_preflight().LiveCatalogPreflight(
        clients={"opencode-go": opencode, "ollama-cloud": ollama},
        credentials=FakeCredentials(),
        profiles=profiles_for_roles(roles),
        runner_identity=runner_identity(),
        cache=InMemoryCatalogCache(),
        now=lambda: NOW,
    )

    result = service.resolve(roles, preflight_policy(), operation_id="operation-a")

    assert opencode.calls == 1
    assert ollama.calls == 1
    assert set(result.catalogs) == {"opencode-go", "ollama-cloud"}
    assert set(result.resolved_models) == set(RoleName)


def test_preflight_requires_exact_role_models_and_validated_model_refs() -> None:
    client = RecordingCatalogClient("opencode-go", [role.value for role in RoleName])
    service = catalog_service(clients={"opencode-go": client})
    missing_role = all_opencode_roles()
    del missing_role[RoleName.REVIEWER]
    unsafe_key = all_opencode_roles()
    analyst = unsafe_key.pop(RoleName.ANALYST)
    unsafe_key["analyst"] = analyst
    unsafe_ref = {role: object() for role in RoleName}

    for role_models in (missing_role, unsafe_key, unsafe_ref):
        with pytest.raises(catalog_preflight().CatalogPreflightError, match="^catalog preflight failed$"):
            service.resolve(role_models, preflight_policy(), operation_id="operation-a")

    assert client.calls == 0


def test_preflight_requires_opaque_ollama_credentials_and_accepts_optional_opencode_credentials() -> None:
    roles = mixed_provider_roles()
    opencode = RecordingCatalogClient("opencode-go", [role.value for role in RoleName if role is not RoleName.PROGRAMMER])
    ollama = RecordingCatalogClient("ollama-cloud", ["programmer"])
    credentials = FakeCredentials(ollama=None)
    service = catalog_preflight().LiveCatalogPreflight(
        clients={"opencode-go": opencode, "ollama-cloud": ollama},
        credentials=credentials,
        profiles=profiles_for_roles(roles),
        runner_identity=runner_identity(),
        cache=InMemoryCatalogCache(),
        now=lambda: NOW,
    )

    with pytest.raises(catalog_preflight().CatalogPreflightError, match="^catalog preflight failed$"):
        service.resolve(roles, preflight_policy(), operation_id="operation-a")

    assert credentials.require_calls == ["ollama-cloud"]
    assert ollama.calls == 0

    client = RecordingCatalogClient("opencode-go", [role.value for role in RoleName])
    optional_service = catalog_service(
        clients={"opencode-go": client},
        credentials=FakeCredentials(opencode=None),
    )
    resolve_opencode_roles(optional_service)
    assert client.calls == 1


@pytest.mark.parametrize(
    "clients",
    (
        {"unknown": RecordingCatalogClient("unknown", ["analyst"], endpoint_identity="unknown-catalog")},
        {"opencode-go": RecordingCatalogClient("ollama-cloud", ["analyst"])},
        {"opencode-go": RecordingCatalogClient("opencode-go", ["analyst"], endpoint_identity="catalog/one")},
    ),
)
def test_preflight_rejects_unknown_inconsistent_or_unsafe_catalog_clients(clients: Mapping[str, object]) -> None:
    service = catalog_service(clients=clients)

    with pytest.raises(catalog_preflight().CatalogPreflightError, match="^catalog preflight failed$"):
        resolve_opencode_roles(service)


@pytest.mark.parametrize("scope_hash", (None, "", "not-a-sha256"))
def test_preflight_rejects_missing_or_invalid_credential_scope_hash(scope_hash: object) -> None:
    client = RecordingCatalogClient("opencode-go", [role.value for role in RoleName])
    service = catalog_service(
        clients={"opencode-go": client},
        credentials=FakeCredentials(scope_hashes={"opencode-go": scope_hash}),
    )

    with pytest.raises(catalog_preflight().CatalogPreflightError, match="^catalog preflight failed$"):
        resolve_opencode_roles(service)

    assert client.calls == 0


@pytest.mark.parametrize(
    "operation_id",
    (
        "sk-" + "live-abcdefgh",
        "api_key-opaque-marker",
        "access_token-opaque-marker",
        "credential-opaque-marker",
        "access_key-opaque-marker",
        "private_key-opaque-marker",
        "authorization-opaque-marker",
    ),
)
def test_preflight_rejects_an_unsafe_operation_id_before_cache_lookup_or_fetch(operation_id: str) -> None:
    cache = InMemoryCatalogCache()
    client = RecordingCatalogClient("opencode-go", [role.value for role in RoleName])
    service = catalog_service(cache=cache, clients={"opencode-go": client})

    with pytest.raises(catalog_preflight().CatalogPreflightError, match="^catalog preflight failed$"):
        resolve_opencode_roles(service, operation_id=operation_id)

    assert cache.get_keys == []
    assert client.calls == 0


@pytest.mark.parametrize(
    "endpoint_identity",
    (
        "sk-" + "live-abcdefgh",
        "api_key-opaque-marker",
        "access_token-opaque-marker",
        "credential-opaque-marker",
        "access_key-opaque-marker",
        "private_key-opaque-marker",
        "authorization-opaque-marker",
    ),
)
def test_preflight_rejects_an_unsafe_endpoint_identity_before_cache_lookup_or_fetch(endpoint_identity: str) -> None:
    cache = InMemoryCatalogCache()
    client = RecordingCatalogClient(
        "opencode-go",
        [role.value for role in RoleName],
        endpoint_identity=endpoint_identity,
    )
    service = catalog_service(cache=cache, clients={"opencode-go": client})

    with pytest.raises(catalog_preflight().CatalogPreflightError, match="^catalog preflight failed$"):
        resolve_opencode_roles(service)

    assert cache.get_keys == []
    assert client.calls == 0


def test_same_operation_reuses_cache_only_with_the_full_safe_cache_key() -> None:
    cache = InMemoryCatalogCache()
    client = RecordingCatalogClient("opencode-go", [role.value for role in RoleName], endpoint_identity="catalog-one")
    credentials = FakeCredentials(scope_hashes={"opencode-go": "e" * 64})
    profiles = profiles_for_roles(all_opencode_roles())
    runner = runner_identity()
    service = catalog_service(
        clients={"opencode-go": client},
        credentials=credentials,
        profiles=profiles,
        runner=runner,
        cache=cache,
    )

    resolve_opencode_roles(service)
    resolve_opencode_roles(service)

    expected_key = catalog_preflight().CatalogCacheKey(
        operation_id="operation-a",
        provider="opencode-go",
        endpoint_identity="catalog-one",
        credential_scope_hash="e" * 64,
        runner_content_hash=runner.content_hash,
        profile_bundle_hash=profiles.profile_bundle_hash,
    )
    assert client.calls == 1
    assert cache.put_keys == [expected_key]
    assert cache.get_keys == [expected_key, expected_key]


def test_each_cache_key_field_isolates_entries_in_a_shared_cache() -> None:
    api = catalog_preflight()
    cache = InMemoryCatalogCache()
    roles = all_opencode_roles()
    ollama_roles = all_ollama_roles()
    profiles = ModelCompatibilityRegistry(
        ModelCompatibilityProfile(
            provider=ref.provider,
            model_id=ref.model_id,
            protocol="ollama" if ref.provider == "ollama-cloud" else "chat",
            capabilities=CAPABILITIES,
            context_limit=128_000,
            version="2026-09",
        )
        for ref in (*roles.values(), *ollama_roles.values())
    )
    base_client = RecordingCatalogClient("opencode-go", [ref.model_id for ref in roles.values()], endpoint_identity="catalog-one")
    base_service = api.LiveCatalogPreflight(
        clients={"opencode-go": base_client},
        credentials=FakeCredentials(scope_hashes={"opencode-go": "c" * 64}),
        profiles=profiles,
        runner_identity=runner_identity(),
        cache=cache,
        now=lambda: NOW,
    )
    base_service.resolve(roles, preflight_policy(), operation_id="operation-a")

    def assert_cache_miss(
        *,
        operation_id: str,
        role_models: Mapping[RoleName, ModelRef],
        provider: str,
        endpoint_identity: str,
        credential_scope_hash: str,
        runner_content_hash: str,
        registry: ModelCompatibilityRegistry,
    ) -> RecordingCatalogClient:
        client = RecordingCatalogClient(
            provider,
            [ref.model_id for ref in role_models.values()],
            endpoint_identity=endpoint_identity,
        )
        service = api.LiveCatalogPreflight(
            clients={provider: client},
            credentials=FakeCredentials(scope_hashes={provider: credential_scope_hash}),
            profiles=registry,
            runner_identity=runner_identity(runner_content_hash),
            cache=cache,
            now=lambda: NOW,
        )

        result = service.resolve(role_models, preflight_policy(), operation_id=operation_id)

        assert client.calls == 1
        assert set(result.catalogs) == {provider}
        return client

    assert base_client.calls == 1
    assert_cache_miss(
        operation_id="operation-b",
        role_models=roles,
        provider="opencode-go",
        endpoint_identity="catalog-one",
        credential_scope_hash="c" * 64,
        runner_content_hash="a" * 64,
        registry=profiles,
    )
    assert_cache_miss(
        operation_id="operation-a",
        role_models=roles,
        provider="opencode-go",
        endpoint_identity="catalog-two",
        credential_scope_hash="c" * 64,
        runner_content_hash="a" * 64,
        registry=profiles,
    )
    assert_cache_miss(
        operation_id="operation-a",
        role_models=roles,
        provider="opencode-go",
        endpoint_identity="catalog-one",
        credential_scope_hash="e" * 64,
        runner_content_hash="a" * 64,
        registry=profiles,
    )
    assert_cache_miss(
        operation_id="operation-a",
        role_models=roles,
        provider="opencode-go",
        endpoint_identity="catalog-one",
        credential_scope_hash="c" * 64,
        runner_content_hash="f" * 64,
        registry=profiles,
    )
    assert_cache_miss(
        operation_id="operation-a",
        role_models=roles,
        provider="opencode-go",
        endpoint_identity="catalog-one",
        credential_scope_hash="c" * 64,
        runner_content_hash="a" * 64,
        registry=profiles_for_roles(roles, version="2026-10"),
    )
    ollama_client = assert_cache_miss(
        operation_id="operation-a",
        role_models=ollama_roles,
        provider="ollama-cloud",
        endpoint_identity="catalog-one",
        credential_scope_hash="c" * 64,
        runner_content_hash="a" * 64,
        registry=profiles,
    )
    base_key = cache.get_keys[0]
    ollama_key = cache.get_keys[-1]
    assert ollama_client.calls == 1
    assert ollama_key.provider == "ollama-cloud"
    assert ollama_key.operation_id == base_key.operation_id
    assert ollama_key.endpoint_identity == base_key.endpoint_identity
    assert ollama_key.credential_scope_hash == base_key.credential_scope_hash
    assert ollama_key.runner_content_hash == base_key.runner_content_hash
    assert ollama_key.profile_bundle_hash == base_key.profile_bundle_hash


def test_cache_returned_expired_fetch_triggers_a_live_fetch() -> None:
    api = catalog_preflight()
    cache = ReturningCatalogCache(
        api.CatalogFetch(
            model_ids=tuple(role.value for role in RoleName),
            response_evidence_hash="d" * 64,
            fetched_at=NOW - timedelta(seconds=300),
            response_bytes=128,
        )
    )
    client = RecordingCatalogClient("opencode-go", [role.value for role in RoleName])
    service = catalog_service(cache=cache, clients={"opencode-go": client})

    result = resolve_opencode_roles(service)

    assert client.calls == 1
    assert len(cache.get_keys) == 1
    assert len(cache.put_keys) == 1
    assert set(result.catalogs) == {"opencode-go"}


@pytest.mark.parametrize(("failure_point", "expected_client_calls"), (("get", 0), ("put", 1)))
def test_preflight_hides_opaque_cache_failures(failure_point: str, expected_client_calls: int) -> None:
    cache = FailingCatalogCache(failure_point)
    client = RecordingCatalogClient("opencode-go", [role.value for role in RoleName])
    service = catalog_service(cache=cache, clients={"opencode-go": client})

    with pytest.raises(catalog_preflight().CatalogPreflightError, match="^catalog preflight failed$") as error:
        resolve_opencode_roles(service)

    assert str(error.value) == "catalog preflight failed"
    assert client.calls == expected_client_calls
    assert cache.get_calls == 1
    assert cache.put_calls == (1 if failure_point == "put" else 0)


def test_new_operation_does_not_use_a_stale_catalog_after_fetch_failure() -> None:
    cache = InMemoryCatalogCache()
    client = RecordingCatalogClient("opencode-go", [role.value for role in RoleName])
    service = catalog_service(cache=cache, clients={"opencode-go": client})
    resolve_opencode_roles(service, operation_id="operation-a")
    client.failure = OpaqueProviderFailure()

    with pytest.raises(catalog_preflight().CatalogPreflightError, match="^catalog preflight failed$") as error:
        resolve_opencode_roles(service, operation_id="operation-b")

    assert str(error.value) == "catalog preflight failed"
    assert client.calls == 2


def test_expired_cache_fetches_live_and_never_returns_stale_data_after_failure() -> None:
    clock = MutableClock()
    cache = InMemoryCatalogCache()
    client = RecordingCatalogClient("opencode-go", [role.value for role in RoleName])
    service = catalog_service(cache=cache, clients={"opencode-go": client}, now=clock)
    resolve_opencode_roles(service)
    clock.value = NOW + timedelta(seconds=301)
    client.failure = OpaqueProviderFailure()

    with pytest.raises(catalog_preflight().CatalogPreflightError, match="^catalog preflight failed$"):
        resolve_opencode_roles(service)

    assert client.calls == 2


def test_preflight_accepts_a_live_fetch_observed_after_cache_lookup_and_before_post_fetch_observation() -> None:
    cache_lookup_time = NOW
    fetched_at = NOW + timedelta(seconds=1)
    post_fetch_time = NOW + timedelta(seconds=2)
    clock = AdvancingClock([cache_lookup_time, post_fetch_time])
    client = RecordingCatalogClient(
        "opencode-go",
        [role.value for role in RoleName],
        fetched_at=fetched_at,
    )
    service = catalog_service(clients={"opencode-go": client}, now=clock)

    result = resolve_opencode_roles(service)

    assert result.catalog_observations["opencode-go"].fetched_at == fetched_at
    assert client.calls == 1
    assert clock.calls == [cache_lookup_time, post_fetch_time]


@pytest.mark.parametrize(
    "change",
    (
        lambda client: setattr(client, "model_ids", ["unsafe/model"]),
        lambda client: setattr(client, "response_bytes", -1),
        lambda client: setattr(client, "response_bytes", 1_025),
        lambda client: setattr(client, "response_evidence_hash", "invalid"),
        lambda client: setattr(client, "fetched_at", datetime(2026, 9, 7, 12, 0)),
        lambda client: setattr(client, "fetched_at", NOW + timedelta(seconds=1)),
        lambda client: setattr(client, "fetched_at", NOW - timedelta(seconds=300)),
    ),
)
def test_preflight_rejects_unsafe_or_expired_catalog_fetches(change: Callable[[RecordingCatalogClient], None]) -> None:
    client = RecordingCatalogClient("opencode-go", [role.value for role in RoleName])
    change(client)
    service = catalog_service(clients={"opencode-go": client})

    with pytest.raises(catalog_preflight().CatalogPreflightError, match="^catalog preflight failed$"):
        resolve_opencode_roles(service)


def test_preflight_rejects_missing_profiles_and_required_capability_mismatches() -> None:
    roles = all_opencode_roles()
    client = RecordingCatalogClient("opencode-go", [role.value for role in RoleName])
    missing_profile_service = catalog_service(
        clients={"opencode-go": client},
        profiles=ModelCompatibilityRegistry([]),
    )

    with pytest.raises(catalog_preflight().CatalogPreflightError, match="^catalog preflight failed$"):
        resolve_opencode_roles(missing_profile_service)

    incomplete_profiles = profiles_for_roles(roles, capabilities=frozenset({"structured_output", "text"}))
    mismatch_service = catalog_service(
        clients={"opencode-go": RecordingCatalogClient("opencode-go", [role.value for role in RoleName])},
        profiles=incomplete_profiles,
    )

    with pytest.raises(catalog_preflight().CatalogPreflightError, match="^catalog preflight failed$"):
        resolve_opencode_roles(mismatch_service)


def test_catalog_observation_is_frozen_canonical_and_secret_free() -> None:
    CatalogObservation = catalog_observation_type()
    observation = CatalogObservation(
        provider="opencode-go",
        endpoint_identity="catalog-one",
        credential_scope_hash="a" * 64,
        fetched_at=NOW,
        expires_at=NOW + timedelta(seconds=300),
        model_set_hash="b" * 64,
        profile_bundle_hash="c" * 64,
        response_evidence_hash="d" * 64,
    )

    assert observation.content_hash == hash_json(observation.model_dump(mode="json", round_trip=True))
    assert observation.model_dump() == {
        "provider": "opencode-go",
        "endpoint_identity": "catalog-one",
        "credential_scope_hash": "a" * 64,
        "fetched_at": NOW,
        "expires_at": NOW + timedelta(seconds=300),
        "model_set_hash": "b" * 64,
        "profile_bundle_hash": "c" * 64,
        "response_evidence_hash": "d" * 64,
    }
    with pytest.raises(ValidationError):
        observation.provider = "ollama-cloud"
    assert "OpaqueCredential" not in repr(observation)


@pytest.mark.parametrize(
    "changes",
    (
        {"provider": "unknown"},
        {"endpoint_identity": "https://catalog.invalid"},
        {"endpoint_identity": "api_key-opaque-marker"},
        {"endpoint_identity": "access_key-opaque-marker"},
        {"endpoint_identity": "private_key-opaque-marker"},
        {"endpoint_identity": "authorization-opaque-marker"},
        {"credential_scope_hash": "invalid"},
        {"fetched_at": datetime(2026, 9, 7, 12, 0)},
        {"expires_at": NOW},
    ),
)
def test_catalog_observation_rejects_invalid_provider_hash_endpoint_or_timestamp(changes: Mapping[str, object]) -> None:
    CatalogObservation = catalog_observation_type()
    values: dict[str, object] = {
        "provider": "opencode-go",
        "endpoint_identity": "catalog-one",
        "credential_scope_hash": "a" * 64,
        "fetched_at": NOW,
        "expires_at": NOW + timedelta(seconds=300),
        "model_set_hash": "b" * 64,
        "profile_bundle_hash": "c" * 64,
        "response_evidence_hash": "d" * 64,
    }
    values.update(changes)

    with pytest.raises(ValidationError):
        CatalogObservation(**values)


def test_preflight_result_mapping_is_factory_boundary_without_additional_catalog_fetch() -> None:
    client = RecordingCatalogClient("opencode-go", [role.value for role in RoleName])
    service = catalog_service(clients={"opencode-go": client})
    result = resolve_opencode_roles(service)
    config = RoleModelConfig(models=all_opencode_roles())
    calls_before_factory = client.calls
    factory = ModelFactory(
        config=config,
        compatibility_registry=profiles_for_roles(config.models),
        live_catalogs=result.catalogs,
        transport=ModelTransport(opencode_key="", ollama_key="", retry_policy=RetryPolicy()),
    )

    with pytest.raises(TypeError):
        result.catalogs["ollama-cloud"] = ModelCatalog(["programmer"])
    with pytest.raises(TypeError):
        result.resolved_models[RoleName.ANALYST] = factory.for_role(RoleName.ANALYST, "run-1").metadata
    with pytest.raises(TypeError):
        result.catalog_observations["ollama-cloud"] = result.catalog_observations["opencode-go"]
    assert factory.for_role(RoleName.REVIEWER, "run-1").model == "reviewer"
    assert client.calls == calls_before_factory
