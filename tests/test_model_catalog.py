from __future__ import annotations

import pytest

from auto_code.hashing import hash_json
from auto_code.model_catalog import ModelCatalog, ModelRef
from auto_code.model_compatibility import ModelCompatibilityProfile, ModelCompatibilityRegistry


class HostileText(str):
    def __repr__(self) -> str:
        return "hostile-text-marker"


@pytest.mark.parametrize(
    "model_ids",
    (
        "model",
        b"model",
        [1],
        [" "],
        ["nested/model"],
        ["model?query=value"],
        ["model#fragment"],
        ["user@model"],
        ["model:credential"],
        ["model-access_key-opaque-marker"],
        ["model-private_key-opaque-marker"],
        ["model-authorization-opaque-marker"],
        ["model\x00control"],
        ["model-sk-live-abcdefgh"],
        ["model:sk-live-abcdefgh"],
        ["https://models.example/model"],
    ),
)
def test_catalog_rejects_unsafe_model_ids(model_ids: object) -> None:
    with pytest.raises(ValueError):
        ModelCatalog(model_ids)  # type: ignore[arg-type]


def test_catalog_accepts_an_ordinary_safe_model_identifier() -> None:
    assert ModelCatalog(["model.2_beta-1"]).is_available("model.2_beta-1")


def test_ollama_tagged_model_refs_catalogs_and_profiles_resolve() -> None:
    ref = ModelRef.parse("ollama-cloud/qwen3:8b")
    catalog = ModelCatalog(["qwen3:8b"])
    registry = ModelCompatibilityRegistry(
        [
            ModelCompatibilityProfile(
                provider="ollama-cloud",
                model_id="qwen3:8b",
                protocol="ollama",
                capabilities=frozenset({"tool_calling"}),
            )
        ]
    )

    metadata = registry.resolve(ref, catalog, frozenset({"tool_calling"}))

    assert metadata.model_id == "qwen3:8b"
    assert metadata.protocol == "ollama"


@pytest.mark.parametrize(
    "capabilities",
    (
        "tool_calling",
        b"tool_calling",
        [""],
        [1],
        ["tool/calling"],
        ["tool:calling"],
        ["tool?calling"],
        ["capability-sk-live-abcdefgh"],
    ),
)
def test_profile_rejects_invalid_capability_containers_and_members(capabilities: object) -> None:
    with pytest.raises(ValueError):
        ModelCompatibilityProfile(
            provider="opencode-go",
            model_id="a",
            protocol="chat",
            capabilities=capabilities,  # type: ignore[arg-type]
        )


def test_registry_rejects_a_string_required_capability_before_character_expansion() -> None:
    registry = ModelCompatibilityRegistry(
        [
            ModelCompatibilityProfile(
                provider="opencode-go",
                model_id="a",
                protocol="chat",
                capabilities=frozenset({"t"}),
            )
        ]
    )

    with pytest.raises(ValueError):
        registry.resolve(ModelRef.parse("opencode-go/a"), ModelCatalog(["a"]), "t")  # type: ignore[arg-type]


def test_registry_rejects_a_bytes_required_capability_container() -> None:
    registry = ModelCompatibilityRegistry(
        [
            ModelCompatibilityProfile(
                provider="opencode-go",
                model_id="a",
                protocol="chat",
                capabilities=frozenset(),
            )
        ]
    )

    with pytest.raises(ValueError):
        registry.resolve(ModelRef.parse("opencode-go/a"), ModelCatalog(["a"]), b"")  # type: ignore[arg-type]


def test_catalog_rejects_missing_tool_capability() -> None:
    catalog = ModelCatalog(["a"])
    registry = ModelCompatibilityRegistry(
        [
            ModelCompatibilityProfile(
                provider="opencode-go",
                model_id="a",
                protocol="chat",
                capabilities=frozenset(),
            )
        ]
    )

    with pytest.raises(ValueError, match="tool_calling"):
        registry.resolve(ModelRef.parse("opencode-go/a"), catalog, frozenset({"tool_calling"}))


def test_registry_returns_a_live_model_with_its_versioned_compatibility_profile() -> None:
    catalog = ModelCatalog(["a"])
    registry = ModelCompatibilityRegistry(
        [
            ModelCompatibilityProfile(
                provider="opencode-go",
                model_id="a",
                protocol="responses",
                context_limit=128_000,
                capabilities=frozenset({"structured_output", "tool_calling"}),
                version="2026-09",
            )
        ]
    )

    metadata = registry.resolve(
        ModelRef.parse("opencode-go/a"),
        catalog,
        frozenset({"structured_output", "tool_calling"}),
    )

    assert metadata.provider == "opencode-go"
    assert metadata.model_id == "a"
    assert metadata.protocol == "responses"
    assert metadata.context_limit == 128_000
    assert metadata.capabilities == frozenset({"structured_output", "tool_calling"})
    assert metadata.compatibility_version == "2026-09"


def test_registry_rejects_a_profiled_model_missing_from_the_live_catalog() -> None:
    registry = ModelCompatibilityRegistry(
        [
            ModelCompatibilityProfile(
                provider="opencode-go",
                model_id="a",
                protocol="chat",
                capabilities=frozenset(),
            )
        ]
    )

    with pytest.raises(ValueError, match="not available"):
        registry.resolve(ModelRef.parse("opencode-go/a"), ModelCatalog([]), frozenset())


def test_catalog_availability_cannot_supply_a_missing_compatibility_profile() -> None:
    registry = ModelCompatibilityRegistry([])

    with pytest.raises(ValueError, match="compatibility profile"):
        registry.resolve(ModelRef.parse("opencode-go/a"), ModelCatalog(["a"]), frozenset())


def test_profile_rejects_a_provider_protocol_pair_that_cannot_be_requested() -> None:
    with pytest.raises(ValueError, match="protocol"):
        ModelCompatibilityProfile(
            provider="ollama-cloud",
            model_id="qwen3:8b",
            protocol="chat",
            capabilities=frozenset(),
        )


def test_profile_bundle_hash_is_order_independent_and_changes_for_profile_content() -> None:
    analyst = ModelCompatibilityProfile(
        provider="opencode-go",
        model_id="analyst",
        protocol="responses",
        capabilities=frozenset({"text", "structured_output"}),
        context_limit=128_000,
        version="2026-09",
    )
    programmer = ModelCompatibilityProfile(
        provider="ollama-cloud",
        model_id="programmer:8b",
        protocol="ollama",
        capabilities=frozenset({"tool_calling", "text", "structured_output"}),
        context_limit=64_000,
        version="2026-09",
    )

    first = ModelCompatibilityRegistry([programmer, analyst])
    second = ModelCompatibilityRegistry([analyst, programmer])
    changed = ModelCompatibilityRegistry(
        [
            analyst,
            ModelCompatibilityProfile(
                provider="ollama-cloud",
                model_id="programmer:8b",
                protocol="ollama",
                capabilities=frozenset({"tool_calling", "text", "structured_output"}),
                context_limit=64_000,
                version="2026-10",
            ),
        ]
    )

    expected = hash_json(
        {
            "schema_version": "v1",
            "profiles": [
                {
                    "provider": "ollama-cloud",
                    "model_id": "programmer:8b",
                    "protocol": "ollama",
                    "capabilities": ["structured_output", "text", "tool_calling"],
                    "context_limit": 64_000,
                    "version": "2026-09",
                },
                {
                    "provider": "opencode-go",
                    "model_id": "analyst",
                    "protocol": "responses",
                    "capabilities": ["structured_output", "text"],
                    "context_limit": 128_000,
                    "version": "2026-09",
                },
            ],
        }
    )

    assert first.profile_bundle_hash == expected
    assert second.profile_bundle_hash == expected
    assert changed.profile_bundle_hash != expected


def test_model_catalog_profile_and_metadata_canonicalize_hostile_text_subclasses() -> None:
    provider = HostileText("opencode-go")
    model_id = HostileText("model")
    protocol = HostileText("chat")
    capability = HostileText("tool_calling")
    version = HostileText("2026-09")
    ref = ModelRef(provider=provider, model_id=model_id)
    parsed = ModelRef.parse(HostileText("opencode-go/model"))
    catalog = ModelCatalog([model_id])
    profile = ModelCompatibilityProfile(
        provider=provider,
        model_id=model_id,
        protocol=protocol,
        capabilities=frozenset({capability}),
        version=version,
    )
    metadata = ModelCompatibilityRegistry([profile]).resolve(ref, catalog, frozenset({capability}))

    assert all(
        type(value) is str
        for value in (
            ref.provider,
            ref.model_id,
            parsed.provider,
            parsed.model_id,
            profile.provider,
            profile.model_id,
            profile.protocol,
            profile.version,
            metadata.provider,
            metadata.model_id,
            metadata.protocol,
            metadata.compatibility_version,
        )
    )
    assert all(type(value) is str for value in catalog.model_ids)
    assert all(type(value) is str for value in profile.capabilities)
    assert all(type(value) is str for value in metadata.capabilities)
    assert "hostile-text-marker" not in repr((ref, catalog, profile, metadata))
