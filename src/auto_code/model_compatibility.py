from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType

from .hashing import hash_json
from .model_catalog import (
    ModelCatalog,
    ModelMetadata,
    ModelRef,
    canonical_text,
    is_supported_provider_protocol,
    normalize_capabilities,
)


@dataclass(frozen=True)
class ModelCompatibilityProfile:
    provider: str
    model_id: str
    protocol: str
    capabilities: frozenset[str]
    context_limit: int | None = None
    version: str = "1"

    def __post_init__(self) -> None:
        ref = ModelRef(provider=self.provider, model_id=self.model_id)
        protocol = canonical_text(self.protocol, "Model protocol")
        if not protocol or protocol != protocol.strip():
            raise ValueError("Model protocol must be non-empty")
        if not is_supported_provider_protocol(ref.provider, protocol):
            raise ValueError("Model provider and protocol are incompatible")
        if self.context_limit is not None and self.context_limit <= 0:
            raise ValueError("Model context limit must be positive")
        version = canonical_text(self.version, "Compatibility version")
        if not version or version != version.strip():
            raise ValueError("Compatibility version must be non-empty")
        object.__setattr__(self, "provider", ref.provider)
        object.__setattr__(self, "model_id", ref.model_id)
        object.__setattr__(self, "protocol", protocol)
        object.__setattr__(self, "version", version)
        object.__setattr__(self, "capabilities", normalize_capabilities(self.capabilities))


class ModelCompatibilityRegistry:
    def __init__(self, profiles: Iterable[ModelCompatibilityProfile]) -> None:
        resolved: dict[tuple[str, str], ModelCompatibilityProfile] = {}
        for profile in profiles:
            key = (profile.provider, profile.model_id)
            if key in resolved:
                raise ValueError(f"Duplicate compatibility profile for {profile.provider}/{profile.model_id}")
            resolved[key] = profile
        self._profiles: Mapping[tuple[str, str], ModelCompatibilityProfile] = MappingProxyType(resolved)

    @property
    def profile_bundle_hash(self) -> str:
        profiles = [
            {
                "provider": profile.provider,
                "model_id": profile.model_id,
                "protocol": profile.protocol,
                "capabilities": sorted(profile.capabilities),
                "context_limit": profile.context_limit,
                "version": profile.version,
            }
            for _, profile in sorted(self._profiles.items())
        ]
        return hash_json({"schema_version": "v1", "profiles": profiles})

    def resolve(
        self,
        ref: ModelRef,
        live_catalog: ModelCatalog,
        capabilities: Iterable[str],
    ) -> ModelMetadata:
        if not live_catalog.is_available(ref.model_id):
            raise ValueError(f"Model {ref.provider}/{ref.model_id} is not available in the live catalog")
        profile = self._profiles.get((ref.provider, ref.model_id))
        if profile is None:
            raise ValueError(f"No compatibility profile for {ref.provider}/{ref.model_id}")
        missing = normalize_capabilities(capabilities) - profile.capabilities
        if missing:
            raise ValueError(f"Model is missing required capabilities: {', '.join(sorted(missing))}")
        return ModelMetadata(
            provider=profile.provider,
            model_id=profile.model_id,
            protocol=profile.protocol,
            context_limit=profile.context_limit,
            capabilities=profile.capabilities,
            compatibility_version=profile.version,
        )
