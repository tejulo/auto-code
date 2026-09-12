from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
import re


SUPPORTED_PROVIDERS = frozenset({"opencode-go", "ollama-cloud"})
_SAFE_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_SAFE_MODEL_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*(?::[A-Za-z0-9][A-Za-z0-9._-]*)?")
_SECRET_LIKE_VALUE = re.compile(
    r"(?:sk-[A-Za-z0-9_-]{8,}|eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+|(?:^|[:._-])(?:api[_-]?key|access[_-]?key|private[_-]?key|token|password|secret|credential|authorization)(?:$|[:._-]))",
    re.IGNORECASE,
)
_PROVIDER_PROTOCOLS = {
    "opencode-go": frozenset({"chat", "responses", "messages"}),
    "ollama-cloud": frozenset({"ollama"}),
}


def canonical_text(value: object, name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name} must be text")
    return str.__str__(value)


def is_secret_like_identifier(value: str) -> bool:
    return _SECRET_LIKE_VALUE.search(value) is not None


def _safe_identifier(value: object, name: str) -> str:
    candidate = canonical_text(value, name)
    if _SAFE_IDENTIFIER.fullmatch(candidate) is None or is_secret_like_identifier(candidate):
        raise ValueError(f"{name} must be a non-empty safe identifier")
    return candidate


def _safe_model_identifier(value: object, name: str) -> str:
    candidate = canonical_text(value, name)
    if _SAFE_MODEL_ID.fullmatch(candidate) is None or is_secret_like_identifier(candidate):
        raise ValueError(f"{name} must be a non-empty safe identifier")
    return candidate


def is_supported_provider_protocol(provider: str, protocol: str) -> bool:
    return protocol in _PROVIDER_PROTOCOLS.get(provider, frozenset())


def normalize_capabilities(values: object) -> frozenset[str]:
    if isinstance(values, (str, bytes)) or not isinstance(values, Iterable):
        raise ValueError("Capabilities must be a non-string iterable")
    return frozenset(_safe_identifier(value, "Capability") for value in values)


@dataclass(frozen=True)
class ModelRef:
    provider: str
    model_id: str

    def __post_init__(self) -> None:
        provider = canonical_text(self.provider, "Model provider")
        if provider not in SUPPORTED_PROVIDERS:
            raise ValueError("Unsupported model provider")
        model_id = _safe_model_identifier(self.model_id, "Model ID")
        object.__setattr__(self, "provider", provider)
        object.__setattr__(self, "model_id", model_id)

    @classmethod
    def parse(cls, value: str) -> ModelRef:
        if not isinstance(value, str):
            raise ValueError("Model reference must use provider/model with exactly one '/'")
        candidate = canonical_text(value, "Model reference")
        if candidate.count("/") != 1:
            raise ValueError("Model reference must use provider/model with exactly one '/'")
        provider, model_id = candidate.split("/")
        if not provider or not model_id or provider != provider.strip():
            raise ValueError("Model reference must use provider/model with exactly one '/'")
        return cls(provider=provider, model_id=model_id)


@dataclass(frozen=True, init=False)
class ModelCatalog:
    model_ids: frozenset[str]

    def __init__(self, model_ids: Iterable[str]) -> None:
        if isinstance(model_ids, (str, bytes)) or not isinstance(model_ids, Iterable):
            raise ValueError("Catalog model IDs must be a non-string iterable")
        available = frozenset(_safe_model_identifier(model_id, "Catalog model ID") for model_id in model_ids)
        object.__setattr__(self, "model_ids", available)

    def is_available(self, model_id: str) -> bool:
        return model_id in self.model_ids


@dataclass(frozen=True)
class ModelMetadata:
    provider: str
    model_id: str
    protocol: str
    capabilities: frozenset[str]
    context_limit: int | None = None
    compatibility_version: str = "1"

    def __post_init__(self) -> None:
        ref = ModelRef(provider=self.provider, model_id=self.model_id)
        protocol = canonical_text(self.protocol, "Model protocol")
        if not protocol or protocol != protocol.strip():
            raise ValueError("Model protocol must be non-empty")
        if self.context_limit is not None and self.context_limit <= 0:
            raise ValueError("Model context limit must be positive")
        compatibility_version = canonical_text(self.compatibility_version, "Compatibility version")
        if not compatibility_version or compatibility_version != compatibility_version.strip():
            raise ValueError("Compatibility version must be non-empty")
        object.__setattr__(self, "provider", ref.provider)
        object.__setattr__(self, "model_id", ref.model_id)
        object.__setattr__(self, "protocol", protocol)
        object.__setattr__(self, "compatibility_version", compatibility_version)
        object.__setattr__(self, "capabilities", normalize_capabilities(self.capabilities))
