from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from .model_catalog import ModelRef


class RoleName(StrEnum):
    ANALYST = "analyst"
    ARCHITECT = "architect"
    PROGRAMMER = "programmer"
    TESTER = "tester"
    REVIEWER = "reviewer"


ROLE_KEYS: Mapping[RoleName, str] = MappingProxyType(
    {
        RoleName.ANALYST: "ANALYST_MODEL",
        RoleName.ARCHITECT: "ARCHITECT_MODEL",
        RoleName.PROGRAMMER: "PROGRAMMER_MODEL",
        RoleName.TESTER: "TESTER_MODEL",
        RoleName.REVIEWER: "REVIEWER_MODEL",
    }
)


@dataclass(frozen=True, repr=False)
class RoleModelConfig:
    models: Mapping[RoleName, ModelRef]
    opencode_api_key: str = ""
    ollama_api_key: str = ""

    def __post_init__(self) -> None:
        if set(self.models) != set(RoleName):
            raise ValueError("Every role requires an explicit model")
        if not all(isinstance(model, ModelRef) for model in self.models.values()):
            raise ValueError("Role models must be model references")
        object.__setattr__(self, "models", MappingProxyType(dict(self.models)))

    @classmethod
    def from_env(cls, environ: Mapping[str, str]) -> RoleModelConfig:
        missing = [key for key in ROLE_KEYS.values() if not environ.get(key)]
        if missing:
            raise ValueError(f"Missing model settings: {', '.join(missing)}")
        return cls(
            models={role: ModelRef.parse(environ[key]) for role, key in ROLE_KEYS.items()},
            opencode_api_key=environ.get("OPENCODE_API_KEY", "") or "",
            ollama_api_key=environ.get("OLLAMA_API_KEY", "") or "",
        )

    def __repr__(self) -> str:
        return (
            f"RoleModelConfig(models={dict(self.models)!r}, "
            "OPENCODE_API_KEY='***', OLLAMA_API_KEY='***')"
        )
