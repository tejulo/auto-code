from __future__ import annotations

import pytest

from auto_code.model_catalog import ModelRef
from auto_code.model_config import RoleModelConfig, RoleName


def complete_environ() -> dict[str, str]:
    return {
        "ANALYST_MODEL": "opencode-go/analyst-model",
        "ARCHITECT_MODEL": "opencode-go/architect-model",
        "PROGRAMMER_MODEL": "ollama-cloud/programmer-model",
        "TESTER_MODEL": "opencode-go/tester-model",
        "REVIEWER_MODEL": "opencode-go/reviewer-model",
    }


def test_every_role_requires_an_explicit_model() -> None:
    environ = complete_environ()
    del environ["REVIEWER_MODEL"]

    with pytest.raises(ValueError, match="REVIEWER_MODEL"):
        RoleModelConfig.from_env(environ)


def test_role_model_config_parses_each_required_role_uri() -> None:
    config = RoleModelConfig.from_env(complete_environ())

    assert config.models == {
        RoleName.ANALYST: ModelRef(provider="opencode-go", model_id="analyst-model"),
        RoleName.ARCHITECT: ModelRef(provider="opencode-go", model_id="architect-model"),
        RoleName.PROGRAMMER: ModelRef(provider="ollama-cloud", model_id="programmer-model"),
        RoleName.TESTER: ModelRef(provider="opencode-go", model_id="tester-model"),
        RoleName.REVIEWER: ModelRef(provider="opencode-go", model_id="reviewer-model"),
    }


@pytest.mark.parametrize(
    "value",
    (
        "opencode-go",
        "opencode-go/",
        "/model",
        "opencode-go/model/extra",
        "opencode-go//model",
    ),
)
def test_model_ref_requires_exactly_one_provider_separator(value: str) -> None:
    with pytest.raises(ValueError, match="provider/model"):
        ModelRef.parse(value)


def test_model_ref_rejects_an_unknown_provider() -> None:
    with pytest.raises(ValueError, match="Unsupported model provider"):
        ModelRef.parse("other/model")


@pytest.mark.parametrize(
    "model_id",
    (
        1,
        "",
        " ",
        "nested/model",
        "model?query=value",
        "model#fragment",
        "user@model",
        "model:credential",
        "model\x00control",
        "model-sk-live-abcdefgh",
    ),
)
def test_direct_model_ref_rejects_unsafe_model_ids(model_id: object) -> None:
    with pytest.raises(ValueError):
        ModelRef(provider="opencode-go", model_id=model_id)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "model_id",
    (
        "model?query=value",
        "model#fragment",
        "user@model",
        "model:credential",
        "model\x00control",
        "model-sk-live-abcdefgh",
    ),
)
def test_model_ref_parser_rejects_unsafe_model_ids(model_id: str) -> None:
    with pytest.raises(ValueError):
        ModelRef.parse(f"opencode-go/{model_id}")


def test_model_ref_accepts_an_ordinary_safe_identifier() -> None:
    assert ModelRef.parse("ollama-cloud/model.2_beta-1").model_id == "model.2_beta-1"


def test_malformed_model_uri_does_not_leak_an_embedded_secret() -> None:
    secret = "sk-live-abcdefgh"
    environ = complete_environ()
    environ["ANALYST_MODEL"] = f"opencode-go/{secret}"

    try:
        config = RoleModelConfig.from_env(environ)
    except ValueError as error:
        assert secret not in str(error)
    else:
        assert secret not in repr(config)
        pytest.fail("unsafe model URI was accepted")


def test_role_config_representation_redacts_provider_keys() -> None:
    environ = complete_environ()
    environ.update(
        {
            "OPENCODE_API_KEY": "opencode-secret",
            "OLLAMA_API_KEY": "ollama-secret",
        }
    )

    rendered = repr(RoleModelConfig.from_env(environ))

    assert "opencode-secret" not in rendered
    assert "ollama-secret" not in rendered
    assert rendered.count("***") == 2
