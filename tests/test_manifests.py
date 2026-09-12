from __future__ import annotations

from hashlib import sha256

import pytest

from auto_code.contracts import (
    ArtifactUnitManifestEntry,
    BrowserE2EDecision,
    BrowserResult,
    BuildIdentity,
    ChangeOutline,
    EvidenceRef,
    RequirementsPackage,
    TaskDefinition,
    TaskDefinitionManifest,
    TaskStatus,
    TaskStatusManifest,
    UnitStatus,
    VerificationCheck,
    VerificationResult,
)
from auto_code.git import GitManifestFile, GitManifestInputs, UnauthorizedUntrackedPathError
from auto_code.hashing import hash_json
from auto_code.manifests import BuildIdentityFactory, ManifestBindingError, ProductChangeManifestBuilder, ReviewManifestBuilder
from auto_code.project_config import (
    AutomationPolicy,
    BrowserPolicy,
    CatalogPreflightPolicy,
    FinalizationPolicy,
    GitPolicy,
    LinearPolicy,
    ProcessPolicy,
    ProjectConfig,
    ReviewPolicy,
    TransportPolicy,
    VerificationPolicy,
)


def digest(value: str) -> str:
    return sha256(value.encode("ascii")).hexdigest()


def policy() -> ProjectConfig:
    return ProjectConfig(
        git=GitPolicy(remote="origin", base_branch=None),
        verification=VerificationPolicy(commands=(("/bin/check",),)),
        browser=BrowserPolicy(
            start_command=None,
            base_url=None,
            ready_timeout_seconds=1,
            command_timeout_seconds=1,
            playwright_command_prefix=("/bin/true",),
            allowed_operations=(),
        ),
        process=ProcessPolicy(command_timeout_seconds=1, termination_grace_seconds=1),
        transport=TransportPolicy(total_retry_wait_seconds=0),
        preflight=CatalogPreflightPolicy(
            catalog_timeout_seconds=1,
            max_catalog_response_bytes=1024,
            catalog_retry_budget=0,
            catalog_cache_validity_seconds=1,
        ),
        finalization=FinalizationPolicy(max_invocations_per_effect=1, total_retry_wait_seconds=0),
        automation=AutomationPolicy(regression_command=("/bin/true",)),
        protected_paths=(".env",),
        commit_excluded_paths=(".superpowers",),
        writable_roots=("generated",),
        environment_allowlist=(),
        linear=LinearPolicy(started_state_id=None, completed_state_id=None),
        review=ReviewPolicy(),
    )


def git_inputs(*, path: str = "src/auto_code/example.py", untracked: bool = False) -> GitManifestInputs:
    return GitManifestInputs(
        baseline_sha="a" * 40,
        files=(
            GitManifestFile(
                path=path,
                status="A",
                old_path=None,
                old_mode="000000",
                new_mode="100644",
                old_object_id=None,
                object_id="b" * 40,
                binary=False,
                untracked=untracked,
            ),
        ),
    )


def evidence(name: str) -> EvidenceRef:
    return EvidenceRef(
        relative_path=f"evidence/{name}.json",
        sha256=digest(name),
        media_type="application/json",
        creator="test",
    )


def requirements() -> RequirementsPackage:
    citation = {"source_id": "ticket", "locator": "line-1", "source_hash": digest("ticket")}
    return RequirementsPackage(
        objective="Build trusted manifests.",
        in_scope=("Bind implementation inputs.",),
        out_of_scope=("Run Git.",),
        requirements=({"requirement_id": "REQ-1", "text": "Inputs are hash-bound.", "sources": (citation,)},),
        acceptance_criteria=(
            {"criterion_id": "AC-1", "text": "Drift is rejected.", "sources": (citation,)},
        ),
        constraints=(),
        dependencies=(),
        ambiguities=(),
    )


def review_inputs() -> dict[str, object]:
    config = policy()
    product = ProductChangeManifestBuilder(config).build(git_inputs())
    build = BuildIdentityFactory.create(
        product.baseline_sha,
        product,
        config,
        config.verification.commands,
        digest("runtime"),
    )
    decision = BrowserE2EDecision(required=False, reason="No browser behavior changed.", scenarios=())
    outline = ChangeOutline(
        change_id="trusted-manifests",
        artifact_units=(
            ArtifactUnitManifestEntry(
                artifact_id="proposal",
                stage="architect_proposal",
                output_contract="ArtifactEnvelope",
            ),
        ),
        direct_dependency_hashes={"requirements": hash_json(requirements().model_dump(mode="json", round_trip=True))},
        browser_e2e_decision=decision,
    )
    definitions = TaskDefinitionManifest(
        definition_hash=hash_json([{"task_id": "1", "text": "Build manifests."}]),
        tasks=(TaskDefinition(task_id="1", text="Build manifests."),),
    )
    status = TaskStatusManifest(
        definition_hash=definitions.definition_hash,
        statuses=(TaskStatus(task_id="1", status=UnitStatus.CHECKED),),
    )
    verification = VerificationResult(
        build_identity_hash=hash_json(build.model_dump(mode="json", round_trip=True)),
        checks=(
            VerificationCheck(
                command_id="check-1",
                command_hash=hash_json(config.verification.commands[0]),
                returncode=0,
                failure_kind=None,
                stdout_evidence=evidence("verification-stdout"),
                stderr_evidence=evidence("verification-stderr"),
            ),
        ),
        passed=True,
        empty_authorized=False,
    )
    browser = BrowserResult(
        status="skipped",
        browser_e2e_decision_hash=hash_json(decision.model_dump(mode="json", round_trip=True)),
        build_identity_hash=hash_json(build.model_dump(mode="json", round_trip=True)),
        reason=decision.reason,
        scenario_observations=(),
        evidence=(evidence("browser"),),
    )
    return {
        "requirements": requirements(),
        "outline": outline,
        "artifact_hashes": {
            "proposal": digest("proposal"),
            "specs": digest("specs"),
            "design": digest("design"),
            "tasks": digest("tasks"),
        },
        "definitions": definitions,
        "status": status,
        "product_manifest": product,
        "policy": config,
        "build": build,
        "verification": verification,
        "browser": browser,
    }


def test_product_builder_maps_trusted_git_fields_and_allows_untracked_writable_paths() -> None:
    inputs = GitManifestInputs(
        baseline_sha="a" * 40,
        files=(
            GitManifestFile(
                path="generated/result.json",
                status="R100",
                old_path="generated/input.json",
                old_mode="100644",
                new_mode="100755",
                old_object_id="b" * 40,
                object_id="c" * 40,
                binary=True,
                untracked=False,
            ),
            git_inputs(path="generated/new.json", untracked=True).files[0],
        ),
    )

    product = ProductChangeManifestBuilder(policy()).build(inputs)

    assert product.files[0].model_dump() == {
        "schema_version": "v1",
        "path": "generated/result.json",
        "status": "R100",
        "old_path": "generated/input.json",
        "old_mode": "100644",
        "mode": "100755",
        "old_object_id": "b" * 40,
        "object_id": "c" * 40,
        "binary": True,
        "untracked": False,
    }
    assert product.files[1].untracked is True


def test_product_builder_rejects_untracked_or_denied_paths() -> None:
    builder = ProductChangeManifestBuilder(policy())

    with pytest.raises(UnauthorizedUntrackedPathError):
        builder.build(git_inputs(path="notes.txt", untracked=True))
    with pytest.raises(ManifestBindingError):
        builder.build(git_inputs(path=".env"))
    with pytest.raises(ManifestBindingError):
        builder.build(git_inputs(path=".superpowers/task-4-report.md"))


def test_build_identity_binds_every_product_policy_command_and_runtime_input() -> None:
    config = policy()
    inputs = git_inputs()
    product = ProductChangeManifestBuilder(config).build(inputs)

    build = BuildIdentityFactory.create(
        inputs.baseline_sha,
        product,
        config,
        config.verification.commands,
        digest("runtime"),
    )

    assert build.product_manifest_hash == product.content_hash
    assert build.project_policy_hash == config.policy_hash
    assert tuple(build.command_hashes.values()) == tuple(hash_json(command) for command in config.verification.commands)
    assert build.runtime_hash == digest("runtime")
    with pytest.raises(ManifestBindingError):
        BuildIdentityFactory.create("c" * 40, product, config, config.verification.commands, digest("runtime"))
    with pytest.raises(ManifestBindingError):
        BuildIdentityFactory.create(inputs.baseline_sha, product, config, (("/bin/other",),), digest("runtime"))


def test_review_manifest_derives_hashes_and_rejects_drifted_bindings() -> None:
    inputs = review_inputs()

    manifest = ReviewManifestBuilder.create(**inputs)  # type: ignore[arg-type]

    assert manifest.product_manifest_hash == inputs["product_manifest"].content_hash  # type: ignore[union-attr]
    assert manifest.build_identity_hash == hash_json(inputs["build"].model_dump(mode="json", round_trip=True))  # type: ignore[union-attr]
    assert manifest.verification_result_hash == hash_json(inputs["verification"].model_dump(mode="json", round_trip=True))  # type: ignore[union-attr]
    with pytest.raises(ManifestBindingError):
        ReviewManifestBuilder.create(**{**inputs, "build": inputs["build"].model_copy(update={"product_manifest_hash": digest("stale")})})  # type: ignore[arg-type,union-attr]
    with pytest.raises(ManifestBindingError):
        ReviewManifestBuilder.create(**{**inputs, "verification": inputs["verification"].model_copy(update={"build_identity_hash": digest("stale")})})  # type: ignore[arg-type,union-attr]
    with pytest.raises(ManifestBindingError):
        ReviewManifestBuilder.create(**{**inputs, "browser": inputs["browser"].model_copy(update={"browser_e2e_decision_hash": digest("stale")})})  # type: ignore[arg-type,union-attr]


def test_review_manifest_rejects_a_skipped_browser_result_when_e2e_is_required() -> None:
    inputs = review_inputs()
    decision = BrowserE2EDecision(
        required=True,
        reason="The changed page requires browser coverage.",
        scenarios=(
            {
                "scenario_id": "homepage-loads",
                "description": "Open the homepage.",
                "expected_result": "The homepage loads.",
            },
        ),
    )
    outline = inputs["outline"].model_copy(update={"browser_e2e_decision": decision})  # type: ignore[union-attr]
    browser = inputs["browser"].model_copy(  # type: ignore[union-attr]
        update={
            "browser_e2e_decision_hash": hash_json(decision.model_dump(mode="json", round_trip=True)),
            "reason": decision.reason,
        }
    )

    with pytest.raises(ManifestBindingError, match="Browser Result"):
        ReviewManifestBuilder.create(**{**inputs, "outline": outline, "browser": browser})  # type: ignore[arg-type]


@pytest.mark.parametrize("command_hashes", ({}, {"check-1": digest("other-command")}))
def test_review_manifest_rejects_build_commands_that_do_not_match_policy(command_hashes: dict[str, str]) -> None:
    inputs = review_inputs()
    build = inputs["build"].model_copy(update={"command_hashes": command_hashes})  # type: ignore[union-attr]
    checks = (
        ()
        if not command_hashes
        else (inputs["verification"].checks[0].model_copy(update={"command_hash": command_hashes["check-1"]}),)  # type: ignore[union-attr]
    )
    verification = inputs["verification"].model_copy(  # type: ignore[union-attr]
        update={
            "build_identity_hash": hash_json(build.model_dump(mode="json", round_trip=True)),
            "checks": checks,
            "passed": True,
            "empty_authorized": not checks,
        }
    )
    browser = inputs["browser"].model_copy(  # type: ignore[union-attr]
        update={"build_identity_hash": hash_json(build.model_dump(mode="json", round_trip=True))}
    )

    with pytest.raises(ManifestBindingError, match="Build commands"):
        ReviewManifestBuilder.create(**{**inputs, "build": build, "verification": verification, "browser": browser})  # type: ignore[arg-type]


def test_review_manifest_rejects_reordered_build_commands() -> None:
    inputs = review_inputs()
    policy = inputs["policy"].model_copy(  # type: ignore[union-attr]
        update={"verification": VerificationPolicy(commands=(("/bin/check",), ("/bin/other",)))}
    )
    command_hashes = {
        "check-2": hash_json(policy.verification.commands[1]),
        "check-1": hash_json(policy.verification.commands[0]),
    }
    build = inputs["build"].model_copy(  # type: ignore[union-attr]
        update={"project_policy_hash": policy.policy_hash, "command_hashes": command_hashes}
    )
    checks = (
        inputs["verification"].checks[0].model_copy(  # type: ignore[union-attr]
            update={"command_id": "check-2", "command_hash": command_hashes["check-2"]}
        ),
        inputs["verification"].checks[0].model_copy(  # type: ignore[union-attr]
            update={"command_id": "check-1", "command_hash": command_hashes["check-1"]}
        ),
    )
    verification = inputs["verification"].model_copy(  # type: ignore[union-attr]
        update={
            "build_identity_hash": hash_json(build.model_dump(mode="json", round_trip=True)),
            "checks": checks,
            "passed": True,
            "empty_authorized": False,
        }
    )
    browser = inputs["browser"].model_copy(  # type: ignore[union-attr]
        update={"build_identity_hash": hash_json(build.model_dump(mode="json", round_trip=True))}
    )

    with pytest.raises(ManifestBindingError, match="Build commands"):
        ReviewManifestBuilder.create(
            **{**inputs, "policy": policy, "build": build, "verification": verification, "browser": browser}
        )  # type: ignore[arg-type]
