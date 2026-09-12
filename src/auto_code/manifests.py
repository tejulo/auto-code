from __future__ import annotations

from collections.abc import Mapping

from .contracts import (
    BrowserResult,
    BuildIdentity,
    ChangeOutline,
    ProductChangeFile,
    ProductChangeManifest,
    RequirementsPackage,
    ReviewManifest,
    TaskDefinitionManifest,
    TaskStatusManifest,
    VerificationResult,
)
from .git import GitManifestFile, GitManifestInputs, UnauthorizedUntrackedPathError
from .hashing import hash_json
from .project_config import ProjectConfig


class ManifestBindingError(ValueError):
    pass


class ProductChangeManifestBuilder:
    def __init__(self, config: ProjectConfig) -> None:
        if not isinstance(config, ProjectConfig):
            raise TypeError("Product manifests require a Project Policy")
        self._config = config

    def build(self, inputs: GitManifestInputs) -> ProductChangeManifest:
        if not isinstance(inputs, GitManifestInputs):
            raise TypeError("Product manifests require trusted Git inputs")
        return ProductChangeManifest.from_files(
            inputs.baseline_sha,
            tuple(self._product_file(entry) for entry in inputs.files),
        )

    def _product_file(self, entry: GitManifestFile) -> ProductChangeFile:
        if entry.untracked and not any(_under(entry.path, root) for root in self._config.writable_roots):
            raise UnauthorizedUntrackedPathError("Untracked path is outside Project Policy writable roots")
        for path in (entry.path, entry.old_path):
            if path is not None and _overlaps_policy(
                path,
                self._config.protected_paths + self._config.commit_excluded_paths,
            ):
                raise ManifestBindingError("Product manifest contains a denied path")
        return ProductChangeFile(
            path=entry.path,
            status=entry.status,
            old_path=entry.old_path,
            old_mode=entry.old_mode,
            mode=entry.new_mode,
            old_object_id=entry.old_object_id,
            object_id=entry.object_id,
            binary=entry.binary,
            untracked=entry.untracked,
        )


class BuildIdentityFactory:
    @staticmethod
    def create(
        baseline_sha: str,
        product_manifest: ProductChangeManifest,
        policy: ProjectConfig,
        commands: tuple[tuple[str, ...], ...],
        runtime_hash: str,
    ) -> BuildIdentity:
        if not isinstance(product_manifest, ProductChangeManifest) or not isinstance(policy, ProjectConfig):
            raise TypeError("Build Identity requires product and Project Policy contracts")
        if baseline_sha.lower() != product_manifest.baseline_sha.lower():
            raise ManifestBindingError("Build baseline does not match product manifest")
        if commands != policy.verification.commands:
            raise ManifestBindingError("Build commands do not match Project Policy")
        return BuildIdentity(
            baseline_sha=baseline_sha,
            product_manifest_hash=product_manifest.content_hash,
            project_policy_hash=policy.policy_hash,
            command_hashes={f"check-{index}": hash_json(command) for index, command in enumerate(commands, start=1)},
            runtime_hash=runtime_hash,
        )


class ReviewManifestBuilder:
    @staticmethod
    def create(
        requirements: RequirementsPackage,
        outline: ChangeOutline,
        artifact_hashes: Mapping[str, str],
        definitions: TaskDefinitionManifest,
        status: TaskStatusManifest,
        product_manifest: ProductChangeManifest,
        policy: ProjectConfig,
        build: BuildIdentity,
        verification: VerificationResult,
        browser: BrowserResult,
    ) -> ReviewManifest:
        if not all(
            isinstance(value, expected)
            for value, expected in (
                (requirements, RequirementsPackage),
                (outline, ChangeOutline),
                (definitions, TaskDefinitionManifest),
                (status, TaskStatusManifest),
                (product_manifest, ProductChangeManifest),
                (policy, ProjectConfig),
                (build, BuildIdentity),
                (verification, VerificationResult),
                (browser, BrowserResult),
            )
        ):
            raise TypeError("Review Manifest requires trusted contracts")
        if not isinstance(artifact_hashes, Mapping) or set(artifact_hashes) != {"proposal", "specs", "design", "tasks"}:
            raise ManifestBindingError("Review Manifest requires every visible OpenSpec artifact")
        if status.definition_hash.lower() != definitions.definition_hash.lower():
            raise ManifestBindingError("Task Status definition does not match Task Definition")
        if (
            build.baseline_sha.lower() != product_manifest.baseline_sha.lower()
            or build.product_manifest_hash.lower() != product_manifest.content_hash.lower()
            or build.project_policy_hash.lower() != policy.policy_hash.lower()
        ):
            raise ManifestBindingError("Build Identity does not match its inputs")
        expected_commands = tuple(
            (f"check-{index}", hash_json(command))
            for index, command in enumerate(policy.verification.commands, start=1)
        )
        if tuple(build.command_hashes.items()) != expected_commands:
            raise ManifestBindingError("Build commands do not match Project Policy")
        build_hash = hash_json(build.model_dump(mode="json", round_trip=True))
        ReviewManifestBuilder._validate_verification(verification, build, build_hash)
        try:
            BrowserResult.model_validate(
                browser.model_dump(mode="json", round_trip=True),
                context={"browser_e2e_decision": outline.browser_e2e_decision, "build_identity": build},
            )
        except ValueError as error:
            raise ManifestBindingError("Browser Result does not match Tester context") from error

        return ReviewManifest(
            baseline_sha=product_manifest.baseline_sha,
            requirements_package_hash=hash_json(requirements.model_dump(mode="json", round_trip=True)),
            change_outline_hash=hash_json(outline.model_dump(mode="json", round_trip=True)),
            artifact_hashes=dict(artifact_hashes),
            task_definition_hash=definitions.definition_hash,
            task_status_hash=hash_json(status.model_dump(mode="json", round_trip=True)),
            product_manifest_hash=product_manifest.content_hash,
            build_identity_hash=build_hash,
            project_policy_hash=policy.policy_hash,
            verification_result_hash=hash_json(verification.model_dump(mode="json", round_trip=True)),
            browser_result_hash=hash_json(browser.model_dump(mode="json", round_trip=True)),
        )

    @staticmethod
    def _validate_verification(
        verification: VerificationResult,
        build: BuildIdentity,
        build_hash: str,
    ) -> None:
        if verification.build_identity_hash.lower() != build_hash.lower():
            raise ManifestBindingError("Verification Result does not match Build Identity")
        try:
            VerificationResult.model_validate(
                verification.model_dump(mode="json", round_trip=True),
                context={"build_identity": build},
            )
        except ValueError as error:
            raise ManifestBindingError("Verification Result does not match Build Identity") from error


def _under(path: str, root: str) -> bool:
    return path == root or path.startswith(f"{root}/")


def _overlaps_policy(path: str, roots: tuple[str, ...]) -> bool:
    return any(_under(path, root) or _under(root, path) for root in roots)
