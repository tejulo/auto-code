from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
import os
import socket
import threading

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from auto_code.checkpoint import CheckpointAuthority
from auto_code.cli import TrustedRuntimeConfig, main
from auto_code.contracts import (
    ArtifactUnitManifestEntry,
    BrowserE2EDecision,
    BrowserResult,
    BuildIdentity,
    ChangeOutline,
    EffectIntention,
    EvidenceRef,
    ProductChangeFile,
    ProductChangeManifest,
    RequirementsPackage,
    IndexReleaseReceipt,
    ReviewManifest,
    ReviewResult,
    RunState,
    Stage,
    StageOutput,
    TaskDefinition,
    TaskDefinitionManifest,
    TaskStatus,
    TaskStatusManifest,
    TicketConstraintProjection,
    TicketSnapshot,
    UnitStatus,
    VerificationCheck,
    VerificationResult,
)
from auto_code.finalizer import (
    _FinalizationArtifacts as FinalizationArtifacts,
    _Finalizer as Finalizer,
    _FinalizerDependencies as FinalizerDependencies,
)
from auto_code import finalization_service
from auto_code.finalization_service import (
    FinalizationKeyAuthority,
    FinalizationTrustMaterial,
    _FinalizationHandlers as FinalizationHandlers,
    _LauncherFinalizationService as FinalizationService,
)
from auto_code.hashing import canonical_json_bytes, hash_json
from auto_code.linear import LinearGateway
from auto_code.mcp_bridge import McpToolResult, TrustedLinearBridge
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
from auto_code.state import EMPTY_STATE_HASH, RunStateStore, StateGeneration
from auto_code.supervisor import StepKind


def digest(value: str) -> str:
    return sha256(value.encode("ascii")).hexdigest()


def evidence(name: str) -> EvidenceRef:
    return EvidenceRef(
        relative_path=f"evidence/{name}.json",
        sha256=digest(name),
        media_type="application/json",
        creator="test",
    )


def policy() -> ProjectConfig:
    return ProjectConfig(
        git=GitPolicy(remote="origin", base_branch="main"),
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
        finalization=FinalizationPolicy(max_invocations_per_effect=3, total_retry_wait_seconds=5),
        automation=AutomationPolicy(regression_command=("/bin/true",)),
        protected_paths=(".env",),
        commit_excluded_paths=(".superpowers",),
        writable_roots=("generated",),
        environment_allowlist=(),
        linear=LinearPolicy(started_state_id="started", completed_state_id="done"),
        review=ReviewPolicy(),
    )


def ticket_snapshot() -> TicketSnapshot:
    return TicketSnapshot.from_untrusted(
        {"id": "ENG-1", "title": "Finalize safely"},
        captured_at=datetime(2026, 9, 12, tzinfo=UTC),
        pagination_complete=True,
        source_page_hashes={"page-1": digest("ticket-page")},
    )


def artifacts() -> FinalizationArtifacts:
    current_policy = policy()
    requirements = RequirementsPackage(
        objective="Finalize exactly one reviewed change.",
        in_scope=("Commit the approved product manifest.",),
        out_of_scope=("Rebase the branch.",),
        requirements=(
            {
                "requirement_id": "REQ-1",
                "text": "Finalization is idempotent.",
                "sources": ({"source_id": "ticket", "locator": "body", "source_hash": digest("ticket")},),
            },
        ),
        acceptance_criteria=(
            {
                "criterion_id": "AC-1",
                "text": "No effect is repeated after a restart.",
                "sources": ({"source_id": "ticket", "locator": "body", "source_hash": digest("ticket")},),
            },
        ),
        constraints=(),
        dependencies=(),
        ambiguities=(),
    )
    decision = BrowserE2EDecision(required=False, reason="No browser behavior changed.", scenarios=())
    outline = ChangeOutline(
        change_id="idempotent-finalizer",
        artifact_units=(
            ArtifactUnitManifestEntry(
                artifact_id="proposal", stage=Stage.ARCHITECT_PROPOSAL, output_contract="ArtifactEnvelope"
            ),
        ),
        direct_dependency_hashes={"requirements": hash_json(requirements.model_dump(mode="json", round_trip=True))},
        browser_e2e_decision=decision,
    )
    definitions = TaskDefinitionManifest(
        definition_hash=hash_json([{"task_id": "1", "text": "Finalize the reviewed change."}]),
        tasks=(TaskDefinition(task_id="1", text="Finalize the reviewed change."),),
    )
    status = TaskStatusManifest(
        definition_hash=definitions.definition_hash,
        statuses=(TaskStatus(task_id="1", status=UnitStatus.CHECKED),),
    )
    product = ProductChangeManifest.from_files(
        "a" * 40,
        (
            ProductChangeFile(
                path="src/auto_code/example.py",
                status="A",
                old_path=None,
                old_mode="000000",
                mode="100644",
                old_object_id=None,
                object_id="b" * 40,
                binary=False,
                untracked=False,
            ),
        ),
    )
    build = BuildIdentity(
        baseline_sha=product.baseline_sha,
        product_manifest_hash=product.content_hash,
        project_policy_hash=current_policy.policy_hash,
        command_hashes={"check-1": hash_json(current_policy.verification.commands[0])},
        runtime_hash=digest("runtime"),
    )
    verification = VerificationResult(
        build_identity_hash=hash_json(build.model_dump(mode="json", round_trip=True)),
        checks=(
            VerificationCheck(
                command_id="check-1",
                command_hash=hash_json(current_policy.verification.commands[0]),
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
    manifest = ReviewManifest(
        baseline_sha=product.baseline_sha,
        requirements_package_hash=hash_json(requirements.model_dump(mode="json", round_trip=True)),
        change_outline_hash=hash_json(outline.model_dump(mode="json", round_trip=True)),
        artifact_hashes={"proposal": digest("proposal"), "specs": digest("specs"), "design": digest("design"), "tasks": digest("tasks")},
        task_definition_hash=definitions.definition_hash,
        task_status_hash=hash_json(status.model_dump(mode="json", round_trip=True)),
        product_manifest_hash=product.content_hash,
        build_identity_hash=hash_json(build.model_dump(mode="json", round_trip=True)),
        project_policy_hash=current_policy.policy_hash,
        verification_result_hash=hash_json(verification.model_dump(mode="json", round_trip=True)),
        browser_result_hash=hash_json(browser.model_dump(mode="json", round_trip=True)),
    )
    review = ReviewResult(
        approved=True,
        review_manifest_hash=manifest.content_hash,
        cited_ids=(),
        blocking_findings=(),
        evidence=(),
        next_action="Finalize the approved change.",
    )
    return FinalizationArtifacts(
        ticket_snapshot=ticket_snapshot(),
        original_state_id="started",
        original_external_revision="revision-1",
        project_policy=current_policy,
        requirements=requirements,
        change_outline=outline,
        artifact_hashes=manifest.artifact_hashes,
        task_definition=definitions,
        task_status=status,
        product_manifest=product,
        build_identity=build,
        verification_result=verification,
        browser_result=browser,
        review_manifest=manifest,
        review_result=review,
    )


@dataclass
class FakeGitGuard:
    baseline_sha: str
    branch: str = "ENG-1-finalize-safely"
    commit_sha: str | None = None
    pushed_sha: str | None = None
    fail_commit: bool = False
    fail_push: bool = False
    commit_calls: int = 0
    push_calls: int = 0
    fresh: bool = True
    refresh_calls: int = 0

    def remote_base_sha(self) -> str:
        return self.baseline_sha

    def current_branch(self) -> str:
        return self.branch

    def commit_manifest(self, manifest: object, message: str) -> str:
        assert manifest is not None
        assert message == "ENG-1: Finalize safely"
        self.commit_calls += 1
        if self.fail_commit:
            raise RuntimeError("commit failed")
        self.commit_sha = "c" * 40
        return self.commit_sha

    def push(self, commit_sha: str) -> str:
        self.push_calls += 1
        if self.fail_push:
            raise RuntimeError("push failed")
        assert commit_sha == self.commit_sha
        self.pushed_sha = commit_sha
        return commit_sha

    def observe_commit(self) -> str | None:
        return self.commit_sha

    def observe_push(self) -> str | None:
        return self.pushed_sha

    def refresh_finalization(self, branch: str, baseline_sha: str) -> bool:
        self.refresh_calls += 1
        return self.fresh and branch == self.branch and baseline_sha == self.baseline_sha

    def commit_product_manifest(self, manifest: object, message: str) -> str:
        return self.commit_manifest(manifest, message)

    def push_product_commit(self, commit_sha: str) -> str:
        return self.push(commit_sha)

    def reconcile_product_commit(self, manifest: object, commit_sha: str | None) -> str | None:
        del manifest
        if self.commit_sha is None or (commit_sha is not None and self.commit_sha != commit_sha):
            return None
        return self.commit_sha

    def reconcile_product_push(self, branch: str, commit_sha: str) -> str | None:
        return self.pushed_sha if branch == self.branch and self.pushed_sha == commit_sha else None


class FakeLinearClient:
    def __init__(self, projection: TicketConstraintProjection) -> None:
        self.projection = projection
        self.always_fail_done = False
        self.projection_state_id = "started"
        self.completed_state_id = "done"
        self.retry_after: float | None = None
        self.calls: list[str] = []

    def call(self, server_identity: str, tool_name: str, arguments: object) -> McpToolResult:
        del server_identity, arguments
        self.calls.append(tool_name)
        if tool_name == "query_ticket_projection":
            return McpToolResult(
                tool_call_id="projection",
                result=self.projection.model_dump(mode="json", round_trip=True),
                external_revision="revision-1",
                observed_state_id=self.projection_state_id,
            )
        assert tool_name == "compare_and_complete_ticket"
        return McpToolResult(
            tool_call_id=f"done-{len(self.calls)}",
            result={"state_id": self.completed_state_id},
            external_revision="revision-2",
            outcome="failure" if self.always_fail_done else "success",
            observed_state_id=self.completed_state_id,
            observations=() if self.retry_after is None else (f"retry-after={self.retry_after}",),
        )


@dataclass
class FakeActiveRunIndex:
    release_calls: int = 0
    active: bool = True
    run_id: str = "run-1"
    index_revision: int = 1
    index_hash: str = "a" * 64
    fail_after_release: bool = False
    crash_before_release_marker: bool = False
    write_release_receipt: bool = True
    release_receipt: IndexReleaseReceipt | None = None
    signing_key: Ed25519PrivateKey | None = None
    sign_with_attacker_key: bool = False

    def lookup(self, repository_id: str) -> FakeActiveRunIndex | None:
        assert repository_id == "repo-1"
        return self if self.active else None

    def release(self, *args: object) -> IndexReleaseReceipt:
        assert args[1] == self.run_id
        self.release_calls += 1
        unsigned = IndexReleaseReceipt.create(
            repository_id=str(args[0]),
            run_id=str(args[1]),
            prior_revision=int(args[2]),
            prior_hash=str(args[3]),
            terminal_generation_hash=str(args[4]),
        )
        assert self.signing_key is not None
        signer = Ed25519PrivateKey.generate() if self.sign_with_attacker_key else self.signing_key
        receipt = unsigned.with_signature(
            signer.sign(canonical_json_bytes(unsigned.signing_payload())).hex()
        )
        if self.write_release_receipt:
            self.release_receipt = receipt
        self.active = False
        if self.crash_before_release_marker:
            raise KeyboardInterrupt("crash after index release")
        if self.fail_after_release:
            raise RuntimeError("crash after index release")
        return receipt

    def verify_release(self, receipt: IndexReleaseReceipt) -> None:
        if self.release_receipt is None or not self.release_receipt.matches(receipt) or self.signing_key is None:
            raise RuntimeError("release receipt is missing")
        public_key = self.signing_key.public_key().public_bytes_raw().hex()
        try:
            self.release_receipt.verify_signature(public_key, sha256(bytes.fromhex(public_key)).hexdigest())
        except ValueError as error:
            raise RuntimeError("release receipt signature is invalid") from error

    def load_verified_release(self, receipt: IndexReleaseReceipt) -> IndexReleaseReceipt:
        self.verify_release(receipt)
        assert self.release_receipt is not None
        return self.release_receipt


@dataclass
class FinalizerHarness:
    store: RunStateStore
    finalizer: Finalizer
    bridge: TrustedLinearBridge
    git: FakeGitGuard
    client: FakeLinearClient
    index: FakeActiveRunIndex
    artifacts: FinalizationArtifacts
    generation: StateGeneration

    def accept(self, result: object) -> StateGeneration:
        action = getattr(result, "action")
        assert action is not None
        return self.finalizer.accept_trusted_receipt(self.store.load(), self.bridge.execute(action))

    def request_done(self) -> object:
        first = self.finalizer.advance(self.generation)
        assert first.kind is StepKind.MCP_ACTION
        assert first.action is not None
        assert first.action.operation == "query_ticket_projection"
        assert self.git.commit_calls == 0
        self.generation = self.accept(first)
        done = self.finalizer.advance(self.generation)
        assert done.kind is StepKind.MCP_ACTION
        return done


@pytest.fixture
def harness(tmp_path: Path) -> FinalizerHarness:
    approved = artifacts()
    client = FakeLinearClient(TicketConstraintProjection.from_snapshot(approved.ticket_snapshot))
    bridge = TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=client,
    )
    store = RunStateStore(tmp_path, "run-1", receipt_authority=bridge.receipt_authority)
    finalization_binding = FinalizationKeyAuthority(tmp_path).provision("finalization-test-reservation")
    initial = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(
            run_id="run-1",
            ticket_id="ENG-1",
            repository_id="repo-1",
            max_crew_iterations=3,
            finalization_public_key=finalization_binding.public_key,
            finalization_public_key_hash=finalization_binding.public_key_hash,
        ),
    )
    definitions = store.compare_and_swap(
        initial.revision,
        initial.state_hash,
        initial.state.model_copy(update={"task_definition_manifest": approved.review_manifest and TaskDefinitionManifest(
            definition_hash=approved.review_manifest.task_definition_hash,
            tasks=(TaskDefinition(task_id="1", text="Finalize the reviewed change."),),
        )}),
    )
    statuses = store.compare_and_swap(
        definitions.revision,
        definitions.state_hash,
        definitions.state.model_copy(
            update={
                "task_status_manifest": TaskStatusManifest(
                    definition_hash=approved.review_manifest.task_definition_hash,
                    statuses=(TaskStatus(task_id="1", status=UnitStatus.UNCHECKED),),
                )
            }
        ),
    )
    authority = CheckpointAuthority(tmp_path)
    review_hash = hash_json(approved.review_result.model_dump(mode="json", round_trip=True))
    checkpoint = authority.issue(
        stage=Stage.REVIEWER,
        contract_hash=digest("review-contract"),
        input_hashes={"review": approved.review_manifest.content_hash},
        output_manifest_hash=review_hash,
        validator="test-validator",
        validator_version="1",
        validation_receipt_hash=digest("review-receipt"),
    )
    state = statuses.state.model_copy(
        update={
            "branch": "ENG-1-finalize-safely",
            "task_status_manifest": TaskStatusManifest(
                definition_hash=approved.review_manifest.task_definition_hash,
                statuses=(TaskStatus(task_id="1", status=UnitStatus.CHECKED),),
            ),
            "requirements_package": approved.review_manifest.requirements_package_hash,
            "change_outline": approved.review_manifest.change_outline_hash,
            "product_change_manifest": "product-manifest",
            "product_change_manifest_hash": approved.review_manifest.product_manifest_hash,
            "build_identity": approved.review_manifest.build_identity_hash,
            "verification_result": approved.review_manifest.verification_result_hash,
            "browser_result": approved.review_manifest.browser_result_hash,
            "review_manifest": approved.review_manifest.content_hash,
            "review_result": review_hash,
            "checkpoints": {Stage.REVIEWER: checkpoint},
            "stage_outputs": (StageOutput(stage=Stage.REVIEWER, content_hash=review_hash),),
            "finalization_eligible": True,
        }
    )
    generation = store.compare_and_swap(statuses.revision, statuses.state_hash, state)
    git = FakeGitGuard(approved.product_manifest.baseline_sha)
    index = FakeActiveRunIndex(
        signing_key=FinalizationKeyAuthority(tmp_path).load_private_key(finalization_binding.public_key_hash)
    )
    finalizer = Finalizer(
        FinalizerDependencies(
            store=store,
            linear=LinearGateway(store, bridge.receipt_authority),
            git_guard=git,
            active_run_index=index,
            project_policy=policy(),
            artifacts=approved,
        )
    )
    return FinalizerHarness(store, finalizer, bridge, git, client, index, approved, generation)


def test_linear_failure_after_push_never_creates_second_commit(harness: FinalizerHarness) -> None:
    """Fails if a resumed finalization repeats a durable Git effect."""

    harness.client.always_fail_done = True
    action = harness.request_done()
    assert harness.git.commit_calls == 1
    assert harness.git.push_calls == 1
    harness.generation = harness.accept(action)

    resumed = harness.finalizer.advance(harness.store.load())

    assert resumed.kind is StepKind.MCP_ACTION
    assert resumed.action is not None
    assert resumed.action.operation == "compare_and_complete_ticket"
    assert resumed.action.arguments["state_id"] == "done"
    assert harness.git.commit_calls == 1
    assert harness.git.push_calls == 1


def test_prefinalization_projection_binds_original_revision_and_state(harness: FinalizerHarness) -> None:
    action = harness.finalizer.advance(harness.generation)

    assert action.kind is StepKind.MCP_ACTION
    assert action.action is not None
    assert action.action.expected_external_revision == "revision-1"
    assert action.action.arguments == {"ticket_id": "ENG-1", "state_id": "started"}


def test_artifact_loader_cannot_substitute_the_ticket_baseline(harness: FinalizerHarness) -> None:
    """An artifact callback must not select a different ticket than the immutable Active Run."""

    substituted = replace(
        harness.artifacts,
        ticket_snapshot=TicketSnapshot.from_untrusted(
            {"id": "ENG-2", "title": "Attacker baseline"},
            captured_at=datetime(2026, 9, 12, tzinfo=UTC),
            pagination_complete=True,
            source_page_hashes={"page-1": digest("ticket-page")},
        ),
    )
    harness.finalizer = Finalizer(replace(harness.finalizer.dependencies, artifacts=substituted))

    result = harness.finalizer.advance(harness.generation)

    assert result.kind is StepKind.HUMAN_REVIEW
    assert harness.client.calls == []


def test_finalization_rejects_projection_with_the_wrong_observed_ticket_state(harness: FinalizerHarness) -> None:
    harness.client.projection_state_id = "other"

    action = harness.finalizer.advance(harness.generation)
    assert action.action is not None
    accepted = harness.accept(action)
    result = harness.finalizer.advance(accepted)

    assert result.kind is StepKind.HUMAN_REVIEW
    assert harness.git.commit_calls == 0
    assert harness.git.push_calls == 0


def test_finalization_rejects_completion_with_the_wrong_observed_ticket_state(harness: FinalizerHarness) -> None:
    action = harness.request_done()
    harness.client.completed_state_id = "other"
    accepted = harness.accept(action)
    result = harness.finalizer.advance(accepted)

    assert result.kind is StepKind.HUMAN_REVIEW
    assert harness.git.commit_calls == 1
    assert harness.git.push_calls == 1


def test_finalization_fetches_the_remote_after_projection_before_git_effects(harness: FinalizerHarness) -> None:
    projection = harness.finalizer.advance(harness.generation)
    harness.generation = harness.accept(projection)
    harness.git.fresh = False

    result = harness.finalizer.advance(harness.generation)

    assert result.kind is StepKind.HUMAN_REVIEW
    assert harness.git.refresh_calls == 1
    assert harness.git.commit_calls == 0
    assert harness.git.push_calls == 0


def test_finalization_requires_an_exact_active_run_index_entry_before_done(harness: FinalizerHarness) -> None:
    action = harness.request_done()
    harness.index.active = False
    accepted = harness.accept(action)

    result = harness.finalizer.advance(accepted)

    assert result.kind is StepKind.HUMAN_REVIEW
    assert harness.store.load().state.disposition.value == "human_review"
    assert harness.index.release_calls == 0


def test_crash_after_index_release_recovers_done_without_human_review(harness: FinalizerHarness) -> None:
    """A release that completed before a crash must reconcile to DONE on restart."""

    action = harness.request_done()
    harness.generation = harness.accept(action)
    harness.index.fail_after_release = True

    first = harness.finalizer.advance(harness.generation)
    resumed = harness.finalizer.advance(harness.store.load())

    assert first.kind is StepKind.DONE
    assert resumed.kind is StepKind.DONE
    assert harness.store.load().state.disposition.value == "done"


def test_done_recovery_marks_released_only_after_verifying_the_exact_receipt(
    harness: FinalizerHarness,
) -> None:
    """A restart may finish the marker CAS after an interrupted index release."""

    action = harness.request_done()
    generation = harness.accept(action)
    harness.index.crash_before_release_marker = True

    with pytest.raises(KeyboardInterrupt, match="crash after index release"):
        harness.finalizer.advance(generation)

    resumed = harness.finalizer.advance(harness.store.load())

    assert resumed.kind is StepKind.DONE
    assert harness.store.load().state.finalization_index_released is True


def test_done_recovery_rejects_missing_index_without_a_verified_release_receipt(
    harness: FinalizerHarness,
) -> None:
    """A missing index is not proof of a completed Active Run release."""

    action = harness.request_done()
    generation = harness.accept(action)
    harness.index.crash_before_release_marker = True
    harness.index.write_release_receipt = False

    with pytest.raises(KeyboardInterrupt, match="crash after index release"):
        harness.finalizer.advance(generation)

    resumed = harness.finalizer.advance(harness.store.load())

    assert resumed.kind is StepKind.HUMAN_REVIEW
    assert harness.store.load().state.disposition.value == "human_review"


def test_done_recovery_rejects_an_attacker_signed_release_receipt(
    harness: FinalizerHarness,
) -> None:
    """A restart must reject a tombstone signed by a key other than the Active Run key."""

    action = harness.request_done()
    generation = harness.accept(action)
    harness.index.crash_before_release_marker = True
    harness.index.sign_with_attacker_key = True

    with pytest.raises(KeyboardInterrupt, match="crash after index release"):
        harness.finalizer.advance(generation)

    resumed = harness.finalizer.advance(harness.store.load())

    assert resumed.kind is StepKind.HUMAN_REVIEW
    assert harness.store.load().state.disposition.value == "human_review"


@pytest.mark.parametrize("effect", ("commit", "push", "linear_done"))
def test_finalization_effect_exhaustion_survives_restart_without_an_iteration(
    harness: FinalizerHarness,
    effect: str,
) -> None:
    """Fails if finalization retries are volatile or open a Crew Iteration."""

    if effect == "commit":
        harness.git.fail_commit = True
    elif effect == "push":
        harness.git.fail_push = True
    else:
        harness.client.always_fail_done = True
    before = harness.generation.state.crew_iteration_count
    operation = "compare_and_complete_ticket" if effect == "linear_done" else effect
    while sum(
        isinstance(event, EffectIntention) and event.payload.operation == operation
        for event in harness.store.load().state.effect_ledger
    ) < 3:
        result = harness.finalizer.advance(harness.store.load())
        if getattr(result, "kind") is StepKind.MCP_ACTION:
            harness.accept(result)

    terminal = harness.finalizer.advance(harness.store.load())
    state = harness.store.load().state

    assert terminal.kind is StepKind.HUMAN_REVIEW
    assert state.crew_iteration_count == before
    assert state.failure_history[-1].failure_source.value == "finalization"
    assert sum(
        isinstance(event, EffectIntention) and event.payload.operation == operation for event in state.effect_ledger
    ) == 3


def test_retry_after_persists_eligibility_across_a_finalization_restart(harness: FinalizerHarness) -> None:
    """Ignoring durable Retry-After state would immediately repeat a failed Linear effect."""

    harness.client.always_fail_done = True
    harness.client.retry_after = 2
    action = harness.request_done()
    accepted = harness.accept(action)

    resumed = harness.finalizer.advance(harness.store.load())
    state = harness.store.load().state

    assert accepted.state.finalization_retry_wait_seconds == 2
    assert accepted.state.finalization_next_eligible_at is not None
    assert resumed.kind is StepKind.READY_TO_FINALIZE
    assert state.crew_iteration_count == harness.generation.state.crew_iteration_count


@pytest.mark.parametrize(
    "drift",
    ("product_content", "file_mode", "policy", "build_identity", "verification", "browser_decision", "browser_result", "task_status"),
)
def test_post_review_binding_drift_requires_human_review_before_effects(
    harness: FinalizerHarness,
    drift: str,
) -> None:
    """Fails if any reviewed binding can change before an external effect."""

    original = harness.artifacts
    if drift in {"product_content", "file_mode"}:
        changed_product = ProductChangeManifest.from_files(
            original.product_manifest.baseline_sha,
            (
                original.product_manifest.files[0].model_copy(
                    update={"object_id": "c" * 40, "mode": "100755" if drift == "file_mode" else "100644"}
                ),
            ),
        )
        changed = replace(original, product_manifest=changed_product)
    elif drift == "policy":
        changed = replace(
            original,
            project_policy=original.project_policy.model_copy(
                update={"finalization": FinalizationPolicy(max_invocations_per_effect=2, total_retry_wait_seconds=0)}
            ),
        )
    elif drift == "build_identity":
        changed = replace(original, build_identity=original.build_identity.model_copy(update={"runtime_hash": digest("changed-runtime")}))
    elif drift == "verification":
        changed = replace(original, verification_result=original.verification_result.model_copy(update={"build_identity_hash": digest("changed-build")}))
    elif drift == "browser_decision":
        changed = replace(original, change_outline=original.change_outline.model_copy(update={"browser_e2e_decision": BrowserE2EDecision(required=False, reason="Changed.", scenarios=())}))
    elif drift == "browser_result":
        changed = replace(original, browser_result=original.browser_result.model_copy(update={"reason": "Changed."}))
    else:
        changed = replace(
            original,
            task_status=TaskStatusManifest(
                definition_hash=original.review_manifest.task_definition_hash,
                statuses=(TaskStatus(task_id="1", status=UnitStatus.UNCHECKED),),
            ),
        )
    harness.finalizer = Finalizer(
        replace(harness.finalizer.dependencies, artifacts=changed)
    )

    result = harness.finalizer.advance(harness.generation)

    assert result.kind is StepKind.HUMAN_REVIEW
    assert harness.git.commit_calls == 0
    assert harness.git.push_calls == 0
    assert harness.client.calls == []


def test_finalize_and_receipt_cli_dispatch_only_through_the_launcher_socket(
    harness: FinalizerHarness,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Fails if installed finalization commands bypass descriptor-bound launcher composition."""

    socket_path = harness.store.root / "launcher.sock"
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(socket_path))
    listener.listen(2)
    service = FinalizationService(
        signing_key=FinalizationKeyAuthority(harness.store.root).load_private_key(
            harness.store.load().state.finalization_public_key_hash
        ),
        state_root=harness.store.root,
        handlers=FinalizationHandlers(
            finalize=lambda _: harness.finalizer.advance(harness.store.load()),
            receipt=lambda request: StepResult(kind=StepKind.READY_TO_FINALIZE, run_id=request.run_id, state_revision=request.expected_revision, state_hash=request.expected_state_hash),
        ),
    )

    def invoke(operation: str, revision: int, state_hash: str, request_id: str | None = None) -> int:
        descriptor = service.issue_descriptor(operation=operation, run_id="run-1", expected_revision=revision, expected_state_hash=state_hash, request_id=request_id, socket_path=socket_path, expires_at=datetime.now(UTC) + __import__("datetime").timedelta(minutes=1), timeout_seconds=1.0)
        capability_path = harness.store.root / f"{descriptor.nonce}.json"
        trust_path = harness.store.root / "finalization-trust.json"
        capability_path.write_bytes(descriptor.to_bytes())
        trust_path.write_bytes(
            FinalizationTrustMaterial(
                public_key=service.public_key,
                state_root=harness.store.root,
                descriptor_hash=sha256(descriptor.to_bytes()).hexdigest(),
            ).to_bytes()
        )
        capability_fd = os.open(capability_path, os.O_RDONLY)
        trust_fd = os.open(trust_path, os.O_RDONLY)
        monkeypatch.setattr(finalization_service, "_LAUNCHER_FINALIZATION_FD", capability_fd)
        monkeypatch.setattr(finalization_service, "_LAUNCHER_FINALIZATION_TRUST_FD", trust_fd)
        worker = threading.Thread(target=service.serve_once, args=(listener,), daemon=True)
        worker.start()
        try:
            argv = [operation, "--run", "run-1", "--expected-revision", str(revision), "--expected-hash", state_hash]
            if request_id is not None:
                argv.extend(("--request-id", request_id))
            return main(argv, runtime=type("Runtime", (), {"state_root": harness.store.root})())
        finally:
            worker.join(timeout=2)
            os.close(capability_fd)
            os.close(trust_fd)

    try:
        assert invoke("finalize", harness.generation.revision, harness.generation.state_hash) == 0
        assert '"kind":"mcp_action"' in capsys.readouterr().out
    finally:
        listener.close()
