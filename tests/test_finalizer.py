from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest

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
from auto_code.finalizer import FinalizationArtifacts, Finalizer, FinalizerDependencies
from auto_code.hashing import hash_json
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
        finalization=FinalizationPolicy(max_invocations_per_effect=3, total_retry_wait_seconds=0),
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


class FakeLinearClient:
    def __init__(self, projection: TicketConstraintProjection) -> None:
        self.projection = projection
        self.always_fail_done = False
        self.calls: list[str] = []

    def call(self, server_identity: str, tool_name: str, arguments: object) -> McpToolResult:
        del server_identity, arguments
        self.calls.append(tool_name)
        if tool_name == "query_ticket_projection":
            return McpToolResult(tool_call_id="projection", result=self.projection.model_dump(mode="json", round_trip=True), external_revision="revision-1")
        assert tool_name == "compare_and_complete_ticket"
        return McpToolResult(
            tool_call_id=f"done-{len(self.calls)}",
            result={"state_id": "done"},
            external_revision="revision-2",
            outcome="failure" if self.always_fail_done else "success",
        )


@dataclass
class FakeActiveRunIndex:
    release_calls: int = 0

    def release(self, *args: object) -> None:
        del args
        self.release_calls += 1


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
    initial = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3),
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
    index = FakeActiveRunIndex()
    finalizer = Finalizer(
        FinalizerDependencies(
            store=store,
            linear=LinearGateway(store, bridge.receipt_authority),
            git_guard=git,
            active_run_index=index,
            project_policy=policy(),
            load_artifacts=lambda _: approved,
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
        replace(harness.finalizer.dependencies, load_artifacts=lambda _: changed)
    )

    result = harness.finalizer.advance(harness.generation)

    assert result.kind is StepKind.HUMAN_REVIEW
    assert harness.git.commit_calls == 0
    assert harness.git.push_calls == 0
    assert harness.client.calls == []


def test_finalize_and_receipt_cli_dispatch_only_injected_trusted_boundaries(
    harness: FinalizerHarness,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Fails if finalization or receipt ingestion accepts unbound caller input."""

    calls: list[tuple[object, ...]] = []
    runtime = TrustedRuntimeConfig(
        state_root=harness.store.root,
        project_root=harness.store.root,
        project_policy_path=harness.store.root / "auto-code.yaml",
        project_policy_hash=policy().policy_hash,
        runner_identity=__import__("auto_code.contracts", fromlist=["RunnerIdentity"]).RunnerIdentity(
            content_hash="a" * 64,
            source_sha="b" * 64,
            dependency_lock_hash="c" * 64,
            contract_bundle_hash="d" * 64,
            runner_archive_hash="e" * 64,
            built_at="2026-09-12T00:00:00Z",
        ),
    )

    assert main(
        ["finalize", "--run", "run-1", "--expected-revision", str(harness.generation.revision), "--expected-hash", harness.generation.state_hash],
        runtime=runtime,
        finalizer_factory=lambda _: harness.finalizer,
    ) == 0
    assert '"kind":"mcp_action"' in capsys.readouterr().out

    assert main(
        ["receipt", "--run", "run-1", "--expected-revision", "1", "--expected-hash", "a" * 64, "--request-id", "11111111-1111-4111-8111-111111111111"],
        runtime=runtime,
        receipt_handler=lambda _, run, revision, state_hash, request_id: calls.append((run, revision, state_hash, request_id)),
    ) == 0
    assert calls == [("run-1", 1, "a" * 64, "11111111-1111-4111-8111-111111111111")]
