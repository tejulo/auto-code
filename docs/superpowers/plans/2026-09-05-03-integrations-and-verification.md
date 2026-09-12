# Integrations and Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build safe Linear MCP boundaries, Git and OpenSpec adapters, bounded Programmer tools, project verification, and real localhost browser testing.

**Architecture:** External effects use CAS-persisted requests and Trusted MCP Receipts written by a launcher-owned bridge. Git and local CLIs run through injected sandboxed subprocess executors with absolute executables, explicit environments, argument arrays, path containment, timeouts, and redacted evidence.

**Tech Stack:** Python 3.12, Pydantic 2, PyYAML, pytest, Git CLI, OpenSpec 1.12.0 on Node >=20.19.0, `@playwright/cli` 0.1.19 with `playwright`/`playwright-core` 1.63.0-alpha-2026-08-31.

**Spec:** `docs/superpowers/specs/2026-09-05-automated-development-orchestration-design.md`

## Global Constraints

- Complete plans 01 and 02 first.
- OpenCode invokes the launcher-owned Linear MCP bridge; Python selects requests and accepts only bridge-authenticated receipts.
- Version one permits one Active Run per physical repository and supports only local OpenSpec `spec-driven` changes.
- Never stash, discard, amend, force-push, or modify unrelated worktree changes.
- Use OpenSpec CLI instructions and validation; never archive automatically.
- Run configured commands with argument arrays, absolute hash-verified executables, explicit deny-by-default environment/working directory, OS sandbox, and timeout.
- Tester may write only through the evidence broker under `<state-root>/runs/<run-id>/evidence/browser/`; product subprocesses cannot mount the Authoritative State Root.

## File Map

- `auto-code.example.yaml`: non-secret repository configuration.
- `src/auto_code/project_config.py`: strict YAML configuration.
- `src/auto_code/linear.py`: candidate normalization, filtering, ordering, MCP requests, and receipt checks.
- `src/auto_code/mcp_bridge.py`: launcher-owned Linear tool allowlist and Trusted MCP Receipt creation.
- `src/auto_code/git.py`: repository preflight, branch creation, diff checks, commit, and push primitives.
- `src/auto_code/prepare.py`: durable Preparation Transaction and compensation.
- `src/auto_code/compatibility.py`: exact runtime/tool version baseline and evidence.
- `src/auto_code/manifests.py`: product-change manifests, Build Identity, and Review Manifest construction.
- `src/auto_code/openspec.py`: instructions, artifact materialization, dependency checks, and validation.
- `src/auto_code/programmer_tools.py`: path-safe read/write/search and allowlisted commands.
- `src/auto_code/verification.py`: full ordered project verification.
- `src/auto_code/browser.py`: localhost lifecycle and Playwright-only evidence.

### Task 1: Project Configuration and Linear MCP Boundary

**Files:**
- Create: `auto-code.example.yaml`
- Create: `src/auto_code/project_config.py`
- Create: `src/auto_code/linear.py`
- Modify: `src/auto_code/contracts.py`
- Test: `tests/test_project_config.py`
- Test: `tests/test_linear.py`

**Interfaces:**
- Produces: `ProjectConfig.load(path: Path) -> ProjectConfig`.
- Produces: `CandidateTicket`, sanitized `TicketSnapshot`, `McpActionRequest`, and `TrustedMcpReceipt`.
- Produces: `select_ticket(raw: object, assignee_id: str, milestone_id: str) -> CandidateTicket | None`.
- Produces: `IdentityResolution`, versioned `TicketSnapshot`, `McpActionRequest`, and `TrustedMcpReceipt`.
- Produces: `LinearGateway.request_ticket_projection(...)` and `.request_state(...) -> McpActionRequest`, `.persist_pending(generation, request) -> StateGeneration`, and `.consume_receipt(generation, receipt) -> StateGeneration`.
- Produces: `TrustedLinearBridge.query_preparation(challenge_id, query) -> TrustedPreparationInputRef` and `.execute(request) -> TrustedMcpReceipt`, writing payload/result hashes, bridge identity, MCP server identity, tool-call ID, timestamp, and observations directly to Authoritative State Root.

- [ ] **Step 1: Write failing deterministic-selection tests**

```python
from auto_code.linear import select_ticket


def test_selects_highest_priority_then_oldest_and_excludes_active_blockers() -> None:
    raw = [
        {"id": "ENG-3", "state_type": "unstarted", "assignee_id": "u", "milestone_id": "m", "priority": 1, "created_at": "2026-01-01T00:00:00Z", "blockers": [{"state_type": "started"}]},
        {"id": "ENG-2", "state_type": "unstarted", "assignee_id": "u", "milestone_id": "m", "priority": 1, "created_at": "2026-01-03T00:00:00Z", "blockers": []},
        {"id": "ENG-1", "state_type": "unstarted", "assignee_id": "u", "milestone_id": "m", "priority": 1, "created_at": "2026-01-02T00:00:00Z", "blockers": []},
    ]
    assert select_ticket(raw, "u", "m").id == "ENG-1"


def test_completed_or_canceled_blockers_are_inactive() -> None:
    raw = [{"id": "ENG-1", "state_type": "unstarted", "assignee_id": "u", "milestone_id": "m", "priority": 2, "created_at": "2026-01-01T00:00:00Z", "blockers": [{"state_type": "completed"}, {"state_type": "canceled"}]}]
    assert select_ticket(raw, "u", "m").id == "ENG-1"


def test_caller_authored_receipt_is_rejected(linear_gateway, pending_request) -> None:
    forged = trusted_receipt_like(pending_request, bridge_signature=None)
    with pytest.raises(UntrustedReceiptError):
        linear_gateway.consume_receipt(pending_request.generation, forged)


def test_identical_bridge_receipt_replay_is_idempotent(linear_gateway, trusted_receipt) -> None:
    first = linear_gateway.consume_receipt(trusted_receipt.generation, trusted_receipt)
    assert linear_gateway.consume_receipt(first, trusted_receipt) == first
```

- [ ] **Step 2: Run tests and verify missing interfaces**

Run: `.venv/bin/python -m pytest tests/test_project_config.py tests/test_linear.py -v`

Expected: FAIL during collection.

- [ ] **Step 3: Implement strict normalization and receipt correlation**

Treat smaller positive Linear priority numbers as higher priority and missing/no-priority as lowest. Order by priority, parsed timestamp, then canonical ticket ID; reject duplicate IDs and malformed timestamps. A Candidate Ticket must be `unstarted`. An Active Blocker is any blocking relationship whose state type is neither `completed` nor `canceled`. A started ticket is only a Resumable Ticket with a matching Active Run. Require exact assignee and milestone IDs through `IdentityResolution(resolved|not_found|ambiguous)`.

`TicketSnapshot` freezes normalized title, description, criteria, comments, labels, relations, subtickets, sanitized attachment metadata/safe text, workspace/team IDs, capture time, pagination completeness, source-page evidence hashes, and content hash before mutation. Strip URL userinfo/query/fragment and redact secret-like values before storage/model access. `TicketConstraintProjection` canonically hashes all requirement-bearing fields above, excluding workflow state, assignee, volatile timestamps, and transport metadata; finalization compares a fresh trusted projection. `McpActionRequest` contains UUID, effect/hash bindings, operation, entity, target, expected external revision, and run CAS fields. Persist it before returning `MCP_ACTION`. Accept only a matching bridge-authenticated receipt. Consume by CAS exactly once; identical replay returns the prior generation and conflicting replay fails.

Use this exact example configuration shape:

```yaml
git:
  remote: origin
  base_branch: null
verification:
  allow_empty: false
  commands:
    - ["${PROJECT}/.venv/bin/python", "-m", "pytest", "-q"]
browser:
  start_command: null
  base_url: null
  ready_timeout_seconds: 30
  command_timeout_seconds: 120
  playwright_command_prefix: ["${RUNNER}/bin/playwright-cli"]
  allowed_operations: ["open", "goto", "snapshot", "click", "fill", "type", "press", "screenshot", "close"]
process:
  command_timeout_seconds: 120
  termination_grace_seconds: 5
transport:
  total_retry_wait_seconds: 30
finalization:
  max_invocations_per_effect: 3
  total_retry_wait_seconds: 60
automation:
  regression_command: ["${REPAIR_WORKTREE}/.venv/bin/python", "-m", "pytest", "-q"]
protected_paths:
  - .env
  - .auto-code
  - .git
  - .venv
  - auto-code.yaml
commit_excluded_paths:
  - .auto-code
environment_allowlist: ["LANG", "LC_ALL", "TZ"]
linear:
  started_state_id: null
  completed_state_id: null
review:
  require_distinct_model: false
```

`${PROJECT}`, `${RUNNER}`, and `${REPAIR_WORKTREE}` are non-shell tokens expanded by the trusted launcher to validated absolute roots. The launcher supplies a private temporary directory and empty `HOME`; `PATH` is unnecessary. Authorization keys, state/registry locations, Repair Runner Identity, and receipt trust roots belong only to launcher-owned configuration. Pin the initial Project Policy hash and reject its modification during an Active Run.

- [ ] **Step 4: Run Linear and configuration tests**

Run: `.venv/bin/python -m pytest tests/test_project_config.py tests/test_linear.py -v`

Expected: PASS.

- [ ] **Step 5: Commit the Linear boundary**

```bash
git add auto-code.example.yaml src/auto_code/project_config.py src/auto_code/linear.py src/auto_code/mcp_bridge.py src/auto_code/contracts.py tests/test_project_config.py tests/test_linear.py
git commit -m "feat: select linear tickets safely"
```

### Task 2: Git Guard and Transactional Branch Preparation

**Files:**
- Create: `src/auto_code/process.py`
- Create: `src/auto_code/git.py`
- Test: `tests/test_git.py`
- Test: `tests/test_process.py`

**Interfaces:**
- Produces: `CommandResult(argv, returncode, stdout_text, stderr_text, stdout_path, stderr_path, redacted)` with bounded sanitized text, `.require_success()`, and immutable evidence references.
- Produces: `ProcessRunner.run(argv, cwd, timeout, evidence_sink, environment, sandbox_policy) -> CommandResult`, including timeout/spawn/signal failures rather than raising.
- Produces: `ManagedProcessRunner.start(...) -> ManagedProcess` with readiness, terminate, kill, and reap behavior.
- Produces: `GitGuard.preflight()`, `.create_ticket_branch(ticket_id, title) -> str`, `.reconcile_branch(...)`, `.commit_manifest(manifest, message) -> str`, and `.push() -> str`.
- Produces: `GitGuard.collect_manifest_inputs(baseline_sha) -> GitManifestInputs` from Git plumbing, including modes, renames, binaries, and authorized untracked objects; Task 5 builds the typed Product Change Manifest.

- [ ] **Step 1: Write failing Git behavior tests using temporary repositories**

```python
from pathlib import Path
import pytest
from auto_code.git import DirtyWorktreeError, GitGuard


def test_preflight_rejects_dirty_worktree(git_repo: Path) -> None:
    (git_repo / "dirty.txt").write_text("x", encoding="ascii")
    with pytest.raises(DirtyWorktreeError):
        GitGuard(git_repo).preflight()


def test_branch_name_is_ticket_id_plus_slug(git_repo_with_remote: Path) -> None:
    branch = GitGuard(git_repo_with_remote).create_ticket_branch("ENG-42", "Add safer retries")
    assert branch == "ENG-42-add-safer-retries"


def test_product_process_cannot_see_state_or_secrets(process_runner, sandbox_policy) -> None:
    result = process_runner.run(probe_for_forbidden_mounts(), PROJECT_ROOT, 5, evidence_sink(), {}, sandbox_policy)
    assert result.returncode == 0
    assert result.redacted is True
```

- [ ] **Step 2: Run Git tests and verify failure**

Run: `.venv/bin/python -m pytest tests/test_process.py tests/test_git.py -v`

Expected: FAIL during collection.

- [ ] **Step 3: Implement non-shell subprocesses and Git safeguards**

Use `subprocess.run(argv, shell=False, cwd=..., timeout=..., text=True, env=explicit_env)` and convert timeout/spawn/signal outcomes into `CommandResult`; cap and redact output before the evidence broker stores it outside the target. Resolve argv[0] to an absolute hash-verified executable and reject dynamic downloads. Run product commands in an OS sandbox without Authoritative State Root, secrets, uncontrolled `HOME`, or unrelated host paths mounted; only policy-declared target/build/cache paths are writable. `ManagedProcessRunner` uses the same isolation plus a separate process group and terminate/kill/reap escalation. Discover the remote default branch with Git plumbing, fetch before branch creation, and apply the stated Git safeguards.

```python
class ProcessRunner:
    def run(self, argv, cwd, timeout, evidence_sink, environment, sandbox_policy) -> CommandResult:
        try:
            executable = self.executables.require_absolute_verified(argv[0])
            completed = self.sandbox.run((executable, *argv[1:]), cwd=cwd, timeout=timeout, env=environment, policy=sandbox_policy)
            return evidence_sink.write(redact_and_cap(completed))
        except (OSError, subprocess.TimeoutExpired) as error:
            return evidence_sink.write(redact_and_cap(error))


def create_ticket_branch(self, ticket_id: str, title: str) -> str:
    self.preflight()
    branch = f"{ticket_id}-{slugify(title)}"
    self.run_git("fetch", self.remote)
    self.run_git("switch", "-c", branch, f"{self.remote}/{self.default_branch()}")
    return branch
```

- [ ] **Step 4: Run process and Git tests**

Run: `.venv/bin/python -m pytest tests/test_process.py tests/test_git.py -v`

Expected: PASS.

- [ ] **Step 5: Commit Git safeguards**

```bash
git add src/auto_code/process.py src/auto_code/git.py tests/test_process.py tests/test_git.py
git commit -m "feat: guard git ticket branches"
```

### Task 3: Durable Preparation Transaction

**Files:**
- Create: `src/auto_code/prepare.py`
- Create: `src/auto_code/compatibility.py`
- Modify: `src/auto_code/cli.py`
- Test: `tests/test_prepare.py`

**Interfaces:**
- Consumes: `LinearGateway`, `GitGuard`, model/version checks, repository lock, and `RunStateStore`.
- Produces: bridge-authenticated `PreparationInput(schema_version, repository_identity, max_crew_iterations, assignee_resolution, milestone_resolution, pages, page_hashes, workflow_states, bridge_attestation)`; it never contains the reservation challenge and is never caller-authored.
- Produces: `PreflightVersionVerifier.verify() -> CompatibilityReceipt` for Python 3.12.x, CrewAI 1.15.20, OpenSpec 1.12.0, Node >=20.19.0, `@playwright/cli` 0.1.19, its exact `playwright`/`playwright-core` 1.63.0-alpha-2026-08-31 dependencies, and Ralph 1.0.10.
- Produces: `PrepareCoordinator.probe(repository_path) -> PrepareProbeResult` returning `RESUME`, `BLOCKED`, or a durable short-lived PreparationReservation/`INPUT_REQUIRED` challenge under lock.
- Produces: `PrepareCoordinator.activate_reservation(input_path, input_hash, challenge) -> PrepareResult`, one locked/recoverable activation journal that returns a stable no-candidate or initial Active Run result on identical replay.
- Produces: `PrepareCoordinator.advance(run_id, expected_revision, expected_hash) -> PrepareResult`; receipts arrive only through the trusted bridge and are consumed separately by request ID/CAS.
- Produces CLI: first `auto-code prepare --repository <path>`; only `INPUT_REQUIRED` permits `auto-code prepare --input <external-path> --sha256 <hash> --challenge <value>`; later calls require run ID and expected revision/hash.

- [ ] **Step 1: Write failing crash and compensation tests**

```python
def test_crash_after_linear_start_reconciles_before_branch(prepare_harness):
    prepare_harness.crash_after("IN_PROGRESS_CONFIRMED")
    result = prepare_harness.resume()
    assert result.phase == "BRANCH_CREATED"
    assert prepare_harness.linear.start_calls == 1


def test_branch_failure_refuses_compensation_after_human_change(prepare_harness):
    prepare_harness.git.fail_branch = True
    result = prepare_harness.run()
    assert result.phase == "COMPENSATION_REQUIRED"
    prepare_harness.linear.simulate_human_change()
    assert prepare_harness.resume().kind == "HUMAN_REVIEW"


def test_successful_compensation_preserves_run_for_human_disposition(prepare_harness):
    prepare_harness.git.fail_branch = True
    prepare_harness.run_to_compensation_required()
    result = prepare_harness.resume()
    assert result.kind == "HUMAN_REVIEW"
    assert result.state.compensated is True
    assert prepare_harness.linear.current_state == prepare_harness.original_state
    assert prepare_harness.active_run_index.lookup(result.repository_id).run_id == result.run_id
    assert prepare_harness.git.delete_calls == 0


def test_authorized_resume_restarts_compensated_preparation(prepare_harness):
    compensated = prepare_harness.successfully_compensated_state()
    resumed = prepare_harness.consume_valid_resume(compensated)
    assert resumed.phase == "SELECTED"
    assert resumed.compensated is True
    assert resumed.effect_ledger[:len(compensated.effect_ledger)] == compensated.effect_ledger
    assert prepare_harness.advance(resumed).action.operation == "compare_and_start_ticket"


def test_active_run_precedes_candidate_selection(prepare_harness):
    prepare_harness.index_active_run("run-existing", disposition="HUMAN_REVIEW")
    prepare_harness.add_candidate("ENG-NEW")
    result = prepare_harness.start()
    assert result.run_id == "run-existing"
    assert prepare_harness.linear.candidate_queries == 0


def test_version_mismatch_has_no_linear_or_git_effects(prepare_harness):
    prepare_harness.versions.crewai = "1.15.19"
    result = prepare_harness.start()
    assert result.kind == "HUMAN_REVIEW"
    assert prepare_harness.linear.update_calls == 0
    assert prepare_harness.git.branch_calls == 0


def test_no_candidate_replay_returns_same_durable_outcome(prepare_harness):
    first = prepare_harness.activate_without_candidates()
    replay = prepare_harness.replay_activation()
    assert replay == first
    assert prepare_harness.active_run is None
    assert prepare_harness.linear.update_calls == 0
    assert prepare_harness.git.branch_calls == 0


@pytest.mark.parametrize("tamper", ["caller_authored", "bad_attestation", "wrong_challenge_request", "swapped_path", "page_hash", "incomplete_pagination", "nonpositive_budget"])
def test_untrusted_preparation_input_is_rejected_before_selection(prepare_harness, tamper):
    result = prepare_harness.activate_tampered_input(tamper)
    assert result.kind == "HARD_REJECTION"
    assert prepare_harness.active_run is None
    assert prepare_harness.linear.update_calls == 0
    assert prepare_harness.git.branch_calls == 0
```

- [ ] **Step 2: Run preparation tests and verify failure**

Run: `.venv/bin/python -m pytest tests/test_prepare.py -v`

Expected: FAIL because `auto_code.prepare` does not exist.

- [ ] **Step 3: Implement all durable phases**

Derive RepositoryIdentity from the real path plus filesystem identity of Git's common directory, then use its shared launcher-owned lock/index namespace. Resume the indexed run first, including Human Review; select only with no Active Run. Accept PreparationInput only from the trusted bridge and verify its attestation, complete pagination, repository/challenge request binding, hashes, and positive budget while receiving challenge separately. The activation journal binds reservation/index CAS, challenge/input hashes, selected outcome, chosen run ID, initial generation hash, and phases. Identical replay returns the same result; mismatched replay fails. No-candidate leaves only reservation/outcome bookkeeping. Verify compatibility before Linear/Git mutation. Persist all phases and pending external requests by CAS; append immutable EffectEvents and reconcile before repeats. Compare external revision before compensation. Successful restore enters Human Review and retains the Active Run. Authenticated resume resets only the phase to `SELECTED`, then revalidates/repeats start and branch reconciliation; abandon releases. Clear a stale lock only when same-host ownership is provably dead and no Active Run owns it; otherwise Human Review.

- [ ] **Step 4: Run preparation, Linear, Git, state, and model preflight tests**

Run: `.venv/bin/python -m pytest tests/test_prepare.py tests/test_linear.py tests/test_git.py tests/test_state.py tests/test_model_catalog.py -v`

Expected: PASS.

- [ ] **Step 5: Commit preparation**

```bash
git add src/auto_code/prepare.py src/auto_code/compatibility.py src/auto_code/cli.py tests/test_prepare.py
git commit -m "feat: prepare ticket runs transactionally"
```

### Task 4: OpenSpec Artifact Adapter

**Files:**
- Create: `src/auto_code/openspec.py`
- Test: `tests/test_openspec.py`

**Interfaces:**
- Consumes: `ProcessRunner` and Architect `ArtifactEnvelope`.
- Produces: `OpenSpecClient.ensure_change(change_id, ticket_id, run_id) -> None`.
- Produces: `.instructions(change_id: str, artifact: str) -> ArtifactInstructions`.
- Produces: `.stage_artifact(change_id, envelope) -> StagedArtifactManifest`, `.validate_artifact(staged) -> ValidationReceipt`, and `.publish_artifact(staged, checkpoint: Checkpoint) -> tuple[Path, ...]`.
- Produces: `.validate_complete_change(...)`, `.parse_task_definitions(...) -> TaskDefinitionManifest`, and `.transition_task_status(definitions, before, completed_task_ids) -> TaskStatusManifest`.

- [ ] **Step 1: Write failing dependency and no-archive tests**

```python
from pathlib import Path
import pytest
from auto_code.contracts import ArtifactEnvelope, ArtifactFile
from auto_code.hashing import sha256_text
from auto_code.openspec import ArtifactDependencyError, CheckpointMismatch, OpenSpecClient, TaskDefinitionChanged, UnknownTaskId


def test_tasks_require_specs_and_design(fake_process, tmp_path: Path) -> None:
    client = OpenSpecClient(tmp_path, fake_process)
    with pytest.raises(ArtifactDependencyError):
        client.stage_artifact("eng-1-change", ArtifactEnvelope(artifact="tasks", files=(ArtifactFile(relative_path="tasks.md", content="# Tasks", sha256=sha256_text("# Tasks")),)))


def test_client_never_invokes_archive(fake_process, tmp_path: Path) -> None:
    client = OpenSpecClient(tmp_path, fake_process)
    client.instructions("eng-1-change", "proposal")
    assert all("archive" not in call.argv for call in fake_process.calls)


def test_publication_requires_matching_checkpoint(openspec_client, staged_artifact, other_checkpoint) -> None:
    with pytest.raises(CheckpointMismatch):
        openspec_client.publish_artifact(staged_artifact, other_checkpoint)
    assert not openspec_client.visible_path(staged_artifact).exists()


def test_task_definitions_are_immutable_and_status_is_monotonic(openspec_client, task_definitions, changed_task_definitions, empty_task_status) -> None:
    status = openspec_client.transition_task_status(task_definitions, empty_task_status, ("1.1",))
    with pytest.raises(TaskDefinitionChanged):
        openspec_client.transition_task_status(changed_task_definitions, status, ("1.1",))
    assert openspec_client.transition_task_status(task_definitions, status, ()) == status
    with pytest.raises(UnknownTaskId):
        openspec_client.transition_task_status(task_definitions, status, ("9.9",))
```

- [ ] **Step 2: Run OpenSpec tests and verify failure**

Run: `.venv/bin/python -m pytest tests/test_openspec.py -v`

Expected: FAIL during collection.

- [ ] **Step 3: Implement the official artifact graph**

Require OpenSpec `1.12.0`, Node `>=20.19.0`, local `spec-driven` schema, and no external store. Call `openspec new change <id> --json` idempotently and verify collisions. Parse CLI instructions and permit multi-file specs. `stage_artifact` writes immutable versions without publishing; `validate_artifact` returns a hashed receipt; the supervisor asks CheckpointAuthority to issue the checkpoint; only `publish_artifact` accepts that matching checkpoint and updates visible paths. Run full validation after all artifacts exist. Require unique numeric task IDs matching `^[1-9][0-9]*(\.[1-9][0-9]*)*$`; checkpoint immutable ID/text definitions. Programmer returns completed IDs plus input hashes, and the supervisor applies monotonic status transitions. Do not implement archive.

```python
REQUIRES = {
    "proposal": frozenset(),
    "specs": frozenset({"proposal"}),
    "design": frozenset({"proposal"}),
    "tasks": frozenset({"specs", "design"}),
}


def instructions(self, change_id: str, artifact: str) -> ArtifactInstructions:
    result = self.process.run((self.openspec_executable, "instructions", artifact, "--change", change_id, "--json"), self.root, self.timeout, self.evidence_sink, self.environment, self.sandbox_policy)
    result.require_success()
    return ArtifactInstructions.model_validate_json(result.stdout_text)
```

- [ ] **Step 4: Run OpenSpec and state regression tests**

Run: `.venv/bin/python -m pytest tests/test_openspec.py tests/test_router.py tests/test_state.py -v`

Expected: PASS.

- [ ] **Step 5: Commit OpenSpec support**

```bash
git add src/auto_code/openspec.py tests/test_openspec.py
git commit -m "feat: validate openspec artifact units"
```

### Task 5: Programmer Tools and Full Verification Runner

**Files:**
- Create: `src/auto_code/programmer_tools.py`
- Create: `src/auto_code/verification.py`
- Create: `src/auto_code/manifests.py`
- Modify: `src/auto_code/crew.py`
- Modify: `src/auto_code/tool_broker.py`
- Test: `tests/test_programmer_tools.py`
- Test: `tests/test_verification.py`

**Interfaces:**
- Produces: `RepoToolPolicy.open_read(relative: str) -> BinaryIO` and `.atomic_write(relative: str, content: bytes) -> None` using descriptor-relative no-follow traversal.
- Produces: `ProgrammerTools.read`, `.write`, `.search`, and `.run_configured(index: int)`.
- Produces: `VerificationRunner.run_all(build: BuildIdentity) -> VerificationResult`.
- Produces: `BuildIdentityFactory.create(baseline, product_manifest, policy, commands, runtime) -> BuildIdentity`.
- Produces: `ReviewManifestBuilder.create(requirements, artifacts, task_definitions, task_status, product_manifest, policy, build, verification, browser) -> ReviewManifest`.

- [ ] **Step 1: Write failing containment and full-suite tests**

```python
from pathlib import Path
import pytest
from auto_code.programmer_tools import ProgrammerTools, ProtectedPathError
from auto_code.verification import VerificationRunner


def test_programmer_cannot_escape_to_authoritative_state(tmp_path: Path) -> None:
    tools = ProgrammerTools(tmp_path, protected=(".env", ".auto-code", ".git"))
    with pytest.raises(ProtectedPathError):
        tools.read("../launcher-state/runs/run-1/current.json")


def test_verification_runs_every_command_after_a_failure(fake_process, project_config, build_identity) -> None:
    fake_process.returncodes = [1, 0]
    result = VerificationRunner(project_config, fake_process).run_all(build_identity)
    assert len(result.checks) == 2
    assert result.passed is False


def test_review_manifest_binds_git_objects_and_all_evidence(manifest_builder, changed_repo, review_inputs) -> None:
    changed_repo.rename("old.txt", "new.txt")
    changed_repo.write_binary("image.bin", b"\x00\x01")
    changed_repo.chmod("script.sh", 0o755)
    product = ProductChangeManifestBuilder(changed_repo.collect_manifest_inputs(changed_repo.baseline_sha)).build()
    manifest = manifest_builder.create(product_manifest=product, **review_inputs)
    assert {(entry.path, entry.mode) for entry in manifest.product.files} >= {("new.txt", "100644"), ("script.sh", "100755")}
    assert manifest.product.renames[0].old_path == "old.txt"
    assert manifest.product.file("image.bin").git_object_id
    assert manifest.product_manifest_hash == hash_json(manifest.product.model_dump())
    assert manifest.requirements_hash
    assert manifest.artifact_manifest_hashes
    assert manifest.task_definition_hash
    assert manifest.task_status_hash
    assert manifest.project_policy_hash
    assert manifest.build_identity_hash
    assert manifest.verification_hash
    assert manifest.browser_result_hash
```

- [ ] **Step 2: Run tool and verification tests**

Run: `.venv/bin/python -m pytest tests/test_programmer_tools.py tests/test_verification.py -v`

Expected: FAIL during collection.

- [ ] **Step 3: Implement bounded tools and non-short-circuit verification**

Resolve every read/write/search result, require regular files under authorized roots, deny protected paths for reads and writes, reject symlink/TOCTOU escapes, and cap bytes/results. Expose only Project Policy command indexes through the sandboxed ProcessRunner. `VerificationRunner` rejects an empty suite unless `allow_empty=true`, executes every command even after timeout/failure, and binds results to Build Identity. Mutation commands and read-only verification commands use separate policy lists.

Use descriptor-relative opening with no-follow semantics rather than resolve-then-open for tool operations. Register Programmer tools through ToolBroker. Build product manifests with Git plumbing/object hashes, not rendered `git diff` text. BuildIdentity hashes baseline, complete product manifest, pinned Project Policy, commands, and runtime. ReviewManifest explicitly accepts and hashes that exact Product Change Manifest plus requirements, every OpenSpec file, Task Definition/Status manifests, policy, verification, Browser Result, and authorized untracked entries. Any later file content/mode/rename, policy, build, evidence, or manifest hash drift blocks review/finalization.

```python
def open_read(self, relative: str) -> BinaryIO:
    parts = validate_relative_regular_path(relative, self.protected)
    parent_fd = walk_parent_no_follow(self.root_fd, parts[:-1])
    fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent_fd)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise ProtectedPathError(relative)
    return os.fdopen(fd, "rb")


def run_all(self, build: BuildIdentity) -> VerificationResult:
    if not self.config.verification.commands and not self.config.verification.allow_empty:
        raise EmptyVerificationPolicyError()
    checks = tuple(self.run_command(argv) for argv in self.config.verification.commands)
    return VerificationResult(build_identity_hash=hash_json(build.model_dump()), checks=checks, passed=all(check.returncode == 0 for check in checks), empty_authorized=not checks)
```

- [ ] **Step 4: Run the full non-browser integration suite**

Run: `.venv/bin/python -m pytest tests/test_programmer_tools.py tests/test_verification.py tests/test_git.py tests/test_linear.py tests/test_openspec.py -v`

Expected: PASS.

- [ ] **Step 5: Commit bounded execution**

```bash
git add src/auto_code/programmer_tools.py src/auto_code/verification.py src/auto_code/manifests.py src/auto_code/crew.py src/auto_code/tool_broker.py tests/test_programmer_tools.py tests/test_verification.py
git commit -m "feat: run bounded product verification"
```

### Task 6: Localhost Playwright Tester

**Files:**
- Create: `src/auto_code/browser.py`
- Modify: `src/auto_code/crew.py`
- Modify: `src/auto_code/tool_broker.py`
- Test: `tests/test_browser.py`

**Interfaces:**
- Consumes: `BrowserE2EDecision`, `ProjectConfig`, `ManagedProcessRunner`, sandboxed Playwright CLI wrapper, and Tester `CrewRunner`.
- Produces: `BrowserRunner.run(decision: BrowserE2EDecision, build: BuildIdentity, run_id: str, ticket_id: str) -> BrowserResult | FailureRecord`.

- [ ] **Step 1: Write failing required/skipped tests**

```python
import pytest
from auto_code.browser import BrowserRunner
from auto_code.contracts import BrowserE2EDecision, FailureClass, FailureSource, RunDisposition, Stage
from auto_code.hashing import hash_json
from auto_code.router import route_failure


def test_not_required_returns_skipped_without_starting_process(browser_runner, build_identity) -> None:
    decision = BrowserE2EDecision(required=False, reason="No browser surface", scenarios=[])
    result = browser_runner.run(decision, build_identity, "run-1", "ENG-1")
    assert result.status == "skipped"
    assert result.browser_e2e_decision_hash == hash_json(decision.model_dump())
    assert result.build_identity_hash == hash_json(build_identity.model_dump())
    assert browser_runner.process.calls == []


def test_required_browser_without_localhost_config_blocks(browser_runner, build_identity) -> None:
    result = browser_runner.run(BrowserE2EDecision(required=True, reason="UI change", scenarios=["loads"]), build_identity, "run-1", "ENG-1")
    assert result.failure_class is FailureClass.AMBIGUITY
    assert result.failure_source is FailureSource.BROWSER


def test_browser_scenario_mismatch_routes_to_programmer(browser_runner, build_identity, active_state) -> None:
    result = browser_runner.fail_scenario(required_decision(), build_identity, "run-1", "ENG-1")
    assert route_failure(active_state, result).next_stage is Stage.PROGRAMMER


def test_browser_infrastructure_failure_requires_repair(browser_runner, build_identity, active_state) -> None:
    result = browser_runner.fail_playwright(required_decision(), build_identity, "run-1", "ENG-1")
    assert route_failure(active_state, result).disposition is RunDisposition.REPAIR_REQUIRED
```

- [ ] **Step 2: Run browser tests and verify failure**

Run: `.venv/bin/python -m pytest tests/test_browser.py -v`

Expected: FAIL during collection.

- [ ] **Step 3: Implement real-process lifecycle and Playwright restriction**

Require a localhost address. Start the app through sandboxed `ManagedProcessRunner`, poll readiness, then expose the absolute hash-verified `playwright-cli` wrapper in a named session derived from run ID. Allow only `open/goto/snapshot/click/fill/type/press/screenshot/close`, constrain URLs to configured localhost, route output to brokered evidence, and deny install/arbitrary-code operations. Scenarios come only from BrowserE2EDecision. Every BrowserResult binds exact decision/build hashes; stale hashes or invalid skip block checkpoint/review/finalization. Missing policy returns Ambiguity; scenario mismatch is Product Defect; process/port/CLI/harness failure is Orchestration Defect. In `finally`, close/kill the CLI session and call the owned app process's terminate/kill/reap API.

```python
def run(self, decision: BrowserE2EDecision, build: BuildIdentity, run_id: str, ticket_id: str) -> BrowserResult | FailureRecord:
    if not decision.required:
        return BrowserResult(status="skipped", reason=decision.reason, scenarios=[], browser_e2e_decision_hash=hash_json(decision.model_dump()), build_identity_hash=hash_json(build.model_dump()))
    if not self.config.has_local_browser():
        return missing_browser_policy_failure()
    process = None
    primary = None
    primary_error = None
    try:
        process = self.start_app()
        self.wait_until_ready()
        primary = self.crew.run(Stage.TESTER, self.tester_context(run_id, ticket_id, decision, build))
    except Exception as error:
        primary_error = error
    finally:
        cleanup_errors = collect_cleanup_errors(
            lambda: self.playwright.close_owned_session(run_id),
            lambda: process.stop_and_reap() if process is not None else None,
        )
    if primary_error is not None:
        raise_with_cleanup_evidence(primary_error, cleanup_errors)
    return combine_browser_outcome(primary, cleanup_errors)
```

`ManagedProcessRunner.start()` cleans and reaps any partially started process before raising, so failure before assignment has no orphan. `collect_cleanup_errors` attempts every cleanup without raising. `combine_browser_outcome` preserves the primary result/failure as evidence and returns an Orchestration Defect when cleanup itself fails; `raise_with_cleanup_evidence` re-raises the primary exception with all cleanup evidence attached.

- [ ] **Step 4: Run all third-increment tests**

Run: `.venv/bin/python -m pytest tests/test_browser.py tests/test_verification.py tests/test_programmer_tools.py tests/test_openspec.py tests/test_git.py tests/test_linear.py -v`

Expected: PASS.

- [ ] **Step 5: Commit Browser E2E execution**

```bash
git add src/auto_code/browser.py src/auto_code/crew.py src/auto_code/tool_broker.py tests/test_browser.py
git commit -m "feat: validate localhost browser scenarios"
```
