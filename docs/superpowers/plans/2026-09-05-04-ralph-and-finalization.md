# Ralph and Finalization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Assemble the stage supervisor, OpenCode/Ralph handshake, guarded orchestration repair, and idempotent commit-push-Linear finalization.

**Architecture:** `Supervisor.step()` advances deterministic local work until it needs an OpenCode MCP action, a Ralph continuation, or human input. A content-addressed runner and state-aware Ralph fork perform the typed handshake; the fork stops only after validating persisted terminal state, never by matching model text.

**Tech Stack:** Python 3.12+, CrewAI, Pydantic 2, pytest, OpenCode commands, a state-aware fork based on `charfeng1/opencode-ralph-loop@1.0.10`, Git CLI, Linear MCP.

**Spec:** `docs/superpowers/specs/2026-09-05-automated-development-orchestration-design.md`

## Global Constraints

- Complete plans 01, 02, and 03 first.
- The supervisor, not Ralph or an LLM, owns the Crew Iteration count and stage transitions.
- OpenCode repairs only in an isolated automation worktree after writing a typed repair plan and must activate a new immutable runner identity after the complete suite passes.
- Product Defects resume at Programmer; valid Analyst and Architect checkpoints remain reusable.
- At exhausted budget preserve branch/state/evidence, leave Linear `In Progress`, and stop without final commit or push.
- Never depend on a completion token emitted or repeated by an LLM; the fork validates persisted `DONE` plus finalization evidence.

## File Map

- `src/auto_code/supervisor.py`: one deterministic step and one Crew Iteration.
- `src/auto_code/repair.py`: repair plan contract, allowed diff, and regression gate.
- `src/auto_code/runner.py`: content-addressed runner builds and trusted external launcher/activation registry.
- `src/auto_code/finalizer.py`: checkpointed commit, push, and Linear action request.
- `src/auto_code/authorization.py`: signed out-of-band resume and abandon receipts.
- `src/auto_code/cli.py`: `prepare`, `step`, `receipt`, `repair-request`, `finalize`, `authorization`, `resume`, `abandon`, and `status`, reached through the appropriate trusted launcher boundary.
- `runner/commands/auto-code.md`: OpenCode MCP/Ralph handshake installed outside target repositories.
- `runner/plugins/ralph-loop/`: content-addressed state-aware Ralph fork.
- `runner/opencode.json`: local fork registration installed outside target repositories.
- `tests/integration/`: crash, resume, and end-to-end orchestration tests.

### Task 1: Supervisor Step Protocol

**Files:**
- Create: `src/auto_code/supervisor.py`
- Modify: `src/auto_code/contracts.py`
- Modify: `src/auto_code/cli.py`
- Test: `tests/test_supervisor.py`

**Interfaces:**
- Produces: `StepKind` values `CONTINUE`, `MCP_ACTION`, `ITERATION_FAILED`, `REPAIR_REQUIRED`, `READY_TO_FINALIZE`, `HUMAN_REVIEW`, and `DONE`.
- Produces: `StepResult(kind, run_id, state_revision, state_hash, request_id, stage, action, failure, evidence)`; every actionable result carries CAS/correlation fields while state remains internal.
- Produces: `Supervisor.step(run_id: str, expected_revision: int, expected_hash: str) -> StepResult`.
- Produces CLI: `auto-code step --run <id> --expected-revision <n> --expected-hash <hash> --json`.

- [ ] **Step 1: Write failing resume and budget tests**

```python
from auto_code.contracts import FailureClass, Stage
from auto_code.supervisor import StepKind, Supervisor


def test_product_defect_next_iteration_starts_at_programmer(approved_planning_state, dependencies) -> None:
    supervisor = Supervisor(dependencies, approved_planning_state)
    supervisor.record_failure(FailureClass.PRODUCT, Stage.PROGRAMMER, ["review.json"])
    generation = dependencies.store.load()
    result = supervisor.step(generation.state.run_id, generation.revision, generation.state_hash)
    assert result.stage is Stage.PROGRAMMER
    assert dependencies.checkpoint_authority.matches(approved_planning_state.checkpoints[Stage.ARCHITECT_TASKS], dependencies.expectations[Stage.ARCHITECT_TASKS])


def test_exhausted_budget_requires_human_review(exhausted_state, dependencies) -> None:
    supervisor = Supervisor(dependencies, exhausted_state)
    generation = dependencies.store.load()
    result = supervisor.step(generation.state.run_id, generation.revision, generation.state_hash)
    assert result.kind is StepKind.HUMAN_REVIEW
    assert result.failure.failure_class is FailureClass.BUDGET_EXHAUSTED


def test_reviewer_checkpoint_and_iteration_close_are_one_generation(supervisor, reviewer_generation) -> None:
    supervisor.crash_after_cas = True
    supervisor.execute_and_checkpoint(reviewer_generation, Stage.REVIEWER)
    reloaded = supervisor.store.load()
    assert Stage.REVIEWER in reloaded.state.checkpoints
    assert reloaded.state.iteration_open is False
    assert reloaded.state.finalization_eligible is True


def test_reviewer_rejection_closes_and_routes_in_one_generation(supervisor, rejecting_reviewer_generation) -> None:
    supervisor.crash_after_cas = True
    supervisor.execute_and_checkpoint(rejecting_reviewer_generation, Stage.REVIEWER)
    reloaded = supervisor.store.load().state
    assert reloaded.iteration_open is False
    assert reloaded.finalization_eligible is False
    assert reloaded.current_stage is Stage.PROGRAMMER
    assert Stage.REVIEWER not in reloaded.checkpoints
```

- [ ] **Step 2: Run supervisor tests and verify failure**

Run: `.venv/bin/python -m pytest tests/test_supervisor.py -v`

Expected: FAIL during collection.

- [ ] **Step 3: Implement deterministic stage execution**

On the first executable cognitive stage, call `begin_iteration()` once. For each stage, construct allowlisted context, invoke, validate, write immutable evidence/artifact versions, issue the private Checkpoint, and save before continuing. Invalid model output becomes `INVALID_OUTPUT`; automation/validator malfunction becomes Orchestration Defect. Stop on classified failure. Reviewer approval atomically persists checkpoint, closure, and finalization eligibility; rejection atomically persists evidence/failure, closure, invalidation, and routed next stage without a reusable Reviewer checkpoint. Finalizer is outside `next_stage`. Do not increment for preparation, ambiguity, receipt waiting, repair, status, or finalization.

```python
def step(self, run_id: str, expected_revision: int, expected_hash: str) -> StepResult:
    generation = self.store(run_id).load()
    require_expected(generation, expected_revision, expected_hash)
    state = generation.state
    expectations = self.expectations.for_state(state)
    stage = next_stage(state, expectations)
    if stage is None:
        require(not state.iteration_open)
        require(state.finalization_eligible and state.review_result.approved)
        return StepResult.ready_to_finalize(run_id=state.run_id, state_revision=generation.revision, state_hash=generation.state_hash)
    if not state.iteration_open:
        if not state.can_start_iteration():
            return self.human_review(generation, FailureClass.BUDGET_EXHAUSTED)
        generation = self.persist_begin_iteration(generation)
    return self.execute_and_checkpoint(generation, stage)
```

- [ ] **Step 4: Run supervisor plus routing tests**

Run: `.venv/bin/python -m pytest tests/test_supervisor.py tests/test_router.py tests/test_state.py -v`

Expected: PASS.

- [ ] **Step 5: Commit the supervisor**

```bash
git add src/auto_code/supervisor.py src/auto_code/contracts.py src/auto_code/cli.py tests/test_supervisor.py
git commit -m "feat: coordinate resumable crew iterations"
```

### Task 2: Planned Orchestration Repair Gate

**Files:**
- Create: `src/auto_code/repair.py`
- Create: `src/auto_code/runner.py`
- Create: `src/auto_code/repair_entrypoint.py`
- Modify: `src/auto_code/cli.py`
- Test: `tests/test_repair.py`

**Interfaces:**
- Produces: `RepairPlan(root_cause, files, change, regression_command, evidence)`.
- Produces: `RepairWorkspaceHandle(id, path, baseline_hash, run_id, old_runner_hash, expires_at)` from protected `RepairRunner.prepare_workspace(...)`.
- Produces: `RepairGuard.capture_baseline(repair_worktree) -> RepairBaseline`.
- Produces: `RepairGuard.create_request(plan, baseline, ticket_product_manifest) -> RepairRequest`, hash-bound to run, repository identities, old Runner Identity, policy, baseline, permitted diff, and exact ticket-owned paths.
- Produces: `RunnerIdentity(content_hash, source_sha, dependency_lock_hash, contract_bundle_hash, built_at)`.
- Produces: `RepairRunnerIdentity`, independently pinned by launcher-owned configuration.
- Produces: `TrustedLauncher.invoke(run_id, argv)`, which resolves and verifies Runner Identity for every ticket command.
- Produces: protected `RepairRunner.validate_build_activate(request) -> RunnerActivationReceipt`, including request hash, old/new identities, and contract-bundle hashes; registry activation is journaled and idempotent by request hash.
- Produces: `RunnerRegistry.lookup_activation(request_hash) -> RunnerActivationReceipt` and `TrustedLauncher.reconcile_activation(run_id, request_hash) -> StateGeneration`, invalidating checkpoint/output bindings whose contracts changed before relaunch.
- Produces ticket-runner CLI `auto-code repair-request --run <id> --expected-revision <n> --expected-hash <hash> --workspace <handle> --plan <path> --json` and protected launcher CLIs `auto-code-repair prepare --run <id> --failure <hash>` and `auto-code-repair apply --workspace <handle> --request <hash>`.

- [ ] **Step 1: Write failing plan-first and scope tests**

```python
from pathlib import Path
import pytest
from auto_code.repair import MissingRepairPlanError, RepairGuard, RepairTicketOverlap, UnauthorizedRepairError


def test_repair_requires_a_valid_plan(repair_launcher) -> None:
    workspace = repair_launcher.prepare_workspace("run-1", "failure-hash")
    with pytest.raises(MissingRepairPlanError):
        RepairGuard(workspace.path).validate_path(workspace.path / "missing.json")


def test_repair_rejects_unplanned_product_file(repair_launcher, valid_repair_plan) -> None:
    workspace = repair_launcher.prepare_workspace("run-1", "failure-hash")
    (workspace.path / "product.py").write_text("changed", encoding="ascii")
    with pytest.raises(UnauthorizedRepairError, match="product.py"):
        repair_launcher.validate_build_activate(repair_request(workspace, valid_repair_plan))


def test_repair_rejects_path_owned_by_same_repository_ticket(repair_launcher, overlapping_repair_request) -> None:
    with pytest.raises(RepairTicketOverlap):
        repair_launcher.validate_build_activate(overlapping_repair_request)


def test_active_runner_cannot_activate_itself(active_runner, valid_repair_request) -> None:
    with pytest.raises(PermissionError):
        active_runner.registry.activate(valid_repair_request)


def test_activation_revalidates_contracts_before_restart(repair_launcher, trusted_launcher, valid_repair_request) -> None:
    activation = repair_launcher.validate_build_activate(valid_repair_request)
    generation = trusted_launcher.reconcile_activation("run-1", valid_repair_request.content_hash)
    assert generation.state.runner_identity == activation.new_runner_identity
    assert generation.state.checkpoints.keys() == activation.compatible_checkpoint_stages
    assert trusted_launcher.restart_receipt("run-1").runner_identity == activation.new_runner_identity


def test_crash_after_registry_activation_recovers_receipt(repair_launcher, trusted_launcher, valid_repair_request) -> None:
    repair_launcher.crash_after("REGISTRY_POINTER_REPLACED")
    with pytest.raises(InjectedCrash):
        repair_launcher.validate_build_activate(valid_repair_request)
    activation = repair_launcher.registry.lookup_activation(valid_repair_request.content_hash)
    generation = trusted_launcher.reconcile_activation("run-1", valid_repair_request.content_hash)
    assert generation.state.runner_identity == activation.new_runner_identity
```

- [ ] **Step 2: Run repair tests and verify failure**

Run: `.venv/bin/python -m pytest tests/test_repair.py -v`

Expected: FAIL during collection.

- [ ] **Step 3: Implement repair evidence and complete regression gate**

The protected `prepare` command creates a fresh isolated automation worktree, refuses a preexisting/nonempty destination, hashes its baseline, and returns a short-lived handle before OpenCode writes the plan/change. The active runner validates plan shape/scope against that handle and emits a RepairRequest bound to the current Product Change Manifest but cannot run activation code. The independently pinned Repair Runner rechecks handle, baseline/diff ownership, denied paths, and request; when ticket and repair repository identities match, any path intersection enters Human Review; then it runs the suite and builds a content-addressed Runner Identity. Registry activation writes/fsyncs an immutable request-hash activation record before CAS-replacing its pointer; replay or crash recovery uses `lookup_activation` and never rebuilds or reactivates divergently. TrustedLauncher resolves that durable record, compares contract bundles, CAS-updates the Active Run, invalidates mismatched checkpoints/descendants, terminates the old process, and records a restart receipt under the new identity before any ticket command. Repair files never enter the ticket commit.

```python
def validate_build_activate(self, request: RepairRequest) -> RunnerActivationReceipt:
    self.require_repair_runner_identity()
    plan, baseline = self.load_and_verify_request(request)
    changed = self.git.changed_paths_since(baseline)
    if changed != set(plan.files) or not all(self.is_automation_path(path) for path in changed):
        raise UnauthorizedRepairError(sorted(changed - set(plan.files)))
    if request.ticket_repository_id == request.repair_repository_id:
        overlap = set(changed) & set(request.ticket_owned_paths)
        if overlap:
            raise RepairTicketOverlap(sorted(overlap))
    result = self.process.run(self.launcher_config.automation_regression_command, self.repair_worktree, self.launcher_config.timeout, self.evidence_sink, self.safe_env, self.repair_sandbox)
    result.require_success()
    runner = self.build_content_addressed_runner()
    return self.registry.activate_once(request_hash=request.content_hash, expected_old=request.runner_identity, new=runner)
```

- [ ] **Step 4: Run repair and complete automation tests**

Run: `.venv/bin/python -m pytest -v`

Expected: PASS.

- [ ] **Step 5: Commit repair safeguards**

```bash
git add src/auto_code/repair.py src/auto_code/runner.py src/auto_code/repair_entrypoint.py src/auto_code/cli.py tests/test_repair.py
git commit -m "feat: gate orchestration repairs"
```

### Task 3: Idempotent Finalizer

**Files:**
- Create: `src/auto_code/finalizer.py`
- Modify: `src/auto_code/supervisor.py`
- Modify: `src/auto_code/cli.py`
- Test: `tests/test_finalizer.py`

**Interfaces:**
- Consumes: `GitGuard`, `LinearGateway`, `RunStateStore`, approved `ReviewManifest`, `BuildIdentity`, and Effect Ledger.
- Produces: `Finalizer.advance(generation: StateGeneration) -> StepResult` with persisted per-effect finalization retry/wait accounting.
- Produces CLI: `auto-code finalize --run <id> --expected-revision <n> --expected-hash <hash>` and launcher-internal `auto-code receipt --run <id> --expected-revision <n> --expected-hash <hash> --request-id <id>`; caller-authored receipt files are rejected.

- [ ] **Step 1: Write failing push-then-Linear-resume test**

```python
from auto_code.supervisor import StepKind


def test_linear_failure_after_push_never_creates_second_commit(finalizer, approved_generation, git_guard) -> None:
    reread = finalizer.advance(approved_generation)
    assert reread.kind is StepKind.MCP_ACTION
    assert reread.action.operation == "get_ticket_projection"
    assert git_guard.commit_calls == 0
    generation = finalizer.accept_trusted_receipt(reread.request_id)

    action = finalizer.advance(generation)
    assert action.kind is StepKind.MCP_ACTION
    assert git_guard.commit_calls == 1
    assert git_guard.push_calls == 1

    resumed = finalizer.advance(finalizer.store.load())
    assert resumed.kind is StepKind.MCP_ACTION
    assert git_guard.commit_calls == 1
    assert git_guard.push_calls == 1
    assert resumed.action.target_state_id == finalizer.project_policy.linear.completed_state_id


def test_finalization_retry_exhaustion_survives_restart(finalizer, approved_generation) -> None:
    finalizer.linear.always_fail_done = True
    result = finalizer.run_across_restarts(approved_generation, attempts=3)
    assert result.kind is StepKind.HUMAN_REVIEW
    reloaded = finalizer.store.load().state
    assert reloaded.crew_iteration_count == approved_generation.state.crew_iteration_count
    assert effect_stats(reloaded.effect_ledger, "linear_done").invocation_count == 3
    assert [event.kind for event in events_for(reloaded.effect_ledger, "linear_done")].count(EffectEventKind.INVOCATION) == 3
    assert reloaded.failure_history[-1].failure_source is FailureSource.FINALIZATION
```

- [ ] **Step 2: Run finalizer tests and verify failure**

Run: `.venv/bin/python -m pytest tests/test_finalizer.py -v`

Expected: FAIL during collection.

- [ ] **Step 3: Implement one-way checkpointed finalization**

Before staging, first persist and return a trusted-bridge request for fresh `TicketConstraintProjection`; no commit/push may occur until its receipt matches the Ticket Snapshot. Then fetch/re-read the remote base. Any constraint change or base advancement enters Human Review without automatic rebase/merge. Verify Independent Review, all checks, Browser E2E Decision/Result hashes, complete Task Status bound to immutable definitions, current branch, Build Identity, and every Review Manifest binding. Stage exactly manifest entries; require commit parent to be baseline and compare the baseline-relative commit diff/tree objects with Product Change Manifest. `advance()` loops through deterministic local substeps until MCP, Human Review, or Done. Persist each pending request and EffectEvent by CAS before exposing an action; after crashes reconcile before deciding whether to invoke again. The bridge consumes identical receipt replay idempotently and rejects conflicting receipts.

```python
def advance(self, generation: StateGeneration) -> StepResult:
    while True:
        state = generation.state
        self.verify_approval(state)
        generation = self.reconcile_pending_effect(generation)
        state = generation.state
        if not state.prefinalization_ticket_projection:
            return StepResult.mcp_action(self.persist_ticket_projection_request(generation))
        self.require_unchanged_ticket_constraints(state)
        self.require_unchanged_remote_base(state)
        if not state.commit_sha:
            generation = self.commit_exact_manifest(generation)
            continue
        if not state.pushed_sha:
            generation = self.push_reviewed_commit(generation)
            continue
        if not state.linear_done_receipt:
            return StepResult.mcp_action(self.persist_done_request_once(generation))
        self.revalidate_before_done(state)
        done = self.store.compare_and_swap(generation.revision, generation.state_hash, state.mark_done_with_final_evidence())
        active = self.active_run_index.lookup(done.state.repository_id)
        self.active_run_index.release(done.state.repository_id, done.state.run_id, active.index_revision, active.index_hash, done.state_hash)
        return StepResult.done(run_id=done.state.run_id, state_revision=done.revision, state_hash=done.state_hash)
```

Immutable EffectEvents record each intention, invocation, observation, and reconciliation; retry counts, accumulated wait, and next eligibility are derived against Project Policy maxima after every restart. Exhausting commit, push, or Linear limits records `ORCHESTRATION + FINALIZATION`, changes disposition to Human Review, and never consumes a Crew Iteration. Add these concrete cases to `tests/test_finalizer.py`:

```python
@pytest.mark.parametrize("effect", ["commit", "push", "linear_done"])
def test_effect_exhaustion_survives_restart(finalizer_harness, effect):
    result = finalizer_harness.fail_effect_across_restarts(effect, count=3)
    assert result.kind is StepKind.HUMAN_REVIEW
    assert finalizer_harness.store.load().state.failure_history[-1].failure_source is FailureSource.FINALIZATION


@pytest.mark.parametrize("drift", ["local_commit", "remote_ref", "linear_state"])
def test_divergent_observation_requires_human_review(finalizer_harness, drift):
    finalizer_harness.introduce_drift(drift)
    assert finalizer_harness.resume().kind is StepKind.HUMAN_REVIEW
    assert finalizer_harness.force_operations == []


def test_crash_after_done_before_bound_index_release_is_reconciled(finalizer_harness):
    finalizer_harness.crash_after("DONE_PERSISTED")
    done = finalizer_harness.run_to_crash()
    assert finalizer_harness.next_prepare_probe().kind == "INPUT_REQUIRED"
    assert finalizer_harness.index.release_count(done.run_id) == 1


@pytest.mark.parametrize("drift", ["product_content", "file_mode", "policy", "build_identity", "verification", "browser_decision", "browser_result", "task_status"])
def test_any_post_review_binding_drift_blocks_finalization(finalizer_harness, drift):
    finalizer_harness.mutate_review_binding(drift)
    assert finalizer_harness.advance().kind is StepKind.HUMAN_REVIEW
    assert finalizer_harness.external_effects == []
```

- [ ] **Step 4: Run finalizer and Git tests**

Run: `.venv/bin/python -m pytest tests/test_finalizer.py tests/test_git.py tests/test_linear.py -v`

Expected: PASS.

- [ ] **Step 5: Commit finalization**

```bash
git add src/auto_code/finalizer.py src/auto_code/supervisor.py src/auto_code/cli.py tests/test_finalizer.py
git commit -m "feat: finalize approved tickets idempotently"
```

### Task 4: OpenCode Command and Ralph Contract

**Files:**
- Create: `runner/opencode.json`
- Create: `runner/commands/auto-code.md`
- Create: `runner/plugins/ralph-loop/package.json`
- Create: `runner/plugins/ralph-loop/src/index.ts`
- Create: `runner/plugins/ralph-loop/tests/state-completion.test.ts`
- Create: `src/auto_code/authorization.py`
- Modify: `.gitignore`
- Test: `tests/test_opencode_command.py`
- Test: `tests/test_authorization.py`

**Interfaces:**
- Consumes all ticket commands through the trusted launcher: `prepare`, `step`, `receipt`, `repair-request`, `finalize`, and `status`; protected `auto-code-repair` is a separate executable. Human `authorization`, `resume`, and `abandon` are deliberately outside this command surface.
- Produces: `/auto-code <assignee> <milestone> [max_attempts]`.

- [ ] **Step 1: Write a failing command-contract test**

```python
from pathlib import Path


def test_command_contains_required_safety_transitions(repo_root: Path) -> None:
    text = (repo_root / "runner/commands/auto-code.md").read_text(encoding="utf-8")
    assert "Linear MCP" in text
    assert "repair-request" in text
    assert "trusted launcher" in text
    assert "state-aware" in text
    assert "<promise>DONE</promise>" not in text
    assert "auto-code complete" not in text


def test_resume_requires_external_signed_receipt(authorization_service, active_run) -> None:
    receipt = authorization_service.unsigned_receipt(active_run.run_id, action="resume", additional_iterations=2)
    with pytest.raises(SignatureValidationError):
        authorization_service.consume(receipt)


def test_resume_adds_derived_budget_without_rewriting_original(authorization_service, exhausted_generation) -> None:
    challenge = authorization_service.create_challenge(exhausted_generation, "resume")
    receipt = authorization_service.sign_for_test(challenge, additional_iterations=2)
    resumed = authorization_service.consume(exhausted_generation, receipt)
    assert resumed.state.max_crew_iterations == exhausted_generation.state.max_crew_iterations
    assert resumed.state.authorized_iteration_limit == exhausted_generation.state.max_crew_iterations + 2


def test_authorization_replay_is_idempotent_but_conflict_is_rejected(authorization_service, exhausted_generation) -> None:
    receipt = authorization_service.valid_resume_receipt(exhausted_generation, additional_iterations=1)
    first = authorization_service.consume(exhausted_generation, receipt)
    assert authorization_service.consume(first, receipt) == first
    with pytest.raises(AuthorizationConflict):
        authorization_service.consume(first, differently_signed_receipt_for_same_challenge(receipt))
```

- [ ] **Step 2: Run the command contract and verify failure**

Run: `.venv/bin/python -m pytest tests/test_opencode_command.py -v`

Expected: FAIL because the command file does not exist.

- [ ] **Step 3: Build the state-aware fork and write the exact handshake**

Vendor a minimal state-aware fork with upstream base version/source commit, dependency lock, and content hash pinned in Runner Identity. Register only its absolute content-addressed installation path in `runner/opencode.json`. The trusted launcher starts an absolute hash-pinned OpenCode binary with isolated config, target/global config discovery disabled, sanitized environment, and deny-by-default permissions that expose only the launcher command and required Linear bridge calls. Before editing OpenCode configuration or plugin code, invoke `customize-opencode`. The command never contains or asks the model to emit the upstream completion token. Every invocation uses the trusted launcher's absolute configured path, run ID, expected revision/hash, and request ID where applicable.

```json
{"plugin":["file:///var/lib/auto-code/runners/<runner-hash>/plugins/ralph-loop"]}
```

1. Validate three arguments and default `max_attempts` to `3`.
2. Call `auto-code prepare --repository`; resume/block immediately when instructed, and query Linear only after receiving `INPUT_REQUIRED`.
3. Query assignee, milestone, tickets, blockers, and workflow states only through the launcher-owned Linear bridge; the bridge writes and attests sanitized complete paginated PreparationInput with positive `max_crew_iterations` but no challenge. Pass its opaque path/hash and the separate challenge to `prepare`. For later MCP actions, invoke the bridge with the persisted request ID; the bridge writes Trusted MCP Receipt directly and `receipt` consumes it by CAS.
4. Start or relaunch the state-aware fork with safety cap `max(10, 3 * authorized_iteration_limit + 2)`, recomputed after Human Authorization, and bind immutable run, session, and Runner identities.
5. Run `step` with the latest CAS fields until the pass returns an action or terminal disposition.
6. On `ORCHESTRATION`, invoke protected `auto-code-repair prepare`, write the required RepairPlan/change only in its returned workspace, and obtain `repair-request`; protected `apply` independently validates/builds/activates. TrustedLauncher reconciles contract hashes/invalidation, terminates the old process, and relaunches OpenCode/Ralph under the new Runner Identity.
7. On `PRODUCT` or `INVALID_OUTPUT`, idle so Ralph starts the next Crew Iteration without rewriting valid upstream work.
8. On `HUMAN_REVIEW`, print the report and let the state-aware hook validate persisted state and stop continuation.
9. On `MCP_ACTION`, call only the trusted Linear bridge for that request ID, then consume its correlated receipt.
10. On `READY_TO_FINALIZE`, invoke `finalize` with CAS bindings, service typed MCP actions through correlated receipts, and continue until persisted `DONE` or Human Review.
11. On `DONE`, return a normal report; the plugin hook independently loads state through the trusted launcher and stops without model-text matching.

Implement `authorization challenge --run <id> --expected-revision <n> --expected-hash <hash> --action resume|abandon`, persisting a one-time challenge by CAS. Operator-only `resume` and `abandon` also require expected revision/hash and accept an external Ed25519 signature over canonical UTF-8 JSON with domain `auto-code-human-authorization/v1`, key ID, action, run/challenge, actor, reason, budget, issue time, and expiry. The public-key trust root is launcher-owned. Atomically consume challenge, append authorization, and change disposition/add derived capacity without mutating original budget/history. Resume of a successfully compensated Preparation Transaction additionally changes phase from `COMPENSATION_REQUIRED` to `SELECTED`, preserving `compensated` and all effects, so preparation revalidates/retries. Identical receipt replay is idempotent; conflicting/concurrent consumption, active-automation calls, expiry, wrong run/domain/key, and nonpositive budget fail. `abandon` performs exact run/index/generation-bound release only after authorization persists, and the state-aware hook cancels Ralph.

- [ ] **Step 4: Run command, repair, and supervisor tests**

Run: `npm --prefix runner/plugins/ralph-loop test`

Expected: PASS, including model-text spoof rejection, persisted `DONE`, Human Review cancellation, stale CAS, wrong run/session binding, and launcher failure.

Run: `.venv/bin/python -m pytest tests/test_opencode_command.py tests/test_repair.py tests/test_supervisor.py tests/test_finalizer.py -v`

Expected: PASS, including hostile target config isolation, active-runner self-activation denial, premodified repair workspace rejection, and mandatory restart after activation.

- [ ] **Step 5: Commit OpenCode integration**

```bash
git add runner src/auto_code/authorization.py .gitignore tests/test_opencode_command.py tests/test_authorization.py
git commit -m "feat: integrate ralph delivery loop"
```

### Task 5: Failure-Injection Acceptance Suite

**Files:**
- Create: `tests/integration/test_delivery_flow.py`
- Create: `tests/integration/fakes.py`
- Modify: `pyproject.toml`

**Interfaces:**
- Exercises public CLI and typed MCP handshake only.
- Produces: a `pytest` marker named `provider_smoke` excluded from the default suite.

- [ ] **Step 1: Write failing end-to-end scenarios**

```python
import pytest


def test_reviewer_product_defect_reuses_planning(harness) -> None:
    harness.reviewer_results = ["product_defect", "approved"]
    result = harness.run_to_terminal()
    assert result.kind == "done"
    assert harness.stage_calls["analyst"] == 1
    assert harness.stage_calls["architect_tasks"] == 1
    assert harness.stage_calls["programmer"] == 2
    assert harness.stage_calls["reviewer"] == 2


def test_budget_exhaustion_preserves_work_without_finalization(harness) -> None:
    harness.max_crew_iterations = 3
    harness.reviewer_results = ["product_defect"] * 3
    result = harness.run_to_terminal()
    assert result.kind == "human_review"
    assert harness.git.commit_calls == 0
    assert harness.git.push_calls == 0
    assert harness.linear.current_state == "In Progress"
```

Add these named scenarios with the stated terminal assertions:

```python
def test_e2e_required_passes_before_review(harness):
    assert harness.with_required_e2e().run_to_terminal().kind == "done"
    assert harness.stage_order.index("tester") < harness.stage_order.index("reviewer")


def test_e2e_not_required_is_checkpointed_as_skipped(harness):
    harness.with_skipped_e2e().run_to_terminal()
    assert harness.browser_result.status == "skipped"


def test_architect_design_failure_reuses_prior_artifacts(harness):
    harness.fail_once("architect_design")
    harness.run_to_terminal()
    assert harness.stage_calls["architect_proposal"] == 1
    assert harness.stage_calls["architect_specs"] == 1
    assert harness.stage_calls["architect_design"] == 2


def test_orchestration_failure_requires_repair_receipt(harness):
    paused = harness.with_orchestration_failure().run_until_pause()
    assert paused.kind == "repair_required"
    assert harness.crew_calls_after_failure == 0
    workspace = harness.repair_launcher.prepare(paused)
    request = harness.write_plan_and_create_request(workspace)
    activation = harness.repair_launcher.apply(request)
    harness.trusted_launcher.reconcile_and_restart(activation)
    result = harness.run_to_terminal()
    assert result.kind == "done"
    assert harness.first_post_repair_call.runner_identity == activation.new_runner_identity


def test_no_candidate_has_no_side_effects(harness):
    result = harness.without_candidates().prepare()
    assert result.kind == "no_candidate"
    assert harness.git.branch_calls == 0
    assert harness.linear.update_calls == 0


def test_product_correction_runs_all_checks(harness):
    harness.reviewer_results = ["product_defect", "approved"]
    harness.run_to_terminal()
    assert harness.verification_calls == harness.configured_check_count * 2


def test_each_persisted_effect_resumes_without_duplication(harness):
    for hook in harness.persisted_effect_hooks:
        resumed = harness.crash_at(hook).resume_to_terminal()
        assert resumed.kind == "done"
        assert harness.duplicate_effects == []


def test_push_then_linear_failure_retries_only_linear(harness):
    harness.linear.fail_done_once = True
    harness.run_to_terminal()
    assert harness.git.commit_calls == 1
    assert harness.git.push_calls == 1
    assert harness.linear.done_calls == 2


def test_normative_ticket_drift_blocks_before_commit(harness):
    harness.linear.change_description_before_finalization()
    result = harness.run_to_terminal()
    assert result.kind == "human_review"
    assert harness.git.commit_calls == 0


@pytest.mark.parametrize("boundary", ["forged_receipt", "hostile_opencode_config", "inherited_secret", "state_root_mount", "mutable_trust_root", "active_runner_activation", "premodified_repair_workspace"])
def test_trust_boundary_attack_is_rejected_without_effect(harness, boundary):
    result = harness.inject_boundary_attack(boundary)
    assert result.kind in {"human_review", "hard_rejection"}
    assert harness.external_mutations_after_attack == []
```

- [ ] **Step 2: Run acceptance tests and verify uncovered behavior fails**

Run: `.venv/bin/python -m pytest tests/integration/test_delivery_flow.py -v`

Expected: FAIL until the harness and any missing orchestration edges are implemented.

- [ ] **Step 3: Implement fakes and close only observed integration gaps**

Use temporary bare/local Git repositories, a fake trusted MCP bridge, fake model transports, fake OpenSpec/Playwright CLI executables, and explicit crash hooks immediately before and after every invocation/observation persistence for Linear query/start/compensation/completion, branch creation, commit, push, receipt consumption, Done persistence, ActiveRunIndex release, repair-workspace creation, runner-registry activation, checkpoint revalidation CAS, old-process termination, and restart-receipt persistence. Assert reconciliation before reinvocation at every hook, including that ticket work never resumes between activation and verified restart. Do not contact real providers in default tests. Register `provider_smoke` and exclude it with pytest's default `addopts = "-m 'not provider_smoke'"`.

```python
class DeliveryHarness:
    def crash_at(self, hook: str) -> "DeliveryHarness":
        self.crash_hook = hook
        return self

    def resume_to_terminal(self) -> StepResult:
        while True:
            result = self.invoke_public_step()
            if result.kind in {"done", "human_review", "no_candidate"}:
                return result
            if result.kind == "repair_required":
                raise UnhandledRepairRequired(result)
            self.satisfy_typed_action(result)
```

- [ ] **Step 4: Run full verification**

Run: `.venv/bin/python -m pytest -v`

Expected: PASS with zero failures and provider smoke tests deselected.

Run: `.venv/bin/python -m auto_code --help`

Expected: exit 0 and list `prepare`, `step`, `receipt`, `repair-request`, `finalize`, `authorization`, `resume`, `abandon`, and `status`; `/auto-code` itself never invokes `authorization`, `resume`, or `abandon`, and protected `auto-code-repair` is not a ticket-runner subcommand.

- [ ] **Step 5: Commit acceptance coverage**

```bash
git add pyproject.toml tests/integration
git commit -m "test: cover automated delivery recovery"
```
