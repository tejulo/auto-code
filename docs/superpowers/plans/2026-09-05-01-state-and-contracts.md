# State and Contracts Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the typed domain contracts, atomic run store, and deterministic stage router used by every later increment.

**Architecture:** Pydantic models define persisted and cross-component data. `RunStateStore` writes run-scoped immutable generations under the launcher-owned Authoritative State Root with interprocess CAS; pure routing functions choose and invalidate stages from an explicit dependency graph.

**Tech Stack:** Python 3.12.x, Pydantic 2, pytest, standard-library `hashlib`, `json`, `pathlib`, and `tempfile`.

**Spec:** `docs/superpowers/specs/2026-09-05-automated-development-orchestration-design.md`

## Global Constraints

- Run development Python from `.venv`; never version `.venv`, `.env`, or advisory Ralph state. Authoritative state is never placed in the target repository.
- Keep state transitions deterministic and free of LLM calls.
- Persist no API keys, provider response bodies, or unrestricted prompts.
- A checkpoint is reusable only when contract version and all input hashes match.
- `AUTO_CODE_MAX_ATTEMPTS` maps to `max_crew_iterations`, defaults to `3`, and must be positive.

## File Map

- `pyproject.toml`: package metadata, runtime dependencies, and pytest configuration.
- `.gitignore`: local environment, secret, Ralph, and run-state exclusions.
- `src/auto_code/contracts.py`: enums and Pydantic boundary models.
- `src/auto_code/hashing.py`: canonical JSON hashing.
- `src/auto_code/checkpoint.py`: sole authority for validated checkpoints and hashed evidence.
- `src/auto_code/state.py`: atomic state persistence.
- `src/auto_code/run_index.py`: launcher-owned one-Active-Run lookup by canonical Git common-directory identity.
- `src/auto_code/router.py`: dependency graph, next-stage choice, and invalidation.
- `src/auto_code/cli.py`: status inspection entry point.

### Task 1: Package Skeleton and Typed Contracts

**Files:**
- Create: `pyproject.toml`
- Create: `.gitignore`
- Create: `src/auto_code/__init__.py`
- Create: `src/auto_code/contracts.py`
- Create: `tests/__init__.py`
- Test: `tests/test_contracts.py`

**Interfaces:**
- Produces: `Stage`, `FailureClass`, `FailureSource`, `FindingKind`, `RunDisposition`, `PreparationPhase`, `UnitStatus`, `EvidenceRef`, `Checkpoint`, `FailureRecord`, immutable `EffectEvent` variants, `TaskDefinitionManifest`, `TaskStatusManifest`, `HumanAuthorization`, `RunnerIdentity`, `RepairRunnerIdentity`, `ActivationRequest`, and `RunState`.
- Produces: `RunState.can_start_iteration() -> bool` and `RunState.begin_iteration() -> RunState`.

- [ ] **Step 1: Write failing contract tests**

```python
from pydantic import ValidationError
import pytest

from auto_code.contracts import RunState, Stage


def test_attempt_budget_must_be_positive() -> None:
    with pytest.raises(ValidationError):
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo", max_crew_iterations=0)


def test_begin_iteration_is_immutable_and_budgeted() -> None:
    state = RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo", max_crew_iterations=1)
    started = state.begin_iteration()
    assert state.crew_iteration_count == 0
    assert started.crew_iteration_count == 1
    assert started.iteration_open is True
    assert started.can_start_iteration() is False
    assert started.current_stage is Stage.ANALYST
```

- [ ] **Step 2: Run the tests and confirm the missing-module failure**

Run: `.venv/bin/python -m pytest tests/test_contracts.py -v`

Expected: FAIL during collection because `auto_code.contracts` does not exist.

- [ ] **Step 3: Add the package and minimal contracts**

Configure `pyproject.toml` with `requires-python = ">=3.12,<3.13"`, `pydantic>=2.11,<3`, the `src` package layout, and pytest `testpaths = ["tests"]`. Define the exact stage order:

```python
class Stage(StrEnum):
    ANALYST = "analyst"
    ARCHITECT_OUTLINE = "architect_outline"
    ARCHITECT_PROPOSAL = "architect_proposal"
    ARCHITECT_SPECS = "architect_specs"
    ARCHITECT_DESIGN = "architect_design"
    ARCHITECT_TASKS = "architect_tasks"
    PROGRAMMER = "programmer"
    VERIFICATION = "verification"
    TESTER = "tester"
    REVIEWER = "reviewer"
class FailureClass(StrEnum):
    PRODUCT = "product"
    INVALID_OUTPUT = "invalid_output"
    ORCHESTRATION = "orchestration"
    AMBIGUITY = "ambiguity"
    BUDGET_EXHAUSTED = "budget_exhausted"


class FailureSource(StrEnum):
    PREFLIGHT = "preflight"
    TRANSPORT = "transport"
    ARTIFACT = "artifact"
    VERIFICATION = "verification"
    BROWSER = "browser"
    REVIEW = "review"
    FINALIZATION = "finalization"
    SUPERVISOR = "supervisor"
```

Make every model `extra="forbid"`. `RunDisposition` is exactly `ACTIVE`, `WAITING_MCP`, `REPAIR_REQUIRED`, `HUMAN_REVIEW`, `DONE`, or `ABANDONED`. `Checkpoint` has no public `valid` switch. `FailureRecord` contains class, source, finding kind, optional owner stage, cited IDs, evidence refs, and observed revision. Every EffectEvent is immutable and has effect ID, globally unique/monotonic sequence, event kind (`INTENTION`, `INVOCATION`, `OBSERVATION`, `RECONCILIATION`), timestamp, and typed payload; enforce one intention, zero or more invocation/observation pairs, and one terminal reconciliation per effect. Counts and waits are derived. Task definitions and statuses are separate manifests. `RunState` contains identifiers, preparation/disposition, original iteration budget/count/open flag, current cognitive stage, output references, checkpoints, complete failure history, append-only Effect Ledger, Human Authorizations, Runner/Repair Runner identities, pending external request, and finalization fields. `authorized_iteration_limit` is derived as original budget plus valid consumed resume grants; the original budget never changes.

- [ ] **Step 4: Run contract tests**

Run: `.venv/bin/python -m pytest tests/test_contracts.py -v`

Expected: PASS with 2 tests.

- [ ] **Step 5: Commit the contracts**

```bash
git add pyproject.toml .gitignore src/auto_code tests/__init__.py tests/test_contracts.py
git commit -m "feat: define orchestration contracts"
```

### Task 2: Canonical Hashing and Atomic State Store

**Files:**
- Create: `src/auto_code/hashing.py`
- Create: `src/auto_code/state.py`
- Create: `src/auto_code/checkpoint.py`
- Create: `src/auto_code/run_index.py`
- Create: `tests/state_fixtures.py`
- Test: `tests/test_state.py`

**Interfaces:**
- Consumes: `RunState` from Task 1.
- Produces: `hash_json(value: object) -> str`.
- Produces: `CheckpointAuthority.issue(...) -> Checkpoint`; no other constructor can produce a reusable checkpoint.
- Produces: `RunStateStore(root: Path, run_id: str)`, `.load() -> StateGeneration`, and `.compare_and_swap(expected_revision, expected_hash, state) -> StateGeneration`.
- Produces: `ActiveRunIndex.lookup(repository_id)`, `.reserve(repository_id) -> PreparationReservation`, `.activate_reservation(request: ActivationRequest) -> PrepareResult`, and `.release(repository_id, run_id, expected_index_revision, expected_index_hash, terminal_generation_hash)`.

- [ ] **Step 1: Write failing hashing and interruption tests**

```python
from pathlib import Path
import os
import pytest

from auto_code.contracts import RunDisposition, RunState
from auto_code.hashing import hash_json
from auto_code.run_index import ActiveRunExists, ActiveRunIndex, NonTerminalRunRelease
from auto_code.state import EMPTY_STATE_HASH, AuthoritativeStateCorrupt, InvalidStateTransition, RunStateStore
from tests.state_fixtures import activated_index, activation_request, persist_generation, persist_terminal_generation, run_concurrently, state_with_effect


def test_hash_json_ignores_mapping_order() -> None:
    assert hash_json({"a": 1, "b": 2}) == hash_json({"b": 2, "a": 1})


def test_failed_replace_preserves_previous_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    store = RunStateStore(tmp_path, "run-1")
    original = RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo", max_crew_iterations=3)
    first = store.compare_and_swap(0, EMPTY_STATE_HASH, original)
    monkeypatch.setattr(os, "replace", lambda *_: (_ for _ in ()).throw(OSError("interrupted")))
    with pytest.raises(OSError, match="interrupted"):
        store.compare_and_swap(first.revision, first.state_hash, original.begin_iteration())
    assert store.load().state == original


def test_cas_rejects_non_prefix_effect_ledger(tmp_path: Path) -> None:
    store = RunStateStore(tmp_path, "run-1")
    first = store.compare_and_swap(0, EMPTY_STATE_HASH, state_with_effect("effect-1"))
    rewritten = first.state.model_copy(update={"effect_ledger": ()})
    with pytest.raises(InvalidStateTransition):
        store.compare_and_swap(first.revision, first.state_hash, rewritten)


def test_active_run_blocks_new_claim_until_done(tmp_path: Path) -> None:
    index = ActiveRunIndex(tmp_path)
    reservation = index.reserve("repo-1")
    active = index.activate_reservation(activation_request(reservation, run_id="run-1", preparation_input_hash="preparation-hash"))
    with pytest.raises(ActiveRunExists):
        index.reserve("repo-1")
    done = persist_terminal_generation(active, RunDisposition.DONE)
    index.release("repo-1", "run-1", active.index_revision, active.index_hash, done.state_hash)
    assert index.reserve("repo-1").repository_id == "repo-1"


@pytest.mark.parametrize("disposition", [RunDisposition.ACTIVE, RunDisposition.WAITING_MCP, RunDisposition.HUMAN_REVIEW, RunDisposition.REPAIR_REQUIRED])
def test_active_run_release_rejects_nonterminal_generation(tmp_path: Path, disposition: RunDisposition) -> None:
    index, active = activated_index(tmp_path)
    generation = persist_generation(active, disposition)
    with pytest.raises(NonTerminalRunRelease):
        index.release("repo-1", "run-1", active.index_revision, active.index_hash, generation.state_hash)


def test_only_one_concurrent_cas_writer_succeeds(state_store_with_generation) -> None:
    generation = state_store_with_generation.load()
    results = run_concurrently(2, lambda: state_store_with_generation.compare_and_swap(generation.revision, generation.state_hash, generation.state.begin_iteration()))
    assert sum(result.succeeded for result in results) == 1


def test_corrupt_referenced_generation_never_rewinds(state_store_with_effect) -> None:
    state_store_with_effect.corrupt_current_generation()
    with pytest.raises(AuthoritativeStateCorrupt):
        state_store_with_effect.load()
```

- [ ] **Step 2: Run tests to verify both interfaces are absent**

Run: `.venv/bin/python -m pytest tests/test_state.py -v`

Expected: FAIL during collection for missing modules.

- [ ] **Step 3: Implement deterministic hashing and atomic replacement**

Serialize canonical JSON with SHA-256. Validate identifiers and containment. Store immutable envelopes under `<state-root>/runs/<run-id>/generations/<revision>-<hash>.json`; require the embedded run ID to match the path and its immutable repository ID to match ActiveRunIndex. Hold a per-run interprocess lock across current-pointer re-read, expected revision/hash comparison, exclusive generation creation, fsync, and atomic pointer replacement. Discard only unreferenced temporaries; a missing/corrupt referenced generation enters Human Review and never rewinds Effect Ledger history. Transition validation preserves immutable fields and append-only prefixes. ActiveRunIndex lives in the same launcher-owned root and uses equivalent locked CAS. Release loads the exact bound generation and accepts only `DONE`, or `ABANDONED` with a valid consumed Human Authorization; `ACTIVE`, waiting, repair, and Human Review are rejected. `activate_reservation` owns a recoverable journal with challenge/input hashes, chosen run ID/outcome, generation hash, and phases. Identical replay returns the same run or durable no-candidate result; mismatched replay fails. No-candidate creates no Active Run and performs no Linear/Git effect.

```python
def hash_json(value: object) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


class RunStateStore:
    def compare_and_swap(self, expected_revision: int, expected_hash: str, state: RunState) -> StateGeneration:
        with self.interprocess_lock():
            current = self.load_optional_locked()
            require_expected(current, expected_revision, expected_hash)
            validate_monotonic_transition(current.state if current else None, state)
            generation = StateGeneration.create(expected_revision + 1, state)
            write_exclusive_and_fsync(generation, self.generations_dir)
            replace_and_fsync_pointer(generation.pointer(), self.current_path)
            return generation
```

- [ ] **Step 4: Run state and contract tests**

Run: `.venv/bin/python -m pytest tests/test_contracts.py tests/test_state.py -v`

Expected: PASS with all contract/state tests, including concurrent CAS and corrupt-current refusal.

- [ ] **Step 5: Commit persistence**

```bash
git add src/auto_code/hashing.py src/auto_code/checkpoint.py src/auto_code/state.py src/auto_code/run_index.py tests/state_fixtures.py tests/test_state.py
git commit -m "feat: persist atomic run checkpoints"
```

### Task 3: Deterministic Routing and Invalidation

**Files:**
- Create: `src/auto_code/router.py`
- Test: `tests/test_router.py`

**Interfaces:**
- Consumes: `Checkpoint`, `FailureClass`, `RunState`, and `Stage`.
- Produces: `next_stage(state: RunState, expectations: Mapping[Stage, CheckpointExpectation]) -> Stage | None`.
- Produces: `invalidate_from(state: RunState, owner: Stage) -> RunState`.
- Produces: `route_failure(state: RunState, failure: FailureRecord) -> RouteDecision` with disposition, invalidation roots, and next action.

- [ ] **Step 1: Write failing resume tests**

```python
from auto_code.checkpoint import CheckpointAuthority
from auto_code.contracts import Checkpoint, FailureClass, FailureRecord, FailureSource, FindingKind, RunState, Stage
from auto_code.router import apply_route, invalidate_from, next_stage, route_failure
from tests.state_fixtures import execute_trace, fully_approved_state


def approved(authority: CheckpointAuthority, stage: Stage) -> Checkpoint:
    return authority.issue(stage=stage, contract_hash="contract", input_hashes={}, output_manifest_hash=stage.value, validator="test", validator_version="1", validation_receipt_hash="receipt", evidence=())


def test_architect_design_failure_keeps_prior_units(checkpoint_authority, checkpoint_expectations) -> None:
    state = RunState(
        run_id="run-1",
        ticket_id="ENG-1",
        branch="ENG-1-test",
        repository_id="repo",
        max_crew_iterations=3,
        checkpoints={stage: approved(checkpoint_authority, stage) for stage in [Stage.ANALYST, Stage.ARCHITECT_OUTLINE, Stage.ARCHITECT_PROPOSAL, Stage.ARCHITECT_SPECS]},
    )
    assert next_stage(state, checkpoint_expectations.for_state(state)) is Stage.ARCHITECT_DESIGN


def test_product_defect_invalidates_only_programmer_and_descendants(checkpoint_authority, review_evidence) -> None:
    state = fully_approved_state(checkpoint_authority)
    decision = route_failure(state, FailureRecord(failure_class=FailureClass.PRODUCT, failure_source=FailureSource.REVIEW, finding_kind=FindingKind.IMPLEMENTATION_MISMATCH, owner_stage=Stage.PROGRAMMER, cited_ids=("REQ-1",), evidence_refs=(review_evidence,)))
    routed = apply_route(state, decision)
    assert Stage.ARCHITECT_TASKS in routed.checkpoints
    assert Stage.PROGRAMMER not in routed.checkpoints
    assert Stage.REVIEWER not in routed.checkpoints
    assert routed.build_identity is None
    assert routed.browser_result is None
    assert routed.review_manifest is None
    assert routed.finalization is None


def test_invalid_task_definitions_clear_status_and_all_descendants(implemented_state) -> None:
    routed = invalidate_from(implemented_state, Stage.ARCHITECT_TASKS)
    assert routed.task_definition_manifest is None
    assert routed.task_status_manifest is None
    assert routed.product_change_manifest is None


def test_complete_stage_trace_is_stable(empty_state, expectations) -> None:
    assert execute_trace(empty_state, expectations) == list(Stage)
```

- [ ] **Step 2: Run router tests and verify failure**

Run: `.venv/bin/python -m pytest tests/test_router.py -v`

Expected: FAIL during collection because `auto_code.router` does not exist.

- [ ] **Step 3: Implement the explicit graph**

Use the cognitive stage order from Task 1; Finalizer is not a stage. Expected hashes are mandatory. Product implementation/scenario mismatches from verification/browser/review route to Programmer; a cited Product Architect artifact finding routes to that artifact; Product Analyst attribution enters Human Review. Orchestration transport/tool/harness/provider/validator-execution defects route to Repair Required. `INVALID_OUTPUT` from any cognitive stage closes the iteration and routes the next iteration to that same stage without Automation Repair. Orchestration preflight/finalization/repair failure enters Human Review. Ambiguity from any source enters Human Review. Budget exhausted plus Supervisor enters Human Review. An unlisted combination converts once to terminal `ORCHESTRATION + SUPERVISOR + INVALID_ROUTING` Human Review, never recursively routes. Invalidation removes checkpoints and every descendant output reference; tasks invalidation clears both manifests, and implementation invalidation clears product/build/verification/browser/review/finalization bindings.

```python
DEPENDENCIES = {
    Stage.ARCHITECT_OUTLINE: frozenset({Stage.ANALYST}),
    Stage.ARCHITECT_PROPOSAL: frozenset({Stage.ARCHITECT_OUTLINE}),
    Stage.ARCHITECT_SPECS: frozenset({Stage.ARCHITECT_PROPOSAL}),
    Stage.ARCHITECT_DESIGN: frozenset({Stage.ARCHITECT_PROPOSAL}),
    Stage.ARCHITECT_TASKS: frozenset({Stage.ARCHITECT_SPECS, Stage.ARCHITECT_DESIGN}),
    Stage.PROGRAMMER: frozenset({Stage.ARCHITECT_TASKS}),
    Stage.VERIFICATION: frozenset({Stage.PROGRAMMER}),
    Stage.TESTER: frozenset({Stage.VERIFICATION}),
    Stage.REVIEWER: frozenset({Stage.TESTER}),
}


def invalidate_from(state: RunState, owner: Stage) -> RunState:
    invalid = {owner}
    while added := {stage for stage, requirements in DEPENDENCIES.items() if requirements & invalid} - invalid:
        invalid.update(added)
    return clear_stage_outputs(
        state,
        invalid,
        current_stage=owner,
        checkpoints={stage: checkpoint for stage, checkpoint in state.checkpoints.items() if stage not in invalid},
    )
```

- [ ] **Step 4: Run all increment tests**

Run: `.venv/bin/python -m pytest -v`

Expected: PASS with all contracts, state, and router tests.

- [ ] **Step 5: Commit routing**

```bash
git add src/auto_code/router.py tests/test_router.py
git commit -m "feat: route resumable orchestration stages"
```

### Task 4: Read-Only Status CLI

**Files:**
- Create: `src/auto_code/cli.py`
- Create: `src/auto_code/__main__.py`
- Modify: `pyproject.toml`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `RunStateStore.load()` and `next_stage()`.
- Produces: console script `auto-code` and `python -m auto_code status --run <id> --expected-revision <n> --expected-hash <hash>`.

- [ ] **Step 1: Write a failing CLI output test**

```python
from pathlib import Path
from auto_code.cli import main
from auto_code.contracts import RunState
from auto_code.state import EMPTY_STATE_HASH, RunStateStore


def test_status_reports_attempt_and_next_stage(tmp_path: Path, capsys, trusted_runtime_factory) -> None:
    persisted = RunStateStore(tmp_path, "run-1").compare_and_swap(0, EMPTY_STATE_HASH, RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo", max_crew_iterations=3))
    runtime = trusted_runtime_factory(state_root=tmp_path)
    assert main(["status", "--run", "run-1", "--expected-revision", "1", "--expected-hash", persisted.state_hash], runtime=runtime) == 0
    assert capsys.readouterr().out.strip() == "ENG-1 crew_iterations=0/3 disposition=active freshness=unknown"
```

- [ ] **Step 2: Run the CLI test and verify failure**

Run: `.venv/bin/python -m pytest tests/test_cli.py -v`

Expected: FAIL because `auto_code.cli` does not exist.

- [ ] **Step 3: Implement `argparse` status and package entry points**

Return `2` with a concise stderr message for missing or invalid state. Do not accept a state-root argument or environment override; production receives a launcher-owned runtime configuration through a protected descriptor. Tests inject it directly. Do not print checkpoint bodies or evidence. Add `[project.scripts] auto-code = "auto_code.cli:entrypoint"`; `entrypoint()` raises `SystemExit(main())`.

```python
def main(argv: Sequence[str] | None = None, runtime: TrustedRuntimeConfig | None = None) -> int:
    runtime = runtime or load_launcher_runtime_from_protected_fd()
    args = build_parser().parse_args(argv)
    if args.command == "status":
        generation = RunStateStore(runtime.state_root, args.run).load()
        require_expected(generation, args.expected_revision, args.expected_hash)
        state = generation.state
        print(f"{state.ticket_id} crew_iterations={state.crew_iteration_count}/{state.authorized_iteration_limit} disposition={state.disposition.value} freshness=unknown")
        return 0
    return 2
```

- [ ] **Step 4: Run the complete increment suite**

Run: `.venv/bin/python -m pytest -v`

Expected: PASS.

- [ ] **Step 5: Commit the status command**

```bash
git add pyproject.toml src/auto_code/cli.py src/auto_code/__main__.py tests/test_cli.py
git commit -m "feat: expose orchestration status"
```
