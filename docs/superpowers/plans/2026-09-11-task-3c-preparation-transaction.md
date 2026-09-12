# Task 3c Preparation Transaction Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Compose trusted preparation input, Task 3b compatibility evidence, durable active-run state, Linear receipts, and guarded branch preparation into one recoverable Preparation Transaction.

**Architecture:** `PrepareCoordinator` is a launcher-composed coordinator over existing `ActiveRunIndex`, `RunStateStore`, `TrustedLinearBridge`, `LinearGateway`, `GitGuard`, and `PreflightVersionVerifier` capabilities. It adds only a canonical immutable preparation context for trusted snapshot/original-state data, then drives existing index activation and state CAS APIs; it never performs direct MCP transport or rebuilds Task 3b evidence.

**Tech Stack:** Python 3.12, Pydantic 2, pytest, existing authoritative JSON state/index, launcher-owned Linear bridge, Task 3b compatibility preflight.

**Spec:** `docs/superpowers/specs/2026-09-11-task-3c-preparation-transaction-design.md`

## Global Constraints

- Do not run Git commands or mutate Git state. The repository has an unborn `HEAD`; reports replace commits and Git-generated review packages.
- Preserve Task 3b's `TrustedRuntimeConfig` descriptor shape and consume only `PreflightVersionVerifier.verify(runtime_config, role_config) -> CompatibilityPreflightResult` for compatibility receipt/ref bindings.
- Do not reconstruct catalogs, credentials, policy paths, runtime capabilities, or receipts from CLI input.
- The coordinator persists requests through `LinearGateway.persist_pending()` before bridge execution and consumes only bridge-authenticated receipts with `LinearGateway.consume_receipt()`.
- Probe `ActiveRunIndex` before Candidate Ticket selection. Lock order remains repository index, run ID, then run state.
- No direct network, Linear API, real Git/process/browser, environment/credential lookup, OpenSpec, Active Run state generation outside the existing state/index APIs, or Task 3d behavior in deterministic tests.
- Maintain fixed secret-free public errors/outcomes; do not leak ticket pages, credentials, paths outside trusted roots, raw MCP output, or bridge signatures.

---

### Task 1: Canonical Preparation Context

**Files:**
- Create: `src/auto_code/prepare.py`
- Create: `tests/test_prepare.py`

**Interfaces:**
- Consumes: `TicketSnapshot`, `TrustedPreparationInputRef`, `CompatibilityPreflightResult`, `RunnerIdentity`, `_read_canonical_json`, `_write_new_json`, and the Authoritative State Root.
- Produces: frozen `PreparationContext(run_id, repository_id, ticket_snapshot, ticket_snapshot_hash, original_state_id, original_external_revision, preparation_input_ref, preparation_input_hash, compatibility_receipt_hash, compatibility_receipt_ref, runner_identity)` and `PreparationContextAuthority.write_new(context) -> Path`, `.load_verified(run_id) -> PreparationContext`.
- A context path is exactly `<state-root>/runs/<run-id>/preparation-context.json`; it is canonical JSON, write-once, regular-file-only, and its nested ticket snapshot/hash, input ref/hash, compatibility receipt/ref, repository, and runner bindings must agree.

- [ ] **Step 1: Write failing context-authority tests**

```python
def test_context_write_once_loads_a_complete_preparation_binding(tmp_path: Path, verified_context) -> None:
    authority = PreparationContextAuthority(tmp_path)
    path = authority.write_new(verified_context)
    assert path == tmp_path / "runs" / verified_context.run_id / "preparation-context.json"
    assert authority.load_verified(verified_context.run_id) == verified_context
    assert authority.write_new(verified_context) == path


@pytest.mark.parametrize("tamper", ("snapshot_hash", "input_ref", "receipt_ref", "runner", "path"))
def test_context_rejects_tampered_or_noncanonical_persisted_bindings(tmp_path: Path, verified_context, tamper: str) -> None:
    authority = PreparationContextAuthority(tmp_path)
    authority.write_new(verified_context)
    tamper_context_file(tmp_path, verified_context.run_id, tamper)
    with pytest.raises(PreparationContextError):
        authority.load_verified(verified_context.run_id)
```

- [ ] **Step 2: Run the new tests and confirm RED**

Run: `.venv/bin/python -m pytest tests/test_prepare.py -q -k 'context'`

Expected: collection failure because `auto_code.prepare` and its context authority do not exist.

- [ ] **Step 3: Implement the immutable context boundary**

```python
@dataclass(frozen=True)
class PreparationContext:
    run_id: str
    repository_id: str
    ticket_snapshot: TicketSnapshot
    ticket_snapshot_hash: str
    original_state_id: str
    original_external_revision: str
    preparation_input_ref: TrustedPreparationInputRef
    preparation_input_hash: str
    compatibility_receipt_hash: str
    compatibility_receipt_ref: EvidenceRef
    runner_identity: RunnerIdentity

    def __post_init__(self) -> None:
        if self.ticket_snapshot.content_hash != self.ticket_snapshot_hash:
            raise ValueError("preparation context snapshot is invalid")
        if self.preparation_input_ref.input_hash != self.preparation_input_hash:
            raise ValueError("preparation context input is invalid")
        if self.compatibility_receipt_ref.sha256 != self.compatibility_receipt_hash:
            raise ValueError("preparation context receipt is invalid")


class PreparationContextAuthority:
    def write_new(self, context: PreparationContext) -> Path:
        path = self._path(context.run_id)
        payload = context.to_canonical_payload()
        if not _write_new_json(path, payload) and _read_canonical_json(path, "preparation context") != payload:
            raise PreparationContextError("preparation context cannot be written")
        return path
```

Use the existing safe state-root path helpers. Revalidate every nested Pydantic contract from its JSON dump before writing or returning it. Reject a different payload at an existing path and never accept a caller-controlled path.

- [ ] **Step 4: Run the context tests and affected state tests**

Run: `.venv/bin/python -m pytest tests/test_prepare.py tests/test_state.py -q`

Expected: PASS.

- [ ] **Step 5: Record Task 1 evidence without Git**

Run: `.venv/bin/python -m compileall -q src tests`

Expected: exit `0`. Write `.superpowers/sdd/2026-09-11-task-3c-preparation-transaction/task-1-report.md` with changed files, RED/GREEN output, canonical-path/tamper evidence, and confirmation that no Git or external effect occurred.

### Task 2: Probe And Activate Trusted Preparation

**Files:**
- Modify: `src/auto_code/prepare.py`
- Modify: `tests/test_prepare.py`

**Interfaces:**
- Consumes: Task 1 context authority, the injected repository-bound `GitGuard.repository_identity()`, `ActiveRunIndex.probe_or_reserve()`, `ActiveRunIndex.activate_reservation()`, `TrustedLinearBridge.load_verified_preparation_input()`, `select_ticket()`, `TicketSnapshot.from_untrusted()`, and `PreflightVersionVerifier`.
- Produces: `PrepareProbeResult(kind, repository_id, run_id, reservation_id, challenge)` and `PrepareResult(kind, generation, action_request, run_id)` plus `PrepareCoordinator.probe(repository_path)` and `.activate_reservation(input_path, input_hash, challenge)`.
- `activate_reservation` returns a durable `no_candidate` result without compatibility/Linear/Git work, or a complete initial `RunState` at `PreparationPhase.SELECTED` with all existing preparation bindings before any Linear request.

- [ ] **Step 1: Write failing precedence, activation, and replay tests**

```python
def test_probe_resumes_an_active_run_before_candidate_selection(prepare_harness) -> None:
    prepare_harness.index_active_run("run-existing")
    result = prepare_harness.coordinator.probe(prepare_harness.repository)
    assert result.kind == "RESUME"
    assert result.run_id == "run-existing"
    assert prepare_harness.bridge.preparation_loads == []


def test_activate_persists_snapshot_context_and_compatibility_before_linear_request(prepare_harness) -> None:
    probe = prepare_harness.coordinator.probe(prepare_harness.repository)
    result = prepare_harness.coordinator.activate_reservation(
        prepare_harness.input_path, prepare_harness.input_hash, probe.challenge
    )
    state = prepare_harness.load(result.run_id).state
    assert state.preparation_phase is PreparationPhase.SELECTED
    assert state.ticket_snapshot_hash == prepare_harness.context(result.run_id).ticket_snapshot.content_hash
    assert state.compatibility_receipt_hash == prepare_harness.compatibility.receipt.content_hash
    assert prepare_harness.linear.persist_calls == []


def test_no_candidate_activation_replay_is_stable_and_has_no_external_effect(prepare_harness) -> None:
    probe = prepare_harness.coordinator.probe(prepare_harness.repository)
    first = prepare_harness.activate_without_candidates(probe)
    assert prepare_harness.coordinator.activate_reservation(
        prepare_harness.input_path, prepare_harness.input_hash, probe.challenge
    ) == first
    assert prepare_harness.compatibility.calls == []
    assert prepare_harness.git.calls == []
```

- [ ] **Step 2: Run the activation tests and confirm RED**

Run: `.venv/bin/python -m pytest tests/test_prepare.py -q -k 'probe or activate or candidate'`

Expected: FAIL because `PrepareCoordinator`, `PrepareProbeResult`, and `PrepareResult` do not exist.

- [ ] **Step 3: Implement probe and activation composition**

```python
class PrepareCoordinator:
    def probe(self, repository_path: Path) -> PrepareProbeResult:
        self._require_repository_path(repository_path)
        repository_id = self.git.repository_identity()
        probe = self.index.probe_or_reserve(repository_id, self.reservation_owner())
        if probe.outcome == "active":
            return PrepareProbeResult.resume(repository_id, probe.active_run)
        if probe.outcome == "blocked":
            return PrepareProbeResult.blocked(repository_id, probe.reservation)
        return PrepareProbeResult.input_required(repository_id, probe.reservation)

    def activate_reservation(self, input_path: Path, input_hash: str, challenge: str) -> PrepareResult:
        reference, preparation_input = self.bridge.load_verified_preparation_input(input_path, input_hash)
        reservation = self._require_matching_reservation(reference, challenge)
        candidate = select_ticket(preparation_input.pages, preparation_input.assignee_resolution.id, preparation_input.milestone_resolution.id)
        if candidate is None:
            return self._activate_no_candidate(reservation, reference)
        snapshot = TicketSnapshot.from_untrusted(candidate.raw, captured_at=self.now(), pagination_complete=True, source_page_hashes=reference.source_page_hashes)
        compatibility = self.compatibility.verify(self.runtime_config, self.role_config)
        return self._activate_selected(reservation, reference, snapshot, compatibility)
```

Validate complete pagination, resolved assignee/milestone IDs, reference repository/reservation/challenge hash, exact source-page hashes, and positive budget before selection. Generate the run ID only for a selected candidate. Write the context before calling `ActiveRunIndex.activate_reservation()`; if index activation does not complete, preserve the immutable context for exact replay only. Build `RunState` solely from the verified context and Task 3b result, with `disposition=ACTIVE`, no pending request, no branch, and no effect events.

- [ ] **Step 4: Run preparation, compatibility, and state regressions**

Run: `.venv/bin/python -m pytest tests/test_prepare.py tests/test_compatibility.py tests/test_linear.py tests/test_state.py -q`

Expected: PASS.

- [ ] **Step 5: Record Task 2 evidence without Git**

Run: `.venv/bin/python -m compileall -q src tests`

Expected: exit `0`. Append RED/GREEN, replay, compatibility-before-effect, and no-external-effect evidence to `task-2-report.md`.

### Task 3: Receipt-Driven Start, Branch, And Compensation

**Files:**
- Modify: `src/auto_code/prepare.py`
- Modify: `tests/test_prepare.py`

**Interfaces:**
- Consumes: Task 2 coordinator/context, `load_descriptor_bound_policy()`, `LinearGateway.request_action()`, `.persist_pending()`, `.consume_receipt()`, `GitGuard.create_ticket_branch()`, `GitGuard.reconcile_branch()`, `RunStateStore`, and existing effect/preparation transition validators.
- Produces: `PrepareCoordinator.advance(run_id, expected_revision, expected_hash) -> PrepareResult` and `.consume_receipt(run_id, expected_revision, expected_hash, receipt_ref) -> PrepareResult`.
- `advance` returns one persisted `McpActionRequest` at a time. `consume_receipt` accepts only the bridge-owned receipt loaded by the bound `LinearGateway`; it performs the phase update in the same CAS as receipt reconciliation.

- [ ] **Step 1: Write failing receipt, branch, compensation, and resume tests**

```python
def test_start_request_is_persisted_before_bridge_execution(prepare_harness) -> None:
    run = prepare_harness.activate_selected()
    result = prepare_harness.coordinator.advance(run.run_id, run.revision, run.state_hash)
    assert result.action_request.operation == "compare_and_start_ticket"
    assert prepare_harness.load(run.run_id).state.pending_external_request is not None
    assert prepare_harness.bridge.execute_calls == []


def test_start_receipt_confirms_then_creates_branch(prepare_harness) -> None:
    pending = prepare_harness.start_request()
    confirmed = prepare_harness.consume_successful_start_receipt(pending)
    assert confirmed.generation.state.preparation_phase is PreparationPhase.IN_PROGRESS_CONFIRMED
    branched = prepare_harness.coordinator.advance(confirmed.run_id, confirmed.revision, confirmed.state_hash)
    assert branched.generation.state.preparation_phase is PreparationPhase.BRANCH_CREATED
    assert branched.generation.state.branch == "ENG-1-safe-title"


def test_branch_failure_requires_compare_before_restore_and_human_review(prepare_harness) -> None:
    confirmed = prepare_harness.confirm_started_run()
    prepare_harness.git.fail_branch = True
    compensation = prepare_harness.coordinator.advance(confirmed.run_id, confirmed.revision, confirmed.state_hash)
    assert compensation.generation.state.preparation_phase is PreparationPhase.COMPENSATION_REQUIRED
    restore = prepare_harness.coordinator.advance(*compensation.cas)
    assert restore.action_request.operation == "restore_ticket_state"
    restored = prepare_harness.consume_successful_restore_receipt(restore)
    assert restored.generation.state.disposition is RunDisposition.HUMAN_REVIEW
    assert restored.generation.state.compensated is True
```

- [ ] **Step 2: Run reconciliation tests and confirm RED**

Run: `.venv/bin/python -m pytest tests/test_prepare.py -q -k 'start or branch or compensation or resume'`

Expected: FAIL because coordinator advance/receipt reconciliation does not exist.

- [ ] **Step 3: Implement phase-correct reconciliation**

```python
def advance(self, run_id: str, expected_revision: int, expected_hash: str) -> PrepareResult:
    generation = self._load_expected(run_id, expected_revision, expected_hash)
    load_descriptor_bound_policy(self.runtime_config)
    state = generation.state
    if state.preparation_phase is PreparationPhase.SELECTED:
        request = self.linear.request_action(
            generation, operation="compare_and_start_ticket", entity="ticket", target=state.ticket_id,
            expected_external_revision=self.context.load_verified(run_id).original_external_revision,
            arguments=self._start_arguments(state.ticket_id),
        )
        return PrepareResult.waiting(self.linear.persist_pending(generation, request), request)
    if state.preparation_phase is PreparationPhase.IN_PROGRESS_CONFIRMED:
        return self._reconcile_branch(generation)
    if state.preparation_phase is PreparationPhase.COMPENSATION_REQUIRED:
        return self._request_restore(generation)
    return PrepareResult.current(generation)


def consume_receipt(self, run_id: str, expected_revision: int, expected_hash: str, receipt: TrustedMcpReceipt) -> PrepareResult:
    generation = self._load_expected(run_id, expected_revision, expected_hash)
    state_update = self._receipt_phase_update(generation.state, receipt)
    return PrepareResult.current(self.linear.consume_receipt(generation, receipt, state_update=state_update))
```

`_receipt_phase_update` may confirm only a successful matching start receipt or mark compensation only after a successful matching restore receipt. For Git, append an intention/invocation/observation/reconciliation sequence with the guarded result before setting `BRANCH_CREATED` or `COMPENSATION_REQUIRED`; do not convert a branch failure into a bridge receipt. Reuse an existing branch only through `GitGuard.reconcile_branch()` and its lineage binding. Keep all prior effect events on compensation/resume; a consumed authenticated resume authorization is the only route from compensated Human Review back to `SELECTED`.

- [ ] **Step 4: Run all Task 3c integration regressions**

Run: `.venv/bin/python -m pytest tests/test_prepare.py tests/test_linear.py tests/test_git.py tests/test_state.py tests/test_compatibility.py tests/test_catalog_preflight.py -q`

Expected: PASS.

- [ ] **Step 5: Record Task 3 evidence without Git**

Run: `.venv/bin/python -m compileall -q src tests`

Expected: exit `0`. Append request-before-bridge, receipt/CAS, branch/compensation, resume, fixed-error, and no-external-effect evidence to `task-3-report.md`.

### Task 4: Protected Prepare CLI

**Files:**
- Modify: `src/auto_code/cli.py`
- Modify: `tests/test_cli.py`
- Modify: `tests/test_prepare.py`

**Interfaces:**
- Consumes: protected-FD `TrustedRuntimeConfig`, launcher-composed `PrepareCoordinator`, and Task 3 request/receipt result types.
- Produces CLI modes: `auto-code prepare --repository <path>`; activation-only `auto-code prepare --input <path> --sha256 <hash> --challenge <value>`; later-state `auto-code prepare --run <id> --expected-revision <n> --expected-hash <hash>`; and receipt consumption with one trusted receipt reference accepted only through the launcher-composed bridge authority.
- The CLI has no constructor for coordinator capabilities. Tests inject a coordinator factory; production composition remains launcher-owned.

- [ ] **Step 1: Write failing CLI shape and dispatch tests**

```python
def test_prepare_probe_requires_only_a_repository(cli_harness) -> None:
    assert cli_harness.main(["prepare", "--repository", str(cli_harness.repository)]) == 0
    assert cli_harness.coordinator.probe_calls == [cli_harness.repository]


def test_prepare_rejects_mixed_probe_activation_and_advance_arguments(cli_harness) -> None:
    assert cli_harness.main(["prepare", "--repository", "repo", "--run", "run-1"]) == 2
    assert cli_harness.coordinator.calls == []


def test_prepare_uses_trusted_runtime_before_dispatch(cli_harness) -> None:
    cli_harness.runtime_error = RuntimeConfigurationError("unavailable")
    assert cli_harness.main(["prepare", "--repository", str(cli_harness.repository)]) == 2
    assert cli_harness.coordinator.calls == []
```

- [ ] **Step 2: Run CLI tests and confirm RED**

Run: `.venv/bin/python -m pytest tests/test_cli.py tests/test_prepare.py -q -k 'prepare'`

Expected: FAIL because `prepare` parser modes and coordinator dispatch do not exist.

- [ ] **Step 3: Implement mutually exclusive prepare dispatch**

```python
prepare = commands.add_parser("prepare")
mode = prepare.add_mutually_exclusive_group(required=True)
mode.add_argument("--repository")
mode.add_argument("--input")
mode.add_argument("--run")
prepare.add_argument("--sha256")
prepare.add_argument("--challenge")
prepare.add_argument("--expected-revision")
prepare.add_argument("--expected-hash")
prepare.add_argument("--receipt-ref")

if args.repository is not None:
    result = coordinator.probe(Path(args.repository))
elif args.input is not None:
    result = coordinator.activate_reservation(Path(args.input), args.sha256, args.challenge)
elif args.receipt_ref is not None:
    result = coordinator.consume_receipt(args.run, revision, state_hash, bridge.load_verified_receipt_ref(args.receipt_ref))
else:
    result = coordinator.advance(args.run, revision, state_hash)
```

Require exactly the argument set for each mode before loading the runtime or coordinator. Parse positive integer revision and canonical SHA-256 values locally; route all coordinator and launcher failures to fixed CLI error text without serializing returned ticket, credential, receipt, or path data.

- [ ] **Step 4: Run CLI and complete affected regressions**

Run: `.venv/bin/python -m pytest tests/test_cli.py tests/test_prepare.py tests/test_linear.py tests/test_git.py tests/test_state.py tests/test_compatibility.py -q`

Expected: PASS.

- [ ] **Step 5: Record Task 4 and full verification evidence without Git**

Run: `.venv/bin/python -m pytest -q && .venv/bin/python -m compileall -q src tests`

Expected: full pytest PASS and compilation exit `0`. Write `task-4-report.md` with CLI argument rejection, protected-runtime ordering, all Task 3c evidence, and confirmation that no Git/network/credential/browser/Linear/MCP external action occurred.

## Plan Self-Review

- Spec coverage: Task 1 persists the immutable context; Task 2 covers probe, trusted input, selection, Task 3b preflight, and index activation; Task 3 covers receipt-driven Linear state transitions, branch failure, compensation, and resume; Task 4 adds only protected CLI dispatch.
- Placeholder scan: no deferred implementation markers are present. Every task names concrete files, interfaces, RED command, GREEN command, and no-Git evidence report.
- Type consistency: all coordinator methods use the approved `probe`, `activate_reservation`, and `advance` names; `consume_receipt` is the explicit addition required by the approved design to keep bridge receipt consumption separate from bridge transport.
