# Finalization Launcher Boundary Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Execute finalization only through a capability-isolated launcher service and recover terminal index release exactly after crashes.

**Architecture:** Preparation provisions a dedicated finalization public key and immutable hash in each Active Run. A launcher-only entrypoint composes all finalizer dependencies, signs descriptor/trust FDs, and serves identifier-only IPC; repository CLI remains a client. `ActiveRunIndex` persists a hash-bound release receipt before deletion so a terminal run can reconcile only a proven missing index.

**Tech Stack:** Python 3.12, Ed25519, Unix domain sockets, atomic JSON/fsync state files, pytest.

**Spec:** `docs/superpowers/specs/2026-09-13-finalization-launcher-boundary-design.md`

## Global Constraints

- The Authoritative State Root is launcher-owned and is never mounted into product subprocesses.
- The finalization key pair is dedicated and distinct from the Repair activation key.
- The target repository CLI accepts only identifiers and protected descriptors; it never receives keys, callbacks, Git, Linear, index, or artifact dependencies.
- Every trust, artifact, receipt, socket, state, and index mismatch fails closed before an external effect.
- Retry wait accounting must not increment a Crew Iteration.
- Browser E2E is not required; use deterministic fakes and local Unix sockets.

---

### Task 1: Provision Dedicated Finalization Trust

**Files:**
- Modify: `src/auto_code/contracts.py`, `src/auto_code/state.py`, `src/auto_code/prepare.py`
- Modify: `src/auto_code/finalization_service.py`
- Test: `tests/test_prepare.py`, `tests/test_finalization_service.py`, `tests/test_state.py`

**Interfaces:**
- Produces immutable `RunState.finalization_public_key: str` and `RunState.finalization_public_key_hash: str`.
- Produces `validate_finalization_capability(..., expected_state_root: Path, expected_finalization_key_hash: str)` with no optional trust-binding parameters.

- [ ] **Step 1: Write failing provisioning and rejection tests**

```python
def test_preparation_persists_dedicated_finalization_key_hash(...):
    state = prepare_run(...)
    assert state.finalization_public_key_hash == sha256_hex(state.finalization_public_key)
    assert state.finalization_public_key != state.repair_activation_public_key

def test_capability_rejects_replaced_descriptor_and_trust_fds(...):
    with pytest.raises(FinalizationCapabilityError, match="finalization trust"):
        validate_finalization_capability(attacker_descriptor, attacker_trust, state_root, run.key_hash)
```

- [ ] **Step 2: Run the tests to verify failure**

Run: `pytest tests/test_prepare.py tests/test_finalization_service.py tests/test_state.py -q`

Expected: FAIL because dedicated fields and mandatory validation do not exist.

- [ ] **Step 3: Implement immutable state fields and mandatory descriptor binding**

```python
@dataclass(frozen=True)
class FinalizationTrustBinding:
    public_key: str
    public_key_hash: str

def require_finalization_trust(state: RunState, trust: TrustEnvelope) -> None:
    if trust.public_key != state.finalization_public_key or sha256_hex(trust.public_key) != state.finalization_public_key_hash:
        raise FinalizationCapabilityError("finalization trust binding mismatch")
```

Generate the key during preparation, validate its canonical encoding/hash, preserve it in every legal state transition, and bind descriptor validation to the state root, run identity, revision, generation, and key hash.

- [ ] **Step 4: Run focused tests**

Run: `pytest tests/test_prepare.py tests/test_finalization_service.py tests/test_state.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/auto_code/contracts.py src/auto_code/state.py src/auto_code/prepare.py src/auto_code/finalization_service.py tests/test_prepare.py tests/test_finalization_service.py tests/test_state.py
git commit -m "feat: bind finalization to dedicated trust"
```

### Task 2: Compose Launcher-Owned Finalization

**Files:**
- Create: `src/auto_code/finalization_launcher.py`
- Modify: `src/auto_code/finalization_service.py`, `src/auto_code/finalizer.py`, `src/auto_code/cli.py`
- Test: `tests/test_finalization_launcher.py`, `tests/test_finalization_service.py`, `tests/test_cli.py`

**Interfaces:**
- Produces `FinalizationLauncher.serve(run_id: str, expected_revision: int, expected_generation_hash: str) -> None`.
- Consumes only launcher-owned `RunStateStore`, `ActiveRunIndex`, bridge, Git guard, policy and artifact authority.

- [ ] **Step 1: Write failing entrypoint and CLI-boundary tests**

```python
def test_launcher_composes_finalizer_without_ticket_supplied_callbacks(...):
    launcher = FinalizationLauncher.from_runtime(runtime)
    assert launcher.serve_descriptor(run_id, revision, generation_hash).operation == "finalize"

def test_main_rejects_finalizer_or_handler_injection():
    with pytest.raises(TypeError):
        main(["finalize", "--run-id", "run"], finalizer_factory=lambda: None)
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest tests/test_finalization_launcher.py tests/test_finalization_service.py tests/test_cli.py -q`

Expected: FAIL because no launcher composition exists and ticket-facing injection remains reachable.

- [ ] **Step 3: Implement launcher composition and artifact authority**

```python
class FinalizationLauncher:
    def serve(self, run_id: str, expected_revision: int, expected_generation_hash: str) -> None:
        state = self._store.load_exact(run_id, expected_revision, expected_generation_hash)
        artifacts = self._artifacts.load_for(state)
        service = _LauncherFinalizationService(self._key, self._state_root, self._handlers(state, artifacts))
        service.serve_once(...)
```

`load_for` must obtain the baseline only from `PreparationContextAuthority` and all approval/evidence objects by hashes persisted in `RunState`. Remove ticket-facing construction paths that accept dependencies or callbacks; retain test fakes only through the launcher runtime harness.

- [ ] **Step 4: Run focused tests**

Run: `pytest tests/test_finalization_launcher.py tests/test_finalization_service.py tests/test_finalizer.py tests/test_cli.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/auto_code/finalization_launcher.py src/auto_code/finalization_service.py src/auto_code/finalizer.py src/auto_code/cli.py tests/test_finalization_launcher.py tests/test_finalization_service.py tests/test_cli.py
git commit -m "feat: compose finalization in launcher"
```

### Task 3: Persist Exact Active Run Index Release

**Files:**
- Modify: `src/auto_code/contracts.py`, `src/auto_code/state.py`, `src/auto_code/run_index.py`, `src/auto_code/finalizer.py`
- Test: `tests/test_run_index.py`, `tests/test_finalizer.py`, `tests/test_state.py`

**Interfaces:**
- Produces `IndexReleaseReceipt(repository_id, run_id, prior_revision, prior_hash, terminal_generation_hash, receipt_hash)`.
- Produces `ActiveRunIndex.verify_release(receipt: IndexReleaseReceipt) -> None`.

- [ ] **Step 1: Write failing crash-recovery tests**

```python
def test_done_recovery_accepts_missing_index_only_with_exact_receipt(...):
    receipt = index.release(...)
    crash_before_release_marker_cas()
    assert finalizer.advance(run_id).finalization_index_released is True

def test_done_recovery_rejects_missing_index_without_matching_receipt(...):
    remove_index_without_receipt()
    assert finalizer.advance(run_id).disposition is RunDisposition.HUMAN_REVIEW
```

- [ ] **Step 2: Run tests to verify failure**

Run: `pytest tests/test_run_index.py tests/test_finalizer.py tests/test_state.py -q`

Expected: FAIL because missing-index recovery accepts a non-null binding without a verified receipt.

- [ ] **Step 3: Implement fsynced tombstone and exact reconciliation**

```python
def release(...) -> IndexReleaseReceipt:
    receipt = IndexReleaseReceipt.from_record(record, terminal_generation_hash)
    atomic_write_fsync(self._release_path(receipt), receipt.canonical_json())
    remove_exact_index_record(record)
    return receipt
```

Store the receipt/binding in the terminal release-marker transition. During restart, recompute and validate every receipt field against the terminal state and durable tombstone before marking released. Treat all missing, malformed, substituted, or mismatched receipts as Human Review.

- [ ] **Step 4: Run focused tests**

Run: `pytest tests/test_run_index.py tests/test_finalizer.py tests/test_state.py -q`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/auto_code/contracts.py src/auto_code/state.py src/auto_code/run_index.py src/auto_code/finalizer.py tests/test_run_index.py tests/test_finalizer.py tests/test_state.py
git commit -m "fix: reconcile finalization index release"
```

### Task 4: End-to-End Regression and Independent Review

**Files:**
- Modify: `tests/test_finalization_launcher.py`, `tests/test_finalization_service.py`, `tests/test_finalizer.py`
- Modify: `.superpowers/sdd/2026-09-05-04-ralph-and-finalization/task-3-report.md` (ignored evidence only)

**Interfaces:**
- Consumes all Task 1-3 contracts and verifies the protected IPC path through the launcher harness.

- [ ] **Step 1: Add cross-boundary failure regressions**

```python
def test_attacker_cannot_finalize_with_replaced_fd4_and_fd5(...): ...
def test_launcher_replays_completed_nonce_without_second_git_effect(...): ...
def test_index_tombstone_cannot_authorize_another_run(...): ...
```

- [ ] **Step 2: Run the Task 3 focused suite**

Run: `pytest tests/test_prepare.py tests/test_finalization_launcher.py tests/test_finalization_service.py tests/test_finalizer.py tests/test_run_index.py tests/test_state.py tests/test_cli.py -q`

Expected: PASS.

- [ ] **Step 3: Run repository verification**

Run: `pytest -q && python -m compileall -q src && git diff --check HEAD~4..HEAD`

Expected: all tests pass, compilation succeeds, and no whitespace errors are reported.

- [ ] **Step 4: Record evidence and request independent review**

Append exact commands, counts, commit SHAs, and browser-skip rationale to the ignored Task 3 report. Build a review package from the Task 3 baseline through the current HEAD and obtain a read-only review against the Task 3 brief and this specification.

- [ ] **Step 5: Commit regression coverage**

```bash
git add tests/test_finalization_launcher.py tests/test_finalization_service.py tests/test_finalizer.py
```
