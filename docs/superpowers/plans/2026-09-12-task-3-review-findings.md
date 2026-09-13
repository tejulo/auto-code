# Task 3 Review Findings Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close the five Task 3 finalization trust, baseline, retry, and Active Run Index recovery findings without extending Task 4 or Task 5.

**Architecture:** The launcher, not the ticket process, owns finalization composition and trust. Immutable Active Run preparation bindings determine ticket data; durable state and the Effect Ledger determine retry timing and index-release recovery.

**Tech Stack:** Python 3.12, Pydantic contracts, Ed25519, Unix sockets, immutable RunState CAS, pytest.

**Spec:** User-approved Task 3 review-finding design, 2026-09-12.

## Global Constraints

- Do not modify Task 4 or Task 5 behavior or files.
- Do not invoke provider, Linear, browser, target-repository Git, or push effects in tests.
- Do not dispatch subagents.
- Use test-driven development with recorded RED and GREEN evidence.
- Append verification evidence to the ignored Task 3 report and commit product/test changes only.

---

### Task 1: Launcher-Pinned Finalization Trust

**Files:**
- Modify: `src/auto_code/finalization_service.py`
- Modify: `src/auto_code/contracts.py`
- Modify: `src/auto_code/state.py`
- Test: `tests/test_finalization_service.py`

**Interfaces:**
- Consumes: immutable `RunState` preparation binding and the fixed-FD descriptor/socket identity.
- Produces: a protected trust envelope whose public-key hash, state root, run ID, descriptor hash, and socket identity can be verified before descriptor or response signatures are accepted.

- [ ] **Step 1: Write failing trust-substitution tests**

```python
def test_protected_capability_rejects_attacker_descriptor_and_trust_key_pair(...):
    assert invoke_protected_capability(...) raises FinalizationServiceError
```

- [ ] **Step 2: Run the focused trust tests and verify failure**

Run: `/home/angel/workspace/tejulo/auto-code/.venv/bin/python -m pytest tests/test_finalization_service.py -k trust -v`

- [ ] **Step 3: Bind trust to immutable launcher state**

```python
if trust.public_key_hash != state.finalization_public_key_hash:
    raise FinalizationServiceError("launcher finalization trust binding is invalid")
```

- [ ] **Step 4: Run focused trust tests and verify success**

Run: `/home/angel/workspace/tejulo/auto-code/.venv/bin/python -m pytest tests/test_finalization_service.py -k trust -v`

### Task 2: Launcher-Only Finalizer Composition And Immutable Ticket Baseline

**Files:**
- Modify: `src/auto_code/finalization_service.py`
- Modify: `src/auto_code/finalizer.py`
- Modify: `src/auto_code/run_index.py`
- Test: `tests/test_finalizer.py`
- Test: `tests/test_finalization_service.py`

**Interfaces:**
- Consumes: launcher-owned service capabilities and Active Run preparation context.
- Produces: a non-public installed composition path and a finalizer baseline loader that returns only the state-bound ticket snapshot, original state ID, and external revision.

- [ ] **Step 1: Write failing constructor and baseline-substitution tests**

```python
def test_public_finalizer_constructor_cannot_accept_artifact_or_git_callbacks(...): ...
def test_projection_rejects_baseline_not_bound_to_preparation_context(...): ...
```

- [ ] **Step 2: Run focused composition/baseline tests and verify failure**

Run: `/home/angel/workspace/tejulo/auto-code/.venv/bin/python -m pytest tests/test_finalizer.py tests/test_finalization_service.py -k 'constructor or baseline or projection' -v`

- [ ] **Step 3: Implement launcher protocol and preparation-bound baseline loading**

```python
baseline = launcher.load_finalization_baseline(state)
if baseline.ticket_snapshot.content_hash != state.ticket_snapshot_hash:
    raise FinalizationError("ticket baseline changed")
```

- [ ] **Step 4: Run focused composition/baseline tests and verify success**

Run: `/home/angel/workspace/tejulo/auto-code/.venv/bin/python -m pytest tests/test_finalizer.py tests/test_finalization_service.py -k 'constructor or baseline or projection' -v`

### Task 3: Durable Finalization Retry Eligibility

**Files:**
- Modify: `src/auto_code/contracts.py`
- Modify: `src/auto_code/finalizer.py`
- Modify: `src/auto_code/state.py`
- Test: `tests/test_finalizer.py`
- Test: `tests/test_state.py`

**Interfaces:**
- Consumes: `Retry-After` wait observations and `FinalizationPolicy.total_retry_wait_seconds`.
- Produces: persisted cumulative wait/next eligibility metadata that survives `RunStateStore.load()` and does not alter `crew_iteration_count`.

- [ ] **Step 1: Write failing restart, clock, and exhaustion tests**

```python
def test_retry_after_wait_survives_restart_until_next_eligibility(...): ...
def test_cumulative_retry_wait_exhaustion_enters_human_review_without_iteration(...): ...
```

- [ ] **Step 2: Run focused retry tests and verify failure**

Run: `/home/angel/workspace/tejulo/auto-code/.venv/bin/python -m pytest tests/test_finalizer.py tests/test_state.py -k 'retry or wait or eligibility' -v`

- [ ] **Step 3: Persist and reconcile retry timing**

```python
if cumulative_wait + retry_after > policy.total_retry_wait_seconds:
    return self._human_review(generation)
```

- [ ] **Step 4: Run focused retry tests and verify success**

Run: `/home/angel/workspace/tejulo/auto-code/.venv/bin/python -m pytest tests/test_finalizer.py tests/test_state.py -k 'retry or wait or eligibility' -v`

### Task 4: Crash-Safe Active Run Index Release

**Files:**
- Modify: `src/auto_code/finalizer.py`
- Modify: `src/auto_code/contracts.py`
- Modify: `src/auto_code/state.py`
- Test: `tests/test_finalizer.py`
- Test: `tests/test_state.py`

**Interfaces:**
- Consumes: exact pre-release Active Run Index binding and immutable `DONE` state.
- Produces: a persisted release intention/observation that can reconcile a missing index entry to `DONE` after a crash.

- [ ] **Step 1: Write failing post-release crash recovery tests**

```python
def test_crash_after_index_release_recovers_done_without_human_review(...): ...
def test_unbound_missing_index_entry_requires_human_review(...): ...
```

- [ ] **Step 2: Run focused release tests and verify failure**

Run: `/home/angel/workspace/tejulo/auto-code/.venv/bin/python -m pytest tests/test_finalizer.py tests/test_state.py -k 'index and release' -v`

- [ ] **Step 3: Ledger and reconcile release**

```python
intended, effect_id = self._intend(generation, "release_active_run", state.repository_id)
index.release(...)
return self._record_local_result(intended, effect_id, "release_active_run", EffectOutcome.SUCCESS, ...)
```

- [ ] **Step 4: Run focused release tests and verify success**

Run: `/home/angel/workspace/tejulo/auto-code/.venv/bin/python -m pytest tests/test_finalizer.py tests/test_state.py -k 'index and release' -v`

### Task 5: Task 3 Evidence And Delivery

**Files:**
- Modify: `.superpowers/sdd/2026-09-05-04-ralph-and-finalization/task-3-report.md`

- [ ] **Step 1: Run required focused suite**

Run: `/home/angel/workspace/tejulo/auto-code/.venv/bin/python -m pytest tests/test_finalizer.py tests/test_finalization_service.py tests/test_git.py tests/test_linear.py tests/test_supervisor.py tests/test_state.py tests/test_cli.py -v`

- [ ] **Step 2: Run full verification**

Run: `/home/angel/workspace/tejulo/auto-code/.venv/bin/python -m pytest -q && /home/angel/workspace/tejulo/auto-code/.venv/bin/python -m compileall -q src tests && git diff --check`

- [ ] **Step 3: Append exact RED/GREEN and verification evidence**

```markdown
## Task 3 Review Finding Fix Wave

- RED: ...
- GREEN: ...
- Focused suite: ...
- Full suite: ...
```

- [ ] **Step 4: Commit product and test changes**

```bash
git add src tests docs/superpowers/plans/2026-09-12-task-3-review-findings.md
```
