# OpenSpec Artifact Adapter Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a checkpoint-bound, immutable adapter for OpenSpec artifact units and task manifests.

**Architecture:** `OpenSpecClient` is the sole adapter over injected `ProcessRunner`; it stages and validates artifacts without publishing them. Existing checkpoint/state authorities bind and publish validated stages; no new persistence authority is introduced.

**Tech Stack:** Python 3.12, Pydantic 2, pytest, existing ProcessRunner and contracts, OpenSpec 1.12.0.

**Spec:** `docs/superpowers/specs/2026-09-11-task-3d-openspec-artifact-adapter-design.md`

## Global Constraints

- Do not run Git commands or mutate Git state.
- Use only injected fake process/evidence capabilities in tests; no real process, network, browser, Linear, provider, credential, or state-root effects.
- Permit only local `spec-driven` OpenSpec 1.12.0 behavior; never invoke `archive`.
- Preserve immutable staging, checkpoint-only publication, safe relative paths, canonical hashes, and fixed public errors.
- Task IDs are unique numeric dotted identifiers; task-status changes are monotonic and bound to exact definitions.
- Validate the complete staged change tree, recheck published prerequisite hashes before publication, and advance one authority-verified monotonic pointer per complete change revision; never publish individual artifact files or accept field-matched forged checkpoints.

---

### Task 1: Typed OpenSpec Process Boundary

**Files:**
- Create: `src/auto_code/openspec.py`
- Create: `tests/test_openspec.py`

**Interfaces:**
- Produces: `OpenSpecClient.ensure_change(change_id, ticket_id, run_id) -> None` and `.instructions(change_id, artifact) -> ArtifactInstructions`.
- Consumes: injected `ProcessRunner`, process/evidence configuration, and existing `ArtifactInstructions`/artifact contracts.

- [ ] **Step 1: Write failing boundary tests**

```python
def test_ensure_change_is_idempotent_and_rejects_foreign_collision(client, process) -> None:
    client.ensure_change("eng-1-change", "ENG-1", "run-1")
    client.ensure_change("eng-1-change", "ENG-1", "run-1")
    process.existing_change_owner = ("ENG-2", "run-2")
    with pytest.raises(ChangeOwnershipError):
        client.ensure_change("eng-1-change", "ENG-1", "run-1")

def test_instructions_use_json_and_never_archive(client, process) -> None:
    client.instructions("eng-1-change", "proposal")
    assert ("instructions", "proposal", "--change", "eng-1-change", "--json") in process.argvs
    assert all("archive" not in argv for argv in process.argvs)
```

- [ ] **Step 2: Confirm RED**

Run: `.venv/bin/python -m pytest tests/test_openspec.py -q -k 'ensure_change or instructions'`

Expected: collection fails because `auto_code.openspec` does not exist.

- [ ] **Step 3: Implement minimal typed process calls**

Implement strict artifact-kind/change-ID validation; call `openspec new change <id> --json` and `openspec instructions <artifact> --change <id> --json` through the injected runner; parse only trusted JSON output into existing typed contracts; convert process/schema/ownership failures to fixed adapter exceptions.

- [ ] **Step 4: Confirm GREEN**

Run: `.venv/bin/python -m pytest tests/test_openspec.py -q -k 'ensure_change or instructions'`

Expected: PASS.

### Task 2: Immutable Artifact Staging And Publication

**Files:**
- Modify: `src/auto_code/openspec.py`
- Modify: `tests/test_openspec.py`

**Interfaces:**
- Produces: `stage_artifact(change_id, envelope) -> StagedArtifactManifest`, `validate_artifact(staged) -> ValidationReceipt`, and `publish_artifact(staged, checkpoint) -> tuple[Path, ...]`.
- Consumes: Task 1 instructions, existing `ArtifactEnvelope`, `Checkpoint`, hashing, and safe filesystem helpers.

- [ ] **Step 1: Write failing lifecycle tests**

```python
def test_tasks_require_published_specs_and_design(client, tasks_envelope) -> None:
    with pytest.raises(ArtifactDependencyError):
        client.stage_artifact("eng-1-change", tasks_envelope)

def test_publish_requires_matching_checkpoint_and_keeps_stage_immutable(client, staged, checkpoint, other_checkpoint) -> None:
    with pytest.raises(CheckpointMismatch):
        client.publish_artifact(staged, other_checkpoint)
    assert not client.visible_path(staged).exists()
    assert client.publish_artifact(staged, checkpoint)
    assert client.stage_artifact(staged.change_id, staged.envelope) == staged
```

- [ ] **Step 2: Confirm RED**

Run: `.venv/bin/python -m pytest tests/test_openspec.py -q -k 'stage or publish or dependency'`

Expected: FAIL because lifecycle methods do not exist.

- [ ] **Step 3: Implement staged lifecycle**

Write canonical immutable staged versions below the adapter root using safe no-follow paths. Enforce `proposal -> specs/design -> tasks`; validate staged manifests and CLI validation output before returning a hashed receipt. Only a checkpoint matching staged output and validation receipt may atomically publish returned visible paths. Support multi-file `specs/**` paths; reject traversal, duplicate paths, mismatched content hashes, and external roots.

- [ ] **Step 4: Confirm GREEN**

Run: `.venv/bin/python -m pytest tests/test_openspec.py tests/test_state.py -q`

Expected: PASS.

### Task 3: Immutable Task Definitions And Final Validation

**Files:**
- Modify: `src/auto_code/openspec.py`
- Modify: `tests/test_openspec.py`

**Interfaces:**
- Produces: `parse_task_definitions(staged) -> TaskDefinitionManifest`, `transition_task_status(definitions, before, completed_task_ids) -> TaskStatusManifest`, and `validate_complete_change(change_id) -> ValidationReceipt`.

- [ ] **Step 1: Write failing definition/status tests**

```python
def test_definitions_are_immutable_and_status_is_monotonic(client, definitions, changed, empty_status) -> None:
    checked = client.transition_task_status(definitions, empty_status, ("1.1",))
    assert client.transition_task_status(definitions, checked, ()) == checked
    with pytest.raises(TaskDefinitionChanged):
        client.transition_task_status(changed, checked, ())
    with pytest.raises(UnknownTaskId):
        client.transition_task_status(definitions, checked, ("9.9",))
```

- [ ] **Step 2: Confirm RED**

Run: `.venv/bin/python -m pytest tests/test_openspec.py -q -k 'definition or status or complete'`

Expected: FAIL because task parsing/status methods do not exist.

- [ ] **Step 3: Implement frozen definition/status semantics**

Parse only unique explicit numeric task IDs and their nonempty text into existing manifests. Bind every status to the exact definition hash; retain prior checked items and reject definition drift or unknown IDs. Require all four published artifact kinds before full-change OpenSpec validation; never archive.

- [ ] **Step 4: Final verification**

Run: `.venv/bin/python -m pytest tests/test_openspec.py tests/test_router.py tests/test_state.py -q && .venv/bin/python -m compileall -q src tests`

Expected: PASS and exit `0`.
