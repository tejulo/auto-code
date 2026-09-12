# Task 3d OpenSpec Artifact Adapter Design

## Purpose

Task 3d adds the only product boundary allowed to invoke the locally pinned
OpenSpec CLI. It turns Architect artifact envelopes into immutable staged
files, validation evidence, checkpoint-bound publication, and immutable task
definition/status manifests.

## Scope

- Add `OpenSpecClient` in `src/auto_code/openspec.py` and deterministic tests.
- Invoke the existing `ProcessRunner` only with the verified local OpenSpec
  executable, the configured sandbox policy, bounded environment, and pinned
  `spec-driven` schema.
- Support proposal, specs, design, and tasks in the authoritative dependency
  graph; support multiple files for specs.
- Stage files immutably, validate before checkpointing, and publish visible
  files only for the checkpoint that bound the staged artifact.
- Parse task definitions into the existing immutable contracts and apply only
  monotonic unchecked-to-checked task-status transitions.

## Non-Goals

- No OpenSpec archive command, external/store-backed schemas, direct state
  mutation, Git activity, browser work, provider/network access, or process
  execution outside injected `ProcessRunner` capabilities.
- No Crew supervisor routing, Programmer tools, verification, or finalization.

## Artifact Lifecycle

`ensure_change` creates or verifies one lowercase kebab-case change belonging
to the ticket and Active Run. `instructions` obtains typed JSON instructions
from OpenSpec. `stage_artifact` rejects missing dependencies and writes a
canonical immutable version under the client root without updating visible
paths. `validate_artifact` combines contract validation with relevant OpenSpec
validation and emits a hashed receipt. Checkpoint issuance remains outside the
client. `publish_artifact` accepts only the matching checkpoint and atomically
updates the paths returned by OpenSpec.

The dependency graph is `proposal`, then `specs` and `design`, then `tasks`.
Full change validation occurs only after the four artifact kinds exist. A
published artifact is never rewritten; a new input produces a new staged
version and needs a new checkpoint.

## Publication Recovery Amendment

Each staged version is materialized as a complete immutable change tree that
the OpenSpec validator can inspect directly. The validator runs against that
exact tree; a receipt never attests only to a manifest detached from its
files. Before publication, the client reloads and verifies every currently
published prerequisite hash. It then fsyncs the complete version tree and
atomically replaces one monotonic visible pointer. A pointer may remain at
its current version or advance to a descendant version, but it cannot move
back to an older version. Incomplete/unpointed version trees remain invisible
and are safe to ignore after interruption.

## Complete Change Revision Amendment

Visible state is one complete revision tree per `change_id`, not one pointer
per artifact. Publishing a checkpoint-approved artifact builds a successor
revision from every currently approved artifact plus that artifact, validates
the complete tree, fsyncs it, and atomically advances one `current` pointer.
Readers therefore see either the former complete change or its complete
successor. Publication accepts only a checkpoint verified by the injected
`CheckpointAuthority`; matching caller-created fields are insufficient.

## Task Manifests

Task lines use unique IDs matching `^[1-9][0-9]*(\.[1-9][0-9]*)*$`. Parsing
freezes both ID and text in `TaskDefinitionManifest`. A `TaskStatusManifest`
is bound to that definition hash, rejects unknown IDs and changed definitions,
and can only mark unchecked entries as checked. Passing no completed IDs is
idempotent.

## Testing

Tests use a fake `ProcessRunner`, temporary client roots, deterministic clock
and evidence capabilities. They prove dependency rejection, no archive calls,
idempotent creation/collision checks, immutable staging, checkpoint-matched
publication, CLI/contract validation, multi-file specs, definition immutability,
and monotonic task status. They make no real process, Git, network, browser,
or state-root mutation.
