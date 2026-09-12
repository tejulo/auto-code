# Task 3c Preparation Transaction Design

## Purpose

Task 3c composes the existing launcher-owned repository index, state store,
Linear bridge, Git guard, and Task 3b compatibility preflight into the durable
Preparation Transaction. It creates no alternative receipt, catalog, policy,
or persistence authority.

## Scope

- Add `PrepareCoordinator` and deterministic offline tests.
- Add the protected `auto-code prepare` command modes required to probe,
  activate a trusted input, advance a run, and consume a trusted bridge
  receipt.
- Persist a coordinator-owned preparation context under the Authoritative State
  Root. It binds the normalized Ticket Snapshot, original Linear state/revision,
  trusted input reference/hash, selected ticket, compatibility receipt/ref, and
  branch reconciliation information to the active run.
- Use existing `ActiveRunIndex` reservations and activation journals for
  reservation CAS, idempotent activation, and no-candidate replay.

## Non-Goals

- Do not reimplement Project Policy, Task 3b compatibility preflight, catalog
  fetching, receipt persistence, Linear transport, Git/process execution, or
  state/index primitives.
- Do not add direct Linear MCP calls, real Git/network/browser/process effects,
  arbitrary receipt payload input, or state-root access for product subprocesses.
- Do not add OpenSpec, Programmer, verification, browser, finalization, or
  Task 3d behavior.

## Coordinator Model

`PrepareCoordinator` is launcher-composed. It receives injected capabilities
for `ActiveRunIndex`, `RunStateStore`, `LinearGateway`, `TrustedLinearBridge`,
`GitGuard`, `PreflightVersionVerifier`, receipt authority, deterministic clock
and run IDs. CLI arguments provide only repository paths, CAS bindings,
out-of-band bridge references, and challenges; they never provide credentials,
catalogs, model metadata, receipt payloads, policy paths, or state roots.

The coordinator has four public operations:

1. `probe(repository_path)` derives the existing Git repository identity and
   calls `probe_or_reserve` before any Candidate Ticket selection. An indexed
   Active Run always returns `RESUME`; a blocked reservation returns `BLOCKED`;
   only a new reservation exposes an `INPUT_REQUIRED` challenge.
2. `activate_reservation(input_path, input_hash, challenge)` loads only the
   bridge-authenticated Preparation Input. It validates pagination, attestation,
   reservation/repository binding, assignee and milestone resolution, page
   hashes, and positive budget. It selects a Candidate Ticket deterministically.
   No candidate produces the existing durable no-candidate activation result
   with no compatibility, Linear, or Git effect.
3. `advance(run_id, expected_revision, expected_hash)` rechecks the
   descriptor-bound policy before each new external request and returns the
   next persisted Linear request or local branch reconciliation result. It
   never executes a Linear request itself.
4. `consume_receipt(run_id, expected_revision, expected_hash, receipt_ref)`
   accepts only a root-bound bridge receipt reference. It reloads and validates
   the receipt through the existing gateway, applies the matching CAS
   transition, and continues only from the reconciled phase.

## Preparation Context

For an eligible ticket, activation writes a canonical, immutable preparation
context below the selected run's state-root directory before the initial state
is published. Its content is restricted to safe, typed data already supplied
by existing contracts:

- the `TicketSnapshot` and its content hash;
- original workflow state ID and expected external revision captured from the
  trusted input/snapshot;
- trusted Preparation Input reference and content hash;
- selected Candidate Ticket identity;
- the Task 3b `CompatibilityPreflightResult.receipt` hash/reference and runner
  identity;
- later branch name/base binding and Linear request IDs/receipt references.

The initial `RunState` uses this context's hashes and the compatibility
receipt/reference directly. Live catalogs and resolved model metadata remain
only in the verified in-memory preflight result; this Task does not add a new
durable representation for them. The state must satisfy the existing immutable
preparation-bound validators. The context is not CLI supplied and cannot be
replaced after activation; later generations append only verified effects and
branch data through existing state transitions.

## Ordering And Effects

1. Probe/index reservation precedes every Candidate Ticket query.
2. Trusted input validation and Candidate Ticket selection precede snapshot
   persistence.
3. The Task 3b compatibility verifier runs after an eligible snapshot exists
   and before any Linear or Git effect. Its receipt/ref are the sole initial
   compatibility binding; no CLI input may recompute or substitute them.
4. Activation durably creates the initial `SELECTED` run state and index entry
   before requesting a start-state mutation.
5. A start request is persisted through `LinearGateway.persist_pending` before
   the bridge executes it. Only `consume_receipt` may transition
   `IN_PROGRESS_REQUESTED` to `IN_PROGRESS_CONFIRMED`.
6. Branch creation/reconciliation occurs only after confirmed start. A failure
   appends a reconciled Git effect and enters `COMPENSATION_REQUIRED`; it never
   deletes a partial branch automatically.
7. Compensation requests the original state only when its expected external
   revision still matches. A successful verified restore sets `compensated`,
   preserves all prior effect history, and enters Human Review. An authenticated
   resume resets only the permitted preparation phase to `SELECTED`.

## Failures And Safety

All coordinator failures map to typed, secret-free outcomes. Invalid trusted
input, challenge, path/hash, receipt, or CAS bindings are hard rejections
before selection/effects. Policy or compatibility failure enters Human Review
without Linear/Git mutation. Linear receipt mismatch, stale external revision,
or branch ambiguity enters Human Review; an ordinary branch failure enters the
existing compensation path. Every retry reconciles durable state first, and
identical activation replay returns the recorded result.

## Testing

Deterministic tests use temporary state roots and injected fakes only. They
must prove active-run precedence, trusted-input/challenge rejection,
no-candidate replay, snapshot/context immutability, Task 3b preflight ordering,
persist-before-bridge receipt consumption, confirmed-start branch ordering,
compensation, authenticated resume, and no real external effects. The affected
suite includes preparation, compatibility, Linear, Git, state, and catalog
tests; full pytest and `compileall` remain final gates.
