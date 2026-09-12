# Task 3a Receipt Lifecycle Hardening Design

## Purpose

This amendment hardens the Task 3a preparation foundation after independent review found that a caller could split a signed ticket target from the ticket sent to Linear, revive an old pending request, or compose phase and disposition transitions to bypass current-attempt compensation proof.

It applies to bridge-backed Linear ticket actions and preparation state transitions. It preserves generic non-MCP effect-ledger behavior and leaves Git/process proof authentication to Task 3c.

## Scope

- Canonical ticket dispatch binding in `McpActionRequest` and `TrustedLinearBridge`.
- One launcher-created, root-bound receipt authority shared by `RunStateStore` and `LinearGateway`.
- CAS-bound lifecycle validation for `PendingExternalRequest`.
- Ordered preparation compensation and resume validation.
- Regression tests for every reviewed bypass and valid normal/replay flows.

## Non-Goals

- Do not create a coordinator, CLI command, compatibility service, or Git/process proof mechanism.
- Do not change generic non-MCP ledger semantics.
- Do not add a preparation-attempt identifier. The directed phase graph and trusted ledger ordering provide the required current-episode boundary.
- Do not introduce persisted-data compatibility code. The repository has no shipped persisted run or receipt data.

## Ticket Dispatch Binding

The ticket operations currently allowlisted by the bridge are:

- `query_ticket_projection`
- `query_ticket_state`
- `compare_and_start_ticket`
- `compare_and_complete_ticket`
- `restore_ticket_state`

For those operations, `entity` is `ticket` and the canonical ticket identifier is `arguments["ticket_id"]`. `McpActionRequest` rejects a missing, malformed, or unequal `target` and `ticket_id`. `TrustedLinearBridge.execute()` repeats the validation before invoking MCP and derives the receipt target from the validated ticket identifier. An invalid binding produces no MCP call or receipt.

Other action shapes remain generic until an operation-specific contract is required.

## Receipt Authority

`BridgeReceiptAuthority` is a launcher-created capability bound to exactly one Authoritative State Root, bridge identity, MCP server identity, and signing key. It owns receipt loading and validation:

1. Resolve only a typed receipt evidence reference under its own root.
2. Validate the persisted receipt shape, receipt path, content hash, bridge/MCP identities, and signature.
3. Return the validated receipt or a secret-free failure.

`RunStateStore` accepts this concrete root-bound authority, rejects an authority for another root, and uses it rather than caller-supplied receipt data. `LinearGateway` must use the exact authority attached to its store; it cannot receive a divergent boolean verifier. Launcher composition is the only production path that creates this authority.

## Pending Request Lifecycle

`PendingExternalRequest.expected_revision` and `expected_state_hash` bind a request to the predecessor generation in which it was created.

For every bridge-backed MCP request:

1. Creation occurs from a state with no pending request, appends exactly the matching intention, enters `WAITING_MCP`, and requires the pending source CAS binding to equal the predecessor generation.
2. While unresolved, the pending record is immutable. It cannot be replaced, detached, or reattached, including during `WAITING_MCP` self-transitions or Human Review.
3. Removal occurs only in the same CAS as the authority-validated invocation, observation, and reconciliation sequence for that exact request. The receipt must match run ID, request/effect IDs and hashes, operation, expected CAS/external revision, payload hash, outcome, target, receipt evidence, and timestamped ledger events.
4. An exact receipt replay remains idempotent only after its reconciliation already exists. A mismatched or stale receipt leaves the current generation unchanged.

This blocks a receipt produced against an old local generation from becoming actionable through a later pending mutation.

## Preparation Ordering

Preparation-specific transitions retain the existing directed phase graph and add these cross-field rules:

1. `IN_PROGRESS_CONFIRMED -> COMPENSATION_REQUIRED` requires both prior and new disposition `ACTIVE` plus a newly appended `create_ticket_branch` failure. Human Review cannot be staged before beginning compensation.
2. A successful `restore_ticket_state` receipt may move a run to compensated Human Review only from an already persisted `COMPENSATION_REQUIRED` phase. Its receipt is validated by the shared authority and must follow the current preparation episode's successful start record.
3. `COMPENSATION_REQUIRED + HUMAN_REVIEW -> SELECTED + ACTIVE` is the sole successful-compensation resume. It requires exactly one consumed trusted resume authorization and a current-episode authenticated restore. A direct Human Review-to-active transition may not leave the run in `COMPENSATION_REQUIRED`.
4. Unrelated unsafe conditions may still enter Human Review while confirmed. They must be authentically resumed to `ACTIVE` before any later compensation episode can begin.

`compensated` remains monotonic historical fact. Current-episode proof is derived from the trusted ordered ledger after the latest successful start reconciliation, not inferred from the historical flag or a disposition edge.

## Errors And Tests

Failures expose only fixed, secret-free messages and occur before state publication or MCP invocation where applicable.

Test-first regressions must cover:

- target and `arguments.ticket_id` disagreement rejects before an MCP call;
- a signed receipt for another ticket, run, request, source CAS, effect, or root cannot advance a run;
- missing, forged, mismatched, or replayed evidence cannot remove a pending request;
- pending replacement, detachment, and reattachment are rejected;
- a valid bridge receipt advances the matching preparation phase in its receipt CAS;
- valid exact replay remains idempotent;
- staged Human Review cannot bypass fresh compensation restore after a prior resumed attempt;
- valid branch-failure, restore, and authorized resume ordering still succeeds.

Finish with focused contract/state/Linear tests, the full test suite, compilation, and an independent scoped review.
