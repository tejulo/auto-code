# Task 3a Receipt Lifecycle Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `superpowers:subagent-driven-development` (recommended) or `superpowers:executing-plans` to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent forged, stale, split-target, or out-of-order bridge receipts from advancing a preparation run.

**Architecture:** Introduce one launcher-created `BridgeReceiptAuthority` bound to the Authoritative State Root and share that exact authority between `RunStateStore` and `LinearGateway`. Validate ticket dispatch before bridge invocation, turn each pending MCP request into a CAS-bound lifecycle, and derive current compensation proof from authority-validated receipt history after the latest successful start.

**Tech Stack:** Python 3.12, Pydantic contracts, canonical JSON/HMAC receipts, pytest.

**Spec:** `docs/superpowers/specs/2026-09-06-task-3a-receipt-lifecycle-hardening-design.md`

## Global Constraints

- Read the hardening spec and `task-3a-foundation-brief.md` before each task; the hardening spec controls if it conflicts with the earlier Task 3a brief.
- Preserve immutable generations, CAS, append-only ledger prefixes, replay behavior, secret-free errors, and bridge-only Linear effects.
- Do not create coordinator/CLI/compatibility/Git-process functionality; Task 3c owns coordinator and Git/process proof authentication.
- Keep generic non-MCP ledger semantics unchanged. Only bridge-backed pending requests receive the new receipt lifecycle rules.
- Use `repository_id` as the canonical repository spelling; do not add `BLOCKED` to `RunDisposition`.
- Use real `TrustedLinearBridge`, `RunStateStore`, and `LinearGateway` in boundary tests; fake only `LinearMcpClient`.
- Follow TDD exactly: add one focused test, observe the expected red failure, add the smallest implementation, then observe green before the next behavior.
- Record red/green commands, results, files changed, and self-review in `.superpowers/sdd/2026-09-05-03-integrations-and-verification/task-3a-report.md`.
- Do not commit, push, branch, stash, reset, checkout, or change unrelated files. This repository has an unborn Git baseline and no commit was requested.

---

## File Structure

- `src/auto_code/contracts.py`: validates the canonical ticket target for allowlisted ticket MCP actions and retains it in the signed request/receipt contract.
- `src/auto_code/state.py`: owns `BridgeReceiptAuthority`, root-bound receipt loading, pending lifecycle validation, and preparation phase/disposition ordering.
- `src/auto_code/linear.py`: requires the store's exact receipt authority and persists/consumes requests through the strengthened lifecycle.
- `src/auto_code/mcp_bridge.py`: constructs the authority, revalidates ticket dispatch before MCP invocation, and signs the canonical target.
- `tests/test_contracts.py`: contract-level ticket action validation.
- `tests/test_linear.py`: real bridge/gateway dispatch, authority, pending, receipt, and replay boundaries.
- `tests/test_state.py`: preparation compensation/resume state-machine regressions.
- `.superpowers/sdd/2026-09-05-03-integrations-and-verification/task-3a-report.md`: durable implementation evidence.

## Shared Interfaces

- `McpActionRequest.validated_ticket_target(self) -> str | None`: for the five listed ticket operations, return the validated `arguments["ticket_id"]` only when it equals `target` and `entity == "ticket"`; return `None` for non-ticket operations; otherwise raise `ValueError("MCP ticket target does not match ticket_id")`.
- `BridgeReceiptAuthority(state_root: Path, bridge_identity: str, mcp_server_identity: str, signing_key: bytes)`: normalize and retain one state root, bridge identity, server identity, and signing key.
- `BridgeReceiptAuthority.state_root -> Path`: return the normalized root used for every trusted receipt read.
- `BridgeReceiptAuthority.verify(receipt: TrustedMcpReceipt) -> bool`: return true only when the receipt is signed by this authority and its canonical persisted content exists at the authority root.
- `BridgeReceiptAuthority.load_verified_receipt(evidence: EvidenceRef) -> TrustedMcpReceipt`: require bridge receipt evidence under `trusted-mcp/receipts/`, load canonical JSON under `state_root`, and return only a hash/path/identity/signature-verified receipt; otherwise raise a fixed `ValueError`.
- `RunStateStore(root, run_id, *, authorization_verifier=None, receipt_authority=None)`: accept `None` for state-only use, or a `BridgeReceiptAuthority` whose `state_root` exactly equals the store root.
- `LinearGateway(store, receipt_authority)`: require `store.receipt_authority is receipt_authority`; every gateway receipt check uses that authority.
- `TrustedLinearBridge.receipt_authority`: expose the single authority constructed with the bridge; remove the separately injectable verifier property.

### Task 1: Bind Ticket Dispatch And Receipt Authority

**Files:**
- Modify: `src/auto_code/contracts.py:1396-1635`
- Modify: `src/auto_code/state.py:1-70, 368-400`
- Modify: `src/auto_code/mcp_bridge.py:72-169`
- Modify: `src/auto_code/linear.py:1-60, 184-191`
- Modify: `tests/test_contracts.py`
- Modify: `tests/test_linear.py`
- Modify: `tests/test_state.py:248-318`

**Interfaces:**
- Consumes: current `McpActionRequest`, `TrustedMcpReceipt`, `BridgeReceiptVerifier`, `TrustedLinearBridge`, and `RunStateStore` construction.
- Produces: `McpActionRequest.validated_ticket_target()`, `BridgeReceiptAuthority`, `TrustedLinearBridge.receipt_authority`, and exact store/gateway authority identity binding.

- [ ] **Step 1: Write a contract test for split ticket dispatch**

```python
def test_ticket_action_rejects_a_target_that_differs_from_its_ticket_id() -> None:
    with pytest.raises(ValidationError, match="ticket target"):
        McpActionRequest.create(
            operation="compare_and_start_ticket",
            entity="ticket",
            target="ENG-1",
            expected_external_revision=None,
            run_id="run-1",
            expected_revision=1,
            expected_state_hash="a" * 64,
            arguments={"ticket_id": "ENG-2", "state_id": "started"},
        )
```

- [ ] **Step 2: Run the contract test and observe red**

Run: `.venv/bin/python -m pytest tests/test_contracts.py::test_ticket_action_rejects_a_target_that_differs_from_its_ticket_id -q`

Expected: FAIL because `McpActionRequest` currently accepts independent `target` and `arguments["ticket_id"]`.

- [ ] **Step 3: Add ticket-action validation to the request contract**

```python
_TICKET_MCP_OPERATIONS = frozenset(
    {
        "query_ticket_projection",
        "query_ticket_state",
        "compare_and_start_ticket",
        "compare_and_complete_ticket",
        "restore_ticket_state",
    }
)

def validated_ticket_target(self) -> str | None:
    if self.operation not in _TICKET_MCP_OPERATIONS:
        return None
    ticket_id = self.arguments.get("ticket_id")
    if self.entity != "ticket" or not isinstance(ticket_id, str) or ticket_id != self.target:
        raise ValueError("MCP ticket target does not match ticket_id")
    return ticket_id
```

Call `validated_ticket_target()` from `McpActionRequest.validate_request_hashes()` after hash validation. Keep non-ticket actions generic.

- [ ] **Step 4: Run the contract test and observe green**

Run: `.venv/bin/python -m pytest tests/test_contracts.py::test_ticket_action_rejects_a_target_that_differs_from_its_ticket_id -q`

Expected: PASS.

- [ ] **Step 5: Write focused bridge/authority red tests**

```python
def trusted_bridge(tmp_path: Path, client: FakeLinearMcp) -> TrustedLinearBridge:
    return TrustedLinearBridge(
        state_root=tmp_path,
        bridge_identity="launcher-bridge",
        mcp_server_identity="linear-mcp",
        receipt_signing_key=b"test-only-launcher-key",
        client=client,
    )


def test_bridge_rejects_a_model_copied_split_ticket_request_before_mcp_call(tmp_path: Path) -> None:
    client = FakeLinearMcp({"state": "started"})
    bridge = trusted_bridge(tmp_path, client)
    store = RunStateStore(tmp_path, "run-1", receipt_authority=bridge.receipt_authority)
    initial = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3),
    )
    gateway = LinearGateway(store, bridge.receipt_authority)
    request = gateway.request_state(initial, "ENG-1")
    pending = gateway.persist_pending(initial, request)
    split_request = request.model_copy(update={"target": "ENG-2"})

    with pytest.raises(McpBridgeError, match="ticket target"):
        bridge.execute(split_request)

    assert client.calls == []
    assert store.load() == pending


def test_store_rejects_an_authority_bound_to_another_root(tmp_path: Path) -> None:
    authority = BridgeReceiptAuthority(tmp_path / "other", "launcher-bridge", "linear-mcp", b"test-only-launcher-key")

    with pytest.raises(ValueError, match="state root"):
        RunStateStore(tmp_path, "run-1", receipt_authority=authority)
```

Add `trusted_bridge()` in `tests/test_linear.py` only if an equivalent local helper does not already exist. Do not create a second store over an already initialized state with a different authority.

- [ ] **Step 6: Run the bridge/authority tests and observe red**

Run: `.venv/bin/python -m pytest tests/test_linear.py::test_bridge_rejects_a_model_copied_split_ticket_request_before_mcp_call tests/test_linear.py::test_store_rejects_an_authority_bound_to_another_root -q`

Expected: FAIL because bridge execution does not revalidate a copied request and store accepts structural verifier injection.

- [ ] **Step 7: Implement the root-bound authority and bridge composition**

```python
class BridgeReceiptAuthority:
    def load_verified_receipt(self, evidence: EvidenceRef) -> TrustedMcpReceipt:
        if evidence.creator != "trusted-mcp-bridge" or evidence.media_type != "application/json":
            raise ValueError("trusted MCP receipt evidence is invalid")
        path = self._receipt_path(evidence.relative_path)
        receipt = TrustedMcpReceipt.model_validate(_read_canonical_json(path, "trusted MCP receipt"))
        if (
            receipt.relative_path != evidence.relative_path
            or receipt.content_hash != evidence.sha256
            or not self._signature_matches(receipt)
        ):
            raise ValueError("trusted MCP receipt evidence is invalid")
        return receipt


class TrustedLinearBridge:
    def execute(self, request: McpActionRequest) -> TrustedMcpReceipt:
        try:
            ticket_target = request.validated_ticket_target()
        except ValueError:
            raise McpBridgeError("MCP ticket target is invalid")
        if not self._request_is_persisted(request):
            raise UnpersistedMcpRequestError("MCP request was not persisted before bridge execution")
        result = self._call(request.operation, request.arguments)
        return self._write_signed_receipt(request, result, target=ticket_target or request.target)
```

Implement `_receipt_path()` with the existing root-safe canonical JSON helpers and require exactly `trusted-mcp/receipts/<receipt-id>.json`; `_signature_matches()` must use `hmac.compare_digest()` over canonical signed payload bytes, bridge identity, and MCP server identity. Implement `_write_signed_receipt()` by extracting the existing `TrustedMcpReceipt` construction/write-once code, with the canonical target passed above. Replace `BridgeReceiptVerifier` with `BridgeReceiptAuthority` rather than retaining a permissive compatibility alias. `RunStateStore` accepts only an authority whose `state_root` exactly equals its normalized root. `LinearGateway` requires `store.receipt_authority is receipt_authority` and uses the authority for all receipt checks.

- [ ] **Step 8: Run focused authority and existing receipt tests**

Run: `.venv/bin/python -m pytest tests/test_contracts.py tests/test_linear.py::test_bridge_rejects_unpersisted_requests_and_gateway_accepts_only_authenticated_matching_receipts tests/test_linear.py::test_bridge_rejects_a_model_copied_split_ticket_request_before_mcp_call tests/test_linear.py::test_store_rejects_an_authority_bound_to_another_root -q`

Expected: PASS. The copied split request performs no MCP call; a matching bridge authority still accepts a valid receipt.

- [ ] **Step 9: Record evidence and request independent review**

Append exact red/green results and changed paths to `task-3a-report.md`. Request a read-only scoped review of ticket target validation and authority root/identity binding before starting Task 2. Resolve all Critical and Important findings before proceeding.

### Task 2: Enforce Pending Request CAS Lifecycle

**Files:**
- Modify: `src/auto_code/state.py:495-594, 740-810`
- Modify: `src/auto_code/linear.py:247-436`
- Modify: `src/auto_code/mcp_bridge.py:134-169, 348-429`
- Modify: `tests/test_linear.py:482-909`
- Modify: `tests/test_state.py:850-916`

**Interfaces:**
- Consumes: `BridgeReceiptAuthority.load_verified_receipt()`, `PendingExternalRequest.expected_revision`, `expected_state_hash`, and the authority identity established by Task 1.
- Produces: a state-validated pending lifecycle where creation binds to its predecessor generation, unresolved pending data is immutable, and removal requires one authority-validated receipt reconciliation.

- [ ] **Step 1: Write red tests for invalid pending lifecycle transitions**

```python
def persisted_ticket_request(
    tmp_path: Path,
    ticket_id: str,
) -> tuple[RunStateStore, TrustedLinearBridge, LinearGateway, StateGeneration, McpActionRequest]:
    bridge = trusted_bridge(tmp_path, FakeLinearMcp({"state": "started"}))
    store = RunStateStore(tmp_path, "run-1", receipt_authority=bridge.receipt_authority)
    initial = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3),
    )
    gateway = LinearGateway(store, bridge.receipt_authority)
    request = gateway.request_state(initial, ticket_id)
    return store, bridge, gateway, gateway.persist_pending(initial, request), request


def test_pending_request_cannot_be_detached_without_its_authenticated_reconciliation(tmp_path: Path) -> None:
    store, _, _, pending, _ = persisted_ticket_request(tmp_path, "ENG-1")

    with pytest.raises(InvalidStateTransition, match="pending request"):
        store.compare_and_swap(
            pending.revision,
            pending.state_hash,
            pending.state.model_copy(update={"pending_external_request": None}),
        )

    assert store.load() == pending


def test_pending_request_cannot_be_replaced_or_reattached_after_its_source_generation(tmp_path: Path) -> None:
    store, _, gateway, pending, _ = persisted_ticket_request(tmp_path, "ENG-1")
    replacement = gateway.request_state(pending, "ENG-2")
    replacement_pending = PendingExternalRequest(
        request_id=replacement.request_id,
        effect_id=replacement.effect_id,
        request_hash=replacement.request_hash,
        operation=replacement.operation,
        effect_hash=replacement.effect_hash,
        expected_revision=replacement.expected_revision,
        expected_state_hash=replacement.expected_state_hash,
        expected_external_revision=replacement.expected_external_revision,
        payload_hash=replacement.payload_hash,
    )
    replacement_intention = EffectIntention(
        effect_id=replacement.effect_id,
        sequence=pending.state.effect_ledger[-1].sequence + 1,
        timestamp=NOW,
        payload=EffectIntentionPayload(
            operation=replacement.operation,
            target=replacement.target,
            request_hash=replacement.request_hash,
        ),
    )
    replacement_state = pending.state.model_copy(
        update={
            "pending_external_request": replacement_pending,
            "effect_ledger": (*pending.state.effect_ledger, replacement_intention),
        }
    )

    with pytest.raises(InvalidStateTransition, match="pending request"):
        store.compare_and_swap(pending.revision, pending.state_hash, replacement_state)

    assert store.load() == pending


def test_new_pending_request_must_bind_to_the_predecessor_generation(tmp_path: Path) -> None:
    bridge = trusted_bridge(tmp_path, FakeLinearMcp({"state": "started"}))
    store = RunStateStore(tmp_path, "run-1", receipt_authority=bridge.receipt_authority)
    initial = store.compare_and_swap(
        0,
        EMPTY_STATE_HASH,
        RunState(run_id="run-1", ticket_id="ENG-1", repository_id="repo-1", max_crew_iterations=3),
    )
    gateway = LinearGateway(store, bridge.receipt_authority)
    request = gateway.request_state(initial, "ENG-1")
    misbound_pending = PendingExternalRequest(
        request_id=request.request_id,
        effect_id=request.effect_id,
        request_hash=request.request_hash,
        operation=request.operation,
        effect_hash=request.effect_hash,
        expected_revision=initial.revision + 1,
        expected_state_hash="f" * 64,
        expected_external_revision=request.expected_external_revision,
        payload_hash=request.payload_hash,
    )
    candidate = initial.state.model_copy(
        update={
            "disposition": RunDisposition.WAITING_MCP,
            "pending_external_request": misbound_pending,
            "effect_ledger": (
                EffectIntention(
                    effect_id=request.effect_id,
                    sequence=1,
                    timestamp=NOW,
                    payload=EffectIntentionPayload(
                        operation=request.operation,
                        target=request.target,
                        request_hash=request.request_hash,
                    ),
                ),
            ),
        }
    )

    with pytest.raises(InvalidStateTransition, match="predecessor generation"):
        store.compare_and_swap(initial.revision, initial.state_hash, candidate)
```

Keep all assertions on actual state equality, not authority call counts.

- [ ] **Step 2: Run the pending lifecycle tests and observe red**

Run: `.venv/bin/python -m pytest tests/test_linear.py -k 'pending_request_cannot_be_detached or pending_request_cannot_be_replaced_or_reattached or new_pending_request_must_bind_to_the_predecessor_generation' -q`

Expected: FAIL because the current state validator allows pending removal/replacement while preserving only ledger prefixes.

- [ ] **Step 3: Pass the previous generation into transition validation**

```python
def compare_and_swap_locked(self, expected_revision: int, expected_hash: str, state: RunState) -> StateGeneration:
    current = self.load_optional_locked(allow_orphaned_recovery=True)
    self._require_expected(current, expected_revision, expected_hash)
    state = self._validate_transition(current, state)

def _validate_transition(self, previous_generation: StateGeneration | None, state: RunState) -> RunState:
    previous = previous_generation.state if previous_generation is not None else None
    if previous is None:
        self._validate_initial_state(state)
        return state
    self._validate_pending_lifecycle(previous_generation, state)
```

After `_validate_pending_lifecycle()`, retain the existing immutable-field, append-only, terminal, authorization, iteration, task, disposition, and preparation validation statements in their current order, then return the validated `state`. Keep the existing generation-creation/write/pointer-replacement statements in `compare_and_swap_locked()` unchanged. Do not derive source revision/hash from a caller-owned value when `previous_generation` is available.

- [ ] **Step 4: Implement pending creation, continuity, and removal guards**

```python
def _validate_pending_lifecycle(
    self,
    previous_generation: StateGeneration,
    state: RunState,
) -> TrustedMcpReceipt | None:
    previous = previous_generation.state
    if previous.pending_external_request is None:
        self._require_new_pending_matches_predecessor(previous_generation, state)
        return None
    if state.pending_external_request == previous.pending_external_request:
        return None
    if state.pending_external_request is not None:
        raise InvalidStateTransition("pending request cannot be replaced")
    return self._require_authenticated_pending_reconciliation(previous, state)
```

Define `_require_new_pending_matches_predecessor(previous_generation, state)` to return when both states have no pending request; otherwise require exactly one appended matching `EffectIntention`, `WAITING_MCP`, and pending `expected_revision`/`expected_state_hash` equal to the predecessor generation. Define `_require_authenticated_pending_reconciliation(previous, state)` to load receipt evidence only through `receipt_authority`, then require the pending effect's three ordered events and all receipt/pending/run/hash/outcome/timestamp bindings before returning its `TrustedMcpReceipt`. Do not use caller-provided `TrustedMcpReceipt` objects as proof.

Make `LinearGateway.consume_receipt()` rely on the same store authority and retain exact replay behavior. Keep bridge execution limited to a currently persisted matching pending record.

- [ ] **Step 5: Run pending lifecycle tests and observe green**

Run: `.venv/bin/python -m pytest tests/test_linear.py tests/test_state.py -k 'pending_request_cannot_be_detached or pending_request_cannot_be_replaced_or_reattached or new_pending_request_must_bind_to_the_predecessor_generation or conflicting_authenticated_receipt_replay or waiting_mcp' -q`

Expected: PASS. Direct CAS cannot detach, replace, or revive a pending request; normal matching receipt consumption and exact replay still work.

- [ ] **Step 6: Add a real stale-receipt regression**

```python
def test_old_receipt_cannot_be_consumed_after_pending_lifecycle_tampering(tmp_path: Path) -> None:
    store, bridge, gateway, pending, request = persisted_ticket_request(tmp_path, "ENG-1")
    old_receipt = bridge.execute(request)

    tampered = pending.state.model_copy(update={"pending_external_request": None})
    with pytest.raises(InvalidStateTransition):
        store.compare_and_swap(pending.revision, pending.state_hash, tampered)

    assert gateway.consume_receipt(pending, old_receipt).state.pending_external_request is None
```

This test proves the only legal path for the outstanding receipt is its uninterrupted pending generation, not a later reattachment.

- [ ] **Step 7: Run the stale-receipt regression and focused suite**

Run: `.venv/bin/python -m pytest tests/test_contracts.py tests/test_linear.py tests/test_state.py -q`

Expected: PASS.

- [ ] **Step 8: Record evidence and request independent review**

Append all TDD evidence to `task-3a-report.md`. Request a read-only scoped review that attempts target split, receipt replay, source-CAS mismatch, pending detachment, replacement, and reattachment. Resolve all Critical and Important findings before Task 3.

### Task 3: Order Compensation And Authorized Resume

**Files:**
- Modify: `src/auto_code/state.py:635-827, 908-980`
- Modify: `tests/test_state.py:1603-1808`
- Modify: `tests/test_linear.py:532-843`

**Interfaces:**
- Consumes: Task 2's authority-validated pending reconciliation and the existing `PreparationPhase`, `RunDisposition`, `HumanAuthorization`, and append-only effect ledger.
- Produces: ordered compensation transitions based on the current episode's trusted start/restore history, without a new persisted attempt identifier.

- [ ] **Step 1: Write a current-episode restore red test**

```python
def resumed_and_reconfirmed_preparation(
    tmp_path: Path,
) -> tuple[RunStateStore, TrustedLinearBridge, LinearGateway, StateGeneration]:
    verifier = TrustedAuthorizations("resume-1", "resume-2")
    store, bridge, gateway, requested = preparation_receipt_boundary(
        tmp_path,
        authorization_verifier=verifier,
    )
    confirmed = confirm_preparation(bridge, gateway, requested)
    first_compensation = store.compare_and_swap(
        confirmed.revision,
        confirmed.state_hash,
        confirmed.state.model_copy(
            update={
                "preparation_phase": PreparationPhase.COMPENSATION_REQUIRED,
                "effect_ledger": (
                    *confirmed.state.effect_ledger,
                    *reconciled_effect_events(
                        "first-branch-effect",
                        confirmed.state.effect_ledger[-1].sequence + 1,
                        "create_ticket_branch",
                        EffectOutcome.FAILURE,
                    ),
                ),
            }
        ),
    )
    restored = restore_preparation(bridge, gateway, first_compensation)
    resumed = store.compare_and_swap(
        restored.revision,
        restored.state_hash,
        restored.state.model_copy(
            update={
                "preparation_phase": PreparationPhase.SELECTED,
                "disposition": RunDisposition.ACTIVE,
                "human_authorizations": (
                    consumed_authorization("run-1", HumanAuthorizationAction.RESUME, "resume-1"),
                ),
            }
        ),
    )
    second_requested = store.compare_and_swap(
        resumed.revision,
        resumed.state_hash,
        resumed.state.model_copy(update={"preparation_phase": PreparationPhase.IN_PROGRESS_REQUESTED}),
    )
    return store, bridge, gateway, confirm_preparation(bridge, gateway, second_requested)


def staged_second_compensation(tmp_path: Path) -> tuple[RunStateStore, StateGeneration]:
    store, _, _, second_confirmed = resumed_and_reconfirmed_preparation(tmp_path)
    staged = store.compare_and_swap(
        second_confirmed.revision,
        second_confirmed.state_hash,
        second_confirmed.state.model_copy(update={"disposition": RunDisposition.HUMAN_REVIEW}),
    )

    return store, store.compare_and_swap(
        staged.revision,
        staged.state_hash,
        staged.state.model_copy(
            update={
                "preparation_phase": PreparationPhase.COMPENSATION_REQUIRED,
                "effect_ledger": (
                    *staged.state.effect_ledger,
                    *reconciled_effect_events(
                        "second-branch-effect",
                        staged.state.effect_ledger[-1].sequence + 1,
                        "create_ticket_branch",
                        EffectOutcome.FAILURE,
                    ),
                ),
            }
        ),
    )


def test_compensation_resume_requires_restore_after_the_latest_successful_start(tmp_path: Path) -> None:
    store, bypassed = staged_second_compensation(tmp_path)
    resume = consumed_authorization("run-1", HumanAuthorizationAction.RESUME, "resume-2")

    with pytest.raises(InvalidStateTransition, match="current preparation episode"):
        store.compare_and_swap(
            bypassed.revision,
            bypassed.state_hash,
            bypassed.state.model_copy(
                update={
                    "preparation_phase": PreparationPhase.SELECTED,
                    "disposition": RunDisposition.ACTIVE,
                    "human_authorizations": (*bypassed.state.human_authorizations, resume),
                }
            ),
        )
```

The helper creates the first valid start, branch failure, bridge restore receipt, authorized reset, and second valid start using the real bridge/gateway. It intentionally uses the existing cross-field bypass only to prove that a first attempt's restore cannot authorize a second attempt's reset.

- [ ] **Step 2: Run the current-episode restore test and observe red**

Run: `.venv/bin/python -m pytest tests/test_state.py::test_compensation_resume_requires_restore_after_the_latest_successful_start -q`

Expected: FAIL because historical `compensated=True` and the first restore let the second compensation reset without a second restore.

- [ ] **Step 3: Derive current-episode restore proof from trusted ledger history**

```python
def _has_current_preparation_restore(self, state: RunState) -> bool:
    receipt_events = self._trusted_receipt_reconciliations(state)
    latest_start = max(
        (
            (reconciliation, receipt)
            for reconciliation, receipt in receipt_events
            if receipt.operation == "compare_and_start_ticket"
            and receipt.outcome is EffectOutcome.SUCCESS
            and receipt.target == state.ticket_id
        ),
        key=lambda pair: pair[0].sequence,
        default=None,
    )
    return latest_start is not None and any(
        reconciliation.sequence > latest_start[0].sequence
        and receipt.operation == "restore_ticket_state"
        and receipt.outcome is EffectOutcome.SUCCESS
        and receipt.target == state.ticket_id
        for reconciliation, receipt in receipt_events
    )
```

Define `_trusted_receipt_reconciliations(state)` to return an ordered tuple whose every item is an `(EffectReconciliation, TrustedMcpReceipt)` pair, only after it validates that reconciliation's matching invocation/observation group and calls `receipt_authority.load_verified_receipt()` for the evidence. On `COMPENSATION_REQUIRED + HUMAN_REVIEW -> SELECTED + ACTIVE`, require `_has_current_preparation_restore(previous)`, exactly one appended consumed resume authorization, and no pending request.

- [ ] **Step 4: Run the current-episode restore test and observe green**

Run: `.venv/bin/python -m pytest tests/test_state.py::test_compensation_resume_requires_restore_after_the_latest_successful_start -q`

Expected: PASS.

- [ ] **Step 5: Write the staged-Human-Review entry red test**

```python
def test_resumed_preparation_cannot_stage_human_review_before_a_second_compensation(tmp_path: Path) -> None:
    store, _, _, second_confirmed = resumed_and_reconfirmed_preparation(tmp_path)
    staged = store.compare_and_swap(
        second_confirmed.revision,
        second_confirmed.state_hash,
        second_confirmed.state.model_copy(update={"disposition": RunDisposition.HUMAN_REVIEW}),
    )

    with pytest.raises(InvalidStateTransition, match="active confirmation"):
        store.compare_and_swap(
            staged.revision,
            staged.state_hash,
            staged.state.model_copy(
                update={
                    "preparation_phase": PreparationPhase.COMPENSATION_REQUIRED,
                    "effect_ledger": (
                        *staged.state.effect_ledger,
                        *reconciled_effect_events(
                            "second-branch-effect",
                            staged.state.effect_ledger[-1].sequence + 1,
                            "create_ticket_branch",
                            EffectOutcome.FAILURE,
                        ),
                    ),
                }
            ),
        )


def test_compensation_human_review_cannot_resume_without_resetting_its_phase(tmp_path: Path) -> None:
    verifier = TrustedAuthorizations("resume-1")
    store, bridge, gateway, requested = preparation_receipt_boundary(
        tmp_path,
        authorization_verifier=verifier,
    )
    confirmed = confirm_preparation(bridge, gateway, requested)
    compensation = store.compare_and_swap(
        confirmed.revision,
        confirmed.state_hash,
        confirmed.state.model_copy(
            update={
                "preparation_phase": PreparationPhase.COMPENSATION_REQUIRED,
                "effect_ledger": (
                    *confirmed.state.effect_ledger,
                    *reconciled_effect_events(
                        "branch-effect",
                        confirmed.state.effect_ledger[-1].sequence + 1,
                        "create_ticket_branch",
                        EffectOutcome.FAILURE,
                    ),
                ),
            }
        ),
    )
    restored = restore_preparation(bridge, gateway, compensation)

    with pytest.raises(InvalidStateTransition, match="reset the compensation phase"):
        store.compare_and_swap(
            restored.revision,
            restored.state_hash,
            restored.state.model_copy(
                update={
                    "disposition": RunDisposition.ACTIVE,
                    "human_authorizations": (
                        consumed_authorization("run-1", HumanAuthorizationAction.RESUME, "resume-1"),
                    ),
                }
            ),
        )
```

These tests preserve unrelated Human Review routing while forbidding it from starting compensation or resuming a compensated run without the required phase reset.

- [ ] **Step 6: Run the staged-Human-Review test and observe red**

Run: `.venv/bin/python -m pytest tests/test_state.py -k 'resumed_preparation_cannot_stage_human_review_before_a_second_compensation or compensation_human_review_cannot_resume_without_resetting_its_phase' -q`

Expected: FAIL because `HUMAN_REVIEW -> HUMAN_REVIEW` currently bypasses the disposition-edge receipt guard and `HUMAN_REVIEW -> ACTIVE` can leave a compensated run in `COMPENSATION_REQUIRED`.

- [ ] **Step 7: Require active-to-active branch failure entry and atomic reset**

```python
if previous.preparation_phase is PreparationPhase.IN_PROGRESS_CONFIRMED and (
    state.preparation_phase is PreparationPhase.COMPENSATION_REQUIRED
):
    if previous.disposition is not RunDisposition.ACTIVE or state.disposition is not RunDisposition.ACTIVE:
        raise InvalidStateTransition("preparation compensation must begin from active confirmation")
    if not self._has_reconciliation_appended(previous, state, "create_ticket_branch", EffectOutcome.FAILURE):
        raise InvalidStateTransition("preparation compensation requires a recorded branch failure")

if (
    previous.preparation_phase is PreparationPhase.COMPENSATION_REQUIRED
    and previous.disposition is RunDisposition.HUMAN_REVIEW
    and state.disposition is RunDisposition.ACTIVE
    and state.preparation_phase is not PreparationPhase.SELECTED
):
    raise InvalidStateTransition("preparation Human Review resume must reset the compensation phase")
```

Require an already persisted `COMPENSATION_REQUIRED` phase before a successful restore reaches Human Review, including when `compensated` was already true historically. Keep unrelated `IN_PROGRESS_CONFIRMED -> HUMAN_REVIEW` safety routing legal; it must be authentically resumed to `ACTIVE` before a compensation episode begins.

- [ ] **Step 8: Run compensation ordering tests and observe green**

Run: `.venv/bin/python -m pytest tests/test_state.py tests/test_linear.py -k 'compensation or resumed_preparation or preparation_reset' -q`

Expected: PASS. Valid start, branch failure, restore, and authorized reset still work; stale or staged evidence cannot authorize a later attempt.

- [ ] **Step 9: Record evidence and request independent review**

Append red/green evidence and self-review to `task-3a-report.md`. Request a read-only review covering all Task 3a hardening requirements, especially cross-product phase/disposition paths and receipt-ledger scans. Resolve all Critical and Important findings before final verification.

### Task 4: Verify The Complete Hardening Unit

**Files:**
- Modify: `.superpowers/sdd/2026-09-05-03-integrations-and-verification/task-3a-report.md`
- Modify: `.superpowers/sdd/2026-09-05-03-integrations-and-verification/progress.md`
- Test: `tests/test_contracts.py`
- Test: `tests/test_state.py`
- Test: `tests/test_linear.py`

**Interfaces:**
- Consumes: all Task 1–3 contracts and tests.
- Produces: final verification evidence and a Task 3a approval decision before Task 3b begins.

- [ ] **Step 1: Run the complete focused unit suite**

Run: `.venv/bin/python -m pytest tests/test_contracts.py tests/test_state.py tests/test_linear.py -q`

Expected: PASS with only known non-failing third-party warnings.

- [ ] **Step 2: Run the full repository suite**

Run: `.venv/bin/python -m pytest -q`

Expected: PASS. Record the exact pass count and warning count; do not treat expected LiteAgent fixture output as a test failure.

- [ ] **Step 3: Compile production sources**

Run: `.venv/bin/python -m compileall -q src`

Expected: exit code `0` and no output.

- [ ] **Step 4: Inspect the scoped change and request final independent review**

Review `contracts.py`, `state.py`, `linear.py`, `mcp_bridge.py`, and their changed tests against both Task 3a specs. Verify no caller-controlled verifier, raw receipt, alternate root, pending replacement, target split, stale receipt, or phase/disposition bypass remains. Do not rely on `git diff` because the repository has no baseline commit.

- [ ] **Step 5: Record completion only after approval**

Append final commands/results and reviewer verdict to `task-3a-report.md`. If the reviewer has no Critical or Important findings, mark Task 3a hardening complete in `progress.md` and move the active todo to Task 3b. Otherwise record the finding and start a new TDD repair round without proceeding to Task 3b.
