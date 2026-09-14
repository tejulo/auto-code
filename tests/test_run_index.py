from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.state_fixtures import activated_index, persist_terminal_generation
from auto_code.contracts import RunDisposition
from auto_code.hashing import canonical_json_bytes
from auto_code.run_index import AuthoritativeIndexCorrupt


def test_release_persists_a_receipt_before_removing_the_active_index(tmp_path: Path) -> None:
    """Removing the index without a durable receipt makes recovery unsafe."""

    index, active = activated_index(tmp_path)
    done = persist_terminal_generation(active, RunDisposition.DONE)

    receipt = index.release("repo-1", "run-1", active.index_revision, active.index_hash, done.state_hash)

    assert receipt is not None
    index.verify_release(receipt)


def test_verify_release_rejects_a_self_consistent_unsigned_tombstone(tmp_path: Path) -> None:
    """A receipt hash alone is forgeable after the active index has been removed."""

    index, active = activated_index(tmp_path)
    done = persist_terminal_generation(active, RunDisposition.DONE)
    receipt = index.release("repo-1", "run-1", active.index_revision, active.index_hash, done.state_hash)

    unsigned = {**receipt.model_dump(mode="json", round_trip=True), "signature": None}
    index._release_path(receipt).write_bytes(canonical_json_bytes(unsigned))

    with pytest.raises(AuthoritativeIndexCorrupt, match="receipt"):
        index.verify_release(receipt)


def test_verify_release_rejects_an_attacker_signed_tombstone(tmp_path: Path) -> None:
    """An attacker key cannot replace the immutable finalization trust key."""

    index, active = activated_index(tmp_path)
    done = persist_terminal_generation(active, RunDisposition.DONE)
    receipt = index.release("repo-1", "run-1", active.index_revision, active.index_hash, done.state_hash)
    attacker_signature = Ed25519PrivateKey.generate().sign(canonical_json_bytes(receipt.signing_payload())).hex()
    forged = {**receipt.model_dump(mode="json", round_trip=True), "signature": attacker_signature}

    index._release_path(receipt).write_bytes(canonical_json_bytes(forged))

    with pytest.raises(AuthoritativeIndexCorrupt, match="signature"):
        index.verify_release(receipt)
