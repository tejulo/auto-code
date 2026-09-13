from __future__ import annotations

from pathlib import Path

from tests.state_fixtures import activated_index, persist_terminal_generation
from auto_code.contracts import RunDisposition


def test_release_persists_a_receipt_before_removing_the_active_index(tmp_path: Path) -> None:
    """Removing the index without a durable receipt makes recovery unsafe."""

    index, active = activated_index(tmp_path)
    done = persist_terminal_generation(active, RunDisposition.DONE)

    receipt = index.release("repo-1", "run-1", active.index_revision, active.index_hash, done.state_hash)

    assert receipt is not None
    index.verify_release(receipt)
