from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
import re
import uuid

from pydantic import ValidationError

from .contracts import Checkpoint, CheckpointId, EvidenceRef, Sha256, Stage
from .hashing import hash_json
from .state import (
    AuthoritativeStateCorrupt,
    InvalidStateTransition,
    _validate_persisted_value,
    _ensure_directory,
    _normalize_state_root,
    _path_lstat,
    _read_canonical_json,
    _write_new_json,
)


_CHECKPOINT_ID = re.compile(r"[0-9a-f]{32}\Z")


class CheckpointRegistryCorrupt(RuntimeError):
    pass


class CheckpointAuthority:
    """Launcher-root authority that records validated checkpoints before issuing them."""

    def __init__(self, root: Path) -> None:
        self.root = _normalize_state_root(root)
        self.registry_dir = _ensure_directory(self.root, self.root / "checkpoint-authority")

    def issue(
        self,
        *,
        stage: Stage,
        contract_hash: Sha256,
        input_hashes: Mapping[str, Sha256],
        output_manifest_hash: Sha256,
        validator: str,
        validator_version: str,
        validation_receipt_hash: Sha256,
        evidence: tuple[EvidenceRef, ...] = (),
    ) -> Checkpoint:
        for _ in range(3):
            checkpoint = Checkpoint(
                checkpoint_id=uuid.uuid4().hex,
                stage=stage,
                contract_hash=contract_hash,
                input_hashes=input_hashes,
                output_manifest_hash=output_manifest_hash,
                validator=validator,
                validator_version=validator_version,
                validation_receipt_hash=validation_receipt_hash,
                evidence=evidence,
            )
            payload = self._payload(checkpoint)
            if _write_new_json(
                self.registry_path(checkpoint.checkpoint_id),
                {
                    "checkpoint_id": checkpoint.checkpoint_id,
                    "payload_hash": hash_json(payload),
                    "checkpoint": payload,
                },
            ):
                return checkpoint
        raise CheckpointRegistryCorrupt("checkpoint ID collision prevented durable issuance")

    def matches(
        self,
        checkpoint: Checkpoint,
        *,
        stage: Stage,
        contract_hash: Sha256,
        input_hashes: Mapping[str, Sha256],
    ) -> bool:
        checkpoint_id = checkpoint.checkpoint_id
        if checkpoint_id is None or _CHECKPOINT_ID.fullmatch(checkpoint_id) is None:
            return False
        try:
            path = self.registry_path(checkpoint_id)
            if _path_lstat(path, "checkpoint authority record") is None:
                return False
            record = _read_canonical_json(path, "checkpoint authority record")
        except AuthoritativeStateCorrupt as error:
            raise CheckpointRegistryCorrupt("checkpoint authority registry is corrupt") from error
        try:
            payload = self._payload(checkpoint)
            persisted = record.get("checkpoint") if isinstance(record, dict) else None
            if not isinstance(persisted, dict):
                return False
            persisted_payload = self._payload(Checkpoint.model_validate(persisted))
        except (InvalidStateTransition, ValidationError) as error:
            raise CheckpointRegistryCorrupt("checkpoint authority registry is corrupt") from error
        if (
            not isinstance(record, dict)
            or set(record) != {"checkpoint_id", "payload_hash", "checkpoint"}
            or record["checkpoint_id"] != checkpoint_id
            or record["payload_hash"] != hash_json(payload)
            or persisted_payload != payload
        ):
            return False
        return (
            checkpoint.stage is stage
            and checkpoint.contract_hash == contract_hash
            and dict(checkpoint.input_hashes) == dict(input_hashes)
        )

    def is_reusable(
        self,
        checkpoint: Checkpoint,
        *,
        stage: Stage,
        contract_hash: Sha256,
        input_hashes: Mapping[str, Sha256],
    ) -> bool:
        return self.matches(
            checkpoint,
            stage=stage,
            contract_hash=contract_hash,
            input_hashes=input_hashes,
        )

    def registry_path(self, checkpoint_id: CheckpointId) -> Path:
        return self.registry_dir / f"{checkpoint_id}.json"

    @staticmethod
    def _payload(checkpoint: Checkpoint) -> dict[str, object]:
        payload = checkpoint.model_dump(mode="json", round_trip=True)
        _validate_persisted_value(payload)
        return Checkpoint.model_validate(payload).model_dump(mode="json", round_trip=True)
