from __future__ import annotations

import hashlib
import json


def canonical_json_bytes(value: object) -> bytes:
    """Return the one JSON representation used for all persisted hashes."""
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("ascii")


def hash_json(value: object) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()
