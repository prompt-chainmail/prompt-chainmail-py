from __future__ import annotations

import hashlib


def sha256_hex(data: bytes) -> str:
    """Lowercase hex SHA-256 of `data` (must match manifest `model_sha256`)."""
    return hashlib.sha256(data).hexdigest()
