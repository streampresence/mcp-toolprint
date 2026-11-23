"""JCS (RFC 8785) canonical JSON for the subset Toolprint signs.

Signed payloads may contain only: strings, integers, booleans, null,
arrays, and objects with string keys. Floats are rejected outright —
canonical float serialization is where implementations diverge, and a
receipt format has no business containing one.
"""

import hashlib
import json


def _check(obj, path="$"):
    if obj is None or isinstance(obj, (bool, str)):
        return
    if isinstance(obj, int):
        return
    if isinstance(obj, float):
        raise ValueError(f"float not allowed in signed payload at {path}")
    if isinstance(obj, list):
        for i, v in enumerate(obj):
            _check(v, f"{path}[{i}]")
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            if not isinstance(k, str):
                raise ValueError(f"non-string key at {path}")
            _check(v, f"{path}.{k}")
        return
    raise ValueError(f"unsupported type {type(obj).__name__} at {path}")


def canonical(obj) -> bytes:
    """Deterministic canonical bytes: sorted keys, no whitespace,
    raw UTF-8 (no \\u escaping beyond JSON's mandatory escapes)."""
    _check(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hash_obj(obj) -> str:
    """sha256:<hex> of the JCS-canonical form of obj."""
    return "sha256:" + sha256_hex(canonical(obj))
