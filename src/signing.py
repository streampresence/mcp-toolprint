"""Minimal did:key / Ed25519 helpers for MCP Toolprint.

Vendored from the Stream Presence receipts codebase (core.py)
and reduced to exactly what Toolprint needs: the current time,
base64url, did:key encoding for Ed25519 keys, and signature
verification. A did:key for an Ed25519 key is the base58btc
encoding of the multicodec prefix 0xED 0x01 followed by the
32-byte public key, prefixed "did:key:z".

The base58btc codec is vendored too (public-domain style
implementation), so the only runtime dependency is PyNaCl.
"""

import base64
from datetime import datetime, timezone

import nacl.exceptions
import nacl.signing

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZ" \
                "abcdefghijkmnopqrstuvwxyz"
_B58_INDEX = {c: i for i, c in enumerate(_B58_ALPHABET)}


def _b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, r = divmod(n, 58)
        out = _B58_ALPHABET[r] + out
    pad = 0
    for b in data:
        if b == 0:
            pad += 1
        else:
            break
    return "1" * pad + (out or "")


def _b58decode(s: str) -> bytes:
    n = 0
    for c in s:
        if c not in _B58_INDEX:
            raise ValueError(f"invalid base58 character {c!r}")
        n = n * 58 + _B58_INDEX[c]
    pad = 0
    for c in s:
        if c == "1":
            pad += 1
        else:
            break
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\x00" * pad + body


def now_iso() -> str:
    """Current UTC time as 'YYYY-MM-DDTHH:MM:SSZ'."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def b64u(data: bytes) -> str:
    """Base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def did_from_pubkey(pubkey_bytes: bytes) -> str:
    payload = bytes([0xED, 0x01]) + pubkey_bytes
    return "did:key:z" + _b58encode(payload)


def pubkey_from_did(did: str) -> bytes:
    if not did.startswith("did:key:z"):
        raise ValueError("unsupported DID form")
    raw = _b58decode(did[len("did:key:z"):])
    if raw[:2] != bytes([0xED, 0x01]):
        raise ValueError("not an ed25519 did:key")
    return raw[2:]


def verify_signature(did: str, payload: bytes,
                     signature_b64u: str) -> bool:
    """True iff signature_b64u is did's Ed25519 signature over
    payload. Any malformed input is simply False."""
    try:
        vk = nacl.signing.VerifyKey(pubkey_from_did(did))
        vk.verify(payload, b64u_decode(signature_b64u))
        return True
    except Exception:
        return False
