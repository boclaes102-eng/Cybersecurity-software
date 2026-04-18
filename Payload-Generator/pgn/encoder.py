"""Payload encoding utilities."""
from __future__ import annotations

import base64
import binascii
import urllib.parse


def encode_base64(payload: str) -> str:
    return base64.b64encode(payload.encode()).decode()


def decode_base64(payload: str) -> str:
    return base64.b64decode(payload.encode()).decode(errors="replace")


def encode_url(payload: str) -> str:
    return urllib.parse.quote(payload, safe="")


def encode_hex(payload: str) -> str:
    return binascii.hexlify(payload.encode()).decode()


def encode_powershell(payload: str) -> str:
    """Encode as PowerShell -EncodedCommand (UTF-16LE base64)."""
    return base64.b64encode(payload.encode("utf-16-le")).decode()


def decode_powershell(encoded: str) -> str:
    return base64.b64decode(encoded).decode("utf-16-le", errors="replace")


def encode_xor(payload: str, key: int) -> str:
    """XOR every byte with key and return as hex string."""
    return binascii.hexlify(bytes(b ^ key for b in payload.encode())).decode()


_ENCODERS = {
    "base64":     encode_base64,
    "url":        encode_url,
    "hex":        encode_hex,
    "powershell": encode_powershell,
}

FORMATS = list(_ENCODERS)


def encode(payload: str, fmt: str) -> str:
    fn = _ENCODERS.get(fmt)
    if not fn:
        raise ValueError(f"Unknown format '{fmt}'. Available: {FORMATS}")
    return fn(payload)
