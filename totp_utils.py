# totp_utils.py
import base64
import binascii
import re
from typing import Tuple

import pyotp

HEX_RE = re.compile(r"^[0-9a-f]{64}$")

def _hex_to_base32(hex_seed: str) -> str:
    """
    Convert 64-char hex seed -> base32 string suitable for TOTP libraries.
    Raises ValueError on invalid input.
    """
    if not isinstance(hex_seed, str):
        raise ValueError("hex_seed must be a string")
    hex_seed = hex_seed.strip().lower()
    if not HEX_RE.fullmatch(hex_seed):
        raise ValueError("hex_seed must be a 64-character lowercase hex string [0-9a-f]{64}")
    seed_bytes = binascii.unhexlify(hex_seed)          # bytes from hex
    b32 = base64.b32encode(seed_bytes).decode('utf-8') # base32 string
    return b32

def generate_totp_code(hex_seed: str) -> str:
    """
    Generate current 6-digit TOTP code from a 64-character hex seed.

    - Algorithm: SHA-1 (pyotp default)
    - Period: 30 seconds
    - Digits: 6

    Returns:
        6-digit string, zero-padded if necessary (e.g. "012345")
    Raises:
        ValueError on invalid hex_seed
    """
    b32 = _hex_to_base32(hex_seed)
    totp = pyotp.TOTP(b32, digits=6, interval=30)  # SHA-1 is default
    return totp.now()

def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify a 6-digit TOTP code with time-window tolerance.

    Args:
        hex_seed: 64-character hex string
        code: 6-digit code (string or numeric-like)
        valid_window: number of periods before/after to accept (default 1 → ±30s)

    Returns:
        True if valid, False otherwise

    Raises:
        ValueError on invalid hex_seed or code format
    """
    if not isinstance(code, str):
        code = str(code)
    code = code.strip()
    if not (len(code) == 6 and code.isdigit()):
        raise ValueError("code must be a 6-digit string")

    b32 = _hex_to_base32(hex_seed)
    totp = pyotp.TOTP(b32, digits=6, interval=30)
    # pyotp.TOTP.verify accepts valid_window to allow ±windows
    return bool(totp.verify(code, valid_window=valid_window))
