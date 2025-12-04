#!/usr/bin/env python3
"""
decrypt_seed.py

Reads:  encrypted_seed.txt   (one-line Base64 ciphertext)
Reads:  student_private.pem  (PEM RSA private key)
Writes: data/seed.txt        (one-line 64-character hex seed)

Implements RSA/OAEP decryption with:
 - OAEP padding
 - MGF1 with SHA-256
 - Hash = SHA-256
 - Label = None
"""
import base64
import re
from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

ENC_FILE = Path("encrypted_seed.txt")
PRIV_KEY_FILE = Path("student_private.pem")
OUT_DIR = Path("data")
OUT_FILE = OUT_DIR / "seed.txt"

HEX_RE = re.compile(r"^[0-9a-f]{64}$")

def load_private_key(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"Private key file not found: {path}")
    data = path.read_bytes()
    return serialization.load_pem_private_key(data, password=None)

def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP (SHA-256).
    Returns: 64-character lower-case hex seed string on success.
    Raises ValueError on invalid format or decryption errors.
    """
    try:
        ct = base64.b64decode(encrypted_seed_b64.strip())
    except Exception as e:
        raise ValueError(f"Base64 decode failed: {e}")

    try:
        plain = private_key.decrypt(
            ct,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except Exception as e:
        raise ValueError(f"RSA/OAEP decryption failed: {e}")

    try:
        hex_seed = plain.decode("utf-8").strip().lower()
    except Exception as e:
        raise ValueError(f"UTF-8 decode failed: {e}")

    if not HEX_RE.match(hex_seed):
        raise ValueError("Decrypted value is not a 64-character hex string.")

    return hex_seed

def main():
    if not ENC_FILE.exists():
        print(f"ERROR: {ENC_FILE} not found. Save the API 'encrypted_seed' value there.")
        return
    if not PRIV_KEY_FILE.exists():
        print(f"ERROR: {PRIV_KEY_FILE} not found. Place your student_private.pem in repo root.")
        return

    encrypted_b64 = ENC_FILE.read_text().strip()
    priv = load_private_key(PRIV_KEY_FILE)

    try:
        hex_seed = decrypt_seed(encrypted_b64, priv)
    except ValueError as e:
        print("Decryption failed:", e)
        return

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    OUT_FILE.write_text(hex_seed + "\n")   # include newline
    print("Decryption successful.")
    print("Hex seed (64 chars):", hex_seed)
    print("Saved to:", OUT_FILE.resolve())

if __name__ == "__main__":
    main()

