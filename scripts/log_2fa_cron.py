#!/usr/bin/env python3
import sys
from pathlib import Path
from datetime import datetime, timezone

# Add project root (/app) to sys.path so we can import totp_utils
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from totp_utils import generate_totp_code

SEED_FILE = Path("/data/seed.txt")

def main():
    if not SEED_FILE.exists():
        print("Seed file not found at /data/seed.txt")
        return

    hex_seed = SEED_FILE.read_text().strip()

    if len(hex_seed) != 64:
        print("Invalid seed length:", len(hex_seed))
        return

    try:
        code = generate_totp_code(hex_seed)
    except Exception as e:
        print("Error generating TOTP:", e)
        return

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    print(f"{ts} - 2FA Code: {code}")

if __name__ == "__main__":
    main()
