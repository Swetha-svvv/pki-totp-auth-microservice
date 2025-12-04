from totp_utils import generate_totp_code, verify_totp_code

hex_seed = "9ea9c8f09aa2ac70dee698339c1ff9615dfa551e46d672e92ffd68ac580f49fa"  # example from your decrypt step

# Generate current code
code = generate_totp_code(hex_seed)
print("Current TOTP code:", code)

# Verify immediately (should be True)
print("Verify:", verify_totp_code(hex_seed, code))

