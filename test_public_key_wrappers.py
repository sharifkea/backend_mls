# test_public_key_wrappers.py
import sys

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

from mls_stuff.Crypto import HPKEPublicKey, SignaturePublicKey

print("=== Step 12: Wrapping public keys into MLS types ===\n")

# Use example bytes from your previous runs (replace with your actual ones!)
# Example from Step 8:
x25519_pub_bytes = bytes.fromhex("fe291c5526bb947f0a36df9a5953779e5e87135f086c465eae3b5dae7b253461")

# Example Ed25519 pub (replace with real one from your Step 7 run)
ed25519_pub_bytes = bytes.fromhex("77c02329fdc4b5c750a4c4d0a5e8204bb9d5a42a223a240ac49b553969d3fc5b")   # ← PASTE OUR REAL 64 HEX CHARS HERE

try:
    hpke_pub = HPKEPublicKey(x25519_pub_bytes)
    print("HPKEPublicKey created successfully!")
    print(f"  Length: {len(hpke_pub)} bytes")
    print(f"  Hex prefix: {hpke_pub.hex()[:40]}...")
except Exception as e:
    print("HPKEPublicKey failed:", e)

try:
    sig_pub = SignaturePublicKey(ed25519_pub_bytes)
    print("\nSignaturePublicKey created successfully!")
    print(f"  Length: {len(sig_pub)} bytes")
    print(f"  Hex prefix: {sig_pub.hex()[:40]}...")
except Exception as e:
    print("SignaturePublicKey failed:", e)