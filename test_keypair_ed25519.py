# test_keypair_ed25519.py
import sys
import os

# Adjust path if needed
sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

from mls_stuff.Crypto._key_pair import KeyPair
from mls_stuff.Enums import KeyType

print("=== Step 7: KeyPair with Ed25519 (signing key for MLS) ===\n")

# 1. Generate fresh keypair (library should support this indirectly via cryptography)
print("Generating new Ed25519 keypair...")
def get_ed25519_keys():
# We create via cryptography first (since KeyPair doesn't have .generate())
    from cryptography.hazmat.primitives.asymmetric import ed25519

    raw_priv = ed25519.Ed25519PrivateKey.generate()
    raw_pub = raw_priv.public_key()

    priv_bytes = raw_priv.private_bytes_raw()     # 32 bytes
    pub_bytes  = raw_pub.public_bytes_raw()       # 32 bytes

    print(f"Raw private key length: {len(priv_bytes)} bytes")
    print(f"Raw public key length : {len(pub_bytes)} bytes\n")

    # 2. Wrap it in KeyPair
    kp = KeyPair(
    key_type=KeyType.ED25519,
    private_key=priv_bytes,
    public_key=pub_bytes
    )

    print("KeyPair created successfully!")
    print(f"  key_type: {kp.key_type.name}")
    print(f"  private bytes length: {len(kp.private)}")
    print(f"  public bytes length : {len(kp.public)}")

    # 3. Test signing & verification (very important for KeyPackage)
    message = b"Hello, this is a test message for MLS signing"

    signature = kp.sign(message)
    print(f"\nSignature length: {len(signature)} bytes")

    verified = kp.verify(message, signature)
    print(f"Verify same message   → {verified}")   # should be True

    verified_wrong = kp.verify(b"tampered message", signature)
    print(f"Verify tampered message → {verified_wrong}")  # should be False
    print(f"Public key (hex): {kp.public.hex()[:64]}{'...' if len(kp.public) > 32 else ''}")
    print(f"Private key (hex): {kp.private.hex()[:64]}{'...' if len(kp.private) > 32 else ''}")
    return kp.private, kp.public
if __name__ == "__main__":
    get_ed25519_keys()