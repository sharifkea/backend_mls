# test_keypair_x25519.py
import sys

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

from mls_stuff.Crypto._key_pair import KeyPair
from mls_stuff.Enums import KeyType

print("=== Step 8: Generating X25519 HPKE Init Keypair ===\n")

# Generate fresh X25519 keypair using cryptography
from cryptography.hazmat.primitives.asymmetric import x25519

raw_priv = x25519.X25519PrivateKey.generate()
raw_pub = raw_priv.public_key()

priv_bytes = raw_priv.private_bytes_raw()     # 32 bytes
pub_bytes  = raw_pub.public_bytes_raw()       # 32 bytes

print(f"Raw private key length: {len(priv_bytes)} bytes")
print(f"Raw public key length : {len(pub_bytes)} bytes\n")

# Wrap into KeyPair (this is what MLS will expect for init_key)
kp = KeyPair(
    key_type=KeyType.X25519,
    private_key=priv_bytes,
    public_key=pub_bytes
)

print("X25519 KeyPair created successfully!")
print(f"  key_type: {kp.key_type.name}")
print(f"  private bytes length: {len(kp.private)}")
print(f"  public bytes length : {len(kp.public)}")

# Show the public key bytes that will go into KeyPackageTBS.init_key
print("\nPublic key bytes (hex prefix):")
print(kp.public.hex()[:64] + "..." if len(kp.public) > 32 else kp.public.hex())