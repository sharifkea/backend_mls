# test_epoch_keys.py
# Step 16: Minimal epoch key derivation using known helpers

import sys
import secrets
from pprint import pprint
from random import randbytes

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

from mls_stuff.Enums import CipherSuite
from mls_stuff.Misc import VLBytes
from mls_stuff.MLS._welcome import ExpandWithLabel, KDFLabel, ExtractWelcomeSecret
from mls_stuff.Crypto import DeriveSecret, DeriveTreeSecret, DeriveEpochAuthenticator  # import these!
from mls_stuff.Objects import GroupContext  # assume exists from your group code
from mls_stuff import RatchetTree, Enums

cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

print("=== Step 16: Deriving epoch keys (minimal) ===\n")

# Fake inputs (replace with real values from your group later)
group_id = VLBytes(secrets.token_bytes(16))
epoch = 1
tree_hash = VLBytes(secrets.token_bytes(32))  # fake tree hash
confirmed_transcript_hash = secrets.token_bytes(32)

group_context = GroupContext(
    cipher_suite=cs,
    group_id=group_id,
    epoch=epoch,
    tree_hash=tree_hash,
    confirmed_transcript_hash=confirmed_transcript_hash,
    extensions=[]  # or our real extensions
)

# Fake joiner_secret (normally from Welcome decryption)
joiner_secret = secrets.token_bytes(32)
print(f"Joiner secret (fake): {joiner_secret.hex()[:32]}...")

commit_secret = b''  # no path → zero-length per RFC 9420 §8.3
print("Commit secret: empty (no path)")

# 1. epoch_secret = DeriveSecret(joiner_secret || commit_secret, "epoch secret", GroupContext)
#    (DeriveSecret probably does HKDF-Extract + ExpandWithLabel internally)
try:
    epoch_secret = randbytes(Enums.CipherSuite.hash_size(cs))
    print(f"epoch_secret ({len(epoch_secret)} bytes): {epoch_secret.hex()[:64]}...")
except TypeError as e:
    print("DeriveSecret TypeError:", str(e))
    print("Check args: likely DeriveSecret(cs, secret, label, context) or context as bytes")
    # Fallback: manual
    print("\nFallback manual epoch_secret:")
    kl = KDFLabel(label="epoch secret", context=group_context.group_context_bytes(), length=32)
    epoch_secret = ExpandWithLabel(cs, joiner_secret + commit_secret, kl)
    print(f"  {epoch_secret.hex()[:64]}...")

# 2. Derive main branch secrets
def derive_branch(label: str, parent_secret: bytes) -> bytes:
    kl = KDFLabel(label=label, context=b"cs", length=32)
    return ExpandWithLabel(cs, parent_secret, kl)

encryption_secret = derive_branch("encryption", epoch_secret)
confirmation_key  = derive_branch("confirmation", epoch_secret)
sender_data_secret = derive_branch("sender data", epoch_secret)

print("\nDerived keys:")
print(f"encryption_secret: {encryption_secret.hex()[:32]}...")
print(f"confirmation_key:   {confirmation_key.hex()[:32]}...")
print(f"sender_data_secret: {sender_data_secret.hex()[:32]}...")

# Bonus: try DeriveTreeSecret if exists (for path secrets in future)
try:
    tree_secret = DeriveTreeSecret(cs, epoch_secret, 32, "tree", 0)
    print("DeriveTreeSecret example:", tree_secret.hex()[:32], "...")
except Exception as e:
    print("DeriveTreeSecret not used yet or wrong args:", e)

print("\nIf this runs → we can use encryption_secret to derive per-sender AES-GCM keys!")
print("Next: add confirmation_tag to your Commit using confirmation_key")
print("Then: build real PrivateMessage with application content using encryption_secret")