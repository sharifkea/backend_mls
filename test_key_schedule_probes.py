# test_key_schedule_probes.py
# Step 15: Fixed ExpandWithLabel call + deeper probe

import sys
import secrets
from pprint import pprint

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

from mls_stuff.Enums import CipherSuite
from mls_stuff.Misc import VLBytes
from mls_stuff.MLS._welcome import ExpandWithLabel, ExtractWelcomeSecret, KDFLabel  # try import KDFLabel here

cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

print("=== Step 15: Fixed key schedule probes ===\n")

# 1. Test ExpandWithLabel with correct args
print("Testing ExpandWithLabel (correct style):\n")

secret = secrets.token_bytes(32)
print(f"Input secret (32 bytes): {secret.hex()[:32]}...")

try:
    # Create KDFLabel
    kdflabel = KDFLabel(
        label="test expand",
        context=b"some context bytes",
        length=32   # requested output length
    )
    expanded = ExpandWithLabel(cs, secret, kdflabel)
    print(f"SUCCESS: Expanded to {len(expanded)} bytes")
    print(f"Output (hex): {expanded.hex()[:64]}...")
except ImportError:
    print("KDFLabel not found in _welcome — try other locations below")
except TypeError as e:
    print("TypeError on KDFLabel or ExpandWithLabel:", str(e))
    print("→ Print dir(KDFLabel) or check source for exact fields (likely label/context/length)")
except Exception as e:
    print("Unexpected:", type(e).__name__, str(e))

# 2. Probe more locations for key derivation helpers
print("\nProbing additional modules for key/secret functions:\n")

probe_modules = [
    "mls_stuff.MLS._welcome",
    "mls_stuff.MLS._commit",
    "mls_stuff.Crypto",
    "mls_stuff.Misc",
    "mls_stuff.MLS._transcript_hash",  # sometimes transcript helpers derive things
]

for mod_path in probe_modules:
    try:
        mod = __import__(mod_path, fromlist=[""])
        callables = [n for n in dir(mod) if callable(getattr(mod, n)) and not n.startswith("_")]
        promising = [n for n in callables if any(kw in n.lower() for kw in ["derive", "expand", "extract", "secret", "epoch", "key", "schedule"])]
        print(f"{mod_path}:")
        print("  All callables:", callables)
        if promising:
            print("  → Promising functions:", promising)
    except ImportError:
        print(f"{mod_path}: not found")

# 3. If KDFLabel found → try realistic MLS labels
if 'KDFLabel' in globals():
    print("\nTrying realistic MLS key labels (RFC 9420 §8):")
    for label in ["epoch secret", "encryption", "sender data", "confirmation", "exporter", "external init secret"]:
        try:
            kl = KDFLabel(label=label, context=b"", length=32)
            out = ExpandWithLabel(cs, secret, kl)
            print(f"  {label:20} → {out.hex()[:32]}...")
        except Exception as e:
            print(f"  {label}: failed → {e}")

print("\nPaste full output back. If ExpandWithLabel works → we can build minimal epoch keys!")
print("Next goal: use it to derive encryption_secret → then try PrivateMessage framing.")