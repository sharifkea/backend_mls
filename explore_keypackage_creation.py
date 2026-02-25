# explore_keypackage_creation.py
import sys
import inspect

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

print("=== Step 5: Exploring how to CREATE KeyPackageTBS ===\n")

from mls_stuff.MLS import KeyPackageTBS
from mls_stuff.Crypto import Credential
from mls_stuff.Enums import CipherSuite

cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

print("Inspecting KeyPackageTBS class:\n")

# 1. Check for classmethods / staticmethods / special constructors
print("Class methods & static methods:")
for name, member in inspect.getmembers(KeyPackageTBS):
    if inspect.isfunction(member) or inspect.ismethod(member):
        if name.startswith("_"): continue
        kind = "classmethod" if isinstance(member, classmethod) else \
               "staticmethod" if isinstance(member, staticmethod) else "method"
        print(f"   {name:20} ({kind})")

# 2. Try common creation patterns (safe try-except)
print("\nTrying common creation patterns (expect some to fail — that's ok):")

try_patterns = [
    lambda: KeyPackageTBS(),                              # default init
    lambda: KeyPackageTBS(cs),                            # with ciphersuite
    lambda: KeyPackageTBS.from_bytes(b""),                # common parse method
    lambda: KeyPackageTBS.deserialize(b""),               # from your dir()
]

for i, pattern in enumerate(try_patterns, 1):
    try:
        obj = pattern()
        print(f"Pattern {i}: SUCCESS → {type(obj).__name__}")
        break
    except TypeError as e:
        print(f"Pattern {i}: TypeError → {e}")
    except Exception as e:
        print(f"Pattern {i}: Other error → {e}")

print("\nNext: look inside the source file that defines KeyPackageTBS.")
print("Please run this command in Git Bash and paste the output:")
print("    grep -r -i 'KeyPackageTBS' mls_stuff/mls_stuff/MLS/")
print("    # or if grep not available, open MLS/ folder and tell me which file contains 'class KeyPackageTBS'")