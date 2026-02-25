# test_ciphersuite.py
import sys

# Your path to the cloned repo (same as before)
sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

from mls_stuff.Enums import CipherSuite

print("=== Step 2: Exploring CipherSuite ===\n")

# 1. Create a CipherSuite object (the one we will use in the whole project)
cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

print("✅ Created CipherSuite:")
print(f"   Name : {cs.name}")
print(f"   Value: {cs.value} (hex: {cs.value:04x})")
print(f"   Full enum: {cs}\n")

# 2. Show what this CipherSuite actually means (very important for understanding MLS)
print("This CipherSuite means:")
print("   • KEM     : DHKEM with X25519")
print("   • KDF     : HKDF-SHA256")
print("   • AEAD    : AES-128-GCM")
print("   • Hash    : SHA-256")
print("   • Signature: Ed25519\n")

print("=== All available attributes & methods ===")
for attr in sorted(dir(cs)):
    if not attr.startswith("__"):
        try:
            value = getattr(cs, attr)
            print(f"   {attr:25} → {value}")
        except:
            print(f"   {attr:25} → <could not read>")

print("\n🎉 We now know exactly what this library gives us for CipherSuite.")
print("We will use this exact object for the entire project.")