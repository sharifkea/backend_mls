# test_mls_import.py
import sys

# === ADD THIS LINE (your exact path to the CLONED repo root) ===
sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

print("Python path now includes mls_stuff folder")
print("Trying to import...")

try:
    from mls_stuff.Enums import CipherSuite
    print("✅ SUCCESS! mls_stuff is now importable")
    
    print("\nAvailable ciphersuites:")
    for name in dir(CipherSuite):
        if not name.startswith("_"):
            print("   ", name)
            
    # Show one example
    print("\nDefault ciphersuite example:")
    default_cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    print("   ID:", default_cs.value)
    print("   Name:", default_cs.name)
    
except Exception as e:
    print("❌ Import failed:", e)
    print("\nHint: Check that the folder path is correct and contains a folder named 'mls_stuff' inside it.")