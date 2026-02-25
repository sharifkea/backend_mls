# test_keypackage.py
import sys

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

print("=== Step 4: Exploring KeyPackage ===\n")

try:
    from mls_stuff.MLS import KeyPackageTBS, Credential
    from mls_stuff.Enums import CipherSuite
    
    print("✅ Successfully imported KeyPackageTBS and Credential from mls_stuff.MLS")
    
    cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    
    print("\nAvailable classes in Packages module:")
    for name in sorted(dir()):
        if "KeyPackage" in name or "Credential" in name or name in ["KeyPackage", "Credential"]:
            print("   ", name)
    
    # Show what a KeyPackage looks like
    print("\nTrying to understand KeyPackage structure...")
    print("KeyPackage class methods/attributes:")
    for attr in sorted(dir(KeyPackageTBS)):
        if not attr.startswith("_"):
            print("   ", attr)
            
except ImportError as e:
    print("❌ Import failed:", e)
    print("\nHint: Look inside the mls_stuff folder and tell me what .py files are in mls_stuff/Packages/ or mls_stuff/")
    print("   (e.g. is there a file called packages.py or keypackage.py?)")
except Exception as e:
    print("❌ Unexpected error:", e)

print("\nOnce this runs, we will try to actually CREATE a KeyPackage in the next step.")