# test_credential.py
import sys

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

print("=== Step 6.1: Creating BasicCredential ===\n")

try:
    from mls_stuff.Crypto.Credential import BasicCredential
    from mls_stuff.Enums import CredentialType

    identity_bytes = b"alice@example.com"

    print("Attempt 1: BasicCredential(identity=...)")
    try:
        cred = BasicCredential(identity=identity_bytes)
        print("SUCCESS (identity only)!")
        print(f"  Type: {cred.credential_type}")
        print(f"  Identity: {cred.identity!r}")
    except Exception as e1:
        print("  Failed:", e1)

    print("\nAttempt 2: BasicCredential(credential_type=..., identity=...)")
    try:
        cred2 = BasicCredential(
            credential_type=CredentialType.basic,
            identity=identity_bytes
        )
        print("SUCCESS (with type)!")
        print(f"  Type: {cred2.credential_type}")
        print(f"  Identity: {cred2.identity!r}")
    except Exception as e2:
        print("  Failed:", e2)

    # If one succeeded, try serialize
    if 'cred' in locals() or 'cred2' in locals():
        obj = cred if 'cred' in locals() else cred2
        try:
            ser = obj.serialize()
            print(f"\nSerialized length: {len(ser)} bytes")
            print(f"First bytes (hex): {ser.hex()[:60]}...")
        except Exception as es:
            print("Serialize failed:", es)

except ImportError as ie:
    print("Import failed:", ie)
    print("Try: from mls_stuff.Crypto._basic_credential import BasicCredential")

except Exception as e:
    print("Unexpected error:", e)