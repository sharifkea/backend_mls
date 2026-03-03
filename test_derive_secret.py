# test_derive_secret.py
import sys
sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

from mls_stuff.Crypto._derive_secrets import DeriveSecret
from mls_stuff import Enums
import inspect

def test_derive_secret():
    """Test how DeriveSecret works"""
    
    print("=" * 60)
    print("TESTING DeriveSecret FUNCTION")
    print("=" * 60)
    
    cs = Enums.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    
    # Check what DeriveSecret is
    print(f"\n1️⃣  DeriveSecret type: {type(DeriveSecret)}")
    
    if inspect.isclass(DeriveSecret):
        print("   DeriveSecret is a class")
        # Try to create an instance
        try:
            ds = DeriveSecret()
            print(f"   Instance created: {ds}")
            # Look at methods
            for name in dir(ds):
                if not name.startswith('_') and callable(getattr(ds, name)):
                    print(f"      method: {name}()")
        except Exception as e:
            print(f"   Error creating instance: {e}")
    
    elif inspect.isfunction(DeriveSecret):
        print("   DeriveSecret is a function")
        print(f"   Signature: {inspect.signature(DeriveSecret)}")
        
        # Try to call it with test data
        try:
            secret = b"test_secret" * 4
            label = b"test_label"
            result = DeriveSecret(cs, secret, label)
            print(f"   ✅ Called successfully")
            print(f"   Result type: {type(result)}")
            print(f"   Result length: {len(result) if hasattr(result, '__len__') else 'N/A'}")
        except Exception as e:
            print(f"   ❌ Error calling: {e}")

if __name__ == "__main__":
    test_derive_secret()