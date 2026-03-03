# check_ratchet_encryption.py
import sys
sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

from mls_stuff.RatchetTree import _ratchet_tree
from mls_stuff.Crypto import _derive_secrets
import inspect

def check_encryption_methods():
    """Check for proper ratchet encryption methods"""
    
    print("=== Checking for Ratchet Encryption Methods ===\n")
    
    # Check RatchetTree for encryption methods
    print("RatchetTree methods:")
    for name in dir(_ratchet_tree.RatchetTree):
        if not name.startswith('_'):
            print(f"  - {name}")
    
    # Check for key schedule
    print("\nDeriveSecrets methods:")
    for name in dir(_derive_secrets):
        if not name.startswith('_'):
            attr = getattr(_derive_secrets, name)
            if inspect.isfunction(attr):
                print(f"  - {name}")
    
    # Look for any class that might handle message protection
    try:
        from mls_stuff.MLS import PrivateMessage
        print("\nPrivateMessage signature:")
        print(inspect.signature(PrivateMessage.__init__))
    except:
        print("\nPrivateMessage not found or can't inspect")

if __name__ == "__main__":
    check_encryption_methods()