def check_encryption_classes():
    """Check what encryption classes are available"""
    import inspect
    from mls_stuff import Crypto, RatchetTree
    
    print("\n=== Encryption Classes Available ===")
    
    # Check Crypto module
    crypto_members = [name for name, _ in inspect.getmembers(Crypto) if not name.startswith('_')]
    print(f"Crypto module: {crypto_members[:10]}...")
    
    # Check RatchetTree module
    tree_members = [name for name, _ in inspect.getmembers(RatchetTree) if not name.startswith('_')]
    print(f"RatchetTree module: {tree_members[:10]}...")
    
    # Try to find specific classes
    try:
        from mls_stuff.Crypto import RatchetTreeEra
        print("✅ RatchetTreeEra found")
    except ImportError:
        print("❌ RatchetTreeEra not found")
    
    try:
        from mls_stuff.MLS import PrivateMessage
        print("✅ PrivateMessage found")
    except ImportError:
        print("❌ PrivateMessage not found")
if __name__ == "__main__":
    check_encryption_classes()