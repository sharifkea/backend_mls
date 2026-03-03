# test_ratchet_methods.py
import sys
sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

from mls_stuff import RatchetTree, Enums
from mls_stuff.RatchetTree import _ratchet_tree
import secrets

def test_ratchet_methods():
    """Create a ratchet tree and see what methods are available"""
    
    print("=" * 60)
    print("TESTING RATCHET TREE METHODS")
    print("=" * 60)
    
    # 1. Create a ratchet tree
    cs = Enums.CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    tree = _ratchet_tree.RatchetTree()
    
    # Extend the tree to create structure
    tree.extend()
    tree.extend()
    
    print(f"\n1️⃣  Tree created")
    print(f"   Tree type: {type(tree)}")
    
    # 2. List all available methods on the tree
    print("\n2️⃣  RATCHET TREE METHODS:")
    methods = []
    for name in dir(tree):
        if not name.startswith('_'):
            attr = getattr(tree, name)
            if callable(attr):
                methods.append(f"   🔧 {name}()")
            else:
                methods.append(f"   📊 {name}")
    
    for m in sorted(methods):
        print(m)
    
    # 3. Try to get tree hash
    print("\n3️⃣  TREE HASH:")
    try:
        tree_hash = tree.hash(cs)
        print(f"   Tree hash: {tree_hash.hex()[:32]}...")
        print(f"   Hash type: {type(tree_hash)}")
    except Exception as e:
        print(f"   Error getting hash: {e}")
    
    # 4. Look for any methods that might give us keys
    print("\n4️⃣  LOOKING FOR KEY-RELATED METHODS:")
    key_methods = []
    for name in dir(tree):
        if any(k in name.lower() for k in ['key', 'secret', 'epoch', 'era', 'derive']):
            if not name.startswith('_'):
                attr = getattr(tree, name)
                if callable(attr):
                    key_methods.append(f"   🔑 {name}()")
                else:
                    key_methods.append(f"   📦 {name}")
    
    for m in key_methods:
        print(m)
    
    return tree

if __name__ == "__main__":
    tree = test_ratchet_methods()