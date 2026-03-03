# explore_ratchet.py
import inspect
import sys
sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

from mls_stuff import RatchetTree, Crypto, MLS, Enums
from mls_stuff.RatchetTree import _ratchet_tree, _leaf_node, _parent_node, _ratchet_node, _hash_inputs
from mls_stuff.Crypto import (
    _derive_secrets, _extract_welcome_secret, _key_pair, 
    _crypt_with_label, _group_secrets, _hpke_ciphertext,
    _make_ref, _pre_shared_key, _vlbytes_synonyms
)

def explore_ratchet_functions():
    """Explore all ratchet-related functions in the library"""
    
    print("=" * 60)
    print("EXPLORING RATCHET KEY DERIVATION FUNCTIONS")
    print("=" * 60)
    
    # 1. Check RatchetTree modules
    print("\n1️⃣  RATCHET TREE MODULES")
    ratchet_modules = [
        (_ratchet_tree, "_ratchet_tree"),
        (_leaf_node, "_leaf_node"),
        (_parent_node, "_parent_node"),
        (_ratchet_node, "_ratchet_node"),
        (_hash_inputs, "_hash_inputs")
    ]
    
    for module, name in ratchet_modules:
        print(f"\n--- {name} ---")
        functions = []
        for attr_name, attr in inspect.getmembers(module):
            if not attr_name.startswith('_') or attr_name == '__init__':
                if inspect.isclass(attr):
                    functions.append(f"📦 Class: {attr_name}")
                    # Check class methods
                    for method_name, method in inspect.getmembers(attr):
                        if not method_name.startswith('_') and inspect.isfunction(method):
                            functions.append(f"   └─ method: {method_name}")
                elif inspect.isfunction(attr):
                    functions.append(f"⚙️  Function: {attr_name}")
        
        # Print first 10 items
        for f in functions[:10]:
            print(f"   {f}")
    
    # 2. Check Crypto modules - LOOK FOR KEY DERIVATION
    print("\n2️⃣  CRYPTO MODULES - KEY DERIVATION FOCUS")
    crypto_modules = [
        (_derive_secrets, "_derive_secrets"),
        (_extract_welcome_secret, "_extract_welcome_secret"),
        (_key_pair, "_key_pair"),
        (_crypt_with_label, "_crypt_with_label"),
        (_group_secrets, "_group_secrets"),
        (_pre_shared_key, "_pre_shared_key")
    ]
    
    for module, name in crypto_modules:
        print(f"\n--- {name} ---")
        for attr_name, attr in inspect.getmembers(module):
            if not attr_name.startswith('_') or attr_name == '__init__':
                if 'derive' in attr_name.lower() or 'secret' in attr_name.lower() or 'key' in attr_name.lower():
                    print(f"   🔑 {attr_name}: {type(attr)}")
    
    # 3. Check for DeriveSecret function (you're already using it!)
    print("\n3️⃣  LOOKING FOR DeriveSecret FUNCTION")
    try:
        from mls_stuff.Crypto._derive_secrets import DeriveSecret
        print("✅ Found DeriveSecret in _derive_secrets")
        
        # Inspect DeriveSecret
        print("\n   DeriveSecret signature:")
        print(f"   {inspect.signature(DeriveSecret)}")
        
        # Check if it's a class or function
        if inspect.isclass(DeriveSecret):
            print("   📦 DeriveSecret is a class")
            # Look for methods
            for method_name in dir(DeriveSecret):
                if not method_name.startswith('_'):
                    print(f"      └─ method: {method_name}")
        elif inspect.isfunction(DeriveSecret):
            print("   ⚙️  DeriveSecret is a function")
    except ImportError as e:
        print(f"❌ Error: {e}")
    
    # 4. Check for ExtractWelcomeSecret
    try:
        from mls_stuff.Crypto._extract_welcome_secret import ExtractWelcomeSecret
        print("\n✅ Found ExtractWelcomeSecret in _extract_welcome_secret")
    except ImportError:
        pass
    
    # 5. Look for any classes/functions with 'ratchet' in name
    print("\n4️⃣  SEARCHING FOR RATCHET-SPECIFIC FUNCTIONS")
    all_modules = [
        _ratchet_tree, _ratchet_node, _leaf_node, _parent_node,
        _derive_secrets, _extract_welcome_secret
    ]
    
    for module in all_modules:
        if module:
            module_name = module.__name__.split('.')[-1]
            for attr_name in dir(module):
                if 'ratchet' in attr_name.lower() or 'epoch' in attr_name.lower() or 'generation' in attr_name.lower():
                    print(f"   🔍 {module_name}.{attr_name}")

if __name__ == "__main__":
    explore_ratchet_functions()