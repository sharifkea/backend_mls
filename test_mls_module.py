"""
test_mls_module.py
Step 12: Inspect mls_stuff.MLS module and sub-modules to discover group/message features

Run this to see what's available for Proposals, Commits, Welcomes, KeySchedule, Messages, etc.
"""

import sys

# Adjust path to your local repo
sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

# Import the main MLS module
import mls_stuff.MLS as MLS

print("=== Exploring mls_stuff.MLS module ===\n")

# List all attributes/classes/functions in MLS
mls_dir = [name for name in dir(MLS) if not name.startswith('__')]
print("Available in mls_stuff.MLS:")
print(sorted(mls_dir))
print(f"Total items: {len(mls_dir)}\n")

# Check for key MLS elements directly in MLS
key_terms = ['Proposal', 'Add', 'Update', 'Remove', 'Commit', 'Welcome', 'FramedContent', 'ApplicationData', 'PrivateMessage', 'PublicMessage', 'KeySchedule', 'Group']
for term in key_terms:
    if term in mls_dir:
        print(f"FOUND: {term} (likely implemented!)")
    else:
        print(f"NOT FOUND: {term} (may be in a sub-module)")

# Now explore known sub-modules (based on previous imports)
sub_modules = [
    '_key_package',    # We know this has KeyPackage, KeyPackageTBS
    '_key_schedule',   # Likely for epoch keys, encryption secrets
    '_proposal',       # If exists, for Add/Update/Remove
    '_commit',         # For Commit messages
    '_welcome',        # For Welcome messages
    '_message',        # For FramedContent, PrivateMessage, etc.
    '_group'           # If there's a Group class
]

for sub in sub_modules:
    try:
        sub_mod = __import__(f"mls_stuff.MLS.{sub}", fromlist=[''])
        print(f"\n=== Sub-module: MLS.{sub} (imported successfully) ===")
        sub_dir = [name for name in dir(sub_mod) if not name.startswith('__')]
        print(sorted(sub_dir))
        print(f"Total items: {len(sub_dir)}")
        
        # Check for constructors/methods
        for item in sub_dir:
            obj = getattr(sub_mod, item)
            if callable(obj):
                print(f"  - Function/Class: {item}")
                try:
                    print(f"    Docstring: {obj.__doc__[:100] if obj.__doc__ else 'No docstring'}...")
                except:
                    pass
    except ImportError:
        print(f"\n=== Sub-module: MLS.{sub} (IMPORT FAILED - may not exist) ===")

# Optional: If KeySchedule exists, try to create one
try:
    from mls_stuff.MLS._key_schedule import KeySchedule
    print("\n=== Testing KeySchedule creation ===")
    from mls_stuff.Enums import CipherSuite
    cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
    # Assume constructor takes cs + init_secret + context
    import secrets
    from mls_stuff.Misc import VLBytes
    from mls_stuff.Objects import GroupContext  # Adjust if needed
    group_id = VLBytes(secrets.token_bytes(16))
    context = GroupContext(cipher_suite=cs, group_id=group_id, epoch=0, tree_hash=VLBytes(b''), confirmed_transcript_hash=b'', extensions=[])
    init_secret = secrets.token_bytes(32)
    ks = KeySchedule(cs=cs, init_secret=init_secret, context=context)  # Guess args - adjust if error
    print("KeySchedule created!")
    print("Available methods:", [name for name in dir(ks) if callable(getattr(ks, name)) and not name.startswith('_')])
except ImportError:
    print("\nKeySchedule import failed - sub-module may not exist")
except TypeError as e:
    print("\nKeySchedule creation TypeError:", e)
    print("→ Check constructor args in _key_schedule.py (e.g., may not take init_secret)")
except Exception as e:
    print("\nUnexpected error with KeySchedule:", type(e).__name__, str(e))