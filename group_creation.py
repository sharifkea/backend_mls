# group_creation.py
import sys
import os
import secrets
from datetime import datetime
from test_keypair_ed25519 import get_ed25519_keys
from test_keypackage_final import GeneratKeyPackage
from test_fet_keypak import fetch_keypackage

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

from mls_stuff.RatchetTree._ratchet_tree import RatchetTree
from mls_stuff.RatchetTree._leaf_node import LeafNode
from mls_stuff.Enums import CipherSuite, ProtocolVersion
from mls_stuff.Objects import GroupContext
#from mls_stuff.MLS._key_schedule import KeySchedule
from mls_stuff.Misc import VLBytes
from mls_stuff.MLS._key_package import KeyPackage



cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

# ────────────────────────────────────────────────
# Helper: Load Bob's private key (you need to have saved it earlier)
# ────────────────────────────────────────────────

#def load_bob_private_key():
    #bob_priv, bob_pub = get_ed25519_keys()  # ← replace with real loading if you saved it
    # For now — replace with your actual Bob private key bytes from generation
    # In real code you would load from secure storage or generate fresh
    # Here we use a dummy — replace with real 32-byte priv key!
    #return secrets.token_bytes(32)  # ← DUMMY – REPLACE WITH REAL BOB ED25519 PRIV KEY
    #return bob_priv
# ────────────────────────────────────────────────
# Create empty group with Bob as first member
# ────────────────────────────────────────────────

def create_empty_group(bob_leaf_node: LeafNode):
    # 1. Random group ID (16 bytes)
    group_id = VLBytes(secrets.token_bytes(16))
    print("Group ID (hex):", group_id.data.hex())

   # 1. Empty tree
    tree = RatchetTree()

    # 2. Force minimal structure: extend once to create root (depth=1)
    tree.extend()  # now depth=1, root exists (blank RatchetNode)

    # Optional: extend again if you want more leaves (depth=2 → 3 nodes)
    # tree.extend()  # now depth=2, 3 nodes (root + 2 children)

    # 3. Assign Bob at leaf index 0
    tree[0] = bob_leaf_node

    # Update indices
    tree.update_leaf_index()
    tree.update_node_index()

    # 6. Group context (epoch 0) – only fields that exist
    group_context = GroupContext(
        cipher_suite=cs,
        group_id=group_id,
        epoch=0,
        tree_hash=VLBytes(tree.hash(cs)),
        confirmed_transcript_hash=b"",   # bytes empty
        extensions=[]   # empty list of extensions

    )

    print("\nEmpty group created successfully!")
    print(f"  Epoch: 0")
    print(f"  Members: ['bob']")
    print(f"  Group context tree_hash (prefix): {group_context.tree_hash.hex()[:32]}...")

    return {
        "group_id": group_id,
        "epoch": 0,
        "tree": tree,
        "group_context": group_context,
        "members": ["bob"]
    }


if __name__ == "__main__":
    alice_priv_bytes = GeneratKeyPackage("alice")
    bob_priv_bytes = GeneratKeyPackage("bob")
    print("This is a skeleton — we need Bob's LeafNode first.")
    print("Next: fetch Bob's KeyPackage → deserialize → get LeafNode")
    # Step 1: Load Bob's private key (you should have generated and saved it earlier)
    bob_kp_bytes = fetch_keypackage("bob")   # your fetch function
    bob_kp_bytes_mutable = bytearray(bob_kp_bytes)   # ← convert to bytearray
    bob_kp = KeyPackage.deserialize(bob_kp_bytes_mutable)
    bob_leaf = bob_kp.content.leaf_node
    print("Bob's LeafNode extracted")
    # For testing: we need Bob's LeafNode
    # In real flow you would generate Bob's KeyPackage → extract LeafNode from it
    # Here we simulate / skip — replace with real Bob LeafNode
    group_info = create_empty_group(bob_leaf)
    print("Group created with Bob as first member")
    print("Group ID:", group_info["group_id"].data.hex())
    print("Epoch:", group_info["epoch"])    