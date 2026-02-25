# group_creation_2.py
import sys
import secrets
import requests
from datetime import datetime, timedelta

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

from mls_stuff.RatchetTree._ratchet_tree import RatchetTree
from mls_stuff.RatchetTree._leaf_node import LeafNode
from mls_stuff.Enums import CipherSuite, ProtocolVersion
from mls_stuff.MLS._key_package import KeyPackage
from mls_stuff.Misc import VLBytes
from mls_stuff.Objects import GroupContext

cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
BASE_URL = "http://127.0.0.1:8000"

def fetch_keypackage(user_id: str) -> bytes | None:
    url = f"{BASE_URL}/key_packages/{user_id}"
    r = requests.get(url)
    if r.status_code == 200:
        print(f"Fetched {user_id}: {len(r.content)} bytes")
        return r.content
    print(f"Fetch {user_id} failed: {r.status_code} {r.text}")
    return None

def create_empty_group(creator_leaf_node: LeafNode, creator_name: str = "bob"):
    print(f"\n=== {creator_name.capitalize()} creates empty group ===")

    # 1. Random group ID
    group_id_bytes = secrets.token_bytes(16)
    group_id = VLBytes(group_id_bytes)
    print("Group ID (hex):", group_id_bytes.hex())

    # 2. Initialize tree
    tree = RatchetTree()
    # Extend until at least one leaf slot exists
    while tree.root is None or len(tree.leaves) < 1:
        tree.extend()

    # Assign creator at leaf index 0
    tree[0] = creator_leaf_node

    # IMPORTANT: update indices NOW, before any hash or serialize
    tree.update_node_index()
    tree.update_leaf_index()

    # Debug: check if index was set
    print(f"Leaf 0 index after update: {tree[0]._leaf_index}")  # should be 0

    # 4. Group context (epoch 0)
    tree_hash = VLBytes(tree.hash(cs))
    confirmed_hash = VLBytes(b"")

    group_context = GroupContext(
        cipher_suite=cs,
        group_id=group_id,
        epoch=0,
        tree_hash=tree_hash,
        confirmed_transcript_hash=confirmed_hash,
        extensions=[]   # empty list of extensions
    )

    print("Empty group created successfully!")
    print(f"  Epoch: 0")
    print(f"  Members: ['{creator_name}']")
    print(f"  Tree hash (prefix): {tree_hash.data.hex()[:32]}...")

    return {
        "group_id": group_id,
        "epoch": 0,
        "tree": tree,
        "group_context": group_context,
        "members": [creator_name]
    }

if __name__ == "__main__":
    # 1. Fetch Bob's KeyPackage
    bob_kp_bytes = fetch_keypackage("bob")
    if not bob_kp_bytes:
        print("Cannot continue — Bob not found")
        sys.exit(1)

    bob_kp_bytes_mutable = bytearray(bob_kp_bytes)
    bob_kp = KeyPackage.deserialize(bob_kp_bytes_mutable)
    bob_leaf = bob_kp.content.leaf_node
    print("Bob's LeafNode extracted")

    # 2. Create group
    group = create_empty_group(bob_leaf, "bob")

    print("\nGroup info:")
    print(group)