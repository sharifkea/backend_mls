# add_member.py
import sys
import secrets
import requests
from test_keypair_ed25519 import get_ed25519_keys
from test_keypackage_final import GeneratKeyPackage
#from test_fet_keypak import fetch_keypackage
from group_creation_2 import create_empty_group

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

from mls_stuff.RatchetTree._ratchet_tree import RatchetTree
from mls_stuff.RatchetTree._leaf_node import LeafNode
from mls_stuff.Enums import CipherSuite, ProtocolVersion, ProposalType, SenderType, ContentType, WireFormat
from mls_stuff.MLS._key_package import KeyPackage
from mls_stuff.MLS._proposal import Add
from mls_stuff.MLS._commit import Commit
from mls_stuff.MLS._welcome import Welcome
from mls_stuff.MLS import MLSMessage, Sender, AuthenticatedContent, FramedContent, FramedContentAuthData, FramedContentTBS
from mls_stuff.Misc import VLBytes, SignContent
from mls_stuff.Crypto._crypt_with_label import SignWithLabel
from mls_stuff.Crypto import GroupSecrets, EncryptedGroupSecrets, HPKECiphertext
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

def add_member(group, new_member_id: str, committer_priv_bytes: bytes, committer_index: int = 0):
    print(f"\n=== Adding {new_member_id} to group ===\n")

    # 1. Fetch new member's KeyPackage
    new_kp_bytes = fetch_keypackage(new_member_id)
    if not new_kp_bytes:
        print("Cannot add – KeyPackage not found")
        return None

    new_kp_bytes_mutable = bytearray(new_kp_bytes)
    new_kp = KeyPackage.deserialize(new_kp_bytes_mutable)
    new_leaf = new_kp.content.leaf_node

    # 2. Create Add proposal
    add_proposal = Add(key_package=new_kp)

    # 3. Create Commit
    commit = Commit(
        proposals=[add_proposal],
        path=None  # no path update for simple add
    )

    # 4. Create FramedContent
    sender = Sender(sender_type=SenderType.member, leaf_index=committer_index)

    framed_content = FramedContent(
        group_id=group["group_id"],
        epoch=group["epoch"],
        sender=sender,
        authenticated_data=VLBytes(b""),
        content_type=ContentType.commit,
        commit=commit
    )

    # 5. Create FramedContentAuthData
    auth = FramedContentAuthData(signature=VLBytes(b""), confirmation_tag=None)

    # 6. Create AuthenticatedContent
    authenticated_content = AuthenticatedContent(
        wire_format=WireFormat.MLS_PUBLIC_MESSAGE,
        content=framed_content,
        auth=auth
    )

    # 7. Sign the content
    tbs = authenticated_content.FramedContentTBS(group["group_context"])
    sign_content = SignContent(b"FramedContentTBS", tbs.serialize())
    signature_bytes = SignWithLabel(cs, sign_content, committer_priv_bytes)
    authenticated_content.auth.signature = VLBytes(signature_bytes)

    # 8. Create MLSMessage (PublicMessage)
    public_commit = MLSMessage(
        wire_format=WireFormat.MLS_PUBLIC_MESSAGE,
        msg_content=authenticated_content
    )

    print("PublicMessage (Commit) created and signed – size:", len(public_commit.serialize()))

    # 9. Apply Commit to tree (add new leaf)
    tree = group["tree"]
    new_leaf_index = len(tree.leaves)  # next free index

    # Extend tree if necessary
    while tree.nodes <= new_leaf_index * 2:
        tree.extend()

    # Assign new leaf
    tree[new_leaf_index] = new_leaf

    # CRITICAL MANUAL FIX: set _leaf_index on the new leaf node
    tree[new_leaf_index]._leaf_index = new_leaf_index

    # Update indices (optional but recommended)
    tree.update_node_index()
    tree.update_leaf_index()

    # Debug: confirm the index was set
    print(f"New leaf index after manual set: {tree[new_leaf_index]._leaf_index}")  # should print the number

    # 10. Update epoch & context (now safe to hash)
    group["epoch"] += 1
    group["group_context"].epoch = group["epoch"]
    group["group_context"].tree_hash = VLBytes(tree.hash(cs))
    group["members"].append(new_member_id)

    # 11. Generate Welcome
    joiner_secret = secrets.token_bytes(32)
    group_secrets = GroupSecrets(
        joiner_secret=VLBytes(joiner_secret),  # wrap in VLBytes
        psks=[],  # empty list
        path_secret=None  # optional
    )
    # Dummy HPKECiphertext (placeholder – real would be HPKE encrypt of group_secrets)
    dummy_hpke = HPKECiphertext(
        kem_output=VLBytes(secrets.token_bytes(32)),
        ciphertext=VLBytes(group_secrets.serialize()),  # raw serialize as ciphertext
        # optional other fields if required
    )

    encrypted_secrets = EncryptedGroupSecrets(
        new_member=VLBytes(b"dummy_ref"),
        encrypted_group_secrets=dummy_hpke
    )

    welcome = Welcome(
        cipher_suite=cs,
        secrets=[encrypted_secrets],
        encrypted_group_info=VLBytes(b"")
    )

    print("Alice added!")
    print(f"  New epoch: {group['epoch']}")
    print(f"  Members: {group['members']}")
    print(f"  Welcome size: {len(welcome.serialize())} bytes")

    return welcome

if __name__ == "__main__":
    # Example group from previous run (replace with your real one)
   
    alice_priv_bytes = GeneratKeyPackage("alice")
    bob_priv_bytes = GeneratKeyPackage("bob")
    
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
    # Bob's private key – replace with real hex from Bob generation
    #bob_priv_bytes = bytes.fromhex("b7c7ba36d2ecbd52069e63dc31942910d8f99e30b06ee913a8ee20dfba74f1a7")
    # Membership key – for epoch 0, empty or from group
    membership_key = b""  # replace with real if needed

    # Add Alice
    welcome = add_member(group, "alice", bob_priv_bytes)

    if welcome:
        print("Welcome ready to send to Alice!")
        print("Group is ready for messaging!")

        # Save group state for later use
        with open("group_state.bin", "wb") as f:
            f.write(group["tree"].serialize())
        print("Group tree saved to group_state.bin")