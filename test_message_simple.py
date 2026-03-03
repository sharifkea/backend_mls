# add_member.py
import sys
import secrets
import requests
from create_keypakage import GeneratKeyPackage
from test_db_api import test_user_registration, test_user_login, test_upload_keypackage, test_get_latest_keypackage


sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

from mls_stuff.RatchetTree._ratchet_tree import RatchetTree
from mls_stuff.RatchetTree._leaf_node import LeafNode
from mls_stuff.Enums import (CipherSuite, ProtocolVersion, 
                             ProposalType, SenderType, 
                             ContentType, WireFormat)
from mls_stuff.MLS._key_package import KeyPackage
from mls_stuff.MLS._proposal import Add
from mls_stuff.MLS._commit import Commit
from mls_stuff.MLS._welcome import Welcome
from mls_stuff.MLS import (MLSMessage, Sender, 
                           AuthenticatedContent, FramedContent, 
                           FramedContentAuthData, FramedContentTBS,
                           AuthenticatedContentTBM,
                            PublicMessage,
                            MLSMessage)
from mls_stuff.Misc import VLBytes, SignContent
from mls_stuff.Crypto._crypt_with_label import SignWithLabel
from mls_stuff.Crypto import GroupSecrets, EncryptedGroupSecrets, HPKECiphertext
from mls_stuff.Objects import GroupContext
from mls_stuff.MLS import PrivateMessage
import os


cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
BASE_URL = "http://localhost:8000"

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


def fetch_keypackage(user_id: str) -> bytes | None:
    url = f"{BASE_URL}/key_packages/{user_id}/latest"
    r = requests.get(url)
    if r.status_code == 200:
        print(f"Fetched {user_id}: {len(r.content)} bytes")
        return r.content
    print(f"Fetch {user_id} failed: {r.status_code} {r.text}")
    return None

def add_member(group, new_member_id: str, committer_priv_bytes: bytes, committer_index: int = 0):
    print(f"\n=== Adding {new_member_id} to group ===\n")

    # 1. Fetch new member's KeyPackage
    new_kp_bytes = test_get_latest_keypackage(new_member_id)
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

    # Manual fix: set _leaf_index on the new leaf
    tree[new_leaf_index]._leaf_index = new_leaf_index

    # Update indices (for other nodes)
    tree.update_node_index()
    tree.update_leaf_index()

    print(f"New leaf index after manual set: {tree[new_leaf_index]._leaf_index}")

    # 10. Update epoch & context (now safe to hash)
    group["epoch"] += 1
    group["group_context"].epoch = group["epoch"]
    group["group_context"].tree_hash = VLBytes(tree.hash(cs))
    group["members"].append(new_member_id)

    # 11. Generate Welcome
    joiner_secret = secrets.token_bytes(32)
    group_secrets = GroupSecrets(
        joiner_secret=VLBytes(joiner_secret),
        psks=[],
        path_secret=None
    )

    dummy_hpke = HPKECiphertext(
        kem_output=VLBytes(secrets.token_bytes(32)),
        ciphertext=VLBytes(group_secrets.serialize())
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

def send_test_message(group, sender_leaf_index: int, sender_priv_bytes: bytes, message_text: str):
    """
    Send a test message from one group member to another
    """
    print(f"\n=== Sending test message from leaf {sender_leaf_index} ===")
    
    # 1. Convert message to bytes
    message_bytes = message_text.encode('utf-8')
    
    # 2. Create FramedContent for application message
    # For application data, we need to pass the bytes directly
    # The FramedContent class likely has a parameter for application data
    sender = Sender(sender_type=SenderType.member, leaf_index=sender_leaf_index)
    
    # Try with application_data parameter
    framed_content = FramedContent(
        group_id=group["group_id"],
        epoch=group["epoch"],
        sender=sender,
        authenticated_data=VLBytes(b""),
        content_type=ContentType.application,
        application_data=VLBytes(message_bytes)  # This is the key parameter
    )
    
    # 3. Create authentication data
    auth = FramedContentAuthData(
        signature=VLBytes(b""), 
        confirmation_tag=None
    )
    
    # 4. Create AuthenticatedContent
    authenticated_content = AuthenticatedContent(
        wire_format=WireFormat.MLS_PUBLIC_MESSAGE,
        content=framed_content,
        auth=auth
    )
    
    # 5. Sign the content
    tbs = authenticated_content.FramedContentTBS(group["group_context"])
    sign_content = SignContent(b"FramedContentTBS", tbs.serialize())
    signature_bytes = SignWithLabel(cs, sign_content, sender_priv_bytes)
    authenticated_content.auth.signature = VLBytes(signature_bytes)
    
    # 6. Create the MLS message (PublicMessage since we're not encrypting yet)
    message = PublicMessage(
        content=framed_content,
        auth=auth,
        membership_tag=VLBytes(b"")  # Empty tag for testing
    )
    
    # Wrap in MLSMessage
    mls_message = MLSMessage(
        wire_format=WireFormat.MLS_PUBLIC_MESSAGE,
        msg_content=message
    )
    
    print(f"   Message created: '{message_text}'")
    print(f"   Message size: {len(mls_message.serialize())} bytes")
    
    return mls_message

def receive_test_message(group, message: MLSMessage, expected_sender_index: int):
    """
    Receive and verify a test message
    """
    print("\n=== Receiving test message ===")
    
    # Extract the PublicMessage
    if not isinstance(message.msg_content, PublicMessage):
        print(" Not a PublicMessage")
        return None
    
    public_msg = message.msg_content
    framed_content = public_msg.content
    
    # Check content type
    if framed_content.content_type != ContentType.application:
        print(f" Not an application message (type: {framed_content.content_type})")
        return None
    
    # Extract the message text - try different possible attribute names
    message_text = None
    
    # Try common attribute names for application data
    if hasattr(framed_content, 'application_data'):
        message_bytes = framed_content.application_data.data
        message_text = message_bytes.decode('utf-8')
    elif hasattr(framed_content, 'data'):
        message_bytes = framed_content.data.data
        message_text = message_bytes.decode('utf-8')
    elif hasattr(framed_content, 'content'):
        # If content exists and is bytes-like
        if isinstance(framed_content.content, VLBytes):
            message_text = framed_content.content.data.decode('utf-8')
    else:
        print(f" Could not find application data in FramedContent")
        print(f"   Available attributes: {dir(framed_content)}")
        return None
    
    # Verify sender
    if framed_content.sender.leaf_index != expected_sender_index:
        print(f" Not a sender mismatch: expected {expected_sender_index}, got {framed_content.sender.leaf_index}")
        return None
    
    # Verify group and epoch
    if framed_content.group_id.data != group["group_id"].data:
        print(" Not a group ID mismatch")
        return None
    
    if framed_content.epoch != group["epoch"]:
        print(f" Not an epoch mismatch: expected {group['epoch']}, got {framed_content.epoch}")
        return None
    
    print(f"   Message received: '{message_text}'")
    print(f"   From leaf index: {framed_content.sender.leaf_index}")
    print(f"   At epoch: {framed_content.epoch}")
    
    return message_text

def simple_chat_demo(group, alice_priv_bytes, bob_priv_bytes):
    """
    Simple chat demo between Alice and Bob
    """
    print("\n" + "="*50)
    print("SIMPLE CHAT DEMO")
    print("="*50)
    
    # Bob sends first message (Bob is at index 0)
    bob_msg = send_test_message(group, 0, bob_priv_bytes, "Hello Alice! Welcome to the group.")
    print("\n Bob sent a message")
    
    # Alice receives it (Alice should be at index 1)
    received = receive_test_message(group, bob_msg, 0)
    
    # Alice replies
    alice_msg = send_test_message(group, 1, alice_priv_bytes, "Thanks Bob! Glad to be here.")
    print("\n Alice sent a reply")
    
    # Bob receives Alice's reply
    received2 = receive_test_message(group, alice_msg, 1)
    
    print("\n" + "="*50)
    print("CHAT DEMO COMPLETE")
    print("="*50)

# Add this to verify encryption keys exist (simplified)
def setup_encryption_keys(group):
    """
    Simplified: In a real implementation, you'd derive encryption keys from the ratchet tree
    For testing, we'll just note that the tree exists
    """
    print("\n=== Encryption Keys Setup ===")
    print(f"  Ratchet tree has {len(group['tree'].leaves)} leaves")
    print(f"  Current epoch: {group['epoch']}")
    print("   (In real MLS, messages would be encrypted with ratchet keys)")
    return True




def simple_message_test(group, sender_index, sender_priv_bytes, receiver_name):
    """
    Ultra-simple message test
    """
    print(f"\n  Testing message from index {sender_index} to {receiver_name}")
    
    # Create and send message
    msg = send_test_message(group, sender_index, sender_priv_bytes, 
                           f"Hello {receiver_name}! This is a test.")
    
    # Receive it
    received = receive_test_message(group, msg, sender_index)
    
    return received

if __name__ == "__main__":

    test_user = "alice"
    user_id_alice = test_user_registration(test_user,"1234")
    if user_id_alice:
        user_id_alice, token_alice = test_user_login(test_user,"1234")
        if user_id_alice and token_alice:
            alice_priv_bytes, kp_user_alice=GeneratKeyPackage(test_user)
            ref_hash_alice, key_package_id_alice = test_upload_keypackage(user_id_alice, kp_user_alice)
    
    test_user = "bob"
    user_id_bob = test_user_registration(test_user,"1234")
    if user_id_bob:
        user_id_bob, token_bob = test_user_login(test_user,"1234")
        if user_id_bob and token_bob:
            bob_priv_bytes, kp_user_bob=GeneratKeyPackage(test_user)
            ref_hash_bob, key_package_id_bob = test_upload_keypackage(user_id_bob, kp_user_bob)
    
    bob_latest_kp = test_get_latest_keypackage(user_id_bob)
    if not bob_latest_kp:
        print("Cannot continue — Bob not found")
        sys.exit(1)

    bob_kp_bytes_mutable = bytearray(bob_latest_kp)
    bob_kp = KeyPackage.deserialize(bob_kp_bytes_mutable)
    bob_leaf = bob_kp.content.leaf_node
    print("Bob's LeafNode extracted")

    group = create_empty_group(bob_leaf, "bob")

    # Add Alice
    welcome = add_member(group, user_id_alice, bob_priv_bytes)

    if welcome:
        print("Welcome ready to send to Alice!")
        # Add this right after creating the welcome
        
        # Simple test: Bob sends a message to Alice
        #simple_message_test(group, 0, bob_priv_bytes, "alice")
        
        # Alice replies
        #simple_message_test(group, 1, alice_priv_bytes, "bob")
        
        # NEW: Send test messages between Alice and Bob
        print("\n" + " "*20)
        print("  NOW TESTING MESSAGE EXCHANGE")
        print(" "*20)
        
        # Setup encryption (simplified)
        setup_encryption_keys(group)
        
        # Run the chat demo
        simple_chat_demo(group, alice_priv_bytes, bob_priv_bytes)
        
        # Send one more message as a test
        print("\n" + " "*20)
        print(" SENDING ONE MORE MESSAGE")
        print(" "*20)
        
        # Alice sends another message
        final_msg = send_test_message(group, 1, alice_priv_bytes, "Let's build something great together!")
        receive_test_message(group, final_msg, 1)
