# test_full_flow.py
import sys
import base64
import secrets
from test_db_api import (
    test_user_registration, test_user_login, test_upload_keypackage,
    test_get_latest_keypackage, test_create_group_with_id, test_add_group_member,
    test_send_message, test_get_group_messages, test_update_group_epoch,
    test_get_group_details, test_get_my_groups, get_user_by_username, get_user_by_id, search_users
)
from create_keypakage import GeneratKeyPackage
from encrypted_message_proper import send_encrypted_message, receive_encrypted_message

# Import MLS stuff
sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")
from mls_stuff.RatchetTree._ratchet_tree import RatchetTree
from mls_stuff.MLS._key_package import KeyPackage
from mls_stuff.Enums import CipherSuite, WireFormat
from mls_stuff.Misc import VLBytes
from mls_stuff.Objects import GroupContext
from mls_stuff.Crypto._derive_secrets import DeriveSecret
from mls_stuff.MLS import PrivateMessage, MLSMessage

cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

# 3. Alice reconstructs the MLS message from DB data
def reconstruct_message_from_db(msg_data, group_id_bytes):
    """Reconstruct an MLSMessage object from database fields"""
    
    # Decode base64 data
    ciphertext = base64.b64decode(msg_data['ciphertext'])
    nonce = base64.b64decode(msg_data['nonce'])
    
    # Create PrivateMessage object
    private_msg = PrivateMessage(
        group_id=VLBytes(group_id_bytes),
        epoch=msg_data['epoch'],
        content_type=msg_data['content_type'],
        authenticated_data=VLBytes(b""),
        encrypted_sender_data=VLBytes(b""),
        ciphertext=VLBytes(ciphertext)
    )
    
    # Wrap in MLSMessage
    mls_message = MLSMessage(
        wire_format=WireFormat.MLS_PRIVATE_MESSAGE,
        msg_content=private_msg
    )
    
    return mls_message, nonce

def create_empty_group(creator_leaf_node, creator_name: str = "bob"):
    """Create empty group (same as in test_message_enc.py)"""
    print(f"\n=== {creator_name.capitalize()} creates empty group ===")

    # 1. Random group ID (public)
    group_id_bytes = secrets.token_bytes(16)
    group_id = VLBytes(group_id_bytes)
    print("Group ID (hex):", group_id_bytes.hex())

    # 2. Initialize tree
    tree = RatchetTree()
    while tree.root is None or len(tree.leaves) < 1:
        tree.extend()

    # Assign creator at leaf index 0
    tree[0] = creator_leaf_node
    tree.update_node_index()
    tree.update_leaf_index()

    # 3. Generate INITIAL EPOCH SECRET
    epoch_secret = secrets.token_bytes(32)
    print(f"Initial epoch secret (first 16 bytes): {epoch_secret[:16].hex()}...")
    
    # 4. Generate init secret
    init_secret = DeriveSecret(cs, epoch_secret, b"init")

    # 5. Group context
    tree_hash = VLBytes(tree.hash(cs))
    confirmed_hash = VLBytes(b"")

    group_context = GroupContext(
        cipher_suite=cs,
        group_id=group_id,
        epoch=0,
        tree_hash=tree_hash,
        confirmed_transcript_hash=confirmed_hash,
        extensions=[]
    )

    return {
        "group_id": group_id,
        "group_id_b64": base64.b64encode(group_id_bytes).decode('ascii'),
        "epoch": 0,
        "tree": tree,
        "group_context": group_context,
        "members": [creator_name],
        "epoch_secret": epoch_secret,
        "init_secret": init_secret
    }

def add_member(group, new_member_id, committer_priv_bytes, committer_index=0):
    """Simplified add member - just update the group state"""
    print(f"\n=== Adding {new_member_id} to group ===")
    
    # Update tree (simplified)
    tree = group["tree"]
    new_leaf_index = len(tree.leaves)
    
    while tree.nodes <= new_leaf_index * 2:
        tree.extend()
    
    # Update secrets (simplified)
    old_epoch_secret = group["epoch_secret"]
    old_init_secret = group["init_secret"]
    
    # For a simple add, derive new secrets
    commit_secret = bytes(32)
    joiner_secret = DeriveSecret(cs, old_init_secret, b"joiner")
    psk_secret = bytes(32)
    
    new_epoch_secret = DeriveSecret(cs, joiner_secret, b"epoch")
    new_init_secret = DeriveSecret(cs, new_epoch_secret, b"init")
    
    # Update group
    group["epoch"] += 1
    group["epoch_secret"] = new_epoch_secret
    group["init_secret"] = new_init_secret
    group["members"].append(new_member_id)
    group["group_context"].epoch = group["epoch"]
    group["group_context"].tree_hash = VLBytes(tree.hash(cs))
    
    print(f"  New epoch: {group['epoch']}")
    return True

def register_user(username, password):
    """Helper to register and login a user"""
    user_id = test_user_registration(username, password)
    if user_id:
        return test_user_login(username, password)
    return None, None

def complete_distributed_flow():
    """Simulate a truly distributed flow with separate sessions"""
    
    # ===== BOB'S SESSION =====
    print("\n" + "="*30 + " BOB'S SESSION " + "="*30)
    
    # Bob logs in
    username="bob"
    password="1234"
    bob_id, bob_token = test_user_login(username, password)

    # 2. Generate and upload key packages
    bob_priv, bob_kp = GeneratKeyPackage(username) # Generating PackageKey
    ref_hash_bob, kp_id_bob = test_upload_keypackage(bob_id, bob_kp) #saving packageKey to DB
    
    # Bob creates group
    bob_kp_bytes = test_get_latest_keypackage(bob_id)
    bob_kp_obj = KeyPackage.deserialize(bytearray(bob_kp_bytes))
    group = create_empty_group(bob_kp_obj.content.leaf_node, "bob")
    
    # Save group to DB
    test_create_group_with_id("MLS Test Group", 1, bob_token, group['group_id_b64'])
    
     # Search for Alice by username
    alice_user_info = get_user_by_username("alice", bob_token)
    
    alice_id = alice_user_info['user_id']
    print(f"Bob found Alice with ID: {alice_id}")
    
    # Now Bob can add Alice to the group
    add_member(group, alice_id, bob_priv)
    test_add_group_member(group['group_id_b64'], alice_id, 1, bob_token)
    
    
    test_update_group_epoch(group['group_id_b64'], group['epoch'], bob_token, group['epoch_secret'])
    
    # Bob sends a message
    bob_msg, nonce = send_encrypted_message(group, 0, "Hello Alice!", group["epoch_secret"])
    test_send_message(group['group_id_b64'], bob_msg.msg_content.ciphertext.data, 
                     nonce, group['epoch'], 1, bob_token)
    
    print("✅ Bob's session complete")
    
    # ===== ALICE'S SESSION (later, different computer) =====
    print("\n" + "="*30 + " ALICE'S SESSION " + "="*30)
    
    # Alice logs in
    alice_id, alice_token = test_user_login("alice", "1234")
    
    # Alice gets her groups - THIS TELLS HER WHICH GROUPS SHE'S IN AND HER LEAF INDEX
    alice_groups = test_get_my_groups(alice_token)
    
    # Find the group Bob added her to
    target_group = None
    for g in alice_groups['groups']:
        if g['group_name'] == "MLS Test Group":
            target_group = g
            break
    
    if target_group:
        print(f"✅ Alice found group: {target_group['group_name']}")
        print(f"   Her leaf index: {target_group['my_leaf_index']}")
        print(f"   Current epoch: {target_group['epoch']}")

        epoch_secret_from_welcome = group["epoch_secret"]  # This is from Bob's session
    
        # Create Alice's group state
        alice_group_state = {
            "group_id_b64": target_group['group_id'],
            "group_id": base64.b64decode(target_group['group_id']),
            "epoch": target_group['epoch'],
            "my_leaf_index": target_group['my_leaf_index'],
            "epoch_secret": epoch_secret_from_welcome,  # From Welcome message
            # Note: In a real implementation, Alice would also reconstruct the ratchet tree
            "tree": None  # Would come from GroupInfo in Welcome message
        }
        
        print(f"✅ Alice reconstructed group state")
        
        # Alice needs the epoch secret to decrypt messages
        # In MLS, this comes from the Welcome message
        # For now, she would need to either:
        # 1. Have stored it from the Welcome message, or
        # 2. Have a secure way to get it (key escrow, etc.)
        
        # Alice fetches messages
        messages = test_get_group_messages(target_group['group_id'], alice_token)
        
        if messages and 'messages' in messages:
            for msg in messages['messages']:
                # Reconstruct message from DB
                reconstructed_msg, nonce = reconstruct_message_from_db(
                    msg, 
                    base64.b64decode(target_group['group_id'])
                )
                
                # Decrypt using epoch secret (Alice needs this!)
                # In a real implementation, Alice would have the epoch secret from Welcome
                if 'epoch_secret' in alice_group_state:
                    decrypted = receive_encrypted_message(
                        alice_group_state,  # Alice's group state with epoch_secret
                        reconstructed_msg,
                        nonce,
                        msg['sender_leaf_index'],
                        alice_group_state['epoch_secret']
                    )
                    print(f"   Alice read: '{decrypted}'")

if __name__ == "__main__":
    # 1. Register users
    print("\n📝 STEP 1: Registering users")
    alice_id, alice_token = register_user("alice", "1234")
    bob_id, bob_token = register_user("bob", "1234")

    complete_distributed_flow()