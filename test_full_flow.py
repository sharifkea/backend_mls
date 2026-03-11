# test_full_flow.py
import sys
import base64
import secrets
from test_db_api import (
    test_user_registration, test_user_login, test_upload_keypackage,
    test_get_latest_keypackage, test_create_group_with_id, test_add_group_member,
    test_send_message, test_get_group_messages, test_update_group_epoch,
    test_get_group_details, test_get_my_groups
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
def run_reg_flwo():
    # 1. Register users
    print("\n📝 STEP 1: Registering users")
    alice_id= register_user("alice", "1234")
    bob_id = register_user("bob", "1234")
    
    if not alice_id or not bob_id:
        print("❌ Failed to register users")
        return

def run_full_flow():
    """Run complete MLS flow with database persistence"""
    
    print("\n" + "="*60)
    print("COMPLETE MLS FLOW WITH DATABASE PERSISTENCE")
    print("="*60)

    alice_id, alice_token=test_user_login("alice", "1234")
    bob_id, bob_token=test_user_login("bob", "1234")

    
    # 2. Generate and upload key packages
    print("\n🔑 STEP 2: Uploading key packages")
    alice_priv, alice_kp = GeneratKeyPackage("alice")
    bob_priv, bob_kp = GeneratKeyPackage("bob")
    
    ref_hash_alice, kp_id_alice = test_upload_keypackage(alice_id, alice_kp)
    ref_hash_bob, kp_id_bob = test_upload_keypackage(bob_id, bob_kp)
    
    # 3. Bob creates group
    print("\n👥 STEP 3: Bob creates group")
    bob_kp_bytes = test_get_latest_keypackage(bob_id)
    if not bob_kp_bytes:
        print("❌ Cannot get Bob's key package")
        return
        
    bob_kp_obj = KeyPackage.deserialize(bytearray(bob_kp_bytes))
    group = create_empty_group(bob_kp_obj.content.leaf_node, "bob")
    
    # Save group to database with the SAME group ID
    print(f"\n=== Saving group to database with ID: {group['group_id_b64']} ===")
    create_response = test_create_group_with_id(
        "MLS Test Group", 
        1, 
        bob_token, 
        group['group_id_b64']  # Pass the existing group ID
    )
    
    if not create_response:
        print("❌ Failed to save group to database")
        return
    
    print("✅ Group successfully saved to database")
    
    # 4. Bob adds Alice to group
    print("\n➕ STEP 4: Bob adds Alice to group")
    add_member(group, alice_id, bob_priv)
    
    # Add member to database
    test_add_group_member(group['group_id_b64'], alice_id, 1, bob_token)
    
    # Update epoch in database
    print("\n🔄 Updating group epoch in database after adding Alice")
    if (test_update_group_epoch(
        group['group_id_b64'], 
        group['epoch'],  # Should be 1 after add_member
        bob_token, 
        group['epoch_secret']
    )):
        print("✅ Group epoch updated in database")
    else:
        print("❌ Failed to update group epoch in database")
    
    # 5. Bob sends an encrypted message
    print("\n💬 STEP 5: Bob sends encrypted message")
    bob_msg, bob_nonce = send_encrypted_message(
        group, 0, "Hello Alice! This message is stored in the database!", 
        group["epoch_secret"]
    )
    
    # Bob saves his message to database
    bob_msg_id = test_send_message(
        group['group_id_b64'],
        bob_msg.msg_content.ciphertext.data,
        bob_nonce,
        group['epoch'],
        1,  # ContentType.application
        bob_token
    )
    
    if bob_msg_id:
        print(f"✅ Bob's message saved to DB with ID: {bob_msg_id}")
    
    # 6. Alice retrieves and decrypts messages (simulating separate session)
    print("\n📥 STEP 6: Alice retrieves messages from database")
    
    # Alice fetches messages from the database
    messages_response = test_get_group_messages(group['group_id_b64'], alice_token)
    #receive_encrypted_message()
    
    if messages_response and 'messages' in messages_response:
        messages = messages_response['messages']
        print(f"📨 Alice retrieved {len(messages)} messages from database")
        
        for msg_data in messages_response['messages']:
            reconstructed_msg, nonce = reconstruct_message_from_db(
                msg_data, 
                base64.b64decode(group['group_id_b64'])
            )
            
            decrypted = receive_encrypted_message(
                group, 
                reconstructed_msg,  # ✅ From DB, not from Bob's memory!
                nonce, 
                msg_data['sender_leaf_index'], 
                group["epoch_secret"]
            )
            if decrypted:
                print(f"   ✅ Alice read: '{decrypted}'")
    
    # 7. Alice replies
    print("\n📤 STEP 7: Alice sends reply")
    alice_msg, alice_nonce = send_encrypted_message(
        group, 1, "Hi Bob! I got your message from the database!", 
        group["epoch_secret"]
    )
    
    # Alice saves her reply to database
    alice_msg_id = test_send_message(
        group['group_id_b64'],
        alice_msg.msg_content.ciphertext.data,
        alice_nonce,
        group['epoch'],
        1,
        alice_token
    )
    
    if alice_msg_id:
        print(f"✅ Alice's reply saved to DB with ID: {alice_msg_id}")
    
    # 8. Bob retrieves messages (simulating his separate session)
    print("\n📥 STEP 8: Bob retrieves messages from database")
    
    # Bob fetches messages (including Alice's reply)
    bob_messages_response = test_get_group_messages(group['group_id_b64'], bob_token)
    
    if bob_messages_response and 'messages' in bob_messages_response:
        bob_messages = bob_messages_response['messages']
        print(f"📨 Bob retrieved {len(bob_messages)} messages from database")
        
        # Bob should see 2 messages now (his own and Alice's reply)
        for msg_data in bob_messages:
            if msg_data['sender_leaf_index'] == 1:  # Alice's message
                print("\n   📬 Bob decrypting Alice's reply...")
                # Decode data
                ciphertext = base64.b64decode(msg_data['ciphertext'])
                nonce = base64.b64decode(msg_data['nonce'])
                
                # Use the original alice_msg we have in memory
                # In reality, Bob would reconstruct from DB
                decrypted = receive_encrypted_message(
                    group, 
                    alice_msg,  # In reality, this would be reconstructed
                    nonce, 
                    1, 
                    group["epoch_secret"]
                )
                if decrypted:
                    print(f"   ✅ Bob read: '{decrypted}'")
    
    # 9. Final verification
    print("\n✅ STEP 9: Final verification")
    final_messages = test_get_group_messages(group['group_id_b64'], bob_token)
    
    if final_messages and len(final_messages.get('messages', [])) >= 2:
        print("\n" + "="*60)
        print("🎉 SUCCESS: Full MLS flow with database persistence!")
        print("="*60)
        print(f"   Group ID: {group['group_id_b64']}")
        print(f"   Members: {len(group['members'])}")
        print(f"   Current epoch: {group['epoch']}")
        print(f"   Messages in DB: {len(final_messages['messages'])}")
    else:
        print("\n❌ Failed to verify messages in database")

def register_user(username, password):
    """Helper to register and login a user"""
    user_id = test_user_registration(username, password)
    if not user_id:
        print(f"❌ Registration failed for {username}")
        return None, None
        
    return user_id


if __name__ == "__main__":
    run_reg_flwo()
    run_full_flow()