# add_member.py
import sys
import secrets
import requests
from create_keypakage import GeneratKeyPackage
from test_db_api import test_user_registration, test_user_login, test_upload_keypackage, test_get_latest_keypackage


sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

from mls_stuff.RatchetTree._ratchet_tree import RatchetTree
from mls_stuff.RatchetTree._leaf_node import LeafNode
from mls_stuff.Enums import CipherSuite, ProtocolVersion, ProposalType, SenderType, ContentType, WireFormat
from mls_stuff.MLS._key_package import KeyPackage
from mls_stuff.MLS._proposal import Add
from mls_stuff.MLS._commit import Commit
from mls_stuff.MLS import MLSMessage, Sender, AuthenticatedContent, FramedContent, FramedContentAuthData, AuthenticatedContentTBM, ConfirmedTranscriptHashInput
from mls_stuff.MLS._welcome import ExtractWelcomeSecret, GroupInfo, Welcome
from mls_stuff.Misc import VLBytes, SignContent
from mls_stuff.Crypto._crypt_with_label import SignWithLabel
from mls_stuff.Crypto import GroupSecrets, EncryptedGroupSecrets, HPKECiphertext, EncryptWithLabel, DeriveSecret, MAC
from mls_stuff.Objects import GroupContext
from mls_stuff.MLS import PrivateMessage, SenderData, SenderDataAAD, FramedContentTBS
from mls_stuff.Crypto import DeriveTreeSecret  # for sender ratchet
import secrets 

cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
BASE_URL = "http://localhost:8000"

def derive_epoch_keys(cs, group_context, init_secret=None, commit_secret=b'', psk_secret=b'\x00' * cs.hash_size(cs)):
    """
    Derive keys for new epoch after Commit (from test client / GroupContext source).
    - init_secret: random for initial group, or previous epoch_secret.
    - commit_secret: b'' if no UpdatePath.
    - psk_secret: b'' if no PSK.
    Returns dict of secrets/keys.
    """
    if init_secret is None:
        init_secret = secrets.token_bytes(cs.hash_size(cs))

    # Ensure GroupContext fields are VLBytes
    if not isinstance(group_context.tree_hash, VLBytes):
        group_context.tree_hash = VLBytes(group_context.tree_hash)
    if not isinstance(group_context.confirmed_transcript_hash, VLBytes):
        group_context.confirmed_transcript_hash = VLBytes(group_context.confirmed_transcript_hash)

    # Derive joiner_secret
    joiner_secret = group_context.extract_joiner_secret(init_secret, commit_secret)

    # Welcome secret (for Welcome HPKE)
    welcome_secret = ExtractWelcomeSecret(cs, joiner_secret, psk_secret)

    # Epoch secret
    epoch_secret = group_context.extract_epoch_secret(joiner_secret, psk_secret)

    # Branch keys
    confirmation_key = DeriveSecret(cs, epoch_secret, b"confirm")
    membership_key = DeriveSecret(cs, epoch_secret, b"membership")
    encryption_secret = DeriveSecret(cs, epoch_secret, b"encryption")
    sender_data_secret = DeriveSecret(cs, epoch_secret, b"sender data")

    return {
        "joiner_secret": joiner_secret,
        "welcome_secret": welcome_secret,
        "epoch_secret": epoch_secret,
        "confirmation_key": confirmation_key,
        "membership_key": membership_key,
        "encryption_secret": encryption_secret,
        "sender_data_secret": sender_data_secret
    }

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

    # NEW: Before applying Commit, derive initial keys for epoch 0 if not exist
    if "init_secret" not in group:
        group["init_secret"] = secrets.token_bytes(cs.hash_size(cs))  # random initial secret for epoch 0
        print("Initial epoch 0 keys generated")

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

    # 10. Update epoch & context
    group["epoch"] += 1
    group["group_context"].epoch = group["epoch"]
    group["group_context"].tree_hash = VLBytes(group["tree"].hash(cs))
    group["members"].append(new_member_id)

    # NEW: Compute confirmed_transcript_hash (from test client)
    # Assume interim_transcript_hashes = [b''] for epoch 0 (add your list)
    if "interim_transcript_hashes" not in group:
        group["interim_transcript_hashes"] = [b'']
    if "confirmed_transcript_hashes" not in group:
        group["confirmed_transcript_hashes"] = []

    # Sign FramedContentTBS (already done in our step 7)
    # Then compute confirmed_transcript_hash
    
    confirmed_input = ConfirmedTranscriptHashInput(
        authenticated_content.wire_format,                  # or public_commit.msg_content.wire_format
        authenticated_content.content,                      # FramedContent
        authenticated_content.auth.signature                # VLBytes(signature)
    )

    confirmed_transcript_hash = confirmed_input.hash(
        cs, 
        group["interim_transcript_hashes"][-1]              # previous interim hash
    )
    group["confirmed_transcript_hashes"].append(confirmed_transcript_hash)
    group["group_context"].confirmed_transcript_hash = VLBytes(confirmed_transcript_hash)

    # 11. Derive keys for new epoch
    keys = derive_epoch_keys(cs, group["group_context"], group["init_secret"])

    # Update init_secret for next epoch
    group["init_secret"] = keys["epoch_secret"]  # chain to next

    # Set confirmation_tag
    confirmation_tag = MAC.new(cs, keys["confirmation_key"], group["group_context"].confirmed_transcript_hash.data)
    authenticated_content.auth.confirmation_tag = confirmation_tag

    # Step A: Create FramedContentTBS (this is the missing object)
    framed_tbs = FramedContentTBS(
        framed_content=authenticated_content.content,      # FramedContent
        group_context=group["group_context"]               # GroupContext
    )

    # Step B: Now create TBM
    auth_tbm = AuthenticatedContentTBM(
        tbs=framed_tbs,
        auth=authenticated_content.auth                    # already has .signature
    )

    # Step C: Compute membership tag (MAC over TBM using membership_key)
    membership_tag = auth_tbm.to_mac(cs, keys["membership_key"])

    # Attach it to the PublicMessage (assuming PublicMessage has .membership_tag field)
    public_commit.membership_tag = membership_tag

    # Serialize commit_msg
    commit_bytes = public_commit.serialize()

    print("Commit fixed with confirmation_tag & membership_tag – size:", len(commit_bytes))

    # 12. Generate real Welcome
    # GroupSecrets with joiner_secret
    group_secrets = GroupSecrets(
        joiner_secret=VLBytes(keys["joiner_secret"]),
        psks=[],
        path_secret=None
    )

    # Encrypt GroupSecrets to Alice's init_key using welcome_secret-derived key
    # Derive welcome_key, welcome_nonce from welcome_secret (RFC §9.2)
    welcome_key = ExpandWithLabel(cs, keys["welcome_secret"], KDFLabel(label="key", context=b"", length=cs.aead_algorithm().key_size))
    welcome_nonce = ExpandWithLabel(cs, keys["welcome_secret"], KDFLabel(label="nonce", context=b"", length=cs.aead_algorithm().nonce_size))

    # Encrypt
    encrypted_gs = EncryptWithLabel(cs, group_secrets.serialize(), b"", welcome_key, welcome_nonce)  # guess args

    # HPKECiphertext: need HPKE setup with Alice's init_key (HPKEPublicKey)
    alice_init_key = new_kp.content.init_key  # from fetched KeyPackage
    # Assume: kem_output, ciphertext = hpke.encrypt(group_secrets.serialize(), alice_init_key)
    hpke_ct = HPKECiphertext(VLBytes(kem_output), VLBytes(ciphertext))

    encrypted_secrets = EncryptedGroupSecrets(
        new_member=VLBytes(b"alice_ref"),  # or KeyPackage ref_hash
        encrypted_group_secrets=hpke_ct
    )

    # GroupInfo
    
    gi_extensions = []  # add ratchet_tree if needed
    gi = GroupInfo.new(group["group_context"], gi_extensions, confirmation_tag, committer_index, committer_priv_bytes)

    # Encrypt GroupInfo (using welcome_key/welcome_nonce)
    encrypted_gi = EncryptWithLabel(cs, gi.serialize(), b"", welcome_key, welcome_nonce)

    welcome = Welcome(
        cipher_suite=cs,
        secrets=[encrypted_secrets],
        encrypted_group_info=VLBytes(encrypted_gi)
    )

    print("Real Welcome created – size:", len(welcome.serialize()))

    # Save keys to group for messaging
    group["keys"] = keys

    return welcome, commit_bytes

def send_message(group, sender_id: str, message: bytes, sender_priv_bytes: bytes, sender_index: int):
    print(f"\n=== {sender_id} sending message: {message.decode()} ===\n")

    # FramedContent (application)
    framed_content = FramedContent(
        group_id=group["group_id"],
        epoch=group["epoch"],
        sender=Sender(sender_type=SenderType.member, leaf_index=sender_index),
        authenticated_data=VLBytes(b""),
        content_type=ContentType.application,
        application_data=VLBytes(message)
    )

    # Sign
    tbs = FramedContentTBS(framed_content, group["group_context"])
    sign_content = SignContent(b"FramedContentTBS", tbs.serialize())
    signature = SignWithLabel(cs, sign_content, sender_priv_bytes)

    auth = FramedContentAuthData(signature=VLBytes(signature), confirmation_tag=None)  # no confirm for app msg

    authenticated_content = AuthenticatedContent(
        wire_format=WireFormat.MLS_PRIVATE_MESSAGE,
        content=framed_content,
        auth=auth
    )

    

    # Derive sender key/nonce from encryption_secret (secret tree)
    # For small group, simplify: use DeriveTreeSecret for leaf_index
    sender_key = DeriveTreeSecret(cs, group["keys"]["encryption_secret"], b"app sender", sender_index, cs.aead_algorithm().key_size)
    sender_nonce = DeriveTreeSecret(cs, group["keys"]["encryption_secret"], b"app nonce", sender_index, cs.aead_algorithm().nonce_size)

    # SenderData (leaf_index, generation=0 for first msg)
    sender_data = SenderData(sender_index, 0)  # generation increments per msg

    # Encrypt sender_data with sender_data_secret
    sender_data_aad = SenderDataAAD(framed_content.group_id, framed_content.epoch, framed_content.content_type)  # guess
    encrypted_sender_data = EncryptWithLabel(cs, sender_data.serialize(), b"SenderData", sender_data_aad.serialize(), group["keys"]["sender_data_secret"])

    # Encrypt content
    private_content_aad = PrivateContentAAD(authenticated_content.content, authenticated_content.auth)  # guess
    ciphertext = EncryptWithLabel(cs, authenticated_content.serialize(), b"PrivateContent", private_content_aad.serialize(), sender_key, sender_nonce)

    private_msg = PrivateMessage(
        content=VLBytes(ciphertext),
        application_data=VLBytes(b""),  # if needed
        authenticated_data=VLBytes(b""),
        encrypted_sender_data=VLBytes(encrypted_sender_data)
    )

    msg = MLSMessage(wire_format=WireFormat.MLS_PRIVATE_MESSAGE, msg_content=private_msg)

    print("PrivateMessage created – size:", len(msg.serialize()))

    return msg

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
    welcome, commit_bytes =add_member(group, user_id_alice, bob_priv_bytes)

    if welcome:
        print("Welcome ready to send to Alice!")
    
    test_msg = b"Hello Bob!"
    sent = send_message(group, user_id_alice, test_msg, alice_priv_bytes, 1)
