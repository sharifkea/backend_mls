# encrypted_message.py
import sys
sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")


from mls_stuff.MLS import (
    FramedContent, FramedContentAuthData, AuthenticatedContent,
    PrivateMessage, MLSMessage, Sender
)
from mls_stuff.Enums import ContentType, SenderType, WireFormat, CipherSuite
from mls_stuff.RatchetTree._leaf_node import LeafNode
from mls_stuff.Misc import VLBytes, SignContent
from mls_stuff.Crypto._derive_secrets import DeriveSecret, DeriveTreeSecret
from mls_stuff.Crypto._crypt_with_label import EncryptWithLabel, DecryptWithLabel
from mls_stuff.MLS import PrivateMessage

cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

def get_message_encryption_key(group, epoch_secret: bytes, generation: int = 0):
    """
    Derive the message encryption key for a specific generation in the current epoch
    """
    print(f"\n🔑 Deriving message encryption key for epoch {group['epoch']}, generation {generation}")
    
    # Get tree hash
    tree_hash = group["tree"].hash(cs)
    print(f"   Tree hash: {tree_hash[:16].hex()}...")
    
    # Derive message key using DeriveSecret
    # In MLS, message keys are derived from the epoch secret with a label
    message_key = DeriveSecret(
        cs,
        epoch_secret,  # You need to store this!
        f"MLS 1.0 message key {generation}".encode()
    )
    
    print(f"   Message key (first 16 bytes): {message_key[:16].hex()}...")
    return message_key

def send_encrypted_message(group, sender_leaf_index: int, sender_priv_bytes: bytes, 
                          message_text: str, epoch_secret: bytes):
    """
    Send an ENCRYPTED message using ratchet keys
    """
    print(f"\n=== Sending ENCRYPTED message from leaf {sender_leaf_index} ===")
    
    # 1. Convert message to bytes
    message_bytes = message_text.encode('utf-8')
    print(f"   Plaintext: '{message_text}' ({len(message_bytes)} bytes)")
    
    # 2. Create FramedContent (this will be encrypted)
    sender = Sender(sender_type=SenderType.member, leaf_index=sender_leaf_index)
    
    framed_content = FramedContent(
        group_id=group["group_id"],
        epoch=group["epoch"],
        sender=sender,
        authenticated_data=VLBytes(b""),
        content_type=ContentType.application,
        application_data=VLBytes(message_bytes)
    )
    
    # Serialize the content to be encrypted
    content_bytes = framed_content.serialize()
    print(f"   Content to encrypt: {len(content_bytes)} bytes")
    
    # 3. Get the message encryption key
    message_key = get_message_encryption_key(group, epoch_secret, generation=0)
    
    # 4. Generate a random nonce (12 bytes for AES-GCM)
    import secrets
    nonce = secrets.token_bytes(12)
    print(f"   Nonce: {nonce.hex()}")
    
    # 5. Encrypt the content using EncryptWithLabel (if available)
    # If EncryptWithLabel isn't available, we'll need to use another method
    try:
        
        ciphertext = EncryptWithLabel(
            cs,
            message_key,
            b"MLS 1.0 message encryption",
            content_bytes
        )
        
        print(f"   Encrypted with EncryptWithLabel: {len(ciphertext)} bytes")
    except ImportError:
        # Fallback to simple AES-GCM (for testing only!)
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(message_key)
        ciphertext = aesgcm.encrypt(nonce, content_bytes, b"")
        print(f"   Encrypted with AESGCM: {len(ciphertext)} bytes")
    
    # 6. Create PrivateMessage
    # You'll need to check how PrivateMessage is structured in your library
    
    
    # This depends on your PrivateMessage implementation
    # Assuming it takes encrypted content, nonce, etc.
    private_message = PrivateMessage(
        # Adjust these parameters based on your library
        encrypted_content=VLBytes(ciphertext),
        nonce=VLBytes(nonce),
        # Other parameters...
    )
    
    # 7. Wrap in MLSMessage
    mls_message = MLSMessage(
        wire_format=WireFormat.MLS_PRIVATE_MESSAGE,
        msg_content=private_message
    )
    
    print(f"✅ Encrypted message created")
    print(f"   Total size: {len(mls_message.serialize())} bytes")
    
    return mls_message, message_key, nonce

def receive_encrypted_message(group, message: MLSMessage, expected_sender_index: int, 
                             epoch_secret: bytes):
    """
    Receive and decrypt an encrypted message
    """
    print("\n=== Receiving ENCRYPTED message ===")
    
    # 1. Check if it's a private message
    if message.wire_format != WireFormat.MLS_PRIVATE_MESSAGE:
        print("❌ Not a private message")
        return None
    
    # 2. Extract private message
    private_msg = message.msg_content
    
    # 3. Extract ciphertext and nonce (adjust based on your library)
    # This depends on your PrivateMessage structure
    ciphertext = private_msg.encrypted_content.data  # Adjust!
    nonce = private_msg.nonce.data  # Adjust!
    
    print(f"   Ciphertext: {len(ciphertext)} bytes")
    print(f"   Nonce: {nonce.hex()}")
    
    # 4. Get the same message key
    message_key = get_message_encryption_key(group, epoch_secret, generation=0)
    
    # 5. Decrypt
    try:
        
        plaintext = DecryptWithLabel(
            cs,
            message_key,
            b"MLS 1.0 message encryption",
            b"",  # AAD
            ciphertext
        )
    except ImportError:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        aesgcm = AESGCM(message_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, b"")
    
    print(f"   Decrypted: {len(plaintext)} bytes")
    
    # 6. Parse the FramedContent
    framed_content = FramedContent.deserialize(bytearray(plaintext))
    
    # 7. Verify and extract message
    if framed_content.content_type != ContentType.application:
        print(f"❌ Not an application message")
        return None
    
    # Extract message text
    message_text = framed_content.application_data.data.decode('utf-8')
    
    # Verify sender
    if framed_content.sender.leaf_index != expected_sender_index:
        print(f"❌ Sender mismatch")
        return None
    
    print(f"✅ Decrypted message: '{message_text}'")
    return message_text

# Add this to your main code
def encrypted_chat_demo(group, alice_priv_bytes, bob_priv_bytes, epoch_secret):
    """
    Demo encrypted message exchange
    """
    print("\n" + "="*50)
    print("ENCRYPTED CHAT DEMO")
    print("="*50)
    
    # Bob sends encrypted message
    bob_msg, key, nonce = send_encrypted_message(
        group, 0, bob_priv_bytes, 
        "Hello Alice! This is ENCRYPTED!", 
        epoch_secret
    )
    
    # Alice receives and decrypts
    received = receive_encrypted_message(group, bob_msg, 0, epoch_secret)
    
    # Alice replies
    alice_msg, _, _ = send_encrypted_message(
        group, 1, alice_priv_bytes,
        "Hi Bob! I can read your secret message!",
        epoch_secret
    )
    
    # Bob receives
    received2 = receive_encrypted_message(group, alice_msg, 1, epoch_secret)