# test_leafnode_payload.py

import sys
from datetime import datetime, timedelta

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

# Then use FULL prefix for ALL imports from the package
from mls_stuff.RatchetTree._leaf_node import LeafNode, LeafNodePayload, LeafNodeTBS, LeafNodeSource
from mls_stuff.Enums import CipherSuite, CredentialType, ProtocolVersion
from mls_stuff.Misc._capabilities import Capabilities
from mls_stuff.Misc._lifetime import Lifetime
from mls_stuff.Crypto import HPKEPublicKey, SignaturePublicKey, Credential
from mls_stuff.Crypto._key_pair import KeyPair
from mls_stuff.Misc import VLBytes
from mls_stuff.Crypto.Credential import BasicCredential

# === YOUR VALUES ===
from mls_stuff.Misc import VLBytes

identity_vl = VLBytes(b"alice@example.com")   # ← this is the missing wrapper

credential = BasicCredential(
    credential_type=CredentialType.basic,
    identity=identity_vl                      # ← pass VLBytes here, not raw bytes
)
print("Credential created successfully")
print("  Type:", credential.credential_type)
print("  Identity type:", type(credential.identity).__name__)
print("  Identity value:", credential.identity.data if hasattr(credential.identity, 'data') else credential.identity)

ed25519_priv_hex = "d6925d3e87d9648f71c67077aa700bf4493a4016ba218dfe2523baa469ce0d75"  # ← PASTE OUR REAL PRIVATE HEX
ed25519_priv_bytes = bytes.fromhex(ed25519_priv_hex)

ed25519_pub_bytes = bytes.fromhex("77c02329fdc4b5c750a4c4d0a5e8204bb9d5a42a223a240ac49b553969d3fc5b")  # our real pub hex

x25519_pub_bytes = bytes.fromhex("fe291c5526bb947f0a36df9a5953779e5e87135f086c465eae3b5dae7b253461")

cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

print("=== Step 13: Building & Signing LeafNodePayload ===\n")

# Rest of the code as before (caps, lifetime, hpke_pub, sig_pub, payload, tbs, signature, leaf_node)...
# (copy the creation/signing part from your previous version)

# 1. Capabilities (from Step 10)
caps = Capabilities(
    versions=[ProtocolVersion.MLS10],
    cipher_suites=[cs],
    extensions=[],
    proposals=[],
    credentials=[CredentialType.basic]
)

# 2. Lifetime (from Step 11)
now = int(datetime.now().timestamp())
thirty_days = now + int(timedelta(days=30).total_seconds())
lifetime = Lifetime(not_before=now, not_after=thirty_days)

# 3. Wrap public keys
hpke_pub = HPKEPublicKey(x25519_pub_bytes)
sig_pub  = SignaturePublicKey(ed25519_pub_bytes)

# 4. Create Payload
payload = LeafNodePayload(
    encryption_key=hpke_pub,
    signature_key=sig_pub,
    credential=credential,
    capabilities=caps,
    leaf_node_source=LeafNodeSource.key_package,
    lifetime=lifetime,
    parent_hash=None,
    extensions=None
)

print("LeafNodePayload created successfully!")

# 5. Create TBS (for key_package → no group_id / leaf_index)
tbs = LeafNodeTBS(payload=payload)

# 6. Sign with Ed25519 private key
sign_key = ed25519_priv_bytes   # raw 32 bytes private key

signature_bytes = tbs.signature(cipher_suite=cs, sign_key=sign_key)
print(f"\nSignature generated! Length: {len(signature_bytes)} bytes")

# 7. Create final LeafNode
signature_vl = VLBytes(signature_bytes)
leaf_node = LeafNode(
    value=payload,
    signature=signature_vl
)

print("LeafNode created!")
print(f"  Node type: {leaf_node.node_type}")

# Optional: try serialize (should be payload + signature length)
try:
    ser = leaf_node.serialize()
    print(f"Serialized LeafNode length: {len(ser)} bytes")
except Exception as e:
    print("Serialize failed (expected if not all fields set):", e)