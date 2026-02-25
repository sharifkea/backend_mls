# test_keypackage_tbs.py
import sys
import requests
from datetime import datetime, timedelta

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

from mls_stuff.MLS._key_package import KeyPackageTBS, KeyPackage
from mls_stuff.RatchetTree._leaf_node import LeafNode, LeafNodePayload, LeafNodeTBS, LeafNodeSource
from mls_stuff.Enums import CipherSuite, ProtocolVersion, CredentialType, LeafNodeSource
from mls_stuff.Misc._capabilities import Capabilities
from mls_stuff.Misc._lifetime import Lifetime
from mls_stuff.Crypto import HPKEPublicKey, SignaturePublicKey, Credential
from mls_stuff.Crypto._key_pair import KeyPair
from mls_stuff.Misc import VLBytes
from mls_stuff.Crypto.Credential import BasicCredential
from mls_stuff.Misc import SignContent
from mls_stuff.Crypto import SignWithLabel

# ===OUR VALUES (copy from previous script) ===
cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

# Credential
identity_vl = VLBytes(b"alice@example.com")
credential = BasicCredential(credential_type=CredentialType.basic, identity=identity_vl)

# Keys (from your previous outputs)

ed25519_priv_bytes = bytes.fromhex("d6925d3e87d9648f71c67077aa700bf4493a4016ba218dfe2523baa469ce0d75") # ← PASTE OUR REAL PRIVATE HEX
ed25519_pub_bytes = bytes.fromhex("77c02329fdc4b5c750a4c4d0a5e8204bb9d5a42a223a240ac49b553969d3fc5b")  # our real pub hex
x25519_pub_bytes = bytes.fromhex("fe291c5526bb947f0a36df9a5953779e5e87135f086c465eae3b5dae7b253461")

hpke_pub = HPKEPublicKey(x25519_pub_bytes)
sig_pub = SignaturePublicKey(ed25519_pub_bytes)

# Capabilities
caps = Capabilities(
    versions=[ProtocolVersion.MLS10],
    cipher_suites=[cs],
    extensions=[],
    proposals=[],
    credentials=[CredentialType.basic]
)

# Lifetime
now = int(datetime.now().timestamp())
thirty_days = now + int(timedelta(days=30).total_seconds())
lifetime = Lifetime(not_before=now, not_after=thirty_days)

# LeafNodePayload (same as before)
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

tbs_leaf = LeafNodeTBS(payload=payload)
signature_leaf = tbs_leaf.signature(cipher_suite=cs, sign_key=ed25519_priv_bytes)
leaf_node = LeafNode(value=payload, signature=VLBytes(signature_leaf))

print("=== Step 14: Creating & Signing KeyPackage ===\n")

# 1. KeyPackageTBS
version = ProtocolVersion.MLS10
extensions = []  # minimal, empty list

kptbs = KeyPackageTBS(
    version=version,
    cipher_suite=cs,
    init_key=VLBytes(x25519_pub_bytes),   # init_key is usually VLBytes(raw X25519 pub)
    leaf_node=leaf_node,
    extensions=extensions
)

print("KeyPackageTBS created!")

# 2. Sign the TBS to get full KeyPackage
sign_content = SignContent(b"KeyPackageTBS", kptbs.serialize())
signature_kp = SignWithLabel(cs, sign_content, ed25519_priv_bytes)

key_package = KeyPackage(
    content=kptbs,
    signature=VLBytes(signature_kp)
)

print("Full KeyPackage created!")
print(f"Signature length: {len(signature_kp)} bytes")

# Serialize the whole thing
try:
    kp_bytes = key_package.serialize()
    print(f"Full serialized KeyPackage length: {len(kp_bytes)} bytes")
    print(f"Hex prefix: {kp_bytes.hex()[:80]}...")
except Exception as e:
    print("Serialization failed:", e)
# Save to file for inspection / sending to server
#with open("alice_keypackage.bin", "wb") as f:
#    f.write(kp_bytes)

#print("Saved full KeyPackage to: alice_keypackage.bin")
#print(f"File size: {len(kp_bytes)} bytes")
response = requests.post(
    "http://localhost:8000/key_packages/alice",
    data=kp_bytes
)
print(response.json())