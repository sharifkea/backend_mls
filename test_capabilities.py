# test_capabilities.py
import sys
from datetime import datetime

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

from mls_stuff.Enums import (
    ProtocolVersion,
    CipherSuite,
    CredentialType,
    ExtensionType,
    ProposalType
)

from mls_stuff.Misc._capabilities import Capabilities

print("=== Step 10: Minimales Capabilities-Objekt ===\n")

# Very minimalist – only the essentials for a test KeyPackage
caps = Capabilities(
    versions=[ProtocolVersion.MLS10],
    cipher_suites=[CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519],
    extensions=[],                    # no extra Extensions
    proposals=[],                     # no extra Proposals
    credentials=[CredentialType.basic]
)

print("Capabilities erstellt!")
print(f"  versions     : {[v.name for v in caps.versions]}")
print(f"  cipher_suites: {[cs.name for cs in caps.cipher_suites]}")
print(f"  credentials  : {[ct.name for ct in caps.credentials]}")
print(f"  extensions   : {len(caps.extensions)}")
print(f"  proposals    : {len(caps.proposals)}")

# Serialize test (important for later steps)
ser = caps.serialize()
print(f"\nSerialized length: {len(ser)} bytes")
print(f"Erste Bytes (hex): {ser.hex()[:60]}...")