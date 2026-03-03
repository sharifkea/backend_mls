# test_add_commit_welcome.py
# Step 13: Try to build Add proposal, Commit, Welcome from Alice to add herself to Bob's group

import sys
import secrets
from datetime import datetime, timedelta

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

from mls_stuff.Enums import CipherSuite, ProtocolVersion, ProposalType
from mls_stuff.Objects import GroupInfo
from mls_stuff.MLS import (
    Add, Proposal, ProposalOrRef,
    Commit, UpdatePath,
    Welcome, EncryptedGroupSecrets,
    FramedContent, PrivateMessage, PublicMessage,  # for later messages
)
from mls_stuff.MLS._key_package import KeyPackage
from mls_stuff.Misc import VLBytes
from mls_stuff.RatchetTree import RatchetTree, LeafNode
# Add other needed imports based on errors (e.g. GroupContext, HPKE, etc.)

cs = CipherSuite.MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519

# ────────────────────────────────────────────────
# Assume you have:
# - Bob's group already created (from group_creation.py)
# - Bob's LeafNode at index 0
# - Alice's fresh KeyPackage bytes (from your API or GeneratKeyPackage)
# ────────────────────────────────────────────────

# For testing: replace with real values from your run
bob_group_id = VLBytes(secrets.token_bytes(16))          # ← use real from your group
bob_tree = RatchetTree()                                 # ← your existing tree with Bob at 0
alice_kp_bytes = b''                                     # ← fetch from API or generate
alice_kp = KeyPackage.deserialize(bytearray(alice_kp_bytes))

print("=== Step 13: Building Add Proposal (Alice adding herself) ===\n")

# 1. Create Add proposal
add_proposal = Add(key_package=alice_kp)

proposal = Proposal(proposal_type=ProposalType.add, add=add_proposal)

# Wrap as ProposalOrRef (by value, not ref)
por = ProposalOrRef(proposal=proposal)  # guess — check error for exact args

print("Add Proposal created")
print("Proposal type:", proposal.proposal_type)

# 2. Minimal Commit (just the Add, no path for simplicity — may need path for real)
commit = Commit(
    proposals=[por],
    path=None,           # Optional[UpdatePath] — set to None for test (may fail validation)
    # Other fields like force_init_secret may exist — add if TypeError
)

print("\nCommit created (minimal)")
print("Proposals count:", len(commit.proposals))
print("Has path?:", commit.path is not None)

# 3. Try to build Welcome (this will likely fail without key schedule / secrets)
# But let's see constructor
try:
    # Guess: needs group info + encrypted secrets for each joiner
    group_info = GroupInfo(
        group_context=...,      # ← from your group_context
        epoch=1,                # after commit
        tree_hash=VLBytes(bob_tree.hash(cs)),
        # ... other fields like confirmed_transcript_hash, etc.
    )

    # EncryptedGroupSecrets for Alice (one per joiner)
    # This needs HPKE encryption — library probably has helper
    enc_secrets = [EncryptedGroupSecrets(...)]  # placeholder

    welcome = Welcome(
        cipher_suite=cs,
        secrets=enc_secrets,
        group_info=group_info  # or serialized
    )
    print("\nWelcome object created (placeholder)")
except Exception as e:
    print("\nWelcome creation failed (expected):", type(e).__name__, str(e))
    print("→ This is normal; we need key schedule / HPKE first")

# Next steps printed
print("\nWhat next?")
print("- Check exact args for ProposalOrRef, Commit, Welcome → run dir() on them")
print("- Look for key schedule functions (search code for 'keyschedule' or 'derive')")
print("- If stuck on secrets → search repo for ExpandWithLabel, ExtractWelcomeSecret (they exist!)")

if __name__ == "__main__":
    pass  # run the prints above