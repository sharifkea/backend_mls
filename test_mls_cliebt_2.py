from random import randbytes
from datetime import datetime
import sys
import secrets

#from mls_stuff.mls_test_client import leaf_node_builder,key_package_builder

sys.path.insert(0, r"C:\Users\ronys\Documents\RUC\Thesis\backend_mls\mls_stuff")

from mls_stuff import RatchetTree, Enums
from mls_stuff.Misc import (
    Capabilities,
    VLBytes,
    Lifetime,
    Extension,
    KDFLabel,
    EncryptContext,
)
from mls_stuff.MLS import (
    KeyPackage,
    KeyPackageTBS,
    Add,
    Commit,
    ProposalOrRef,
    Welcome,
    FramedContent,
    FramedContentTBS,
    FramedContentAuthData,
    Sender,
    ConfirmedTranscriptHashInput,
    InterimTranscriptHashInput,
    AuthenticatedContentTBM,
    PublicMessage,
    MLSMessage
)
from mls_stuff.Crypto import (
    HPKEPublicKey,
    Credential,
    Identity,
    SignaturePublicKey,
    EncryptedGroupSecrets,
    GroupSecrets,
    HPKECiphertext,
    DeriveSecret,
    MAC,
    EncryptWithLabel,
    ExtractWelcomeSecret,
    ExpandWithLabel,
)
from mls_stuff.Objects import GroupContext, GroupInfo
from cryptography.hazmat.primitives.asymmetric.ed448 import (
    Ed448PrivateKey,
    Ed448PublicKey,
)
import requests

#AS = "http://127.0.0.1:1337/"
#DS = "http://127.0.0.1:1338/"

CAPABILITIES = Capabilities(
    [Enums.ProtocolVersion.MLS10],
    [Enums.CipherSuite.MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448],
    [Enums.ExtensionType.required_capabilities, Enums.ExtensionType.ratchet_tree],
    [Enums.ProposalType.add],
    [Enums.CredentialType.basic],
)

GROUPID = VLBytes(f"testgroup{datetime.now().timestamp()}")


def main():
    # we use this ciphersuite so we can use the KeyPair of our Identity as Signature Key
    cipher_suite = Enums.CipherSuite.MLS_256_DHKEMX448_AES256GCM_SHA512_Ed448

    # Lists to store interim and confirmed transcript hashes
    alice_interim_transcript_hashes = []
    alice_confirmed_transcript_hashes = []
    bobs_interim_transcript_hashes = []
    bobs_confirmed_transcript_hashes = []

    cs = Enums.CipherSuite.get_hpke_ciphersuite(cipher_suite)
    print("--------------Alice initializes her key material-------------------")
    # here we handle Alice's identity
    print("Alice generates her key pair for signatures and her identity")
    alice_sk = Ed448PrivateKey.generate()
    alice_pk = alice_sk.public_key()
    print("Alice registers these with the Authentication Service")
    #alices_identity = handle_as_registration(alice_sk, alice_pk)
    alices_identity=Identity(alice_pk.public_bytes_raw())
    
    alices_init_key_pair = cs.kem.derive_key_pair(b"alices_super_secret")
    alices_init_key = HPKEPublicKey(alices_init_key_pair.public_key.to_public_bytes())
    alices_credential = Credential.BasicCredential(alices_identity)

    print("--------------Bob initializes his key material--------------------")
    # here we handle Bob's identity
    print("Bob generates his key pair for signatures and his identity")
    bob_sk = Ed448PrivateKey.generate()
    bob_pk = bob_sk.public_key()
    print("Bob registers these with the Authentication Service")
    #bobs_identity = handle_as_registration(bob_sk, bob_pk)
    bobs_identity=Identity(bob_pk.public_bytes_raw())

    # From this identity we create a basic credential
    print("Bob wraps his identity in a BasicCredential")
    bobs_credential = Credential.BasicCredential(bobs_identity)

    # Next we create Bob's 'init_key' and 'signature_key'
    print("Bob generates an Init Key Pair for his KeyPackage")
    bobs_init_key_pair = cs.kem.derive_key_pair(b"bobs_super_secret")
    bobs_init_key = HPKEPublicKey(bobs_init_key_pair.public_key.to_public_bytes())
    bobs_signature_key = SignaturePublicKey(bob_pk.public_bytes_raw())

    print("--------------Bob creates a KeyPackage-----------------------------------")
    # The next step is to create Bob's Leaf Node
    print("Bob first creates a Leaf Node for this")
    
    bobs_leaf_node = leaf_node_builder(
        bobs_init_key,
        bobs_signature_key,
        bobs_credential,
        cipher_suite,
        bob_sk.private_bytes_raw(),
    )

    bobs_key_package = key_package_builder(
        cipher_suite, bobs_init_key, bobs_leaf_node, bob_sk.private_bytes_raw()
    )
    bobs_key_package_serialized = bobs_key_package.serialize()

    

    # Submit Bob's KeyPackage to the DS
    print("We transmit the KeyPackage to the DS")

    print("--------------Alice creates a group with herself as member------")
    print("Alice creates a Ratchet Tree")
    # according to https://www.rfc-editor.org/rfc/rfc9420.html#section-11
    alice_tree = RatchetTree.RatchetTree()
    # Alice's Ratchet Tree initially has no root node.
    # This is created by the first extension
    alice_tree.extend()
    # To have Leaf Nodes we extend the tree a second time
    alice_tree.extend()
    print(
        f"The next free node index for Alice's Leaf Node is '{alice_tree.free_node_index_for_leaf}'"
    )

    print("Alice now creates her Leaf Node")
    alice_leaf_node = leaf_node_builder(
        alices_init_key,
        SignaturePublicKey(alice_pk.public_bytes_raw()),
        alices_credential,
        cipher_suite,
        alice_sk.private_bytes_raw(),
    )
    print (f"Alice's Leaf Node is '{alice_leaf_node}'")
    alices_key_package=key_package_builder(
        cipher_suite, alices_init_key, alice_leaf_node, alice_sk.private_bytes_raw()
    )
    alices_key_package_serialized=alices_key_package.serialize()
    print (f"Alice's KeyPackage is '{alices_key_package}'")

    print("Alice adds her Leaf Node to the RatchetTree")
    alice_tree[0] = alice_leaf_node
    root_secret = VLBytes(alice_tree.hash(cipher_suite))

    print("--------------Alice adds Bob to the group------------------------------")
    # next we create a proposal that adds Bob to the group.
    # for this we first need to get Bob's KeyPackage from the DS
    print("Alice retrieves Bob's KeyPackage from the DS")
    #bobs_kp_request = bobs_key_package_serialized

    # parse Bob's keypackage
    #bobs_kp_parsed = KeyPackage.deserialize(bytearray(bobs_kp_request.content))
    bobs_kp_parsed = KeyPackage.deserialize(bobs_key_package_serialized)

    #verify_identity(bobs_identity_from_kp)
    print("Bob's Identity is known to the AS")

    print("Create an Add Proposal for Bob")
    add_proposal = Add(bobs_kp_parsed)

    print("Apply the proposal to Alice's Ratchet Tree")
    add_proposal.apply_to_tree(alice_tree)

    root_secret = VLBytes(alice_tree.hash(cipher_suite))
    print (f"The root secret of Alice's Ratchet Tree after adding Bob is '{root_secret.hex()}'")

    print("Alice creates a new Ratchet Tree")
    # according to https://www.rfc-editor.org/rfc/rfc9420.html#section-11
    bob_tree = RatchetTree.RatchetTree()
    # Bob's Ratchet Tree initially has no root node.
    # This is created by the first extension
    bob_tree.extend()
    # To have Leaf Nodes we extend the tree a second time
    bob_tree.extend()
    print(
        f"The next free node index for Bob's Leaf Node is '{bob_tree.free_node_index_for_leaf}'"
    )

    

    print("Bob adds his Leaf Node to the RatchetTree")
    new_alices_leaf_node = alices_key_package.content.leaf_node  
    bob_tree[0] = new_alices_leaf_node
    root_secret = VLBytes(bob_tree.hash(cipher_suite))

    print("--------------Alice adds Bob to the group------------------------------")
   
    print("Create an Add Proposal for Bob")
    add_proposal = Add(bobs_key_package)

    print("Apply the proposal to Alice's Ratchet Tree")
    add_proposal.apply_to_tree(bob_tree)

    root_secret = VLBytes(bob_tree.hash(cipher_suite))
    print (f"The root secret of Bob's Ratchet Tree after adding Alice is '{root_secret.hex()}'")


def leaf_node_builder(
    encryption_key: HPKEPublicKey,
    signature_key: SignaturePublicKey,
    credential: Credential.Credential,
    cipher_suite: Enums.CipherSuite,
    signature_private_key: bytes,
    source: Enums.LeafNodeSource = Enums.LeafNodeSource.key_package,
) -> RatchetTree.LeafNode:
    leaf_node_payload = RatchetTree.LeafNodePayload(
        encryption_key,
        signature_key,
        credential,
        CAPABILITIES,
        source,
        Lifetime(0, 99999),
    )

    tbs = RatchetTree.LeafNodeTBS(leaf_node_payload)
    signature = tbs.signature(cipher_suite, signature_private_key)

    return RatchetTree.LeafNode(leaf_node_payload, signature=VLBytes(signature))


def key_package_builder(
    cipher_suite: Enums.CipherSuite,
    init_key: HPKEPublicKey,
    leaf_node: RatchetTree.LeafNode,
    secret_signing_key: bytes,
) -> KeyPackage:
    key_package_payload = KeyPackageTBS(
        Enums.ProtocolVersion.MLS10, cipher_suite, init_key, leaf_node, []
    )
    key_package = KeyPackage(
        key_package_payload,
        VLBytes(key_package_payload.signature(cipher_suite, secret_signing_key)),
    )
    return key_package

if __name__ == "__main__":
    main()