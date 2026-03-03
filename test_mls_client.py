from random import randbytes
from datetime import datetime
import sys
import secrets

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
    DeriveSecret,
    MAC,
    EncryptWithLabel,
    ExtractWelcomeSecret,
)
from mls_stuff.Objects import GroupContext, GroupInfo
from cryptography.hazmat.primitives.asymmetric.ed448 import (
    Ed448PrivateKey,
    Ed448PublicKey,
)
import requests

AS = "http://127.0.0.1:1337/"
DS = "http://127.0.0.1:1338/"

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
    alices_identity = handle_as_registration(alice_sk, alice_pk)
    
    alices_init_key_pair = cs.kem.derive_key_pair(b"alices_super_secret")
    alices_init_key = HPKEPublicKey(alices_init_key_pair.public_key.to_public_bytes())
    alices_credential = Credential.BasicCredential(alices_identity)

    print("--------------Bob initializes his key material--------------------")
    # here we handle Bob's identity
    print("Bob generates his key pair for signatures and his identity")
    bob_sk = Ed448PrivateKey.generate()
    bob_pk = bob_sk.public_key()
    print("Bob registers these with the Authentication Service")
    bobs_identity = handle_as_registration(bob_sk, bob_pk)

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

    # Bob creates his KeyPackage with it
    print(
        "With the LeafNode and Bob's private signature key we create a KeyPackage"
    )
    bobs_key_package = key_package_builder(
        cipher_suite, bobs_init_key, bobs_leaf_node, bob_sk.private_bytes_raw()
    )
    bobs_key_package_serialized = bobs_key_package.serialize()

    # Submit Bob's KeyPackage to the DS
    print("We transmit the KeyPackage to the DS")
    resp = requests.post(f"{DS}user/Bob", bobs_key_package_serialized)
    if resp.status_code != 200:
        raise ValueError("Could not register the KeyPackage with the DS")

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

    print("Alice adds her Leaf Node to the RatchetTree")
    alice_tree[0] = alice_leaf_node

    print("Alice creates a GroupContext")
    gc = GroupContext(
        cipher_suite,
        VLBytes("testgroup"),
        0,
        VLBytes(alice_tree.hash(cipher_suite)),
        VLBytes(),
        [],
    )

    print("Alice generates a random Epoch Secret")
    # sample a fresh epoch_secret
    epoch_secret = randbytes(Enums.CipherSuite.hash_size(cipher_suite))
    print(
        "We also create an init secret here for the next generation of the KeySchedule"
    )
    init_secret = DeriveSecret(cipher_suite, epoch_secret, b"init")
    # calculate the confirmation key
    print("Alice derives a confirmation Key from it")
    confirmation_key = DeriveSecret(cipher_suite, epoch_secret, b"confirm")
    confirmation_tag = MAC.new(
        cipher_suite, confirmation_key, gc.confirmed_transcript_hash
    )
    print("Alice creates the interim transcript hash of epoch 0 with this")
    alice_interim_transcript_hashes.append(
        InterimTranscriptHashInput(confirmation_tag).hash(
            cipher_suite, gc.confirmed_transcript_hash.to_bytes()
        )
    )
    alice_confirmed_transcript_hashes.append(gc.confirmed_transcript_hash.to_bytes())
    print("The group is now created")

    print("--------------Alice adds Bob to the group------------------------------")
    # next we create a proposal that adds Bob to the group.
    # for this we first need to get Bob's KeyPackage from the DS
    print("Alice retrieves Bob's KeyPackage from the DS")
    bobs_kp_request = requests.get(f"{DS}user/Bob")
    if bobs_kp_request.status_code != 200:
        raise ValueError("Request for Bob's KeyPackage was unsuccessful")
    # parse Bob's keypackage
    bobs_kp_parsed = KeyPackage.deserialize(bytearray(bobs_kp_request.content))

    # verify the signature
    if not bobs_kp_parsed.verify_signature(cipher_suite, bobs_kp_parsed.content.leaf_node.value.signature_key.to_bytes()):  # type: ignore
        raise ValueError(
            "Signature of Bob's KeyPackage does not match the signature key of the contained Leaf Node"
        )
    print("Signature of Bob's KeyPackage is valid")

    # check Bob's Identity
    bobs_identity_from_kp = (
        bobs_kp_parsed.content.leaf_node.value.credential.identity.to_bytes()  # type: ignore
    )

    verify_identity(bobs_identity_from_kp)
    print("Bob's Identity is known to the AS")

    print("Create an Add Proposal for Bob")
    add_proposal = Add(bobs_kp_parsed)

    print("Apply the proposal to Alice's Ratchet Tree")
    add_proposal.apply_to_tree(alice_tree)

    print("Create a Commit with this proposal")
    proposal_ref = ProposalOrRef(add_proposal)
    alice_commit = Commit([proposal_ref], None)
    print("Package the commit in FramedContent")
    fc_commit = FramedContent(
        GROUPID,
        gc.epoch,
        Sender(Enums.SenderType.member, 0, 0),
        VLBytes(),
        Enums.ContentType.commit,
        commit=alice_commit,
    )
    fc_tbs = FramedContentTBS(Enums.WireFormat.MLS_PUBLIC_MESSAGE, fc_commit, gc)
    fc_signature = fc_tbs.signature(cipher_suite, alice_sk.private_bytes_raw())
    # we don't provide an update path here since the add proposal doesn't require one
    # consequently our commit secret becomes a zero vector of length KDF.Nh
    commit_secret = bytes(Enums.CipherSuite.hash_size(cipher_suite))
    # since we also have no PSKs, the psk_secret is also a zero vector of length KDF.Nh
    psk_secret = bytes(Enums.CipherSuite.hash_size(cipher_suite))
    # update the confirmed_transcript_hash
    confirmed_transcript_hash = ConfirmedTranscriptHashInput(
            Enums.WireFormat.MLS_PUBLIC_MESSAGE, fc_commit, VLBytes(fc_signature)
        ).hash(cipher_suite, alice_interim_transcript_hashes[0])
    alice_confirmed_transcript_hashes.append(confirmed_transcript_hash)
    # update the GroupContext
    gc.epoch += 1
    gc.tree_hash = VLBytes(alice_tree.hash(cipher_suite))
    gc.confirmed_transcript_hash = VLBytes(confirmed_transcript_hash)

    # calculate the old membership key since the FramedContent should be protected with it
    membership_key = DeriveSecret(cipher_suite, epoch_secret, b"membership")

    # now we need to calculate the joiner_secret, welcome_secret, epoch_secret of the new epoch
    joiner_secret = gc.extract_joiner_secret(init_secret, commit_secret)
    welcomesecret = ExtractWelcomeSecret(cipher_suite, joiner_secret, psk_secret)
    epoch_secret = gc.extract_epoch_secret(joiner_secret, psk_secret)

    confirmation_key = DeriveSecret(cipher_suite, epoch_secret, b"confirm")
    confirmation_tag = MAC.new(
        cipher_suite, confirmation_key, gc.confirmed_transcript_hash
    )
    alice_interim_transcript_hashes.append(
        InterimTranscriptHashInput(confirmation_tag).hash(
            cipher_suite, gc.confirmed_transcript_hash.to_bytes()
        )
    )
    fc_auth = FramedContentAuthData(VLBytes(fc_signature), confirmation_tag)
    auth_tbm = AuthenticatedContentTBM(fc_tbs, fc_auth)
    membership_tag = auth_tbm.to_mac(cipher_suite, membership_key)

    # create the Public Message of the commit
    commit_pm = PublicMessage(fc_commit, fc_auth, membership_tag)
    commit_msg = MLSMessage(Enums.WireFormat.MLS_PUBLIC_MESSAGE, commit_pm)
    commit_msg.serialize()
    # print("Create a Welcome message for Bob")
    # bobs_welcome = Welcome(cipher_suite,)
    print("Alice creates a Welcome for Bob")
    print("for this she first creates a GroupInfo object")
    # the groupinfo also contains an extension with the Ratchet Tree
    tree_extension = Extension(Enums.ExtensionType.ratchet_tree, VLBytes(alice_tree.serialize()))
    gi = GroupInfo.new(
        gc, [tree_extension], confirmation_tag, 0, alice_sk.private_bytes_raw()
    )
    #print("this is now encrypted")
    #ec = EncryptContext(b"Welcome")

    # Welcome(cipher_suite)

    print("send the message containing the commit to the DS")


def handle_as_registration(
    private_key: Ed448PrivateKey, public_key: Ed448PublicKey
) -> Identity:
    """Function to register an identity with the example implementation of the Authentication Service.

    Args:
        private_key (Ed448PrivateKey): Private key to be used for signing.
        public_key (Ed448PublicKey): Public key to be stored as identity with the AS.

    Raises:
        ValueError: If storing the identity fails
    """
    # start registration of Alice's identity
    resp = requests.post(f"{AS}register", public_key.public_bytes_raw())
    challenge = resp.json()
    print("Received challenge from AS:", challenge)
    challenge_id = challenge["challenge_id"]  # type: int
    to_sign = challenge["challenge_phrase"]  # type: str

    # Sign the received challenge
    signature = private_key.sign(to_sign.encode("ascii"))

    # Submit the signature to the AS
    resp = requests.post(f"{AS}challenge/{challenge_id}", signature)

    resp = requests.post(f"{AS}verify", public_key.public_bytes_raw())

    if resp.status_code != 200:
        raise ValueError("Could not register identity with the AS")

    return Identity(public_key.public_bytes_raw())


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


def verify_identity(identity_bytes: bytes) -> None:
    identity_request = requests.post(f"{AS}verify", identity_bytes)

    if identity_request.status_code != 200:
        raise ValueError(
            f"Could not verify identity '0x{identity_bytes.hex()}'"
        )


if __name__ == "__main__":
    main()