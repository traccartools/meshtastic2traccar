"""Utility helpers for decoding Meshtastic direct messages."""
from __future__ import annotations

import secrets
import struct
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESCCM

def encrypt_direct_message(
    private_key_a: bytes,
    public_key_b: bytes,
    plaintext: bytes,
    from_node: int,
    packet_id: int
) -> bytes:
    """
    Encrypt and authenticate a Meshtastic direct-message payload.

    Returns ciphertext || tag || extra_nonce, mirroring firmware output.
    """

    if len(private_key_a) != 32 or len(public_key_b) != 32:
        raise ValueError("Curve25519 keys must be 32 bytes each.")

    extra_nonce_bytes = struct.pack("<I", secrets.randbits(32))

    private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_a)
    peer_key = x25519.X25519PublicKey.from_public_bytes(public_key_b)
    shared_secret = private_key.exchange(peer_key)

    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared_secret)
    aes_key = digest.finalize()

    nonce = bytearray(b"\x00" * 16)
    nonce[0:8] = struct.pack("<Q", packet_id)
    nonce[8:12] = struct.pack("<I", from_node)
    nonce[4:8] = extra_nonce_bytes

    aes_ccm = AESCCM(aes_key, tag_length=8)
    ciphertext_with_tag = aes_ccm.encrypt(nonce[0:13], plaintext, None)
    return ciphertext_with_tag + extra_nonce_bytes

def decrypt_direct_message(
    private_key_a: bytes,
    public_key_b: bytes,
    message: bytes,
    from_node: int,
    packet_id: int,
) -> bytes:
    """
    Decrypt and authenticate a Meshtastic direct-message payload.

    Args:
        private_key_a: 32-byte Curve25519 private key for the local node.
        public_key_b: 32-byte Curve25519 public key for the peer node.
        message: Ciphertext buffer produced by `encryptCurve25519`, containing the
            encrypted payload followed by the 8-byte CCM tag and 4-byte extra nonce.
        from_node: Numeric node ID of the sender (used in nonce derivation).
        packet_id: Packet identifier that was used during transmission.

    Returns:
        The decrypted plaintext bytes if the authentication tag verifies.

    Raises:
        ValueError: If inputs are malformed.
        InvalidTag: Propagated from AES-CCM when authentication fails.
    """

    if len(private_key_a) != 32 or len(public_key_b) != 32:
        raise ValueError("Curve25519 keys must be 32 bytes each.")
    if len(message) < 12:
        raise ValueError("Ciphertext must include the CCM tag and extra nonce.")

    ciphertext = message[:-12]
    tag = message[-12:-4]
    extra_nonce_bytes = message[-4:]
    # extra_nonce = struct.unpack("<I", extra_nonce_bytes)[0]

    # Derive the shared secret via X25519 and hash it with SHA-256, mirroring the firmware.
    private_key = x25519.X25519PrivateKey.from_private_bytes(private_key_a)
    peer_key = x25519.X25519PublicKey.from_public_bytes(public_key_b)
    shared_secret = private_key.exchange(peer_key)

    digest = hashes.Hash(hashes.SHA256())
    digest.update(shared_secret)
    aes_key = digest.finalize()

    # Recreate the nonce exactly as the firmware does.
    nonce = bytearray(b'\x00' * 16);
    nonce[0:8] = struct.pack("<Q", packet_id) 
    nonce[8:12] = struct.pack("<I", from_node)
    nonce[4:8] = extra_nonce_bytes
    # print("Nonce:", nonce.hex())
    # print("Nonce length:", len(nonce))

    aes_ccm = AESCCM(aes_key, tag_length=8)
    plaintext = aes_ccm.decrypt(nonce[0:13], ciphertext + tag, None)
    return plaintext




if __name__ == '__main__':
    
    private_key_a = "QGWR4kGqel2piIgQqVNncTErRwrdozQtcuKZ6/HhBlI="
    public_key_b = "OvK2BQpCotPQdl38F8ICT3wOVbZISyu+thNZn1NJ3xI="

    message = "Bur6XItPmBppLiRwGV86vLsUF7uIxdPYWbIXZYdeQuwAyNjx8nZI/cuiXc5xWCJgRYO/vTeiz13VAJNDuWE="

    from_node = 1735683336 #"!67746d08"
    packet_id = 2449045127

    # Test the decode tool
    import base64
    private_key_a_bytes = base64.b64decode(private_key_a)
    public_key_b_bytes = base64.b64decode(public_key_b)
    message_bytes = base64.b64decode(message)
    plaintext = decrypt_direct_message(
        private_key_a_bytes,
        public_key_b_bytes,
        message_bytes,
        from_node,
        packet_id,
    )
    print("Decrypted plaintext:", plaintext)
    print("Start num: " + str(struct.unpack("<I", plaintext[0:4])[0]))

    # Simple round-trip test ensuring encrypt/decrypt symmetry.
    sender_private = x25519.X25519PrivateKey.generate()
    receiver_private = x25519.X25519PrivateKey.generate()
    sender_public = sender_private.public_key()
    receiver_public = receiver_private.public_key()

    sender_private_bytes = sender_private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    receiver_private_bytes = receiver_private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    sender_public_bytes = sender_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    receiver_public_bytes = receiver_public.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    rt_from_node = 0x11223344
    rt_packet_id = 0x55667788
    rt_plaintext = b"Round-trip Meshtastic DM"

    encrypted_rt = encrypt_direct_message(
        sender_private_bytes,
        receiver_public_bytes,
        rt_plaintext,
        rt_from_node,
        rt_packet_id,
    )
    decrypted_rt = decrypt_direct_message(
        receiver_private_bytes,
        sender_public_bytes,
        encrypted_rt,
        rt_from_node,
        rt_packet_id,
    )

    assert decrypted_rt == rt_plaintext
    print("Round-trip test plaintext:", decrypted_rt)
