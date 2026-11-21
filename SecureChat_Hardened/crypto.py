"""Cryptographic helpers for Secure Chat (hardened version).

Primitives used:
  * Diffie-Hellman over the RFC 7919 ffdhe3072 group (3072-bit safe prime).
  * RSA-PSS (SHA-256) signatures over the DH public values, so the peer is
    authenticated and a man-in-the-middle cannot swap the key exchange.
  * HKDF-SHA256 to derive the AES key from the DH shared secret.
  * AES-256-GCM for confidentiality and integrity of every message.
"""

import base64
import json
import os
import secrets

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import RSA
from Crypto.Signature import pss

from config import DH_G, DH_P, DH_P_BYTES, AES_KEY_SIZE

GCM_NONCE_SIZE = 12
GCM_TAG_SIZE = 16
HKDF_INFO = b"SecureChat AES-256-GCM v1"


class HandshakeError(ValueError):
    """Raised when the peer's key exchange cannot be trusted."""


# ---------- Framing and JSON (unchanged from the baseline) ----------

def send_msg(sock, data):
    """Send one Base64-encoded message followed by a newline."""
    sock.sendall(base64.b64encode(data) + b"\n")


def recv_msg(reader):
    """Read one framed message. Return None if the peer disconnected."""
    line = reader.readline()
    if not line:
        return None
    return base64.b64decode(line.strip(), validate=True)


def encode_json(data):
    return json.dumps(data).encode("utf-8")


def decode_json(data):
    return json.loads(data.decode("utf-8"))


# ---------- Diffie-Hellman ----------

def create_dh_keys():
    """Create a DH private value and its public value."""
    private_value = secrets.randbelow(DH_P - 3) + 2
    public_value = pow(DH_G, private_value, DH_P)
    return private_value, public_value


def validate_public(value):
    """Reject DH public values that are out of range or outside the subgroup.

    For a safe prime p = 2q + 1, valid public values are quadratic residues,
    which is exactly the set with value**q mod p == 1. Rejecting the others
    stops small-subgroup attacks.
    """
    if not isinstance(value, int) or not 2 <= value <= DH_P - 2:
        raise HandshakeError("DH public value out of range")
    q = (DH_P - 1) // 2
    if pow(value, q, DH_P) != 1:
        raise HandshakeError("DH public value is not in the valid subgroup")


def dh_shared_secret(private_value, peer_public):
    validate_public(peer_public)
    shared = pow(peer_public, private_value, DH_P)
    return shared.to_bytes(DH_P_BYTES, "big")


def transcript(client_public, server_public):
    """Bytes that the server signs: both public values, fixed width, client first."""
    return (client_public.to_bytes(DH_P_BYTES, "big")
            + server_public.to_bytes(DH_P_BYTES, "big"))


def derive_session_key(shared_bytes, client_public, server_public):
    """HKDF-SHA256 over the shared secret. The salt binds the key to this exchange."""
    salt = SHA256.new(transcript(client_public, server_public)).digest()
    return HKDF(shared_bytes, AES_KEY_SIZE, salt, SHA256, 1, context=HKDF_INFO)


# ---------- Signatures (RSA-PSS, SHA-256) ----------

def load_private_key(path):
    with open(path, "rb") as file:
        return RSA.import_key(file.read())


def load_public_key(path):
    with open(path, "rb") as file:
        return RSA.import_key(file.read())


def sign(private_key, data):
    return pss.new(private_key).sign(SHA256.new(data))


def verify(public_key, data, signature):
    try:
        pss.new(public_key).verify(SHA256.new(data), signature)
        return True
    except (ValueError, TypeError):
        return False


# ---------- Authenticated handshake helpers ----------

def respond_to_dh(client_public, signing_key):
    """Server side: answer a client's DH public value with a signed reply.

    Returns (session_key, server_public, signature_base64).
    """
    validate_public(client_public)
    private_value, server_public = create_dh_keys()
    shared = dh_shared_secret(private_value, client_public)
    key = derive_session_key(shared, client_public, server_public)
    signature = sign(signing_key, transcript(client_public, server_public))
    return key, server_public, base64.b64encode(signature).decode("ascii")


def complete_dh(private_value, client_public, server_public, signature_b64, verify_key):
    """Client side: check the server's signature, then derive the session key.

    Raises HandshakeError if the signature does not match the pinned public key.
    """
    validate_public(server_public)
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, TypeError):
        raise HandshakeError("Malformed handshake signature")
    if not verify(verify_key, transcript(client_public, server_public), signature):
        raise HandshakeError("Handshake signature check failed. Possible man-in-the-middle.")
    shared = dh_shared_secret(private_value, server_public)
    return derive_session_key(shared, client_public, server_public)


# ---------- AES-256-GCM (confidentiality and integrity) ----------

def encrypt_data(key, plaintext):
    """Return nonce || ciphertext || tag."""
    nonce = secrets.token_bytes(GCM_NONCE_SIZE)
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + ciphertext + tag


def decrypt_data(key, blob):
    """Decrypt and verify. Raises ValueError if the data was changed."""
    if len(blob) < GCM_NONCE_SIZE + GCM_TAG_SIZE:
        raise ValueError("Encrypted message is too short")
    nonce = blob[:GCM_NONCE_SIZE]
    tag = blob[-GCM_TAG_SIZE:]
    ciphertext = blob[GCM_NONCE_SIZE:-GCM_TAG_SIZE]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)
