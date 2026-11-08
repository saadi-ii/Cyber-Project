import base64
import json
import secrets
import hashlib

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from config import DH_G, DH_P, AES_KEY_SIZE


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


def create_dh_keys():
    """Create a DH private value and its public value."""
    private_value = secrets.randbelow(DH_P - 3) + 2
    public_value = pow(DH_G, private_value, DH_P)
    return private_value, public_value


def calculate_shared_key(private_value, other_public_value):
    """Derive a 32-byte AES key from the DH shared value.

    SHA-256 is used here as a simple Phase A baseline derivation.
    Phase D should replace this with a proper KDF such as HKDF.
    """
    if not 2 <= other_public_value <= DH_P - 2:
        raise ValueError("Invalid DH public value")

    shared_value = pow(other_public_value, private_value, DH_P)
    byte_length = (DH_P.bit_length() + 7) // 8
    shared_bytes = shared_value.to_bytes(byte_length, "big")
    return hashlib.sha256(shared_bytes).digest()[:AES_KEY_SIZE]


def encrypt_data(key, plaintext):
    """AES-256-CBC encryption. The random IV is included before ciphertext."""
    iv = secrets.token_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return iv + ciphertext


def decrypt_data(key, encrypted_data):
    """Decrypt AES-256-CBC data containing IV || ciphertext."""
    if len(encrypted_data) < 32 or len(encrypted_data) % AES.block_size != 0:
        raise ValueError("Invalid encrypted message length")

    iv = encrypted_data[:AES.block_size]
    ciphertext = encrypted_data[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)
