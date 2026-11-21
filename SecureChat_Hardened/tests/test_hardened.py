"""Automated tests for the hardened Secure Chat.

Run from the project folder (after python gen_keys.py):

    python -m unittest tests.test_hardened -v

The integration tests copy the project to a temporary folder, so the real
credentials.txt is never changed.
"""

import base64
import json
import secrets
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT))

import authentication  # noqa: E402
import crypto  # noqa: E402
from config import DH_P, SERVER_HOST, SERVER_PORT, SERVER_PUBLIC_KEY_FILE  # noqa: E402
from crypto import HandshakeError  # noqa: E402


def server_key():
    return crypto.load_private_key(PROJECT / "keys" / "server_private.pem")


def server_pub():
    return crypto.load_public_key(PROJECT / SERVER_PUBLIC_KEY_FILE)


class CryptoUnitTests(unittest.TestCase):
    def test_handshake_produces_same_key_on_both_sides(self):
        client_private, client_public = crypto.create_dh_keys()
        key, server_public, signature = crypto.respond_to_dh(client_public, server_key())
        client_key = crypto.complete_dh(
            client_private, client_public, server_public, signature, server_pub()
        )
        self.assertEqual(key, client_key)
        self.assertEqual(len(key), 32)

    def test_tampered_server_value_is_rejected(self):
        client_private, client_public = crypto.create_dh_keys()
        _, server_public, signature = crypto.respond_to_dh(client_public, server_key())
        _, attacker_public = crypto.create_dh_keys()
        with self.assertRaises(HandshakeError):
            crypto.complete_dh(client_private, client_public, attacker_public, signature, server_pub())

    def test_signature_from_other_key_is_rejected(self):
        client_private, client_public = crypto.create_dh_keys()
        other = crypto.RSA.generate(2048)
        _, server_public, signature = crypto.respond_to_dh(client_public, other)
        with self.assertRaises(HandshakeError):
            crypto.complete_dh(client_private, client_public, server_public, signature, server_pub())

    def test_out_of_range_values_are_rejected(self):
        for bad in (0, 1, DH_P - 1, DH_P, -5):
            with self.subTest(value=bad):
                with self.assertRaises(HandshakeError):
                    crypto.validate_public(bad)

    def test_value_outside_subgroup_is_rejected(self):
        q = (DH_P - 1) // 2
        bad = next(y for y in range(2, 1000) if pow(y, q, DH_P) != 1)
        with self.assertRaises(HandshakeError):
            crypto.validate_public(bad)

    def test_gcm_round_trip_and_tamper_detection(self):
        key = os.urandom(32)
        blob = crypto.encrypt_data(key, b"hello bob")
        self.assertEqual(crypto.decrypt_data(key, blob), b"hello bob")
        changed = bytearray(blob)
        changed[15] ^= 0x01
        with self.assertRaises(ValueError):
            crypto.decrypt_data(key, bytes(changed))
        with self.assertRaises(ValueError):
            crypto.decrypt_data(os.urandom(32), blob)


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.original = authentication.CREDENTIAL_FILE
        authentication.CREDENTIAL_FILE = Path(self.tmp.name) / "credentials.txt"

    def tearDown(self):
        authentication.CREDENTIAL_FILE = self.original
        self.tmp.cleanup()

    def test_register_login_and_argon2_format(self):
        ok, _ = authentication.register_user("carol", "Sunshine42!")
        self.assertTrue(ok)
        stored = json.loads(authentication.CREDENTIAL_FILE.read_text())
        self.assertTrue(stored["carol"]["hash"].startswith("$argon2id$"))
        self.assertNotIn("password_hash", stored["carol"])
        self.assertTrue(authentication.login_user("carol", "Sunshine42!")[0])
        self.assertFalse(authentication.login_user("carol", "wrong")[0])

    def test_legacy_sha256_account_logs_in_and_is_upgraded(self):
        import hashlib
        salt = os.urandom(16)
        legacy = {"dave": {
            "salt": salt.hex(),
            "password_hash": hashlib.sha256(salt + b"12345678").hexdigest(),
        }}
        authentication.CREDENTIAL_FILE.write_text(json.dumps(legacy))
        self.assertFalse(authentication.login_user("dave", "nope")[0])
        self.assertTrue(authentication.login_user("dave", "12345678")[0])
        upgraded = json.loads(authentication.CREDENTIAL_FILE.read_text())
        self.assertTrue(upgraded["dave"]["hash"].startswith("$argon2id$"))
        self.assertTrue(authentication.login_user("dave", "12345678")[0])


# ---------- Integration: real server.py over TCP ----------

def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_port(port, timeout=15):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((SERVER_HOST, port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.2)
    return False


def connect_and_login(port, action, username, password, verify_key=None):
    """Client side of the hardened protocol. Returns (sock, reader, key, response)."""
    sock = socket.create_connection((SERVER_HOST, port), timeout=10)
    try:
        reader = sock.makefile("rb")
        private_value, client_public = crypto.create_dh_keys()
        crypto.send_msg(sock, crypto.encode_json({"dh_public": str(client_public)}))
        hello = crypto.decode_json(crypto.recv_msg(reader))
        key = crypto.complete_dh(
            private_value, client_public, int(hello["dh_public"]), hello["signature"],
            verify_key or server_pub(),
        )
        crypto.send_msg(sock, crypto.encrypt_data(key, crypto.encode_json({
            "action": action, "username": username, "password": password
        })))
        response = crypto.decode_json(crypto.decrypt_data(key, crypto.recv_msg(reader)))
    except Exception:
        sock.close()
        raise
    return sock, reader, key, response


class ServerIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Use a free port and a fresh copy of the project, so a server that is
        # already running on the usual port cannot answer these tests.
        cls.tmp = tempfile.mkdtemp()
        copy = Path(cls.tmp) / "project"
        shutil.copytree(PROJECT, copy, ignore=shutil.ignore_patterns("__pycache__", "tests"))
        (copy / "credentials.txt").write_text("{}")
        cls.port = free_port()
        config_text = (copy / "config.py").read_text()
        config_text = config_text.replace(f"SERVER_PORT = {SERVER_PORT}", f"SERVER_PORT = {cls.port}")
        (copy / "config.py").write_text(config_text)
        cls.server = subprocess.Popen(
            [sys.executable, "server.py"], cwd=copy,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if not wait_for_port(cls.port) or cls.server.poll() is not None:
            cls.server.kill()
            raise RuntimeError("test server.py did not start")

    @classmethod
    def tearDownClass(cls):
        cls.server.terminate()
        cls.server.wait(timeout=10)
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_register_login_and_direct_chat(self):
        socks = []
        suffix = secrets.token_hex(3)
        alice, bob = f"alice{suffix}", f"bob{suffix}"
        try:
            a_sock, a_reader, a_key, a_resp = connect_and_login(self.port, "register", alice, "Pw-alice-1")
            socks.append(a_sock)
            self.assertTrue(a_resp["success"], a_resp)
            b_sock, b_reader, b_key, b_resp = connect_and_login(self.port, "register", bob, "Pw-bob-1")
            socks.append(b_sock)
            self.assertTrue(b_resp["success"], b_resp)

            crypto.send_msg(a_sock, crypto.encrypt_data(a_key, crypto.encode_json(
                {"type": "chat", "to": bob, "id": "m1", "message": "secret hello"}
            )))
            received = None
            deadline = time.time() + 10
            while time.time() < deadline and received is None:
                msg = crypto.decode_json(crypto.decrypt_data(b_key, crypto.recv_msg(b_reader)))
                if msg.get("type") == "chat":
                    received = msg
            self.assertIsNotNone(received)
            self.assertEqual(received["from"], alice)
            self.assertEqual(received["message"], "secret hello")
        finally:
            for sock in socks:
                sock.close()

    def test_wrong_password_is_rejected(self):
        sock, _, _, response = connect_and_login(self.port, "login", "nobody-here", "wrong")
        sock.close()
        self.assertFalse(response["success"])

    def test_man_in_the_middle_is_refused(self):
        """A proxy swaps the server's DH value. The client must refuse to connect."""
        proxy_port = free_port()
        stop = threading.Event()
        listener = socket.socket()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", proxy_port))
        listener.listen(1)
        listener.settimeout(0.5)
        _, attacker_public = crypto.create_dh_keys()

        def proxy_once():
            while not stop.is_set():
                try:
                    client_side, _ = listener.accept()
                    break
                except socket.timeout:
                    continue
            else:
                return
            server_side = socket.create_connection((SERVER_HOST, self.port))
            client_reader = client_side.makefile("rb")
            server_reader = server_side.makefile("rb")
            # Client -> server: forward the client's DH value unchanged.
            crypto.send_msg(server_side, crypto.recv_msg(client_reader))
            # Server -> client: replace dh_public, keep the original signature.
            hello = crypto.decode_json(crypto.recv_msg(server_reader))
            hello["dh_public"] = str(attacker_public)
            crypto.send_msg(client_side, crypto.encode_json(hello))
            client_side.close()
            server_side.close()

        t = threading.Thread(target=proxy_once, daemon=True)
        t.start()
        try:
            with self.assertRaises(HandshakeError):
                connect_and_login(proxy_port, "login", "nobody-here", "Pw-alice-1")
        finally:
            stop.set()
            listener.close()
            t.join(timeout=5)


if __name__ == "__main__":
    unittest.main(verbosity=2)