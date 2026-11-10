"""Web chat client for Secure Chat.

Run this file instead of client.py to use the browser interface:

    python server.py       (terminal 1)
    python client_ui.py    (terminal 2)

Then open the link printed in terminal 2 (http://127.0.0.1:8000).

Encryption layers (all in Phase A style, same primitives as client.py):

  1. Browser <-> bridge: the browser runs its own Diffie-Hellman exchange with
     this bridge (POST /api/handshake). Both sides derive an AES-256 key the
     same way crypto.py does. Every later request and response body is
     AES-256-CBC encrypted with that key.
  2. Bridge <-> server.py: the same DH + AES handshake as client.py.

The key exchange on both legs is unauthenticated, as in Phase A.
"""

import base64
import json
import secrets
import socket
import threading
import time
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse

from config import SERVER_HOST, SERVER_PORT, UI_HOST, UI_PORT
from crypto import (
    send_msg, recv_msg, encode_json, decode_json,
    create_dh_keys, calculate_shared_key, encrypt_data, decrypt_data
)

UI_DIR = Path(__file__).with_name("UI")
STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
    "/logo.svg": ("logo.svg", "image/svg+xml"),
}

POLL_WAIT_SECONDS = 20      # how long an events request waits for new events
SESSION_IDLE_SECONDS = 90   # close idle sessions and channels after this
MAX_BODY_BYTES = 64 * 1024
MAX_MESSAGE_CHARS = 2000

sessions = {}   # token -> ChatSession (connection to server.py)
sessions_lock = threading.Lock()
channels = {}   # channel id -> Channel (encrypted browser <-> bridge link)
channels_lock = threading.Lock()


# ---------- Encryption helpers (same format as crypto.py) ----------

def seal(key, payload):
    """Encrypt a JSON-able object with AES-256-CBC. Returns base64 text."""
    return base64.b64encode(encrypt_data(key, encode_json(payload))).decode("ascii")


def open_sealed(key, text):
    """Decrypt base64 text produced by seal()."""
    return decode_json(decrypt_data(key, base64.b64decode(text, validate=True)))


class Channel:
    """One encrypted browser link, created by the browser's handshake."""

    def __init__(self, key):
        self.key = key
        self.last_used = time.time()


def get_channel(channel_id):
    with channels_lock:
        channel = channels.get(channel_id)
        if channel is not None:
            channel.last_used = time.time()
        return channel


# ---------- Chat connection to server.py ----------

class ChatSession:
    """One logged-in browser tab: its TCP connection to server.py and event queue."""

    def __init__(self, token, username, sock, reader, aes_key):
        self.token = token
        self.username = username
        self.sock = sock
        self.reader = reader
        self.key = aes_key
        self.send_lock = threading.Lock()
        self.events = []
        self.event_cond = threading.Condition()
        self.users = {}
        self.connected = True
        self.last_poll = time.time()

    def push(self, event):
        with self.event_cond:
            self.events.append(event)
            self.event_cond.notify_all()

    def take_events(self, wait_seconds):
        with self.event_cond:
            if not self.events:
                self.event_cond.wait(timeout=wait_seconds)
            events, self.events = self.events, []
            return events

    def send(self, message_object):
        encrypted = encrypt_data(self.key, encode_json(message_object))
        with self.send_lock:
            send_msg(self.sock, encrypted)

    def close(self):
        self.connected = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


def open_authenticated_session(action, username, password):
    """Connect to server.py, run DH, then register or log in.

    Returns (session, None) on success or (None, message) on failure.
    """
    sock = socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=10)
    reader = sock.makefile("rb")
    try:
        private_value, client_public = create_dh_keys()
        send_msg(sock, encode_json({"dh_public": str(client_public)}))

        server_hello = recv_msg(reader)
        if server_hello is None:
            raise ConnectionError("Server closed during key exchange.")
        server_public = int(decode_json(server_hello)["dh_public"])
        aes_key = calculate_shared_key(private_value, server_public)

        send_msg(sock, encrypt_data(aes_key, encode_json({
            "action": action,
            "username": username,
            "password": password
        })))

        encrypted_response = recv_msg(reader)
        if encrypted_response is None:
            raise ConnectionError("Server closed before authentication response.")
        response = decode_json(decrypt_data(aes_key, encrypted_response))
    except Exception:
        reader.close()
        sock.close()
        raise

    if not response.get("success"):
        reader.close()
        sock.close()
        return None, response.get("message", "Authentication failed.")

    sock.settimeout(None)
    token = secrets.token_urlsafe(24)
    session = ChatSession(token, username, sock, reader, aes_key)
    with sessions_lock:
        sessions[token] = session

    threading.Thread(target=reader_loop, args=(session,), daemon=True).start()
    session.push({"type": "status", "connected": True})
    session.send({"type": "users"})
    return session, response.get("message", "")


def reader_loop(session):
    """Receive, decrypt and convert server messages into browser events."""
    try:
        while True:
            encrypted = recv_msg(session.reader)
            if encrypted is None:
                break
            message = decode_json(decrypt_data(session.key, encrypted))
            handle_server_message(session, message)
    except (OSError, ValueError, TypeError):
        pass
    finally:
        session.connected = False
        session.push({"type": "status", "connected": False})
        session.close()


def handle_server_message(session, message):
    message_type = message.get("type")

    if message_type == "chat":
        if message.get("notice"):
            return
        session.push({
            "type": "message",
            "from": message.get("from"),
            "id": message.get("id"),
            "text": message.get("message", "")
        })

    elif message_type == "ack":
        session.push({"type": "ack", "id": message.get("id")})

    elif message_type == "read":
        session.push({
            "type": "read",
            "id": message.get("id"),
            "from": message.get("from")
        })

    elif message_type == "error":
        session.push({
            "type": "error",
            "id": message.get("id"),
            "message": message.get("message", "Message not delivered.")
        })

    elif message_type == "presence":
        user = message.get("user")
        online = bool(message.get("online"))
        session.users[user] = online
        session.push({"type": "presence", "user": user, "online": online})

    elif message_type == "users":
        users = message.get("users", [])
        session.users = {item["name"]: bool(item["online"]) for item in users}
        session.push({"type": "users", "users": users})


def reap_idle():
    """Close sessions and channels whose browser tab has stopped polling."""
    while True:
        time.sleep(10)
        now = time.time()
        with sessions_lock:
            stale_sessions = [s for s in sessions.values()
                              if now - s.last_poll > SESSION_IDLE_SECONDS]
            for session in stale_sessions:
                sessions.pop(session.token, None)
        for session in stale_sessions:
            session.close()
        with channels_lock:
            for channel_id in [cid for cid, c in channels.items()
                               if now - c.last_used > SESSION_IDLE_SECONDS]:
                channels.pop(channel_id, None)


def get_session(token):
    with sessions_lock:
        return sessions.get(token)


def remove_session(token):
    with sessions_lock:
        return sessions.pop(token, None)


# ---------- HTTP handler ----------

class ChatHandler(BaseHTTPRequestHandler):
    server_version = "SecureChatUI/1.0"

    def log_message(self, format, *args):
        pass

    # ---------- low-level helpers ----------
    def _send_bytes(self, status, body, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, status, payload):
        """Plain JSON. Used only for the handshake and errors with no secrets."""
        body = json.dumps(payload).encode("utf-8")
        self._send_bytes(status, body, "application/json; charset=utf-8")

    def _send_sealed(self, key, status, payload):
        """Encrypted response: {"data": "<base64 IV||ciphertext>"}."""
        body = json.dumps({"data": seal(key, payload)}).encode("utf-8")
        self._send_bytes(status, body, "application/json; charset=utf-8")

    def _read_json_body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length > MAX_BODY_BYTES:
            raise ValueError("Request is too large.")
        raw = self.rfile.read(length) if length else b"{}"
        data = json.loads(raw.decode("utf-8") or "{}")
        if not isinstance(data, dict):
            raise ValueError("Expected a JSON object.")
        return data

    # ---------- GET: static UI files only ----------
    def do_GET(self):
        url = urlparse(self.path)
        if url.path in STATIC_FILES:
            filename, content_type = STATIC_FILES[url.path]
            try:
                body = (UI_DIR / filename).read_bytes()
            except OSError:
                return self._send_json(404, {"ok": False, "message": "UI file missing."})
            return self._send_bytes(200, body, content_type)
        self._send_json(404, {"ok": False, "message": "Not found."})

    # ---------- POST ----------
    def do_POST(self):
        url = urlparse(self.path)
        try:
            body = self._read_json_body()
        except (ValueError, json.JSONDecodeError):
            return self._send_json(400, {"ok": False, "message": "Bad request."})

        if url.path == "/api/handshake":
            return self._handle_handshake(body)

        channel = get_channel(str(body.get("channel", "")))
        if channel is None:
            return self._send_json(401, {
                "ok": False,
                "message": "Secure channel expired. Reload the page."
            })

        try:
            data = open_sealed(channel.key, str(body.get("data", "")))
        except (ValueError, TypeError):
            return self._send_sealed(channel.key, 400, {
                "ok": False,
                "message": "Bad encrypted request."
            })

        try:
            status, payload = self._route(url.path, data)
        except OSError:
            status, payload = 503, {
                "ok": False,
                "message": "Lost connection to the chat server."
            }
        self._send_sealed(channel.key, status, payload)

    def _handle_handshake(self, body):
        """Browser DH: same steps as client.py. Returns the server's DH public value."""
        try:
            client_public = int(body["dh_public"])
            private_value, server_public = create_dh_keys()
            key = calculate_shared_key(private_value, client_public)
        except (KeyError, ValueError, TypeError):
            return self._send_json(400, {"ok": False, "message": "Invalid key exchange."})

        channel_id = secrets.token_urlsafe(16)
        with channels_lock:
            channels[channel_id] = Channel(key)
        self._send_json(200, {
            "ok": True,
            "channel": channel_id,
            "dh_public": str(server_public)
        })

    def _route(self, path, data):
        """Handle one decrypted request. Returns (status, payload)."""
        if path in ("/api/login", "/api/register"):
            return self.handle_auth(path, data)

        session = get_session(str(data.get("token", "")))
        if session is None:
            return 401, {"ok": False, "message": "Your session has ended. Please log in again."}

        if path == "/api/events":
            session.last_poll = time.time()
            events = session.take_events(POLL_WAIT_SECONDS)
            return 200, {"ok": True, "connected": session.connected, "events": events}
        if path == "/api/send":
            return self.handle_send(session, data)
        if path == "/api/read":
            session.send({"type": "read", "to": str(data.get("to", "")), "id": data.get("id")})
            return 200, {"ok": True}
        if path == "/api/users":
            session.send({"type": "users"})
            return 200, {"ok": True}
        if path == "/api/logout":
            remove_session(session.token)
            session.close()
            return 200, {"ok": True}

        return 404, {"ok": False, "message": "Not found."}

    def handle_auth(self, path, data):
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))

        if not username or not password:
            return 400, {"ok": False, "message": "Enter a username and password."}
        if len(username) > 32:
            return 400, {"ok": False, "message": "Username must be 32 characters or fewer."}

        action = "register" if path == "/api/register" else "login"
        try:
            session, message = open_authenticated_session(action, username, password)
        except ConnectionRefusedError:
            return 503, {"ok": False, "message": "Chat server is not running. Start server.py first."}
        except (OSError, ValueError, KeyError, TypeError, ConnectionError):
            return 503, {"ok": False, "message": "Could not complete the secure connection to the server."}

        if session is None:
            return 200, {"ok": False, "message": message}

        return 200, {
            "ok": True,
            "token": session.token,
            "username": session.username,
            "message": message
        }

    def handle_send(self, session, data):
        if not session.connected:
            return 409, {"ok": False, "message": "Not connected to the chat server."}

        target = str(data.get("to", "")).strip()
        text = str(data.get("text", ""))
        if not target or not text.strip():
            return 400, {"ok": False, "message": "Empty message."}
        if len(text) > MAX_MESSAGE_CHARS:
            return 400, {"ok": False, "message": f"Message is longer than {MAX_MESSAGE_CHARS} characters."}

        session.send({"type": "chat", "to": target, "id": data.get("id"), "message": text})
        return 200, {"ok": True}


def main():
    threading.Thread(target=reap_idle, daemon=True).start()

    httpd = ThreadingHTTPServer((UI_HOST, UI_PORT), ChatHandler)
    print("\n========== Secure Chat Web Client ==========\n")
    print(f"Open this link in your browser: http://{UI_HOST}:{UI_PORT}")
    print("Make sure server.py is running. Press Ctrl+C to stop.\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nWeb client stopped.")
    finally:
        httpd.server_close()


if __name__ == "__main__":
    main()
