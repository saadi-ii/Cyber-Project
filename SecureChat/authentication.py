import hashlib
import json
import secrets
import threading
from pathlib import Path

CREDENTIAL_FILE = Path(__file__).with_name("credentials.txt")
_file_lock = threading.Lock()


def _load_users():
    if not CREDENTIAL_FILE.exists():
        return {}
    content = CREDENTIAL_FILE.read_text(encoding="utf-8").strip()
    if not content:
        return {}
    return json.loads(content)


def _save_users(users):
    CREDENTIAL_FILE.write_text(
        json.dumps(users, indent=4),
        encoding="utf-8"
    )


def list_usernames():
    """Return every registered username (used by the web chat user list)."""
    with _file_lock:
        return sorted(_load_users().keys())


def _password_hash(password, salt):
    # Intentionally fast salted SHA-256 for the Phase A baseline only.
    return hashlib.sha256(salt + password.encode("utf-8")).hexdigest()


def register_user(username, password):
    username = username.strip()

    if not username or not password:
        return False, "Username and password cannot be empty."

    with _file_lock:
        users = _load_users()

        if username in users:
            return False, "That username is already registered."

        salt = secrets.token_bytes(16)
        password_hash = _password_hash(password, salt)

        users[username] = {
            "salt": salt.hex(),
            "password_hash": password_hash
        }
        _save_users(users)

    return True, "Registration successful. You can now log in."


def login_user(username, password):
    with _file_lock:
        users = _load_users()
        user = users.get(username)

        if user is None:
            return False, "Invalid username or password."

        salt = bytes.fromhex(user["salt"])
        expected_hash = user["password_hash"]
        actual_hash = _password_hash(password, salt)

        if secrets.compare_digest(actual_hash, expected_hash):
            return True, "Login successful."

    return False, "Invalid username or password."
