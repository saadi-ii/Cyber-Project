import hashlib
import json
import secrets
import threading
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from config import ARGON2_TIME_COST, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM

CREDENTIAL_FILE = Path(__file__).with_name("credentials.txt")
_file_lock = threading.Lock()

# Argon2id: memory-hard and salted automatically. The salt is stored inside
# the returned hash string, so the credential file needs no separate salt.
_hasher = PasswordHasher(
    time_cost=ARGON2_TIME_COST,
    memory_cost=ARGON2_MEMORY_KIB,
    parallelism=ARGON2_PARALLELISM,
)


def _load_users():
    if not CREDENTIAL_FILE.exists():
        return {}
    content = CREDENTIAL_FILE.read_text(encoding="utf-8").strip()
    if not content:
        return {}
    return json.loads(content)


def _save_users(users):
    CREDENTIAL_FILE.write_text(json.dumps(users, indent=4), encoding="utf-8")


def list_usernames():
    """Return every registered username (used by the web chat user list)."""
    with _file_lock:
        return sorted(_load_users().keys())


def _check_legacy(entry, password):
    """Check a baseline record: salted SHA-256 with salt and password_hash fields."""
    salt = bytes.fromhex(entry["salt"])
    digest = hashlib.sha256(salt + password.encode("utf-8")).hexdigest()
    return secrets.compare_digest(digest, entry["password_hash"])


def _check_password(entry, password):
    if "hash" in entry:
        try:
            return _hasher.verify(entry["hash"], password)
        except VerifyMismatchError:
            return False
    return _check_legacy(entry, password)


def register_user(username, password):
    username = username.strip()

    if not username or not password:
        return False, "Username and password cannot be empty."

    with _file_lock:
        users = _load_users()

        if username in users:
            return False, "That username is already registered."

        users[username] = {"hash": _hasher.hash(password)}
        _save_users(users)

    return True, "Registration successful. You can now log in."


def login_user(username, password):
    with _file_lock:
        users = _load_users()
        entry = users.get(username)

        if entry is None or not _check_password(entry, password):
            return False, "Invalid username or password."

        # Upgrade a baseline (SHA-256) record to Argon2id after a successful login.
        if "hash" not in entry:
            users[username] = {"hash": _hasher.hash(password)}
            _save_users(users)

    return True, "Login successful."
