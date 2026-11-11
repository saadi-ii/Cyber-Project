# Secure Chat — Phase A (Baseline)

## 1. Overview

Secure Chat is a client-server chat application written in Python. Users register and log in, then chat through a central server. This is the Phase A baseline: it is working and encrypted, but it is not meant for real use. Phases B and D will test its weak points.

## 2. Phase A Requirements

- **Key exchange:** Diffie-Hellman (DH) between each client and the server.
- **Confidentiality:** AES encryption for all credential and message traffic.
- **Password storage:** salted hashing, with credentials kept in a file and never in plaintext.
- **Design rationale:** the parameters and algorithms are chosen and justified by the team.

## 3. Project Files

| File | Purpose |
|---|---|
| `server.py` | Starts the server, accepts clients, runs the key exchange and forwards messages. |
| `client.py` | Terminal chat client. Handles registration, login and messaging. |
| `client_ui.py` | Web chat bridge. Serves the web page and talks to the server. |
| `UI/` | Web page files: `index.html`, `style.css`, `app.js` and `logo.svg`. |
| `crypto.py` | Diffie-Hellman, AES encryption and decryption, and key derivation. |
| `authentication.py` | Registration, salted password hashing and login checks. |
| `config.py` | Server address, port, DH values and AES key size. |
| `credentials.txt` | Stores each username with its salt and password hash. |
| `requirements.txt` | Python library needed (`pycryptodome`). |

## 4. Design Choices

| Component | Choice | Reason |
|---|---|---|
| Key exchange | Diffie-Hellman, 2048-bit group (RFC 3526 group 14), generator 2 | Gives both sides the same secret without sending it. 2048 bits is a common safe size for this group. |
| Private values | Random, chosen from the full valid range | A fresh value is made for every connection. |
| Symmetric cipher | AES | A standard, fast block cipher for large amounts of data. |
| Key size | AES-256 (32-byte key) | Largest standard AES key size, with a good safety margin. |
| Mode | CBC (Cipher Block Chaining) | Simple and widely supported. It gives confidentiality only; it does not check integrity. |
| IV | Random 16-byte IV for each message, sent in front of the ciphertext | Stops identical messages from producing identical ciphertext. |
| Padding | PKCS#7 | Fills the last block to the full block size. |
| Key derivation | SHA-256 of the shared secret, first 32 bytes | Simple to explain. It is not a proper key-derivation function, which is intentional for this baseline. |
| Password hashing | SHA-256 of (salt + password) | Shows the salt idea. SHA-256 is fast, which makes it weak for passwords. |
| Salt | Random 16 bytes per user, from `secrets` | Stops two users with the same password from getting the same hash. |

## 5. What Is Encrypted

- **Terminal client:** the registration and login details are encrypted after the DH exchange. Chat messages are encrypted too. The server decrypts each message and re-encrypts it for the receiver.
- **Web client:** the browser runs its own DH exchange with `client_ui.py`. Every request and response after that is AES encrypted.
- **Not encrypted:** the DH public values, which are meant to be public. The message size and timing are also visible.

## 6. Known Limitations (Phases B and D)

- The DH exchange is **not authenticated**, so a man-in-the-middle attack is possible. This is the main Phase D test.
- AES-CBC has **no integrity check (no HMAC)**, so ciphertext can be changed without detection. This is a Phase B finding.
- Passwords use a **fast hash** (SHA-256), which makes guessing easier. Phase D will replace it.
- The key derivation is **weak** (a plain SHA-256). Phase D will replace it with a proper key-derivation function.
- The server **can read chat messages**, since it decrypts them to forward them.

## 7. How to Run

1. Install the library:
   ```
   pip install -r requirements.txt
   ```
2. Start the server in one terminal:
   ```
   python server.py
   ```
3. For the terminal chat, open a second terminal and run:
   ```
   python client.py
   ```
   Choose `1` to register or `2` to log in. Type `bye` to leave.
4. For the web chat, open another terminal and run:
   ```
   python client_ui.py
   ```
   Then open `http://127.0.0.1:8000` in a browser.

Stop any program with `Ctrl+C`.

## 8. Configuration

Change the values in `config.py` if needed:

- `SERVER_HOST` and `SERVER_PORT`: where the server listens.
- `UI_HOST` and `UI_PORT`: where the web page is served.

Use `127.0.0.1` or `localhost` for the web page. Browsers only allow the browser encryption on those addresses.Do not submit this file as README. After testing the project, create README.md with the final installation, run, and test instructions.
