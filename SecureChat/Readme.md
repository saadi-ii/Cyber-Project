# Secure Chat — Baseline Version

## 1. Overview

Secure Chat is a client-server chat application written in Python. Users register and log in, then chat through a central server. Every connection is protected with Diffie-Hellman key exchange and AES encryption, and passwords are stored as salted hashes.

This is the baseline version of the project. It is fully working, and it is kept deliberately simple so that its design choices and weaknesses are easy to understand and test. It is not intended for real-world use.

## 2. Project Goals

- **Key exchange:** Diffie-Hellman (DH) establishes a shared secret between each client and the server.
- **Confidentiality:** AES encryption protects all credential and message traffic.
- **Password storage:** passwords are salted and hashed. Credentials are stored in a file, never in plaintext.
- **Documented design:** every algorithm and parameter is chosen and justified.

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
| Mode | CBC (Cipher Block Chaining) | Simple and widely supported. It provides confidentiality only and does not check integrity. |
| IV | Random 16-byte IV for each message, sent in front of the ciphertext | Stops identical messages from producing identical ciphertext. |
| Padding | PKCS#7 | Fills the last block to the full block size. |
| Key derivation | SHA-256 of the shared secret, first 32 bytes | Simple to explain. It is not a dedicated key-derivation function, which is a known limitation. |
| Password hashing | SHA-256 of (salt + password) | Demonstrates the salting principle. SHA-256 is fast, which makes it weak for passwords. |
| Salt | Random 16 bytes per user, from `secrets` | Stops two users with the same password from getting the same hash. |

## 5. What Is Encrypted

- **Terminal client:** registration and login details are encrypted after the DH exchange. Chat messages are encrypted too. The server decrypts each message and re-encrypts it for the receiver.
- **Web client:** the browser runs its own DH exchange with `client_ui.py`. Every request and response after that is AES encrypted.
- **Not encrypted:** the DH public values, which are meant to be public. The size and timing of messages are also visible.

## 6. Known Limitations

- **Unauthenticated key exchange:** the DH exchange does not verify the identity of either party, so a man-in-the-middle attack is possible.
- **No message integrity:** AES-CBC without a message authentication code (HMAC) does not detect if ciphertext is changed in transit.
- **Fast password hashing:** SHA-256 is quick to compute, which makes password guessing easier. A dedicated password hash such as Argon2, bcrypt or PBKDF2 would be stronger.
- **Basic key derivation:** a plain SHA-256 of the shared secret is used. A proper key-derivation function such as HKDF would be stronger.
- **Server can read messages:** the server decrypts chat messages in order to forward them.

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

Use `127.0.0.1` or `localhost` for the web page. Browsers only allow the browser encryption on those addresses.
