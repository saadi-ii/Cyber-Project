# Secure Chat: Hardened Version

## 1. Overview

Secure Chat is a client-server chat application written in Python. Users register, log in, and send private messages through a central server. Terminal and browser clients are both supported.

This is the hardened version. It fixes the main weaknesses of the baseline version: the key exchange was not authenticated, the password hash was too fast, messages had no integrity check, and the key derivation was basic. It is still a learning project and is not meant for production use.

## 2. What Changed From the Baseline

| Area | Baseline | Hardened |
|---|---|---|
| Diffie-Hellman group | RFC 3526 group 14 (2048-bit) | RFC 7919 ffdhe3072 (3072-bit safe prime) |
| Public value checks | Range check only | Range check and subgroup check (`value^q = 1`) |
| Authentication of the key exchange | None | RSA-PSS (3072-bit, SHA-256) signature over both DH values |
| Key derivation | SHA-256 of the shared secret | HKDF-SHA256, salted with the transcript hash |
| Message encryption | AES-256-CBC | AES-256-GCM (encryption and integrity) |
| Password storage | Salted SHA-256 | Argon2id (memory-hard, salt built in) |
| Old accounts | Not applicable | Still log in, and are upgraded to Argon2id on their next login |
| Browser key check | None | The page verifies the bridge's signature with a pinned public key |

## 3. Project Files

| File | Purpose |
|---|---|
| `server.py` | Accepts clients, runs the signed key exchange, and forwards messages. |
| `client.py` | Terminal chat client. Checks the server's signature before login. |
| `client_ui.py` | Web bridge. Serves the web page and talks to the server. |
| `UI/` | Web page files: `index.html`, `app.js`, `style.css`, `logo.svg`, and `ui_public_key.js` (created by `gen_keys.py`). |
| `crypto.py` | Diffie-Hellman, HKDF, AES-GCM, and RSA-PSS signatures. |
| `authentication.py` | Registration, Argon2id hashing, and login checks. |
| `config.py` | Addresses, DH group, key file paths, and Argon2 settings. |
| `gen_keys.py` | Creates the RSA key pairs and writes the browser's pinned key. |
| `keys/` | RSA keys (created by `gen_keys.py`, never shared except the public keys). |
| `credentials.txt` | Usernames with Argon2id hashes. |
| `tests/test_hardened.py` | Automated unit and integration tests. |
| `tests/browser_check.py` | Optional browser test with Playwright. |
| `tools/mitm_lab.py` | Lab proxy for the man-in-the-middle test. Use only in your own lab. |
| `requirements.txt` | Python libraries. |

## 4. Design Choices

| Component | Choice | Reason |
|---|---|---|
| Key exchange | Diffie-Hellman, RFC 7919 ffdhe3072 | 3072 bits is the NIST recommended size for use beyond 2030. A safe prime makes the subgroup check simple. |
| Signature | RSA-PSS, 3072-bit key, SHA-256 | PSS is the modern RSA padding. The signature covers both DH values, so it cannot be replayed into another session. |
| Public value check | Range check plus `value^q mod p = 1` | Rejects weak values that could leak the shared secret. |
| Key derivation | HKDF-SHA256 with transcript salt and a fixed context label | Designed for turning a shared secret into keys. The label keeps the key tied to this protocol. |
| Cipher | AES-256-GCM | Authenticated encryption. Any change to a message makes decryption fail. |
| Nonce | Random 12 bytes per message | Standard size for GCM. Collisions are very unlikely at this scale. |
| Password hash | Argon2id, time cost 3, memory 64 MiB, parallelism 2 | Memory-hard and salted. Slows down offline guessing. |

## 5. What Is Protected

- **Key exchange:** the server's DH value is signed. A client refuses any connection where the signature does not match the server's public key.
- **Login and messages:** every message after the handshake is AES-256-GCM encrypted and checked.
- **Browser link:** the page checks the bridge's signature against the pinned key in `UI/ui_public_key.js`.
- **Passwords:** stored only as Argon2id hashes.

## 6. Known Limitations

- **Trust in the public keys:** the client must receive `server_public.pem` through a trusted channel. This is the same trust model as SSH known hosts, but it is set up by hand.
- **Server reads messages:** the server decrypts each message to forward it. This is not end-to-end encryption.
- **No replay or session tokens:** GCM protects each message, but there is no per-message counter or session key rotation.
- **Single signing key:** if the server's private key is stolen, an attacker can impersonate the server. Keep `keys/*_private.pem` private.
- **Legacy accounts:** accounts from the baseline use the older SHA-256 format until they log in again.
- **Browser runs on localhost:** the page must be opened at `127.0.0.1` or `localhost`, because browsers only provide the crypto APIs on those addresses.

## 7. How to Run

Tested with Python 3.13 on Linux.

### Step 1: Install the libraries

```
pip install -r requirements.txt
```

### Step 2: Create the keys (once)

```
python gen_keys.py
```

This creates `keys/server_private.pem`, `keys/server_public.pem`, `keys/ui_private.pem`, `keys/ui_public.pem`, and `UI/ui_public_key.js`.

### Step 3: Start the server

In terminal 1:

```
python server.py
```

### Step 4a: Terminal chat

The client needs `server_public.pem`. If the client runs on another machine, copy that file into the client's folder.

In terminal 2:

```
python client.py
```

Choose `1` to register or `2` to log in. Type `bye` to leave.

### Step 4b: Web chat

In terminal 2:

```
python client_ui.py
```

Open `http://127.0.0.1:8000` in a browser.

Press `Ctrl+C` to stop any program.

## 8. How to Test

### Automated tests (no browser needed)

```
python -m unittest tests.test_hardened -v
```

This runs 11 tests. They cover:

- the signed key exchange and the shared key match on both sides,
- a tampered DH value is rejected,
- a signature from another key is rejected,
- out-of-range and out-of-subgroup values are rejected,
- AES-GCM detects a changed byte,
- Argon2id registration and login work,
- old SHA-256 accounts log in and are upgraded,
- a real server accepts registration, login, and a private message,
- a wrong password is rejected,
- a man-in-the-middle proxy that swaps the server's DH value is refused.

### Browser test (optional)

```
pip install playwright
playwright install chromium
python tests/browser_check.py .
```

This registers two users in two browser sessions, sends a message, and checks that it arrives. It also starts a bridge with the wrong pinned key and checks that the page refuses to connect.

### Manual check with Wireshark

1. Start Wireshark on the loopback interface (`lo`).
2. Use the filter `tcp.port == 8080`.
3. Log in with a terminal client.
4. Follow the TCP stream. Each message is a Base64 line. Decoding the handshake lines shows the DH values and the signature. Decoding the later lines gives only encrypted bytes, not the chat text.

## 9. Lab: Man-in-the-Middle Test

Run this only in an isolated lab, on machines you own. The proxy logic was tested on loopback in this project. The ARP steps below must be run on your own VMs.

1. Start the server on machine A.
2. Start the lab proxy on machine B (the attacker). Use the project folder of the build under test:

   ```
   python tools/mitm_lab.py --project /path/to/project --mode hardened --listen-port 8091 --log capture.jsonl
   ```

   Use `--mode baseline` for the baseline build.

3. Send the client's traffic to the proxy. For example, on machine B:

   ```
   sudo sysctl -w net.ipv4.ip_forward=1
   sudo iptables -t nat -A PREROUTING -p tcp --dport 8080 -j REDIRECT --to-port 8091
   ```

4. Poison the ARP tables between the client and the server (for example with `arpspoof` from `dsniff`). Run one command in each direction:

   ```
   sudo arpspoof -i eth0 -t <client_ip> <server_ip>
   sudo arpspoof -i eth0 -t <server_ip> <client_ip>
   ```

5. Log in from the client. With the hardened build, the client shows "Handshake signature check failed" and no password reaches `capture.jsonl`. With the baseline build, the password and messages appear in the capture.

## 10. Configuration

Change the values in `config.py` if needed:

- `SERVER_HOST` and `SERVER_PORT`: where the server listens.
- `UI_HOST` and `UI_PORT`: where the web page is served.
- `ARGON2_TIME_COST`, `ARGON2_MEMORY_KIB`, `ARGON2_PARALLELISM`: password hashing cost. Higher values are slower to crack and slower to log in.

If you change the key file paths or regenerate the keys, run `gen_keys.py` again and copy the new `server_public.pem` to every client.
