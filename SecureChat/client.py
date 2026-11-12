import socket
import threading
import getpass

from config import SERVER_HOST, SERVER_PORT
from crypto import (
    send_msg, recv_msg, encode_json, decode_json,
    create_dh_keys, calculate_shared_key, encrypt_data, decrypt_data
)


def receive_messages(reader, aes_key, stop_event):
    """Receive, decrypt and display messages from the server."""
    while not stop_event.is_set():
        try:
            encrypted_reply = recv_msg(reader)
            if encrypted_reply is None:
                print("\nServer closed the connection.")
                stop_event.set()
                break

            reply = decode_json(decrypt_data(aes_key, encrypted_reply))
            message_type = reply.get("type")

            if message_type == "chat":
                print(f"\n{reply.get('from')}: {reply.get('message')}")
                print("You: ", end="", flush=True)
            elif message_type == "error":
                print(f"\n[Error] {reply.get('message')}")
                print("You: ", end="", flush=True)
            elif message_type == "users":
                names = [
                    f"{u['name']} ({'online' if u['online'] else 'offline'})"
                    for u in reply.get("users", [])
                ]
                print("\nUsers: " + ", ".join(names))
                print("You: ", end="", flush=True)
            elif message_type == "system":
                print("\n" + reply.get("message", ""))
                stop_event.set()
                break

        except (OSError, ValueError, TypeError) as error:
            if not stop_event.is_set():
                print("\nCould not receive message:", error)
            stop_event.set()
            break


def main():
    print("\n========== Secure Chat Client (Phase A) ==========\n")

    action = input("Choose (1) Register or (2) Login: ").strip()
    if action not in ("1", "2"):
        print("Please choose 1 or 2.")
        return

    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    reader = None
    stop_event = threading.Event()

    try:
        sock.connect((SERVER_HOST, SERVER_PORT))
        reader = sock.makefile("rb")
        print("Connected to server.")

        # ---- Diffie-Hellman key exchange ----
        private_value, client_public = create_dh_keys()
        send_msg(sock, encode_json({"dh_public": str(client_public)}))

        server_hello = recv_msg(reader)
        if server_hello is None:
            print("Server closed during key exchange.")
            return

        server_public = int(decode_json(server_hello)["dh_public"])
        aes_key = calculate_shared_key(private_value, server_public)
        print("Diffie-Hellman key exchange completed.")

        # ---- Send credentials inside AES-encrypted data ----
        auth_action = "register" if action == "1" else "login"
        auth_data = {
            "action": auth_action,
            "username": username,
            "password": password
        }
        encrypted_auth = encrypt_data(aes_key, encode_json(auth_data))
        send_msg(sock, encrypted_auth)

        encrypted_response = recv_msg(reader)
        if encrypted_response is None:
            print("Server closed before authentication response.")
            return

        response = decode_json(decrypt_data(aes_key, encrypted_response))
        print(response.get("message", "No response from server."))

        if not response.get("success"):
            return

        print("\nChat started.")
        print("Commands: /users = list users, /to <name> = choose recipient,")
        print("          bye = leave the chat.\n")
        recipient = input("Send messages to (username): ").strip()
        message_id = 0

        receiver = threading.Thread(
            target=receive_messages,
            args=(reader, aes_key, stop_event),
            daemon=True
        )
        receiver.start()

        while not stop_event.is_set():
            try:
                message = input("You: ")
            except (EOFError, KeyboardInterrupt):
                message = "bye"

            if message.strip() == "/users":
                payload = {"type": "users"}
            elif message.startswith("/to "):
                recipient = message[4:].strip()
                print(f"Now messaging: {recipient}")
                continue
            elif not message.strip():
                continue
            else:
                message_id += 1
                payload = {
                    "type": "chat",
                    "to": recipient,
                    "id": message_id,
                    "message": message
                }

            send_msg(sock, encrypt_data(aes_key, encode_json(payload)))

            if message.lower() == "bye":
                stop_event.set()
                break

    except ConnectionRefusedError:
        print("Could not connect. Start server.py first.")
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("Client error:", error)
    finally:
        stop_event.set()
        if reader is not None:
            try:
                reader.close()
            except OSError:
                pass
        sock.close()
        print("Client closed.")


if __name__ == "__main__":
    main()
