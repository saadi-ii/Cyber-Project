import socket
import threading

from config import SERVER_PORT
from crypto import (
    send_msg, recv_msg, encode_json, decode_json,
    create_dh_keys, calculate_shared_key, encrypt_data, decrypt_data
)
from authentication import register_user, login_user

clients = {}  # username -> connection information
clients_lock = threading.Lock()


def send_secure(client_info, message_object):
    """Encrypt and send a JSON message using this client's AES key."""
    encrypted = encrypt_data(
        client_info["key"],
        encode_json(message_object)
    )
    with client_info["send_lock"]:
        send_msg(client_info["socket"], encrypted)


def broadcast(sender_name, message):
    """Send a chat message to every other logged-in client."""
    with clients_lock:
        recipients = list(clients.items())

    for username, client_info in recipients:
        if username == sender_name:
            continue
        try:
            send_secure(client_info, {
                "type": "chat",
                "from": sender_name,
                "message": message
            })
        except (OSError, ValueError):
            print("Could not send a message to", username)


def handle_client(client_socket, client_address):
    reader = client_socket.makefile("rb")
    username = None
    client_info = None

    try:
        # ---- Diffie-Hellman key exchange ----
        client_hello = recv_msg(reader)
        if client_hello is None:
            return

        hello_data = decode_json(client_hello)
        client_public = int(hello_data["dh_public"])

        private_value, server_public = create_dh_keys()
        send_msg(client_socket, encode_json({"dh_public": str(server_public)}))

        aes_key = calculate_shared_key(private_value, client_public)

        # ---- Registration/login data is encrypted after DH ----
        encrypted_auth = recv_msg(reader)
        if encrypted_auth is None:
            return

        auth_data = decode_json(decrypt_data(aes_key, encrypted_auth))
        action = auth_data.get("action")
        requested_username = auth_data.get("username", "")
        password = auth_data.get("password", "")

        if action == "register":
            success, result_message = register_user(requested_username, password)
        elif action == "login":
            success, result_message = login_user(requested_username, password)
        else:
            success, result_message = False, "Unknown authentication action."

        if success:
            with clients_lock:
                if requested_username in clients:
                    success = False
                    result_message = "This user is already logged in."

        if not success:
            response = encrypt_data(
                aes_key,
                encode_json({"type": "auth", "success": False, "message": result_message})
            )
            send_msg(client_socket, response)
            return

        username = requested_username
        client_info = {
            "socket": client_socket,
            "key": aes_key,
            "send_lock": threading.Lock()
        }

        with clients_lock:
            clients[username] = client_info

        response = encrypt_data(
            aes_key,
            encode_json({"type": "auth", "success": True, "message": result_message})
        )
        send_msg(client_socket, response)
        print(f"{username} logged in from {client_address}")

        broadcast(username, f"{username} joined the chat.")

        # ---- Encrypted chat loop ----
        while True:
            encrypted_data = recv_msg(reader)
            if encrypted_data is None:
                break

            message_data = decode_json(decrypt_data(aes_key, encrypted_data))
            if message_data.get("type") != "chat":
                continue

            message = str(message_data.get("message", ""))

            if message.lower() == "bye":
                send_secure(client_info, {
                    "type": "system",
                    "message": "You disconnected from the chat."
                })
                break

            print(f"{username}: {message}")
            broadcast(username, message)

    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Connection error with {client_address}: {error}")
    finally:
        if username is not None:
            with clients_lock:
                clients.pop(username, None)
            broadcast(username, f"{username} left the chat.")
            print(username, "disconnected.")

        try:
            reader.close()
        except OSError:
            pass
        client_socket.close()


def main():
    print("\n========== Secure Chat Server (Phase A) ==========\n")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind(("", SERVER_PORT))
    server_socket.listen(5)

    print(f"Server listening on port {SERVER_PORT}. Waiting for clients...")

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            print("Connection received:", client_address)

            thread = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address),
                daemon=True
            )
            thread.start()

    except KeyboardInterrupt:
        print("\nServer shutting down.")
    finally:
        server_socket.close()


if __name__ == "__main__":
    main()
