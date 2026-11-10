
import socket
import threading

from config import SERVER_PORT
from crypto import (
    send_msg, recv_msg, encode_json, decode_json,
    create_dh_keys, calculate_shared_key, encrypt_data, decrypt_data
)
from authentication import register_user, login_user, list_usernames

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


def send_to_others(sender_name, payload):
    """Send a payload to every logged-in client except the sender."""
    with clients_lock:
        recipients = list(clients.items())

    for username, client_info in recipients:
        if username == sender_name:
            continue

        try:
            send_secure(client_info, payload)
        except (OSError, ValueError):
            print("Could not send an update to", username)


def send_to_user(username, payload):
    """Send a payload to one user. Return False if offline."""
    with clients_lock:
        client_info = clients.get(username)

    if client_info is None:
        return False

    try:
        send_secure(client_info, payload)
        return True
    except (OSError, ValueError):
        return False


def broadcast_presence(username, online):
    """Tell other clients when a user comes online or goes offline."""
    send_to_others(username, {
        "type": "presence",
        "user": username,
        "online": online
    })


def build_user_list():
    """Return all registered users with their online status."""
    with clients_lock:
        online_names = set(clients.keys())

    return [
        {"name": name, "online": name in online_names}
        for name in list_usernames()
    ]


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

        send_msg(
            client_socket,
            encode_json({"dh_public": str(server_public)})
        )

        aes_key = calculate_shared_key(private_value, client_public)

        # ---- Encrypted registration/login ----
        encrypted_auth = recv_msg(reader)

        if encrypted_auth is None:
            return

        auth_data = decode_json(decrypt_data(aes_key, encrypted_auth))

        action = auth_data.get("action")
        requested_username = auth_data.get("username", "")
        password = auth_data.get("password", "")

        if action == "register":
            success, result_message = register_user(
                requested_username, password
            )
        elif action == "login":
            success, result_message = login_user(
                requested_username, password
            )
        else:
            success = False
            result_message = "Unknown authentication action."

        if success:
            with clients_lock:
                if requested_username in clients:
                    success = False
                    result_message = "This user is already logged in."

        if not success:
            response = encrypt_data(
                aes_key,
                encode_json({
                    "type": "auth",
                    "success": False,
                    "message": result_message
                })
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
            encode_json({
                "type": "auth",
                "success": True,
                "message": result_message
            })
        )

        send_msg(client_socket, response)

        print(f"{username} logged in from {client_address}")

        broadcast_presence(username, True)

        # ---- Encrypted private chat loop ----
        while True:
            encrypted_data = recv_msg(reader)

            if encrypted_data is None:
                break

            message_data = decode_json(
                decrypt_data(aes_key, encrypted_data)
            )

            message_type = message_data.get("type")

            # Send registered users and their online status
            if message_type == "users":
                send_secure(client_info, {
                    "type": "users",
                    "users": build_user_list()
                })
                continue

            # Forward read receipt to original sender
            if message_type == "read":
                target = str(message_data.get("to", ""))

                send_to_user(target, {
                    "type": "read",
                    "id": message_data.get("id"),
                    "from": username
                })
                continue

            if message_type != "chat":
                continue

            message = str(message_data.get("message", ""))
            target = message_data.get("to")
            message_id = message_data.get("id")

            # Allow terminal client to disconnect using bye
            if message.lower() == "bye":
                send_secure(client_info, {
                    "type": "system",
                    "message": "You disconnected from the chat."
                })
                break

            # Only private messages are allowed
            if not target:
                send_secure(client_info, {
                    "type": "error",
                    "id": message_id,
                    "message": "Please select a recipient for your message."
                })
                continue

            # Forward the private message only to its recipient
            delivered = send_to_user(str(target), {
                "type": "chat",
                "from": username,
                "to": target,
                "id": message_id,
                "message": message
            })

            # Send delivery acknowledgement to sender
            if message_id is not None:
                if delivered:
                    send_secure(client_info, {
                        "type": "ack",
                        "id": message_id
                    })
                else:
                    send_secure(client_info, {
                        "type": "error",
                        "id": message_id,
                        "message": f"{target} is offline."
                    })

    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Connection error with {client_address}: {error}")

    finally:
        if username is not None:
            with clients_lock:
                clients.pop(username, None)

            broadcast_presence(username, False)

            print(username, "disconnected.")

        try:
            reader.close()
        except OSError:
            pass

        client_socket.close()


def main():
    print("\n========== Secure Chat Server ==========\n")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

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
