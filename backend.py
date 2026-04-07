import sys
import socket
import threading
import datetime
import queue
import msvcrt
import base64
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


class InputError(Exception):
    pass


outgoing_messages_queue = queue.Queue()

database = {}
database_lock = threading.Lock()

client_status_table = {}
client_table_lock = threading.Lock()

msg_id_counter = 0
msg_counter_lock = threading.Lock()


def safe_close(sock):
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def safe_send(sock, data):
    if sock is None:
        return False
    try:
        sock.sendall(data)
        return True
    except (ConnectionResetError, BrokenPipeError, OSError):
        return False


def safe_send_text(sock, message):
    return safe_send(sock, (message + "\n").encode("utf-8"))


def recv_text(sock, shutdown, timeout=1.0):
    """Receive one text message while periodically checking shutdown."""
    old_timeout = sock.gettimeout()
    sock.settimeout(timeout)
    try:
        while not shutdown.is_set():
            try:
                data = sock.recv(1024)
                if not data:
                    raise ConnectionError("client disconnected")
                return data.decode("utf-8").strip()
            except socket.timeout:
                continue
        raise ConnectionError("server shutting down")
    finally:
        sock.settimeout(old_timeout)


def mark_client_offline(username, sock=None):
    with client_table_lock:
        if username in client_status_table:
            current_sock = client_status_table[username].get("socket")
            if sock is None or current_sock is sock:
                client_status_table[username]["online"] = False
                client_status_table[username]["socket"] = None
    if sock is not None:
        safe_close(sock)


def close_all_clients():
    sockets_to_close = []
    with client_table_lock:
        for _, info in client_status_table.items():
            sock = info.get("socket")
            info["online"] = False
            info["socket"] = None
            if sock is not None:
                sockets_to_close.append(sock)
    for sock in sockets_to_close:
        safe_close(sock)


def next_message_id():
    global msg_id_counter
    with msg_counter_lock:
        msg_id_counter += 1
        return msg_id_counter


KEYS_DIR = Path(__file__).resolve().parent / "client_keys"
KEYS_DIR.mkdir(exist_ok=True)

PUBLIC_KEY_REQUEST_PREFIX = "__PUBLIC_KEY__|"
NO_PUBLIC_KEY_PREFIX = "__NO_PUBLIC_KEY__|"
ENCRYPTED_MESSAGE_PREFIX = "__ENCRYPTED_MESSAGE__|"
SEND_PUBLIC_KEY_PROMPT = "__SEND_PUBLIC_KEY__"


def key_paths_for_username(username):
    safe_username = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in username)
    return (
        KEYS_DIR / f"{safe_username}_private.pem",
        KEYS_DIR / f"{safe_username}_public.pem",
    )


def load_or_create_user_keys(username):
    private_path, public_path = key_paths_for_username(username)

    if private_path.exists() and public_path.exists():
        private_key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
        public_key = serialization.load_pem_public_key(public_path.read_bytes())
        return private_key, public_key

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path.write_bytes(private_pem)
    public_path.write_bytes(public_pem)

    return private_key, public_key


def public_key_to_b64(public_key):
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(pem).decode("utf-8")


def public_key_from_b64(public_key_b64):
    pem = base64.b64decode(public_key_b64.encode("utf-8"))
    return serialization.load_pem_public_key(pem)


def encrypt_for_recipient(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return base64.b64encode(ciphertext).decode("utf-8")


def decrypt_for_self(private_key, ciphertext_b64):
    ciphertext = base64.b64decode(ciphertext_b64.encode("utf-8"))
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return plaintext.decode("utf-8")


def clear_current_console_line():
    print("\r" + " " * 180, end="", flush=True)
    print("\r", end="", flush=True)


def render_client_prompt(current_buffer):
    clear_current_console_line()
    print("client >> " + current_buffer, end="", flush=True)



def new_client(shutdown, client_socket, client_name_string, client_address):
    print(f"new_client started for {client_name_string} from {client_address}")

    client_socket.settimeout(1.0)

    try:
        instructions = "Please send messages in this format: receiver_username, text_message"
        if not safe_send_text(client_socket, instructions):
            raise ConnectionError("failed to send instructions")

        while not shutdown.is_set():
            try:
                new_message_enc = client_socket.recv(1024)

                if not new_message_enc:
                    raise ConnectionError("client disconnected")

                new_message = new_message_enc.decode("utf-8").strip()

                if not new_message:
                    continue

                if new_message.lower() == "close":
                    safe_send_text(client_socket, "connection closing")
                    break

                if new_message.startswith("GETKEY|"):
                    requested_username = new_message.split("|", 1)[1].strip()
                    with client_table_lock:
                        user_info = client_status_table.get(requested_username)

                    if user_info and user_info.get("public_key"):
                        response = PUBLIC_KEY_REQUEST_PREFIX + requested_username + "|" + user_info["public_key"]
                    else:
                        response = NO_PUBLIC_KEY_PREFIX + requested_username

                    if not safe_send_text(client_socket, response):
                        raise ConnectionError("client disconnected while sending public key response")
                    continue

                if new_message.startswith("SEND|"):
                    parts = new_message.split("|", 2)
                    if len(parts) != 3:
                        out_msg = "wrong encrypted message format."
                        if not safe_send_text(client_socket, out_msg):
                            raise ConnectionError("client disconnected while sending format error")
                        continue

                    _, receiver_username, encrypted_payload = parts
                    receiver_username = receiver_username.strip()
                    encrypted_payload = encrypted_payload.strip()
                    time_sent = datetime.datetime.now()

                    with client_table_lock:
                        receiver_exists = receiver_username in client_status_table
                        receiver_status = False
                        if receiver_exists:
                            receiver_status = client_status_table[receiver_username]["online"]
                            out_msg = "message received in server. receiver exists"
                        else:
                            out_msg = "receiver does not exist."

                    if not safe_send_text(client_socket, out_msg):
                        raise ConnectionError("client disconnected while sending server ack")

                    if receiver_exists and not receiver_status:
                        out_msg = "receiver offline. not delivered."
                        if not safe_send_text(client_socket, out_msg):
                            raise ConnectionError("client disconnected while sending offline notice")

                    if receiver_exists:
                        current_msg_id = next_message_id()

                        with database_lock:
                            database[receiver_username].append({
                                "message_id": current_msg_id,
                                "message": encrypted_payload,
                                "delivered": False,
                                "time_sent": time_sent,
                                "time_delivered": None,
                                "sender_username": client_name_string,
                                "encrypted": True,
                            })

                        if receiver_status:
                            outgoing_messages_queue.put({
                                "message_id": current_msg_id,
                                "message": encrypted_payload,
                                "sender_username": client_name_string,
                                "receiver_username": receiver_username,
                                "encrypted": True,
                            })
                    continue

                out_msg = "wrong message format."
                if not safe_send_text(client_socket, out_msg):
                    raise ConnectionError("client disconnected while sending wrong-format notice")

            except socket.timeout:
                continue

    except (ConnectionError, ConnectionResetError, BrokenPipeError, OSError) as error:
        print(f"{client_name_string} disconnected: {error}")

    finally:
        mark_client_offline(client_name_string, client_socket)
        print(f"new_client terminated for {client_name_string}")


def send_outgoing_messages(shutdown):
    print("send_outgoing_messages")

    while not shutdown.is_set():
        try:
            out_message = outgoing_messages_queue.get(timeout=1.0)

            payload = (
                ENCRYPTED_MESSAGE_PREFIX
                + out_message["sender_username"]
                + "|"
                + out_message["message"]
            )
            time_delivered = datetime.datetime.now()

            confirmation = "message delivered to receiver"

            with client_table_lock:
                receiver_exists = out_message["receiver_username"] in client_status_table
                sender_exists = out_message["sender_username"] in client_status_table

                receiver_socket = None
                sender_socket = None

                if receiver_exists and client_status_table[out_message["receiver_username"]]["online"]:
                    receiver_socket = client_status_table[out_message["receiver_username"]]["socket"]

                if sender_exists and client_status_table[out_message["sender_username"]]["online"]:
                    sender_socket = client_status_table[out_message["sender_username"]]["socket"]

            delivered_now = False

            if receiver_socket is not None:
                if safe_send_text(receiver_socket, payload):
                    delivered_now = True
                    with database_lock:
                        for msg in database[out_message["receiver_username"]]:
                            if msg["message_id"] == out_message["message_id"]:
                                msg["delivered"] = True
                                msg["time_delivered"] = time_delivered
                                break
                else:
                    mark_client_offline(out_message["receiver_username"], receiver_socket)

            if delivered_now and sender_socket is not None:
                if not safe_send_text(sender_socket, confirmation):
                    mark_client_offline(out_message["sender_username"], sender_socket)

        except queue.Empty:
            continue

    print("send_outgoing_messages terminated")


def get_undelivered_messages(shutdown, client_online_name, client_online_socket):
    print(f"get_undelivered_messages for {client_online_name}")

    with database_lock:
        pending_messages = [
            msg for msg in database.get(client_online_name, [])
            if msg["delivered"] is False
        ]

    for msg in pending_messages:
        if shutdown.is_set():
            break

        payload = ENCRYPTED_MESSAGE_PREFIX + msg["sender_username"] + "|" + msg["message"]
        time_delivered = datetime.datetime.now()

        if not safe_send_text(client_online_socket, payload):
            mark_client_offline(client_online_name, client_online_socket)
            break

        with database_lock:
            for saved_msg in database.get(client_online_name, []):
                if saved_msg["message_id"] == msg["message_id"]:
                    saved_msg["delivered"] = True
                    saved_msg["time_delivered"] = time_delivered
                    break

        with client_table_lock:
            sender_exists = msg["sender_username"] in client_status_table
            sender_socket = None
            if sender_exists and client_status_table[msg["sender_username"]]["online"]:
                sender_socket = client_status_table[msg["sender_username"]]["socket"]

        if sender_socket is not None:
            confirmation = "message delivered to receiver"
            if not safe_send_text(sender_socket, confirmation):
                mark_client_offline(msg["sender_username"], sender_socket)

    print(f"get_undelivered_messages terminated for {client_online_name}")


def handle_new_connection(shutdown, client_socket, client_address, client_threads):
    """Complete signup/signin for one accepted client before returning."""
    client_socket.settimeout(1.0)

    try:
        decision = recv_text(client_socket, shutdown)

        if decision == "signup":
            if not safe_send_text(client_socket, "choose a username:"):
                raise InputError("client disconnected during signup")

            client_name_string = recv_text(client_socket, shutdown)

            while True:
                with client_table_lock:
                    name_exists = client_name_string in client_status_table

                if not name_exists:
                    break

                if not safe_send_text(client_socket, "username already exists, pick another one."):
                    raise InputError("client disconnected during signup")

                client_name_string = recv_text(client_socket, shutdown)

            if not safe_send_text(client_socket, "choose new password:"):
                raise InputError("client disconnected before sending password")

            pwd = recv_text(client_socket, shutdown)

            if not safe_send_text(client_socket, SEND_PUBLIC_KEY_PROMPT):
                raise InputError("client disconnected before sending public key")

            public_key_msg = recv_text(client_socket, shutdown)
            if not public_key_msg.startswith("PUBKEY|"):
                raise InputError("client did not send a valid public key")
            public_key_b64 = public_key_msg.split("|", 1)[1].strip()

            with client_table_lock:
                client_status_table[client_name_string] = {
                    "password": pwd,
                    "socket": client_socket,
                    "online": True,
                    "public_key": public_key_b64,
                }

            with database_lock:
                database.setdefault(client_name_string, [])

            thread = threading.Thread(
                target=new_client,
                args=(shutdown, client_socket, client_name_string, client_address),
                daemon=True
            )
            thread.start()
            client_threads.append(thread)
            return

        if decision == "signin":
            if not safe_send_text(client_socket, "enter your username:"):
                raise InputError("client disconnected before username")

            client_name_string = recv_text(client_socket, shutdown)

            if not safe_send_text(client_socket, "password:"):
                raise InputError("client disconnected before password")

            pwd = recv_text(client_socket, shutdown)

            with client_table_lock:
                user_exists = client_name_string in client_status_table

                if not user_exists:
                    safe_send_text(client_socket, "username does not exist. this connection will terminate.")
                    safe_close(client_socket)
                    return

                if client_status_table[client_name_string]["password"] != pwd:
                    safe_send_text(client_socket, "wrong password. this connection will terminate.")
                    safe_close(client_socket)
                    return

                if client_status_table[client_name_string]["online"]:
                    safe_send_text(client_socket, "There is another active session for this user. this connection will terminate.")
                    safe_close(client_socket)
                    return

            if not safe_send_text(client_socket, SEND_PUBLIC_KEY_PROMPT):
                raise InputError("client disconnected before sending public key")

            public_key_msg = recv_text(client_socket, shutdown)
            if not public_key_msg.startswith("PUBKEY|"):
                raise InputError("client did not send a valid public key")
            public_key_b64 = public_key_msg.split("|", 1)[1].strip()

            with client_table_lock:
                client_status_table[client_name_string]["socket"] = client_socket
                client_status_table[client_name_string]["online"] = True
                client_status_table[client_name_string]["public_key"] = public_key_b64

            thread = threading.Thread(
                target=new_client,
                args=(shutdown, client_socket, client_name_string, client_address),
                daemon=True
            )
            thread.start()
            client_threads.append(thread)

            undelivered_thread = threading.Thread(
                target=get_undelivered_messages,
                args=(shutdown, client_name_string, client_socket),
                daemon=True
            )
            undelivered_thread.start()
            client_threads.append(undelivered_thread)
            return

        safe_send_text(client_socket, "undefined client input. this connection will terminate.")
        safe_close(client_socket)

    except (InputError, ConnectionError, ConnectionResetError, BrokenPipeError, OSError) as error:
        print(f"connection setup error from {client_address}: {error}")
        safe_close(client_socket)

def accept_new_clients(shutdown):
    print("accept_new_clients")

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 0))
    print(server_socket.getsockname())
    server_socket.listen()
    server_socket.settimeout(1.0)

    send_outgoing_messages_thread = threading.Thread(
        target=send_outgoing_messages,
        args=(shutdown,),
        daemon=True
    )
    send_outgoing_messages_thread.start()

    client_threads = []

    try:
        while not shutdown.is_set():
            try:
                client_socket, client_address = server_socket.accept()
                handle_new_connection(shutdown, client_socket, client_address, client_threads)
            except socket.timeout:
                continue
            except OSError as error:
                if shutdown.is_set():
                    break
                print(f"accept error: {error}")

    finally:
        shutdown.set()
        safe_close(server_socket)
        close_all_clients()

        for thread in client_threads:
            thread.join(timeout=2.0)

        send_outgoing_messages_thread.join(timeout=2.0)
        print("accept_new_clients terminated")


def terminal_reader(shutdown):
    print("terminal_reader")

    while not shutdown.is_set():
        try:
            terminal_input = input()
        except EOFError:
            shutdown.set()
            break

        if terminal_input == "server shutdown":
            shutdown.set()
            break

    print("terminal_reader terminated")





def client_print_server_message(message, current_buffer):
    clear_current_console_line()
    print("server >> " + message)
    render_client_prompt(current_buffer)


def parse_server_line(line, current_buffer, state):
    if not line:
        return current_buffer

    if line == SEND_PUBLIC_KEY_PROMPT:
        if not state.get("username"):
            client_print_server_message("cannot send public key yet because username is unknown", current_buffer)
            return current_buffer

        private_key, public_key = load_or_create_user_keys(state["username"])
        state["private_key"] = private_key
        state["public_key"] = public_key
        pub_b64 = public_key_to_b64(public_key)
        state["socket"].sendall(f"PUBKEY|{pub_b64}".encode("utf-8"))
        return current_buffer

    if line.startswith(PUBLIC_KEY_REQUEST_PREFIX):
        _, username, public_key_b64 = line.split("|", 2)
        state["public_key_cache"][username] = public_key_from_b64(public_key_b64)
        state["pending_public_key_response"] = ("ok", username)
        return current_buffer

    if line.startswith(NO_PUBLIC_KEY_PREFIX):
        username = line.split("|", 1)[1]
        state["pending_public_key_response"] = ("missing", username)
        return current_buffer

    if line.startswith(ENCRYPTED_MESSAGE_PREFIX):
        if state.get("private_key") is None:
            client_print_server_message("received encrypted message but no private key is loaded", current_buffer)
            return current_buffer

        _, sender_username, ciphertext_b64 = line.split("|", 2)
        try:
            plaintext = decrypt_for_self(state["private_key"], ciphertext_b64)
            client_print_server_message(f"message from {sender_username} | {plaintext}", current_buffer)
        except Exception:
            client_print_server_message(f"message from {sender_username} | [decryption failed]", current_buffer)
        return current_buffer

    client_print_server_message(line, current_buffer)
    lower_line = line.lower()

    if lower_line == "choose a username:" or lower_line == "enter your username:":
        state["awaiting_username"] = True
    elif lower_line == "choose new password:" or lower_line == "password:":
        state["awaiting_password"] = True

    return current_buffer


def drain_server_messages(client_socket, recv_buffer, current_buffer, state):
    while True:
        try:
            server_msg = client_socket.recv(1024)
            if not server_msg:
                if recv_buffer:
                    while "\n" in recv_buffer:
                        line, recv_buffer = recv_buffer.split("\n", 1)
                        current_buffer = parse_server_line(line.strip(), current_buffer, state)
                    if recv_buffer.strip():
                        current_buffer = parse_server_line(recv_buffer.strip(), current_buffer, state)
                client_print_server_message("connection closed", current_buffer)
                return recv_buffer, current_buffer, False

            recv_buffer += server_msg.decode("utf-8")

            while "\n" in recv_buffer:
                line, recv_buffer = recv_buffer.split("\n", 1)
                current_buffer = parse_server_line(line.strip(), current_buffer, state)

        except socket.timeout:
            return recv_buffer, current_buffer, True
        except (ConnectionResetError, OSError):
            client_print_server_message("connection lost", current_buffer)
            return recv_buffer, current_buffer, False


def request_public_key(client_socket, target_username, recv_buffer, current_buffer, state):
    if target_username in state["public_key_cache"]:
        return state["public_key_cache"][target_username], recv_buffer, current_buffer, True

    state["pending_public_key_response"] = None

    try:
        client_socket.sendall(f"GETKEY|{target_username}".encode("utf-8"))
    except (BrokenPipeError, ConnectionResetError, OSError):
        client_print_server_message("cannot request recipient key because connection is closed", current_buffer)
        return None, recv_buffer, current_buffer, False

    while True:
        recv_buffer, current_buffer, alive = drain_server_messages(client_socket, recv_buffer, current_buffer, state)
        if not alive:
            return None, recv_buffer, current_buffer, False

        response = state.get("pending_public_key_response")
        if response is None:
            continue

        status, username = response
        state["pending_public_key_response"] = None

        if username != target_username:
            continue

        if status == "ok":
            return state["public_key_cache"][target_username], recv_buffer, current_buffer, True

        client_print_server_message(f"receiver {target_username} does not have a public key registered", current_buffer)
        return None, recv_buffer, current_buffer, True


def run_client_console(client_socket):
    current_buffer = ""
    recv_buffer = ""

    state = {
        "socket": client_socket,
        "username": None,
        "private_key": None,
        "public_key": None,
        "awaiting_username": False,
        "awaiting_password": False,
        "public_key_cache": {},
        "pending_public_key_response": None,
    }

    print("Please enter signup or signin:")
    render_client_prompt(current_buffer)

    while True:
        recv_buffer, current_buffer, alive = drain_server_messages(client_socket, recv_buffer, current_buffer, state)
        if not alive:
            return

        if msvcrt.kbhit():
            ch = msvcrt.getwch()

            if ch == "\r":
                print()
                user_input = current_buffer
                current_buffer = ""

                if state["awaiting_username"]:
                    state["username"] = user_input.strip()
                    state["awaiting_username"] = False
                elif state["awaiting_password"]:
                    state["awaiting_password"] = False

                if user_input.strip().lower() == "close":
                    try:
                        client_socket.sendall(b"close")
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        pass
                    return

                stripped = user_input.strip()
                if "," in user_input and state.get("private_key") is not None:
                    receiver_username, plaintext = user_input.split(",", 1)
                    receiver_username = receiver_username.strip()
                    plaintext = plaintext.strip()

                    if receiver_username and plaintext:
                        recipient_key, recv_buffer, current_buffer, alive = request_public_key(
                            client_socket,
                            receiver_username,
                            recv_buffer,
                            current_buffer,
                            state,
                        )
                        if not alive:
                            return

                        if recipient_key is not None:
                            ciphertext_b64 = encrypt_for_recipient(recipient_key, plaintext)
                            try:
                                client_socket.sendall(
                                    f"SEND|{receiver_username}|{ciphertext_b64}".encode("utf-8")
                                )
                            except (BrokenPipeError, ConnectionResetError, OSError):
                                client_print_server_message("cannot send, connection closed", current_buffer)
                                return
                    else:
                        try:
                            client_socket.sendall(user_input.encode("utf-8"))
                        except (BrokenPipeError, ConnectionResetError, OSError):
                            client_print_server_message("cannot send, connection closed", current_buffer)
                            return
                else:
                    try:
                        client_socket.sendall(user_input.encode("utf-8"))
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        client_print_server_message("cannot send, connection closed", current_buffer)
                        return

                render_client_prompt(current_buffer)

            elif ch in ("\x03", "\x1a"):
                print()
                return

            elif ch == "\b":
                if current_buffer:
                    current_buffer = current_buffer[:-1]
                render_client_prompt(current_buffer)

            elif ch in ("\x00", "\xe0"):
                msvcrt.getwch()
                render_client_prompt(current_buffer)

            else:
                current_buffer += ch
                render_client_prompt(current_buffer)

def main():
    if len(sys.argv) < 2:
        print("must include server/client when running the script")
        return

    if sys.argv[1] == "server":
        print("Launching server system:")

        shutdown = threading.Event()

        accept_new_clients_thread = threading.Thread(
            target=accept_new_clients,
            args=(shutdown,)
        )
        terminal_reader_thread = threading.Thread(
            target=terminal_reader,
            args=(shutdown,)
        )

        accept_new_clients_thread.start()
        terminal_reader_thread.start()

        accept_new_clients_thread.join()
        terminal_reader_thread.join()

    elif sys.argv[1] == "client":
        print("Launching client system:")

        server_address = input("Enter the server's address:")
        server_port = int(input("Enter the server's port number:"))

        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.settimeout(0.1)
        client_socket.connect((server_address, server_port))

        print("Connected to server!")

        try:
            run_client_console(client_socket)
        finally:
            safe_close(client_socket)

    else:
        print("first argument must be either server or client")


if __name__ == "__main__":
    main()
