"""Browser bridge for the Wazzap secure chat application.

This module does not replace the original socket server in backend.py.
Instead, it wraps that backend with a lightweight HTTP server so the project can
be used from normal browser pages. It serves the static UI files, starts/stops the
TCP backend, keeps track of live browser sessions, and maintains a plaintext chat
history for the web interface while the Python process is running.
"""

import json
import queue
import socket
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import backend

# Paths and constants for the local web interface.
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / 'static'
HOST = '127.0.0.1'
WEB_PORT = 8000


class AppState:
    """Shared state used by the browser-facing HTTP layer.

    The TCP backend already stores user accounts, sockets, and encrypted mailboxes.
    This class stores only the extra state needed by the browser UI: server logs,
    browser sessions, and a plaintext conversation history used to render the chat
    window in the browser.
    """
    def __init__(self):
        # Locks are needed because the dashboard, browser sessions, and backend wrapper
        # all run on separate threads.
        self.log_lock = threading.Lock()
        self.logs = []
        self.server_lock = threading.Lock()
        self.shutdown = None
        self.server_thread = None
        self.server_socket = None
        self.server_host = None
        self.server_port = None
        self.client_sessions = {}
        self.client_sessions_lock = threading.Lock()
        self.chat_history_lock = threading.Lock()
        self.chat_history = {}

    def log(self, message):
        """Add one timestamped line to the dashboard log buffer."""
        stamp = time.strftime('%Y-%m-%d %H:%M:%S')
        line = f'[{stamp}] {message}'
        with self.log_lock:
            self.logs.append(line)
            self.logs = self.logs[-400:]
        print(line)

    def server_running(self):
        """Return True only when the wrapped TCP backend is alive and not shutting down."""
        return (
            self.server_thread is not None
            and self.server_thread.is_alive()
            and self.shutdown is not None
            and not self.shutdown.is_set()
        )

    def _history_key(self, user_a, user_b):
        """Normalize a conversation key so (A, B) and (B, A) map to the same chat."""
        return tuple(sorted((user_a, user_b)))

    def record_plaintext_message(self, sender, recipient, text, delivered=False, time_sent=None):
        """Store one readable message for the browser chat UI.

        backend.py stores encrypted payloads in memory. The web UI needs readable text,
        so the browser layer keeps its own plaintext history. This method also prevents
        duplicate rows and upgrades pending messages to delivered when confirmation
        arrives later.
        """
        if not sender or not recipient:
            return
        now_ts = time.time()
        row = {
            'sender': sender,
            'recipient': recipient,
            'text': text,
            'time_sent': time_sent or time.strftime('%Y-%m-%d %H:%M:%S'),
            'delivered': bool(delivered),
            '_created_ts': now_ts,
        }
        key = self._history_key(sender, recipient)
        with self.chat_history_lock:
            rows = self.chat_history.setdefault(key, [])

            # If this message is being observed on the receiver side later
            # (for example after offline delivery on next sign-in), match it to
            # the sender-side row that was already recorded when it was sent.
            if delivered:
                for existing in rows:
                    if (
                        existing.get('sender') == sender
                        and existing.get('recipient') == recipient
                        and existing.get('text') == text
                        and not existing.get('delivered')
                    ):
                        existing['delivered'] = True
                        return

            # Also block immediate accidental double-inserts of the exact same message.
            if rows:
                last = rows[-1]
                same_payload = (
                    last.get('sender') == sender
                    and last.get('recipient') == recipient
                    and last.get('text') == text
                )
                last_ts = last.get('_created_ts', 0.0)
                if same_payload and (now_ts - last_ts) < 0.9:
                    if delivered:
                        last['delivered'] = True
                    return

            rows.append(row)

    def mark_latest_outgoing_delivered(self, sender, recipient):
        """Mark the most recent pending outgoing message as delivered."""
        if not sender or not recipient:
            return False
        key = self._history_key(sender, recipient)
        with self.chat_history_lock:
            rows = self.chat_history.get(key, [])
            for row in reversed(rows):
                if row['sender'] == sender and row['recipient'] == recipient and not row.get('delivered'):
                    row['delivered'] = True
                    return True
        return False

    def conversation_rows_for(self, username, initiated_only=False):
        """Build the conversation list and message list expected by client.html."""
        conversations = []
        with self.chat_history_lock:
            items = list(self.chat_history.items())

        for key, rows in items:
            if username not in key:
                continue
            contact = key[0] if key[1] == username else key[1]
            initiated = any(row['sender'] == username for row in rows)
            if initiated_only and not initiated:
                continue

            messages = []
            for idx, row in enumerate(rows, start=1):
                mine = row['sender'] == username
                messages.append({
                    'contact': contact,
                    'direction': 'outgoing' if mine else 'incoming',
                    'text': row['text'],
                    'message_id': idx,
                    'delivered': bool(row.get('delivered')) if mine else True,
                    'time_sent': row.get('time_sent'),
                    'time_delivered': row.get('time_sent') if row.get('delivered') else None,
                    'sender': row['sender'],
                    'recipient': row['recipient'],
                    '_created_ts': row.get('_created_ts', 0.0),
                })

            messages.sort(key=lambda item: (item.get('_created_ts', 0.0), item['message_id'] or 0))
            last = messages[-1] if messages else None
            conversations.append({
                'contact': contact,
                'messages': messages,
                'last_message': last['text'] if last else '',
                'last_time': last['time_sent'] if last else None,
                '_last_created_ts': last.get('_created_ts', 0.0) if last else 0.0,
                'undelivered_outgoing': sum(1 for item in messages if item['direction'] == 'outgoing' and not item['delivered']),
                'initiated_by_me': initiated,
            })

        conversations.sort(key=lambda row: row.get('_last_created_ts', 0.0), reverse=True)
        return conversations


STATE = AppState()


def backend_log(*args, **kwargs):
    """Redirect backend print output into the browser dashboard log."""
    STATE.log(' '.join(str(a) for a in args))


# Rebind backend.print so status messages appear in the web dashboard.
backend.print = backend_log


def start_socket_server(host='127.0.0.1', port=0):
    """Start the TCP socket backend inside a managed thread.

    The browser pages never communicate with one another directly. They always go
    through this wrapped backend server.
    """
    with STATE.server_lock:
        if STATE.server_running():
            return False, 'Server is already running.'

        shutdown = threading.Event()
        STATE.shutdown = shutdown

        # The backend expects a dedicated delivery thread that drains the outgoing
        # message queue and forwards ciphertext to currently-online users.
        def send_outgoing_wrapper():
            STATE.log('send_outgoing_messages thread started')
            backend.send_outgoing_messages(shutdown)
            STATE.log('send_outgoing_messages thread stopped')

        def accept_loop():
            # This loop is the browser-managed version of the backend accept logic. It
            # starts the listening socket, accepts TCP clients, and hands each one to the
            # backend authentication/handler flow.
            client_threads = []
            send_thread = threading.Thread(target=send_outgoing_wrapper, daemon=True)
            send_thread.start()

            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((host, port))
            server_socket.listen()
            server_socket.settimeout(1.0)

            bound_host, bound_port = server_socket.getsockname()
            STATE.server_socket = server_socket
            STATE.server_host = bound_host
            STATE.server_port = bound_port
            STATE.log(f'Socket backend listening on {bound_host}:{bound_port}')

            try:
                while not shutdown.is_set():
                    try:
                        client_socket, client_address = server_socket.accept()
                        STATE.log(f'Accepted TCP client from {client_address[0]}:{client_address[1]}')
                        backend.handle_new_connection(shutdown, client_socket, client_address, client_threads)
                    except socket.timeout:
                        continue
                    except OSError as error:
                        if shutdown.is_set():
                            break
                        STATE.log(f'accept error: {error}')
            finally:
                shutdown.set()
                backend.safe_close(server_socket)
                backend.close_all_clients()
                for thread in client_threads:
                    thread.join(timeout=2.0)
                send_thread.join(timeout=2.0)
                STATE.log('Socket backend stopped')
                with STATE.server_lock:
                    STATE.server_socket = None
                    STATE.server_host = None
                    STATE.server_port = None

        thread = threading.Thread(target=accept_loop, daemon=True)
        STATE.server_thread = thread
        thread.start()
        return True, 'Server started.'


class BrowserClientSession:
    """One signed-in browser tab backed by a live TCP socket.

    Each browser tab gets its own BrowserClientSession object. The object performs
    the socket-level protocol on behalf of the page, including signup/signin,
    public-key exchange, encryption, background reads, and graceful disconnects.
    """
    def __init__(self, host, port):
        # session.id lets the stateless HTTP API look up the correct live socket.
        self.id = str(uuid.uuid4())
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(1.0)
        self.stop_event = threading.Event()
        self.reader_thread = None
        self.events = queue.Queue()
        self.username = None
        self.mode = None
        self.recv_buffer = ''
        self.private_key = None
        self.public_key = None
        self.public_key_cache = {}
        self.pending_key_lock = threading.Lock()
        self.pending_public_key_requests = {}
        self.last_sent_recipient = None
        self.last_send_fingerprint = None
        self.last_send_at = 0.0

    def connect(self):
        """Open the TCP connection to the backend server."""
        self.socket.connect((self.host, self.port))

    def _send_line(self, text):
        """Send one newline-terminated protocol line to backend.py."""
        self.socket.sendall((text + '\n').encode('utf-8'))

    def _recv_line(self, timeout=4.0):
        """Receive one complete protocol line, buffering partial socket data if needed."""
        end = time.time() + timeout
        while time.time() < end and not self.stop_event.is_set():
            if '\n' in self.recv_buffer:
                line, self.recv_buffer = self.recv_buffer.split('\n', 1)
                return line.strip()
            try:
                data = self.socket.recv(4096)
                if not data:
                    raise ConnectionError('connection closed')
                self.recv_buffer += data.decode('utf-8', errors='replace')
            except socket.timeout:
                continue
        raise TimeoutError('timed out waiting for server response')

    def _handle_control_line(self, line):
        """Interpret special backend control lines.

        Some lines are not ordinary chat content. They can request a public key,
        deliver an encrypted payload, or confirm delivery of an earlier message.
        """
        if not line:
            return None
        if line == backend.SEND_PUBLIC_KEY_PROMPT:
            if not self.username:
                raise ConnectionError('username missing before public key exchange')
            self.private_key, self.public_key = backend.load_or_create_user_keys(self.username)
            pub_b64 = backend.public_key_to_b64(self.public_key)
            self._send_line(f'PUBKEY|{pub_b64}')
            return {'kind': 'system', 'text': 'Encryption keys loaded.'}
        if line.startswith(backend.PUBLIC_KEY_REQUEST_PREFIX):
            _, username, public_key_b64 = line.split('|', 2)
            public_key = backend.public_key_from_b64(public_key_b64)
            self.public_key_cache[username] = public_key
            with self.pending_key_lock:
                box = self.pending_public_key_requests.get(username)
            if box is not None:
                box.put(('ok', public_key))
            return None
        if line.startswith(backend.NO_PUBLIC_KEY_PREFIX):
            username = line.split('|', 1)[1]
            with self.pending_key_lock:
                box = self.pending_public_key_requests.get(username)
            if box is not None:
                box.put(('missing', None))
            return None
        if line.startswith(backend.ENCRYPTED_MESSAGE_PREFIX):
            _, sender_username, ciphertext_b64 = line.split('|', 2)
            if self.private_key is None:
                return {'kind': 'system', 'text': f'Encrypted message from {sender_username} could not be decrypted.'}
            try:
                plaintext = backend.decrypt_for_self(self.private_key, ciphertext_b64)
            except Exception:
                plaintext = '[decryption failed]'
            STATE.record_plaintext_message(sender_username, self.username, plaintext, delivered=True)
            return {'kind': 'incoming', 'from': sender_username, 'text': plaintext}
        if line == 'message delivered to receiver':
            if self.last_sent_recipient:
                STATE.mark_latest_outgoing_delivered(self.username, self.last_sent_recipient)
            return {'kind': 'delivery', 'text': line}
        return classify_server_message(line)

    def authenticate(self, mode, username, password):
        """Run the backend's signup/signin dialogue for this browser session."""
        self.mode = mode
        self.username = username
        self._send_line(mode)

        if mode == 'signup':
            prompt = self._recv_line()
            if 'choose a username' not in prompt.lower():
                raise ConnectionError(prompt)
            self._send_line(username)
            prompt = self._recv_line()
            if 'username already exists' in prompt.lower():
                raise ValueError(prompt)
            if 'choose new password' not in prompt.lower():
                raise ConnectionError(prompt)
            self._send_line(password)
            while True:
                line = self._recv_line(timeout=5.0)
                event = self._handle_control_line(line)
                lowered = line.lower()
                if 'please send messages in this format' in lowered:
                    if event:
                        self.events.put(event)
                    self.events.put({'kind': 'system', 'text': line})
                    break
                if event:
                    self.events.put(event)

        elif mode == 'signin':
            prompt = self._recv_line()
            if 'enter your username' not in prompt.lower():
                raise ConnectionError(prompt)
            self._send_line(username)
            prompt = self._recv_line()
            if 'password' not in prompt.lower():
                raise ConnectionError(prompt)
            self._send_line(password)
            while True:
                line = self._recv_line(timeout=5.0)
                lowered = line.lower()
                event = self._handle_control_line(line)
                if 'please send messages in this format' in lowered:
                    if event:
                        self.events.put(event)
                    self.events.put({'kind': 'system', 'text': line})
                    break
                if 'this connection will terminate' in lowered:
                    raise ValueError(line)
                if event:
                    self.events.put(event)
        else:
            raise ValueError('Mode must be signup or signin.')

        self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self.reader_thread.start()

    def _reader_loop(self):
        """Continuously read backend messages after authentication succeeds."""
        while not self.stop_event.is_set():
            try:
                data = self.socket.recv(4096)
                if not data:
                    self.events.put({'kind': 'status', 'text': 'Connection closed by server.'})
                    self.stop_event.set()
                    break
                self.recv_buffer += data.decode('utf-8', errors='replace')
                while '\n' in self.recv_buffer:
                    line, self.recv_buffer = self.recv_buffer.split('\n', 1)
                    event = self._handle_control_line(line.strip())
                    if event is not None:
                        self.events.put(event)
            except socket.timeout:
                continue
            except (ConnectionResetError, OSError):
                self.events.put({'kind': 'status', 'text': 'Connection lost.'})
                self.stop_event.set()
                break

    def _request_public_key(self, username, timeout=4.0):
        """Request and cache another user's public key before sending a message."""
        if username in self.public_key_cache:
            return self.public_key_cache[username]
        box = queue.Queue()
        with self.pending_key_lock:
            self.pending_public_key_requests[username] = box
        try:
            self._send_line(f'GETKEY|{username}')
            status, key = box.get(timeout=timeout)
            if status == 'ok':
                return key
            return None
        finally:
            with self.pending_key_lock:
                self.pending_public_key_requests.pop(username, None)

    def send_chat(self, recipient, text):
        """Encrypt one plaintext message and send it through the socket backend."""
        recipient_key = self._request_public_key(recipient)
        if recipient_key is None:
            raise ValueError(f'User "{recipient}" does not exist.')
        ciphertext_b64 = backend.encrypt_for_recipient(recipient_key, text)
        self.last_sent_recipient = recipient
        self._send_line(f'SEND|{recipient}|{ciphertext_b64}')
        STATE.record_plaintext_message(self.username, recipient, text, delivered=False)

    def poll_events(self):
        """Return all queued browser events without blocking."""
        out = []
        while True:
            try:
                out.append(self.events.get_nowait())
            except queue.Empty:
                break
        return out

    def close(self):
        """Close the session socket and stop the background reader thread."""
        self.stop_event.set()
        try:
            self._send_line('close')
        except Exception:
            pass
        backend.safe_close(self.socket)


def classify_server_message(text):
    """Convert backend acknowledgements into small event objects for the UI."""
    if text == 'message delivered to receiver':
        return {'kind': 'delivery', 'text': text}
    if text == 'message received in server. receiver exists':
        return {'kind': 'server_ack', 'text': text}
    if text == 'receiver offline. not delivered.':
        return {'kind': 'offline_notice', 'text': text}
    return {'kind': 'system', 'text': text}


def known_users(current_username=None):
    """Return a simple list of known users and online status for the browser UI."""
    with backend.client_table_lock:
        users = []
        for username, info in backend.client_status_table.items():
            if username == current_username:
                continue
            users.append({
                'username': username,
                'online': bool(info.get('online')),
            })
    users.sort(key=lambda item: (not item['online'], item['username'].lower()))
    return users


class Handler(BaseHTTPRequestHandler):
    """Small HTTP router used by the local browser interface."""
    def do_GET(self):
        """Serve static HTML/CSS files and read-only JSON state endpoints."""
        parsed = urlparse(self.path)
        if parsed.path == '/':
            return self._serve_file('index.html')
        if parsed.path == '/server':
            return self._serve_file('server.html')
        if parsed.path == '/client':
            return self._serve_file('client.html')
        if parsed.path.startswith('/static/'):
            rel = parsed.path[len('/static/'):]
            return self._serve_file(rel)
        if parsed.path == '/api/server/state':
            return self._send_json(self._server_state())
        if parsed.path == '/api/client/state':
            qs = parse_qs(parsed.query)
            session_id = qs.get('session_id', [''])[0]
            return self._send_json(self._client_state(session_id))
        self.send_error(404, 'Not Found')

    def do_POST(self):
        """Handle state-changing operations such as start, shutdown, login, and send."""
        parsed = urlparse(self.path)
        data = self._read_json()
        if parsed.path == '/api/server/start':
            ok, message = start_socket_server(host='127.0.0.1', port=int(data.get('port', 0) or 0))
            return self._send_json({'ok': ok, 'message': message, 'state': self._server_state()})
        if parsed.path == '/api/server/shutdown':
            with STATE.server_lock:
                if STATE.shutdown is not None:
                    STATE.shutdown.set()
                    if STATE.server_socket is not None:
                        backend.safe_close(STATE.server_socket)
            return self._send_json({'ok': True, 'message': 'Shutdown signal sent.', 'state': self._server_state()})
        if parsed.path == '/api/client/auth':
            return self._send_json(self._client_auth(data))
        if parsed.path == '/api/client/send_chat':
            return self._send_json(self._client_send_chat(data))
        if parsed.path == '/api/client/disconnect':
            return self._send_json(self._client_disconnect(data))
        self.send_error(404, 'Not Found')

    def _server_state(self):
        """Collect one complete dashboard snapshot."""
        with backend.client_table_lock:
            users = {
                username: {
                    'online': info.get('online', False),
                    'has_socket': info.get('socket') is not None,
                    'has_public_key': bool(info.get('public_key')),
                }
                for username, info in backend.client_status_table.items()
            }
        with backend.database_lock:
            mailboxes = {
                username: {
                    'total': len(msgs),
                    'undelivered': sum(1 for m in msgs if not m['delivered']),
                    'delivered': sum(1 for m in msgs if m['delivered']),
                }
                for username, msgs in backend.database.items()
            }
        with STATE.log_lock:
            logs = list(STATE.logs)
        return {
            'running': STATE.server_running(),
            'host': STATE.server_host,
            'port': STATE.server_port,
            'users': users,
            'mailboxes': mailboxes,
            'queued_messages': backend.outgoing_messages_queue.qsize(),
            'logs': logs,
        }

    def _client_auth(self, data):
        """Create a BrowserClientSession and authenticate it."""
        host = data.get('host', '127.0.0.1')
        port = int(data.get('port'))
        mode = data.get('mode', '').strip().lower()
        username = data.get('username', '').strip()
        password = data.get('password', '')

        if mode not in {'signup', 'signin'}:
            return {'ok': False, 'message': 'Choose signup or signin.'}
        if not username or not password:
            return {'ok': False, 'message': 'Username and password are required.'}

        session = BrowserClientSession(host, port)
        try:
            session.connect()
            session.authenticate(mode, username, password)
        except Exception as error:
            session.close()
            return {'ok': False, 'message': str(error)}

        with STATE.client_sessions_lock:
            STATE.client_sessions[session.id] = session
        STATE.log(f'Browser user {username} authenticated by {mode} at {host}:{port}')
        return {
            'ok': True,
            'session_id': session.id,
            'username': username,
            'mode': mode,
        }

    def _client_send_chat(self, data):
        """Validate and forward one browser send request."""
        session_id = data.get('session_id', '')
        recipient = data.get('recipient', '').strip()
        text = data.get('text', '').strip()
        with STATE.client_sessions_lock:
            session = STATE.client_sessions.get(session_id)
        if session is None:
            return {'ok': False, 'message': 'Invalid session.'}
        if not recipient or not text:
            return {'ok': False, 'message': 'Pick a recipient and type a message.'}
        fingerprint = (recipient, text)
        now_ts = time.time()
        if session.last_send_fingerprint == fingerprint and (now_ts - session.last_send_at) < 0.9:
            return {'ok': True, 'message': 'Skipped duplicate.'}
        session.last_send_fingerprint = fingerprint
        session.last_send_at = now_ts
        try:
            session.send_chat(recipient, text)
            return {'ok': True, 'message': 'Sent.'}
        except Exception as error:
            return {'ok': False, 'message': str(error)}

    def _client_state(self, session_id):
        """Return the latest per-client state used by the chat page."""
        with STATE.client_sessions_lock:
            session = STATE.client_sessions.get(session_id)
        if session is None:
            return {'ok': False, 'closed': True}

        events = session.poll_events()
        return {
            'ok': True,
            'closed': session.stop_event.is_set(),
            'username': session.username,
            'events': events,
            'conversations': STATE.conversation_rows_for(session.username, initiated_only=False),
            'all_conversations': STATE.conversation_rows_for(session.username, initiated_only=False),
            'known_users': known_users(session.username),
        }

    def _client_disconnect(self, data):
        """Disconnect a browser client and remove its live session object."""
        session_id = data.get('session_id', '')
        with STATE.client_sessions_lock:
            session = STATE.client_sessions.pop(session_id, None)
        if session is None:
            return {'ok': True, 'message': 'Already disconnected.'}
        username = session.username
        session.close()
        STATE.log(f'Browser user {username} disconnected')
        return {'ok': True, 'message': 'Disconnected.'}

    def _read_json(self):
        """Read and decode a JSON request body, falling back to {} on bad input."""
        length = int(self.headers.get('Content-Length', '0'))
        raw = self.rfile.read(length) if length else b'{}'
        if not raw:
            return {}
        text = raw.decode('utf-8', errors='replace').strip()
        if not text:
            return {}
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {}

    def _serve_file(self, relative_path):
        """Serve one file from the static/ directory."""
        path = STATIC_DIR / relative_path
        if not path.exists() or not path.is_file():
            self.send_error(404, 'Not Found')
            return
        content = path.read_bytes()
        suffix = path.suffix.lower()
        content_type = {
            '.html': 'text/html; charset=utf-8',
            '.css': 'text/css; charset=utf-8',
            '.js': 'application/javascript; charset=utf-8',
            '.json': 'application/json; charset=utf-8',
        }.get(suffix, 'application/octet-stream')
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _send_json(self, payload, status=200):
        """Serialize a Python object as JSON and send it as an HTTP response."""
        raw = json.dumps(payload).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format, *args):
        """Silence the default BaseHTTPRequestHandler console logging."""
        return


# Start the local web interface. The browser pages then control the socket backend
# through the JSON endpoints defined above.
if __name__ == '__main__':
    STATE.log(f'Web UI available at http://{HOST}:{WEB_PORT}/')
    httpd = ThreadingHTTPServer((HOST, WEB_PORT), Handler)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if STATE.shutdown is not None:
            STATE.shutdown.set()
            if STATE.server_socket is not None:
                backend.safe_close(STATE.server_socket)
        with STATE.client_sessions_lock:
            sessions = list(STATE.client_sessions.values())
            STATE.client_sessions.clear()
        for session in sessions:
            session.close()
        httpd.server_close()
