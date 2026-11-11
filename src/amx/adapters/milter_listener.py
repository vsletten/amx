"""Listener-bound provenance for libmilter's single-socket server.

Both TCP endpoints forward to one private Unix socket, keeping the gateway's
registry, replay cache and reload state in one process. Only CONNECT's unused
hostname is replaced with a one-use opaque handle. SMTP addresses, macros and
message bytes are untouched. The handle resolves to the actual listening port,
never an MTA macro or a message header; it is not sent back to the MTA.
"""

from __future__ import annotations

import contextlib
import secrets
import select
import socket
import socketserver
import struct
import threading
from contextlib import ExitStack


def _exact(sock: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise EOFError
        data.extend(part)
    return bytes(data)


class MilterListeners:
    """Two bounded-frame TCP frontends for one private native milter backend."""

    def __init__(self, host: str, ingress: int, sibling: int, backend: str) -> None:
        self.backend = backend
        self._pending: dict[str, bool] = {}
        self._lock = threading.Lock()
        self._servers: list[socketserver.ThreadingTCPServer] = []
        self._threads: list[threading.Thread] = []
        self._connections: set[socket.socket] = set()
        self._closing = False
        owner = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                owner._forward(self.request, self.server.sibling)  # type: ignore[attr-defined]

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True
            sibling: bool

        try:
            for port, trusted in ((ingress, False), (sibling, True)):
                server = Server((host, port), Handler)
                server.sibling = trusted
                self._servers.append(server)
        except BaseException:
            for server in self._servers:
                server.server_close()
            raise

    def resolve(self, handle: str) -> bool:
        """Consume provenance; missing/forged/reused handles fail closed."""
        with self._lock:
            return self._pending.pop(handle)

    def _forward(self, client: socket.socket, sibling: bool) -> None:
        handle = secrets.token_hex(32)
        with socket.socket(socket.AF_UNIX) as backend:
            with self._lock:
                if self._closing:
                    return
                self._connections.update((client, backend))
            try:
                client.settimeout(120)
                backend.settimeout(120)
                backend.connect(self.backend)
                connected = False
                while True:
                    readable, _, _ = select.select((client, backend), (), (), 120)
                    if not readable:
                        return
                    for source in readable:
                        if source is backend:
                            data = backend.recv(65536)
                            if not data:
                                return
                            client.sendall(data)
                        else:
                            length = struct.unpack("!I", _exact(client, 4))[0]
                            if not 1 <= length <= 1024 * 1024:
                                return
                            frame = _exact(client, length)
                            if frame[:1] == b"C":
                                if connected or b"\0" not in frame:
                                    return
                                connected = True
                                with self._lock:
                                    self._pending[handle] = sibling
                                frame = b"C" + handle.encode() + b"\0" + frame.partition(b"\0")[2]
                            backend.sendall(struct.pack("!I", len(frame)) + frame)
                            if frame[:1] == b"Q":
                                return
            except (OSError, EOFError, ValueError):
                pass  # disconnect: the MTA's tempFailOnError keeps custody upstream
            finally:
                with self._lock:
                    self._pending.pop(handle, None)
                    self._connections.difference_update((client, backend))

    def __enter__(self) -> MilterListeners:
        for server in self._servers:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self._threads.append(thread)
        return self

    def __exit__(self, *_args: object) -> None:
        with self._lock:
            self._closing = True
            for connection in self._connections:
                with contextlib.suppress(OSError):
                    connection.shutdown(socket.SHUT_RDWR)
        with ExitStack() as stack:
            for server in self._servers:
                stack.callback(server.server_close)
                server.shutdown()
        for thread in self._threads:
            thread.join()
