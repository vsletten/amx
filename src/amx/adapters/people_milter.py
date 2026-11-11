"""Listener-bound Stalwart submission identity for the native milter.

Stalwart sends no listener macro. Its submission-only MtaMilter connects here,
not to the public ingress endpoint. Replace the trusted daemon macro before
forwarding to libmilter, preserving Stalwart's whole-message/replay dialect.
Like LMTP and the main milter, this port belongs only on the private MTA network.
"""

from __future__ import annotations

import contextlib
import select
import socket
import socketserver
import struct
import threading
from collections.abc import Iterator

DAEMON = b"Stalwart amx-submission"
MAX_FRAME = 16 * 1024 * 1024


def submission_macro(frame: bytes) -> bytes:
    """Bind CONNECT's daemon identity to this endpoint, never to sender content."""
    if frame[:2] != b"DC":
        return frame
    fields = frame[2:].split(b"\0")
    if fields[-1] != b"" or len(fields) % 2 != 1:
        raise ValueError("malformed milter macros")
    pairs = list(zip(fields[:-1:2], fields[1:-1:2], strict=True))
    pairs = [(key, value) for key, value in pairs if key != b"{daemon_name}"]
    pairs.append((b"{daemon_name}", DAEMON))
    return b"DC" + b"".join(key + b"\0" + value + b"\0" for key, value in pairs)


def _read(sock: socket.socket, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise EOFError
        result.extend(chunk)
    return bytes(result)


@contextlib.contextmanager
def people_listener(host: str, port: int, upstream: tuple[str, int]) -> Iterator[None]:
    """Forward framed requests and byte-preserved responses; refuse on any error."""

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            try:
                self.request.settimeout(120)
                with socket.create_connection(upstream, timeout=120) as target:
                    while True:
                        readable, _, _ = select.select([self.request, target], [], [], 120)
                        if not readable:
                            return
                        for source in readable:
                            if source is target:
                                data = target.recv(65536)
                                if not data:
                                    return
                                self.request.sendall(data)
                            else:
                                size = struct.unpack("!I", _read(self.request, 4))[0]
                                if not 0 < size <= MAX_FRAME:
                                    return
                                frame = submission_macro(_read(self.request, size))
                                target.sendall(struct.pack("!I", len(frame)) + frame)
            except (OSError, EOFError, ValueError):
                return  # Connection failure is tempfail in Stalwart, never accept.

    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    with Server((host, port), Handler) as server:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield
        finally:
            server.shutdown()
            thread.join()
