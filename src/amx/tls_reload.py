"""Explicit local-only submission TLS renewal; never signal libmilter."""

from __future__ import annotations

import argparse
import os
import socket
import socketserver
import ssl
import threading
from pathlib import Path


class ReloadableTLS:
    """Select a validated immutable context at each handshake, including without SNI.

    Already established sessions retain their context. Even SMTP connections opened
    before renewal use the current certificate when they eventually send STARTTLS.
    """

    def __init__(self, cert: Path, key: Path):
        self.cert, self.key = cert, key
        self._lock = threading.Lock()
        self.context = self._load()
        self._current = self.context
        self.context.sni_callback = self._select

    def _load(self) -> ssl.SSLContext:
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(self.cert, self.key)
        return context

    def _select(self, connection, _name, _context):
        connection.context = self._current

    def reload(self) -> None:
        with self._lock:
            # A missing, malformed or mismatched pair must not mutate the good context.
            self._current = self._load()


class ReloadServer(socketserver.UnixStreamServer):
    """0600 operator socket: fixed reload action, bounded request, explicit receipt."""

    def __init__(self, directory: Path, tls: ReloadableTLS):
        self.path = directory / "tls-reload.sock"
        # The gateway exclusively owns its data directory; an old socket can remain
        # after a process crash. No network port or application token is exposed.
        self.path.unlink(missing_ok=True)

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(5)
                try:
                    if self.request.recv(32) != b"reload\n":
                        self.request.sendall(b"ERROR invalid action\n")
                        return
                    tls.reload()
                except (OSError, ValueError):
                    self.request.sendall(b"ERROR TLS reload failed\n")
                else:
                    self.request.sendall(b"OK\n")

        super().__init__(str(self.path), Handler)
        os.chmod(self.path, 0o600)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.shutdown()
        self.server_close()
        self.thread.join()
        self.path.unlink(missing_ok=True)


def request_reload(directory: Path) -> None:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(15)
        client.connect(str(directory / "tls-reload.sock"))
        client.sendall(b"reload\n")
        if client.recv(128) != b"OK\n":
            raise RuntimeError("gateway TLS reload failed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    arguments = parser.parse_args()
    request_reload(arguments.data_dir)


if __name__ == "__main__":
    main()
