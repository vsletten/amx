import hashlib
import smtplib
import socket
import ssl
import subprocess
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from amx.adapters.submission import controller as submission_controller
from amx.config import LimitsConfig
from amx.tls_reload import ReloadableTLS, ReloadServer, request_reload


def certificate(directory):
    cert, key = directory / "cert.pem", directory / "key.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "2",
            "-subj",
            "/CN=localhost",
            "-keyout",
            str(key),
            "-out",
            str(cert),
        ],
        check=True,
        capture_output=True,
    )
    return cert, key


def fingerprint(smtp):
    return hashlib.sha256(smtp.sock.getpeercert(binary_form=True)).hexdigest()


@pytest.fixture
def short_path():
    with tempfile.TemporaryDirectory(prefix="tls-") as directory:
        yield Path(directory)


@pytest.mark.parametrize("server_name", ["localhost", None])
def test_live_starttls_reload_keeps_sessions_and_rejects_invalid_pair(short_path, server_name):
    tmp_path = short_path
    cert, key = certificate(tmp_path)
    tls = ReloadableTLS(cert, key)
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    service = SimpleNamespace(
        config=SimpleNamespace(
            submission_tls_cert=cert,
            submission_tls_key=key,
            submission_host="127.0.0.1",
            submission_port=port,
            limits=LimitsConfig(),
        )
    )
    controller = submission_controller(service, tls_context=tls.context)
    server = ReloadServer(tmp_path, tls)
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    controller.start()
    server.start()

    def connect():
        smtp = smtplib.SMTP("127.0.0.1", port, timeout=5)
        # OpenSSL omits SNI for an IP literal.
        smtp._host = server_name or "127.0.0.1"
        return smtp

    try:
        with connect() as established, connect() as pending:
            established.starttls(context=client_context)
            old = fingerprint(established)
            old_key = key.read_bytes()
            certificate(tmp_path)
            request_reload(tmp_path)
            pending.starttls(context=client_context)
            new = fingerprint(pending)
            assert new != old
            assert established.noop()[0] == 250
            assert fingerprint(established) == old
            with connect() as fresh:
                fresh.starttls(context=client_context)
                assert fingerprint(fresh) == new
            # Mismatched and malformed replacements both fail, retaining new.
            key.write_bytes(old_key)
            with pytest.raises(RuntimeError, match="reload failed"):
                request_reload(tmp_path)
            cert.write_text("not a certificate")
            with pytest.raises(RuntimeError, match="reload failed"):
                request_reload(tmp_path)
            with connect() as fresh:
                fresh.starttls(context=client_context)
                assert fingerprint(fresh) == new
        with socket.socket(socket.AF_UNIX) as client:
            client.connect(str(server.path))
            client.sendall(b"arbitrary-action\n")
            assert client.recv(128).startswith(b"ERROR invalid action")
        assert server.path.stat().st_mode & 0o777 == 0o600
    finally:
        server.stop()
        controller.stop()
