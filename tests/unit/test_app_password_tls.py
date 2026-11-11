"""Real HTTPS trust regressions for people credentials; no native stack needed."""

import base64
import json
import os
import shutil
import ssl
import subprocess
import threading
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

import pytest
import test_users

from amx import mail_client, users

site = test_users.site
ACCOUNT_PASSWORD = "synthetic-account-password"
APP_PASSWORD = "app_synthetic-server-issued"
ADDRESS = "alice@home.arpa"


@pytest.fixture(scope="module")
def private_ca(tmp_path_factory):
    directory = tmp_path_factory.mktemp("people-ca")
    # Explicit child allowlist: never pass ambient API/mail credentials to openssl.
    env = {key: os.environ[key] for key in ("HOME", "PATH", "TMPDIR") if key in os.environ}

    def openssl(*args):
        subprocess.run(
            ["openssl", *args], cwd=directory, env=env, check=True, capture_output=True, timeout=15
        )

    openssl(
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-days",
        "2",
        "-subj",
        "/CN=synthetic-private-issuer",
        "-keyout",
        "ca.key",
        "-out",
        "ca.pem",
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "keyUsage=critical,keyCertSign,cRLSign",
    )
    openssl(
        "req",
        "-new",
        "-newkey",
        "rsa:2048",
        "-nodes",
        "-subj",
        "/CN=127.0.0.1",
        "-keyout",
        "server.key",
        "-out",
        "server.csr",
    )
    (directory / "extensions").write_text(
        "subjectAltName=IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\n"
        "extendedKeyUsage=serverAuth\n"
    )
    openssl(
        "x509",
        "-req",
        "-in",
        "server.csr",
        "-CA",
        "ca.pem",
        "-CAkey",
        "ca.key",
        "-CAcreateserial",
        "-days",
        "2",
        "-extfile",
        "extensions",
        "-out",
        "server.pem",
    )
    return directory


@pytest.fixture
def native_https(private_ca):
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # No authentication/response payloads in logs.

        def respond(self, payload):
            raw = json.dumps(payload).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def authorized(self):
            expected = (
                "Basic " + base64.b64encode(f"{ADDRESS}:{ACCOUNT_PASSWORD}".encode()).decode()
            )
            if self.headers.get("Authorization") != expected:
                self.send_error(401)
                return False
            return True

        def do_GET(self):
            if not self.authorized():
                return
            calls.append(self.path)
            self.respond(
                {
                    "apiUrl": f"https://127.0.0.1:{server.server_port}/jmap/",
                    "primaryAccounts": {"urn:ietf:params:jmap:mail": "person"},
                }
            )

        def do_POST(self):
            if not self.authorized():
                return
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            method, arguments, tag = payload["methodCalls"][0]
            assert method == "x:AppPassword/set"
            assert arguments["accountId"] == "person"
            assert "secret" not in arguments["create"]["mail"]
            calls.append(self.path)
            self.respond(
                {
                    "methodResponses": [
                        [
                            method,
                            {
                                "created": {"mail": {"id": "native", "secret": APP_PASSWORD}},
                            },
                            tag,
                        ]
                    ]
                }
            )

    server = HTTPServer(("127.0.0.1", 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(private_ca / "server.pem", private_ca / "server.key")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})
    thread.start()
    try:
        yield server.server_port, calls
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        assert not thread.is_alive()


@pytest.fixture(autouse=True)
def finite_session_retry(monkeypatch):
    # Advance only the client's retry clock, never TLS context/verification or transport.
    ticks = iter((0, 46))
    monkeypatch.setattr(mail_client, "time", SimpleNamespace(monotonic=lambda: next(ticks)))


def client_params(tmp_path, private_ca, native_https, mode="files", configured_ca=True):
    tls_dir = tmp_path / "tls"
    tls_dir.mkdir()
    shutil.copyfile(private_ca / "ca.pem", tls_dir / "ca.pem")
    return SimpleNamespace(
        mx_host="127.0.0.1",
        ports={"discovery": native_https[0]},
        tls_mode=mode,
        tls_dir=tls_dir,
        tls_ca_file=tmp_path / "operator-ca.pem" if mode == "files" and configured_ca else None,
    )


def test_https_fixture_private_issuer_is_valid(private_ca, native_https):
    context = ssl.create_default_context(cafile=str(private_ca / "ca.pem"))
    auth = "Basic " + base64.b64encode(f"{ADDRESS}:{ACCOUNT_PASSWORD}".encode()).decode()
    response = mail_client.https_request(
        "127.0.0.1",
        native_https[0],
        "/.well-known/jmap",
        context,
        headers={"Authorization": auth},
    )
    assert json.loads(response)["primaryAccounts"]["urn:ietf:params:jmap:mail"] == "person"


@pytest.mark.parametrize("mode", ["files", "self-signed"])
def test_issue_app_password_with_real_private_ca(tmp_path, private_ca, native_https, mode):
    params = client_params(tmp_path, private_ca, native_https, mode)
    output = tmp_path / "app"
    mail_client.issue_app_password(params, ADDRESS, ACCOUNT_PASSWORD, output)
    assert output.read_text() == APP_PASSWORD + "\n"
    assert output.stat().st_mode & 0o777 == 0o600
    assert native_https[1] == ["/.well-known/jmap", "/jmap/"]


@pytest.mark.parametrize("action", ["add", "passwd"])
def test_people_cli_app_password_uses_files_private_ca(
    site, tmp_path, private_ca, native_https, monkeypatch, action
):
    if action == "passwd":
        assert (
            test_users.invoke(
                site, "add", "alice", "--password-out", str(tmp_path / "old")
            ).exit_code
            == 0
        )
    params = replace(
        site,
        mx_host="127.0.0.1",
        ports={**site.ports, "discovery": native_https[0]},
        tls_mode="files",
        tls_ca_file=private_ca / "ca.pem",
    )
    params.tls_dir.mkdir(parents=True)
    shutil.copyfile(private_ca / "ca.pem", params.tls_dir / "ca.pem")
    # Only map fixture configuration to loopback; CLI/change/client/HTTPS remain real.
    monkeypatch.setattr(users, "load_params", lambda _path: params)
    primary, output = tmp_path / "primary", tmp_path / "app"
    primary.write_text(ACCOUNT_PASSWORD + "\n")
    primary.chmod(0o600)
    result = test_users.invoke(
        site, action, "alice", "--password-file", str(primary), "--app-password-out", str(output)
    )
    assert result.exit_code == 0, result.output
    assert output.read_text().strip() == APP_PASSWORD
    assert ACCOUNT_PASSWORD not in result.output and APP_PASSWORD not in result.output
    person = users.read_people(users.state_path(site))[ADDRESS]
    assert person["enabled"] and ACCOUNT_PASSWORD not in json.dumps(person)
    assert native_https[1] == ["/.well-known/jmap", "/jmap/"]


@pytest.mark.parametrize("failure", ["missing", "malformed"])
@pytest.mark.parametrize("mode", ["files", "self-signed"])
def test_configured_ca_fails_closed(tmp_path, private_ca, native_https, failure, mode):
    params = client_params(tmp_path, private_ca, native_https, mode)
    ca = params.tls_dir / "ca.pem"
    if failure == "missing":
        ca.unlink()
    else:
        ca.write_text("not a certificate")
    with pytest.raises(FileNotFoundError if failure == "missing" else ssl.SSLError):
        mail_client.issue_app_password(params, ADDRESS, ACCOUNT_PASSWORD, tmp_path / "app")
    assert not (tmp_path / "app").exists()
    assert native_https[1] == []


@pytest.mark.parametrize("failure", ["wrong-host", "unknown-issuer"])
def test_untrusted_https_refuses_credentials(tmp_path, private_ca, native_https, failure):
    params = client_params(
        tmp_path, private_ca, native_https, configured_ca=failure != "unknown-issuer"
    )
    if failure == "wrong-host":
        params.mx_host = "localhost"  # Certificate has only IP:127.0.0.1.
    context = ssl.create_default_context(
        cafile=str(params.tls_dir / "ca.pem") if failure == "wrong-host" else None
    )
    reason = "Hostname mismatch" if failure == "wrong-host" else "unable to get local issuer"
    with pytest.raises(ssl.SSLCertVerificationError, match=reason):
        mail_client.https_request(params.mx_host, native_https[0], "/.well-known/jmap", context)
    with pytest.raises(OSError, match="stage=session status=transport"):
        mail_client.issue_app_password(params, ADDRESS, ACCOUNT_PASSWORD, tmp_path / "app")
    assert not (tmp_path / "app").exists()
    assert native_https[1] == []  # TLS fails before any HTTP authentication header arrives.


def test_files_without_ca_uses_default_trust_not_stale_staged_ca(
    tmp_path, private_ca, native_https, monkeypatch
):
    params = client_params(tmp_path, private_ca, native_https, configured_ca=False)
    (params.tls_dir / "ca.pem").write_text("stale malformed CA must be ignored")
    # OpenSSL's process-local default trust store, not a mocked SSLContext.
    monkeypatch.setenv("SSL_CERT_FILE", str(private_ca / "ca.pem"))
    empty = tmp_path / "empty-ca-dir"
    empty.mkdir()
    monkeypatch.setenv("SSL_CERT_DIR", str(empty))
    output = tmp_path / "app"
    mail_client.issue_app_password(params, ADDRESS, ACCOUNT_PASSWORD, output)
    assert output.read_text().strip() == APP_PASSWORD
    assert native_https[1] == ["/.well-known/jmap", "/jmap/"]
