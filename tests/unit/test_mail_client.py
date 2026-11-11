"""Native discovery parsing and JMAP secondary-credential protocol regressions."""

import base64
import json
import ssl
from types import SimpleNamespace

import pytest

from amx.mail_client import discover, issue_app_password

XML = b"""<clientConfig><emailProvider>
<incomingServer type="imap"><hostname>mail.home.arpa</hostname><port>993</port>
<socketType>SSL</socketType><username>%EMAILADDRESS%</username>
<authentication>password-cleartext</authentication></incomingServer>
<outgoingServer type="smtp"><hostname>mail.home.arpa</hostname><port>465</port>
<socketType>SSL</socketType><username>%EMAILADDRESS%</username>
<authentication>password-cleartext</authentication></outgoingServer>
</emailProvider></clientConfig>"""


def test_native_lookup_order_and_real_parsed_settings():
    calls = []

    def request(host, port, path, context):
        calls.append((host, port, path))
        if len(calls) < 3:
            raise OSError("missing native endpoint")
        return XML

    settings = discover(
        "mail.home.arpa", "alice@home.arpa", ssl.create_default_context(), request=request
    )
    assert [call[0] for call in calls] == ["autoconfig.home.arpa", "home.arpa", "mail.home.arpa"]
    assert all("emailaddress=alice%40home.arpa" in call[2] for call in calls)
    assert settings.imap_port == 993 and settings.smtp_port == 465
    assert settings.username == "alice@home.arpa"


@pytest.mark.parametrize(
    "bad",
    [
        XML.replace(b"mail.home.arpa", b"evil.test"),
        XML.replace(b">SSL<", b">plain<"),
        XML.replace(b"%EMAILADDRESS%", b"other@home.arpa"),
    ],
)
def test_no_external_or_plaintext_settings(bad):
    with pytest.raises(ValueError):
        discover(
            "mail.home.arpa",
            "alice@home.arpa",
            ssl.create_default_context(),
            request=lambda *_: bad,
        )


def test_no_invented_static_fallback():
    with pytest.raises(OSError, match="no invented settings"):
        discover(
            "mail.home.arpa",
            "alice@home.arpa",
            ssl.create_default_context(),
            request=lambda *_: b"<missing/>",
        )


def test_native_app_password_is_created_by_server_and_saved_once(tmp_path):
    params = SimpleNamespace(mx_host="mail.home.arpa", ports={"discovery": 443}, tls_mode="acme")
    calls = []

    def request(host, port, path, context, *, body=None, headers=None):
        assert headers["Authorization"].startswith("Basic ")
        decoded = base64.b64decode(headers["Authorization"].removeprefix("Basic "), validate=True)
        if decoded != b"alice@home.arpa:private-account-password":
            raise ValueError("invalid fixture credentials")
        assert "password" not in path
        calls.append((path, body))
        if body is None:
            return json.dumps(
                {
                    "apiUrl": "https://mail.home.arpa/jmap/",
                    "primaryAccounts": {"urn:ietf:params:jmap:mail": "b"},
                }
            ).encode()
        payload = json.loads(body)
        assert payload["methodCalls"][0][0] == "x:AppPassword/set"
        assert payload["methodCalls"][0][1]["accountId"] == "b"
        assert "secret" not in payload["methodCalls"][0][1]["create"]["mail"]
        return json.dumps(
            {
                "methodResponses": [
                    [
                        "x:AppPassword/set",
                        {
                            "created": {
                                "mail": {"id": "b", "secret": "app_fixture-generated-by-server"}
                            }
                        },
                        "app",
                    ]
                ]
            }
        ).encode()

    output = tmp_path / "app"
    issue_app_password(
        params, "alice@home.arpa", "private-account-password", output, request=request
    )
    assert output.read_text().strip() == "app_fixture-generated-by-server"
    assert output.stat().st_mode & 0o777 == 0o600
    with pytest.raises(FileExistsError):
        issue_app_password(
            params, "alice@home.arpa", "private-account-password", output, request=request
        )
    assert len([body for _, body in calls if body]) == 1
    with pytest.raises(ValueError, match="invalid fixture credentials"):
        issue_app_password(params, "alice@home.arpa", "wrong", tmp_path / "wrong", request=request)
    assert not (tmp_path / "wrong").exists()


def test_native_api_cannot_redirect_credentials(tmp_path):
    params = SimpleNamespace(mx_host="mail.home.arpa", ports={"discovery": 443}, tls_mode="acme")

    def request(*args, **kwargs):
        return json.dumps({"apiUrl": "https://evil.test/jmap/"}).encode()

    with pytest.raises(ValueError, match="cross-origin"):
        issue_app_password(params, "alice@home.arpa", "private", tmp_path / "app", request=request)
    assert not (tmp_path / "app").exists()
