from __future__ import annotations

import imaplib

from amx import testkit


class FakeImap:
    def __init__(self, *_args, **_kwargs) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def login(self, _user: str, _password: str) -> None:
        return None

    def lsub(self):
        return "OK", [
            b'(\\HasNoChildren) "/" INBOX',
            b'(\\HasNoChildren) "/" Outbox/Held',
            b'(\\HasNoChildren) "/" "Outbox/Approved"',
            # Stalwart shows another account's folders under a prefix with a space in it.
            b'(\\Subscribed) "/" "Shared Folders/holds@contoso.test/Holds/intake/Held"',
            b'() "/" "odd \\"name\\""',
            None,
        ]


def test_subscribed_folders_parses_lsub_names(monkeypatch) -> None:
    monkeypatch.setattr(imaplib, "IMAP4", FakeImap)
    assert testkit.subscribed_folders("mail.test", "user", "password") == frozenset(
        {
            "INBOX",
            "Outbox/Held",
            "Outbox/Approved",
            "Shared Folders/holds@contoso.test/Holds/intake/Held",
            'odd "name"',
        }
    )
